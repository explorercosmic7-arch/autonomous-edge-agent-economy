/**
 * Shared Edge Shield — adaptive circuit-breaker + agent quarantine.
 * Used by safetyGate and /api/shield routes. No route handlers here.
 */
import { bad } from "./http.js";
import { randomId } from "./utils.js";
import {
  SHIELD_LEVEL_NORMAL,
  SHIELD_LEVEL_WATCH,
  SHIELD_LEVEL_THROTTLE,
  SHIELD_LEVEL_FREEZE,
  SHIELD_LEVEL_EMERGENCY,
  SHIELD_AUTO_LOCKS_TRIP,
  SHIELD_AUTO_WINDOW_SEC,
  SHIELD_COOLDOWN_SEC,
  SHIELD_MAX_LEVEL,
} from "./constants.js";

/* ─── Edge Shield helpers ─── */

export async function logShieldEvent(env, event, { scope, scope_id, level, reason, meta } = {}) {
  try {
    await env.DB.prepare(
      `INSERT INTO shield_events (id, scope, scope_id, event, level, reason, meta_json, created_at)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, datetime('now'))`
    )
      .bind(
        randomId(12),
        scope || "repo",
        scope_id || null,
        event,
        level != null ? Number(level) : null,
        reason ? String(reason).slice(0, 500) : null,
        meta ? JSON.stringify(meta) : null
      )
      .run();
  } catch (e) {
    console.log("shield_event_err", e && e.message);
  }
}

export async function ensureShieldRow(env, id) {
  try {
    await env.DB.prepare(
      `INSERT INTO edge_shield (id, level, trip_count, updated_at)
       VALUES (?1, 0, 0, datetime('now'))
       ON CONFLICT(id) DO NOTHING`
    )
      .bind(id)
      .run();
  } catch (e) {
    // table may be missing — callers handle
  }
}

export async function getShield(env, id) {
  try {
    await ensureShieldRow(env, id);
    const row = await env.DB.prepare(`SELECT * FROM edge_shield WHERE id = ?1`).bind(id).first();
    if (!row) return { id, level: 0, reason: null, cools_at: null };
    // auto cool-down
    if (row.cools_at && Number(row.level) > 0) {
      const ms = Date.parse(String(row.cools_at).replace(" ", "T") + "Z");
      if (Number.isFinite(ms) && ms < Date.now()) {
        await env.DB.prepare(
          `UPDATE edge_shield
           SET level = 0, reason = NULL, cools_at = NULL, updated_at = datetime('now')
           WHERE id = ?1`
        )
          .bind(id)
          .run();
        await logShieldEvent(env, "cooled", {
          scope: id === "global" ? "global" : "repo",
          scope_id: id,
          level: 0,
          reason: "auto_cooldown",
        });
        return { id, level: 0, reason: null, cools_at: null, trip_count: row.trip_count };
      }
    }
    return row;
  } catch {
    return { id, level: 0, reason: null, cools_at: null };
  }
}

export async function setShieldLevel(env, id, level, reason, { cooldownSec } = {}) {
  level = Math.max(0, Math.min(SHIELD_MAX_LEVEL, Math.floor(Number(level) || 0)));
  const cd = cooldownSec != null ? Number(cooldownSec) : SHIELD_COOLDOWN_SEC;
  const modifier = level > 0 ? "+" + Math.max(30, cd) + " seconds" : null;
  await ensureShieldRow(env, id);
  if (level === 0) {
    await env.DB.prepare(
      `UPDATE edge_shield
       SET level = 0, reason = NULL, cools_at = NULL, updated_at = datetime('now')
       WHERE id = ?1`
    )
      .bind(id)
      .run();
  } else {
    await env.DB.prepare(
      `UPDATE edge_shield
       SET level = ?2,
           reason = ?3,
           trip_count = trip_count + 1,
           last_trip_at = datetime('now'),
           cools_at = datetime('now', ?4),
           updated_at = datetime('now')
       WHERE id = ?1`
    )
      .bind(id, level, String(reason || "shield").slice(0, 500), modifier)
      .run();
  }
  await logShieldEvent(env, level === 0 ? "released" : "trip", {
    scope: id === "global" ? "global" : "repo",
    scope_id: id,
    level,
    reason,
  });
  return getShield(env, id);
}

/** Count recent wallet locks — drives global auto-trip. */
export async function countRecentWalletLocks(env) {
  try {
    const row = await env.DB.prepare(
      `SELECT COUNT(*) AS c FROM safety_events
       WHERE event = 'wallet.locked'
         AND created_at >= datetime('now', ?1)`
    )
      .bind("-" + SHIELD_AUTO_WINDOW_SEC + " seconds")
      .first();
    return Number(row?.c || 0);
  } catch {
    return 0;
  }
}

/**
 * Shield gate: returns bad() Response if spend blocked, or null if OK.
 * Throttle level only annotates; FREEZE+ blocks discretionary spends.
 */
export async function checkShieldGate(request, env, fromRepo) {
  const global = await getShield(env, "global");
  const gLevel = Number(global.level || 0);
  if (gLevel >= SHIELD_LEVEL_EMERGENCY) {
    return bad(request, "Global emergency shield active — discretionary spends frozen", 503, {
      code: "shield_emergency",
      shield_level: gLevel,
      reason: global.reason || "emergency",
      cools_at: global.cools_at || null,
    });
  }
  if (gLevel >= SHIELD_LEVEL_FREEZE) {
    return bad(request, "Network shield freeze — new spends paused (refunds/settles still work)", 503, {
      code: "shield_freeze",
      shield_level: gLevel,
      reason: global.reason || "freeze",
      cools_at: global.cools_at || null,
    });
  }

  if (fromRepo) {
    const local = await getShield(env, fromRepo);
    const lLevel = Number(local.level || 0);
    if (lLevel >= SHIELD_LEVEL_FREEZE) {
      return bad(request, "Agent quarantined by Edge Shield — new spends blocked until cool-down or release", 403, {
        code: "shield_quarantine",
        shield_level: lLevel,
        reason: local.reason || "quarantine",
        cools_at: local.cools_at || null,
        repo_id: fromRepo,
      });
    }
  }
  return null;
}

export async function maybeAutoTripGlobalShield(env) {
  try {
    const locks = await countRecentWalletLocks(env);
    if (locks < SHIELD_AUTO_LOCKS_TRIP) return null;
    const g = await getShield(env, "global");
    const cur = Number(g.level || 0);
    if (cur >= SHIELD_LEVEL_THROTTLE) return g;
    return await setShieldLevel(
      env,
      "global",
      SHIELD_LEVEL_THROTTLE,
      "auto: " + locks + " wallet locks in " + SHIELD_AUTO_WINDOW_SEC + "s",
      { cooldownSec: SHIELD_COOLDOWN_SEC }
    );
  } catch (e) {
    console.log("auto_trip_shield", e && e.message);
    return null;
  }
}
