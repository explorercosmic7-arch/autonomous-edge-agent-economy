/**
 * Shared Shield API — public/me/admin shield handlers.
 * Core state lives in shield.js; this module is the HTTP surface.
 */
import { json, bad } from "./http.js";
import { parseRepo } from "./utils.js";
import { getAuthUser } from "./auth.js";
import { getShield, setShieldLevel } from "./shield.js";
import { unlockWallet } from "./safety.js";
import { scheduleWebhook } from "./webhooks.js";
import { assertAdminSecret } from "./admin.js";
import {
  SHIELD_MAX_LEVEL,
  SHIELD_COOLDOWN_SEC,
} from "./constants.js";

/* ─── Edge Shield API ─── */

export async function handleShieldPublic(request, env) {
  const global = await getShield(env, "global");
  return json(request, {
    ok: true,
    global: {
      level: Number(global.level || 0),
      reason: global.reason || null,
      cools_at: global.cools_at || null,
      last_trip_at: global.last_trip_at || null,
    },
    levels: {
      0: "normal",
      1: "watch",
      2: "throttle",
      3: "freeze / quarantine",
      4: "emergency",
    },
    hint: "Level ≥3 blocks new spends. Auto-trips on runaway loops and mass wallet locks.",
  });
}

export async function handleMeShieldGet(request, env) {
  const authUser = await getAuthUser(request, env);
  if (!authUser) return bad(request, "Sign in or API key required", 401);

  const global = await getShield(env, "global");
  let repo = authUser.default_repo ? parseRepo(authUser.default_repo) : null;
  let local = null;
  if (repo) local = await getShield(env, repo);

  let events = [];
  try {
    const q = await env.DB.prepare(
      `SELECT event, scope, scope_id, level, reason, created_at
       FROM shield_events
       WHERE scope_id = 'global' OR scope_id = ?1
       ORDER BY created_at DESC LIMIT 20`
    )
      .bind(repo || "")
      .all();
    events = q.results || [];
  } catch (_) {}

  return json(request, {
    ok: true,
    global: {
      level: Number(global.level || 0),
      reason: global.reason || null,
      cools_at: global.cools_at || null,
    },
    agent: local
      ? {
          repo_id: repo,
          level: Number(local.level || 0),
          reason: local.reason || null,
          cools_at: local.cools_at || null,
          trip_count: Number(local.trip_count || 0),
        }
      : null,
    events,
  });
}

export async function handleMeShieldRelease(request, env) {
  const authUser = await getAuthUser(request, env);
  if (!authUser) return bad(request, "Sign in or API key required", 401);

  let body = {};
  try {
    body = await request.json();
  } catch (_) {}

  let repo = parseRepo(body.repo_id || body.repo) || parseRepo(authUser.default_repo);
  if (!repo) return bad(request, "repo_id required (or set default agent)");

  // Only owner session (not pure API key of different agent) — session or matching default_repo
  if (authUser.auth_via === "api_key" && authUser.default_repo !== repo) {
    return bad(request, "API key not bound to this agent", 403);
  }

  const before = await getShield(env, repo);
  if (Number(before.level || 0) === 0) {
    return json(request, { ok: true, already: true, agent: { repo_id: repo, level: 0 } });
  }

  const after = await setShieldLevel(env, repo, 0, "owner_release");
  // Also unlock wallet if locked
  try {
    await unlockWallet(env, repo, { user_id: authUser.id });
  } catch (_) {}

  if (authUser.id) {
    scheduleWebhook(null, env, authUser.id, "shield.released", {
      repo_id: repo,
      previous_level: Number(before.level || 0),
    });
  }

  return json(request, {
    ok: true,
    released: true,
    agent: {
      repo_id: repo,
      level: Number(after.level || 0),
      reason: after.reason || null,
    },
  });
}

export async function handleAdminShield(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return bad(request, "Invalid JSON body");
  }
  const admin = await assertAdminSecret(request, env, body);
  if (!admin.ok) return admin.response;

  const scope = String(body.scope || "global").toLowerCase();
  const id = scope === "global" ? "global" : parseRepo(body.repo_id || body.repo);
  if (scope !== "global" && !id) return bad(request, "repo_id required for repo scope");

  const level = Math.max(0, Math.min(SHIELD_MAX_LEVEL, Math.floor(Number(body.level) || 0)));
  const reason = body.reason ? String(body.reason).slice(0, 500) : "admin";
  const cooldownSec = body.cooldown_sec != null ? Number(body.cooldown_sec) : SHIELD_COOLDOWN_SEC;

  const row = await setShieldLevel(env, id, level, reason, { cooldownSec });
  return json(request, {
    ok: true,
    shield: {
      id,
      level: Number(row.level || 0),
      reason: row.reason || null,
      cools_at: row.cools_at || null,
    },
  }); 
}
