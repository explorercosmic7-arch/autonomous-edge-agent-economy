/**
 * Immutable security event log + anomaly detection (burst / denial storm).
 *
 * Table: security_events (append-only from app code — INSERT only).
 * See d1-security-events.sql
 *
 * Kinds:
 *   pay.ok | pay.fail | scope.deny
 *   key.create | key.revoke | key.rotate | key.suspend | key.disable | key.unsuspend | key.expired
 *   key.edge_mismatch (optional)
 */
import { randomId } from "./utils.js";
import { getRequestEdge } from "./edge.js";
import {
  ANOMALY_BURST_MAX,
  ANOMALY_BURST_WINDOW_SEC,
  ANOMALY_DENY_MAX,
  ANOMALY_DENY_WINDOW_SEC,
  SECURITY_EVENTS_LIST_MAX,
} from "./constants.js";

function safeMeta(meta) {
  if (meta == null) return null;
  try {
    const s = JSON.stringify(meta);
    if (s.length > 4000) return s.slice(0, 4000);
    return s;
  } catch {
    return null;
  }
}

/**
 * Append one security event. Never throws to callers (logs and returns).
 * @param {object} env
 * @param {object} row
 * @param {Request} [request] — optional, fills ip from CF-Connecting-IP
 */
export async function recordSecurityEvent(env, row, request) {
  if (!env || !env.DB || !row || !row.kind) return null;
  const id = row.id || "sevt_" + randomId(12);
  let ip = row.ip || null;
  if (!ip && request) {
    try {
      const edge = getRequestEdge(request);
      ip = edge && edge.ip ? String(edge.ip).slice(0, 64) : null;
    } catch (_) {}
  }
  const severity = row.severity || "info";
  try {
    await env.DB.prepare(
      `INSERT INTO security_events (
         id, created_at, kind, severity,
         user_id, key_id, repo_id, amount_usd,
         request_id, ip, verb, reason, meta_json
       ) VALUES (
         ?1, datetime('now'), ?2, ?3,
         ?4, ?5, ?6, ?7,
         ?8, ?9, ?10, ?11, ?12
       )`
    )
      .bind(
        id,
        String(row.kind).slice(0, 64),
        String(severity).slice(0, 16),
        row.user_id || null,
        row.key_id || null,
        row.repo_id || null,
        row.amount_usd != null ? Number(row.amount_usd) : null,
        row.request_id ? String(row.request_id).slice(0, 128) : null,
        ip,
        row.verb ? String(row.verb).slice(0, 32) : null,
        row.reason ? String(row.reason).slice(0, 256) : null,
        safeMeta(row.meta)
      )
      .run();
    return id;
  } catch (e) {
    // Table missing until migration — soft fail
    console.log("security_event_insert", e && e.message);
    return null;
  }
}

/**
 * List recent events for a user (dashboard).
 */
export async function listSecurityEventsForUser(env, userId, limit) {
  const lim = Math.min(
    Math.max(Number(limit) || SECURITY_EVENTS_LIST_MAX, 1),
    100
  );
  try {
    const { results } = await env.DB.prepare(
      `SELECT id, created_at, kind, severity, user_id, key_id, repo_id,
              amount_usd, request_id, ip, verb, reason, meta_json
       FROM security_events
       WHERE user_id = ?1
       ORDER BY created_at DESC
       LIMIT ?2`
    )
      .bind(userId, lim)
      .all();
    return (results || []).map((r) => ({
      id: r.id,
      created_at: r.created_at,
      kind: r.kind,
      severity: r.severity,
      user_id: r.user_id,
      key_id: r.key_id,
      repo_id: r.repo_id,
      amount_usd: r.amount_usd != null ? Number(r.amount_usd) : null,
      request_id: r.request_id,
      ip: r.ip,
      verb: r.verb,
      reason: r.reason,
      meta: (() => {
        try {
          return r.meta_json ? JSON.parse(r.meta_json) : null;
        } catch {
          return null;
        }
      })(),
    }));
  } catch (e) {
    console.log("security_event_list", e && e.message);
    return [];
  }
}

async function countRecentByKinds(env, keyId, kinds, windowSec) {
  if (!keyId || !kinds || !kinds.length) return 0;
  const placeholders = kinds.map(() => "?").join(",");
  // bind: keyId, ...kinds, windowSec — SQLite datetime('-N seconds')
  const sql = `SELECT COUNT(*) AS c FROM security_events
    WHERE key_id = ?1
      AND kind IN (${placeholders})
      AND created_at >= datetime('now', ?${kinds.length + 2})`;
  const binds = [keyId, ...kinds, `-${Math.max(1, windowSec)} seconds`];
  try {
    // Rebuild with positional binds for D1
    const q = await env.DB.prepare(
      `SELECT COUNT(*) AS c FROM security_events
       WHERE key_id = ?
         AND kind IN (${placeholders})
         AND created_at >= datetime('now', ?)`
    )
      .bind(keyId, ...kinds, `-${Math.max(1, Number(windowSec) || 1)} seconds`)
      .first();
    return Number(q && q.c != null ? q.c : 0);
  } catch (e) {
    console.log("security_count", e && e.message);
    return 0;
  }
}

/**
 * Burst: too many pay events in a short window → temporary suspend.
 * Returns { suspended: true, reason } if action taken.
 */
export async function checkPaymentBurst(env, { keyId, userId, request }) {
  if (!keyId) return null;
  const n = await countRecentByKinds(
    env,
    keyId,
    ["pay.ok", "pay.fail"],
    ANOMALY_BURST_WINDOW_SEC
  );
  if (n < ANOMALY_BURST_MAX) return null;
  try {
    await env.DB.prepare(
      `UPDATE api_keys
       SET suspended_at = datetime('now'),
           suspend_reason = ?2
       WHERE id = ?1 AND revoked_at IS NULL AND suspended_at IS NULL`
    )
      .bind(keyId, "burst_payments")
      .run();
  } catch (e) {
    console.log("burst_suspend", e && e.message);
  }
  await recordSecurityEvent(
    env,
    {
      kind: "key.suspend",
      severity: "critical",
      user_id: userId || null,
      key_id: keyId,
      reason: "burst_payments",
      meta: { count: n, window_sec: ANOMALY_BURST_WINDOW_SEC },
    },
    request
  );
  return { suspended: true, reason: "burst_payments", count: n };
}

/**
 * Denial storm: many scope.deny in a window → permanent disable.
 * Unsuspend must NOT clear disabled_at.
 */
export async function checkDenialStorm(env, { keyId, userId, request }) {
  if (!keyId) return null;
  const n = await countRecentByKinds(
    env,
    keyId,
    ["scope.deny"],
    ANOMALY_DENY_WINDOW_SEC
  );
  if (n < ANOMALY_DENY_MAX) return null;
  try {
    await env.DB.prepare(
      `UPDATE api_keys
       SET disabled_at = datetime('now'),
           disabled_reason = ?2,
           suspended_at = COALESCE(suspended_at, datetime('now')),
           suspend_reason = COALESCE(suspend_reason, 'denial_storm')
       WHERE id = ?1 AND revoked_at IS NULL AND disabled_at IS NULL`
    )
      .bind(keyId, "denial_storm")
      .run();
  } catch (e) {
    console.log("denial_disable", e && e.message);
  }
  await recordSecurityEvent(
    env,
    {
      kind: "key.disable",
      severity: "critical",
      user_id: userId || null,
      key_id: keyId,
      reason: "denial_storm",
      meta: { count: n, window_sec: ANOMALY_DENY_WINDOW_SEC },
    },
    request
  );
  return { disabled: true, reason: "denial_storm", count: n };
}

/**
 * Call after a pay attempt (success or fail) when auth was API key.
 */
export async function afterPaySecurity(env, request, {
  ok,
  authUser,
  repoId,
  amountUsd,
  requestId,
  reason,
}) {
  if (!authUser || authUser.auth_via !== "api_key") {
    // Still log session pays for audit if desired — include user_id
  }
  const keyId = authUser && authUser.key_id ? authUser.key_id : null;
  const userId = authUser && (authUser.id || authUser.user_id) ? (authUser.id || authUser.user_id) : null;
  await recordSecurityEvent(
    env,
    {
      kind: ok ? "pay.ok" : "pay.fail",
      severity: ok ? "info" : "warn",
      user_id: userId,
      key_id: keyId,
      repo_id: repoId || null,
      amount_usd: amountUsd,
      request_id: requestId || null,
      verb: "pay",
      reason: reason || null,
    },
    request
  );
  if (keyId) {
    return await checkPaymentBurst(env, { keyId, userId, request });
  }
  return null;
}

/**
 * Call when checkKeyScope returns a denial (API key only).
 */
export async function afterScopeDeny(env, request, {
  authUser,
  verb,
  code,
  toRepo,
  amount,
}) {
  if (!authUser || authUser.auth_via !== "api_key") return null;
  const keyId = authUser.key_id || null;
  const userId = authUser.id || authUser.user_id || null;
  await recordSecurityEvent(
    env,
    {
      kind: "scope.deny",
      severity: "warn",
      user_id: userId,
      key_id: keyId,
      verb: verb || null,
      reason: code || "key_scope_denied",
      amount_usd: amount != null ? Number(amount) : null,
      meta: { to_repo: toRepo || null },
    },
    request
  );
  if (keyId) {
    return await checkDenialStorm(env, { keyId, userId, request });
  }
  return null;
}
