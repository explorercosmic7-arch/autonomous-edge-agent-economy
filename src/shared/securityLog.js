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

let _securityEventsReady = false;
let _lastSecurityError = null;

export function getLastSecurityError() {
  return _lastSecurityError;
}

const CREATE_SQL =
  "CREATE TABLE IF NOT EXISTS security_events (" +
  "id TEXT PRIMARY KEY, " +
  "created_at TEXT NOT NULL, " +
  "kind TEXT NOT NULL, " +
  "severity TEXT NOT NULL DEFAULT 'info', " +
  "user_id TEXT, " +
  "key_id TEXT, " +
  "repo_id TEXT, " +
  "amount_usd REAL, " +
  "request_id TEXT, " +
  "ip TEXT, " +
  "verb TEXT, " +
  "reason TEXT, " +
  "meta_json TEXT" +
  ")";

export async function ensureSecurityEventsTable(env) {
  if (!env || !env.DB) {
    _lastSecurityError = "no_db_binding";
    return false;
  }
  if (_securityEventsReady) return true;
  try {
    await env.DB.prepare(CREATE_SQL).run();
    try {
      await env.DB.prepare(
        "CREATE INDEX IF NOT EXISTS idx_sevt_user_created ON security_events(user_id, created_at)"
      ).run();
    } catch (_) {}
    try {
      await env.DB.prepare(
        "CREATE INDEX IF NOT EXISTS idx_sevt_kind_created ON security_events(kind, created_at)"
      ).run();
    } catch (_) {}
    // Prove table is readable
    await env.DB.prepare("SELECT 1 AS ok FROM security_events LIMIT 1").all();
    _securityEventsReady = true;
    _lastSecurityError = null;
    return true;
  } catch (e) {
    _lastSecurityError = "ensure: " + String(e && e.message ? e.message : e);
    console.log("security_events_ensure", _lastSecurityError);
    return false;
  }
}

export async function recordSecurityEvent(env, row, request) {
  if (!env || !env.DB || !row || !row.kind) {
    _lastSecurityError = "record_skip_bad_args";
    return null;
  }
  await ensureSecurityEventsTable(env);
  const id = row.id || "sevt_" + randomId(12);
  let ip = row.ip || null;
  if (!ip && request) {
    try {
      const edge = getRequestEdge(request);
      ip = edge && edge.ip ? String(edge.ip).slice(0, 64) : null;
    } catch (_) {}
  }
  const severity = row.severity || "info";
  const binds = [
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
    safeMeta(row.meta),
  ];
  const INSERT_SQL =
    "INSERT INTO security_events (" +
    "id, created_at, kind, severity, " +
    "user_id, key_id, repo_id, amount_usd, " +
    "request_id, ip, verb, reason, meta_json" +
    ") VALUES (?1, datetime('now'), ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)";

  try {
    await env.DB.prepare(INSERT_SQL).bind(...binds).run();
    _lastSecurityError = null;
    return id;
  } catch (e) {
    _lastSecurityError = "insert: " + String(e && e.message ? e.message : e);
    console.log("security_event_insert", _lastSecurityError);
    // force re-ensure + one retry
    try {
      _securityEventsReady = false;
      await ensureSecurityEventsTable(env);
      await env.DB.prepare(INSERT_SQL).bind(...binds).run();
      _lastSecurityError = null;
      return id;
    } catch (e2) {
      _lastSecurityError = "insert_retry: " + String(e2 && e2.message ? e2.message : e2);
      console.log("security_event_insert_retry", _lastSecurityError);
      return null;
    }
  }
}

/**
 * List recent events for a user (dashboard).
 */
export async function listSecurityEventsForUser(env, userId, limit) {
  const lim = Math.min(
    Math.max(Number(limit) || SECURITY_EVENTS_LIST_MAX || 50, 1),
    100
  );
  await ensureSecurityEventsTable(env);
  try {
    const { results } = await env.DB.prepare(
      "SELECT id, created_at, kind, severity, user_id, key_id, repo_id, " +
        "amount_usd, request_id, ip, verb, reason, meta_json " +
        "FROM security_events WHERE user_id = ?1 " +
        "ORDER BY created_at DESC LIMIT ?2"
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
    _lastSecurityError = "list: " + String(e && e.message ? e.message : e);
    console.log("security_event_list", _lastSecurityError);
    return [];
  }
}

/** Debug: total rows in table (any user). */
export async function countSecurityEventsAll(env) {
  try {
    await ensureSecurityEventsTable(env);
    const row = await env.DB.prepare(
      "SELECT COUNT(*) AS c FROM security_events"
    ).first();
    return Number(row && row.c) || 0;
  } catch (e) {
    _lastSecurityError = "count: " + String(e && e.message ? e.message : e);
    console.log("security_event_count_all", _lastSecurityError);
    return -1;
  }
}

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


/** Debug: total rows in table (any user). */
