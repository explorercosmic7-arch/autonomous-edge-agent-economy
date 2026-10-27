/**
 * Shared auth — sessions, API keys, colo/IP binding, getAuthUser.
 */
import { parseCookies, sha256Hex, COOKIE_NAME } from "./utils.js";
import { getRequestEdge, hashIp } from "./edge.js";
import { logSafetyEvent } from "./safety.js";
import { bad } from "./http.js";
import { DASHBOARD_URL } from "./constants.js";

/* ─── Auth ─── */

export async function getSessionUser(request, env) {
  const cookies = parseCookies(request.headers.get("Cookie"));
  const sid = cookies[COOKIE_NAME];
  if (!sid) return null;

  const row = await env.DB.prepare(
    `SELECT s.id AS session_id, s.expires_at,
            u.id, u.email, u.name, u.picture, u.provider, u.default_repo
     FROM sessions s
     JOIN users u ON u.id = s.user_id
     WHERE s.id = ?1`
  )
    .bind(sid)
    .first();

  if (!row) return null;
  if (new Date(row.expires_at).getTime() < Date.now()) {
    await env.DB.prepare(`DELETE FROM sessions WHERE id = ?`).bind(sid).run();
    return null;
  }
  return row;
}

/**
 * Security: if a valid session already exists, OAuth callbacks must not
 * silently switch identity. User must POST /api/auth/logout first, then
 * sign in with the other provider.
 * Returns Response redirect when blocked; null when OK to continue OAuth.
 */
export async function rejectIfAlreadySignedIn(request, env) {
  const existing = await getSessionUser(request, env);
  if (!existing) return null;
  return Response.redirect(
    `${DASHBOARD_URL}?auth_error=${encodeURIComponent("already_signed_in")}`,
    302
  );
}


/**
 * Enforce colo/IP binding on an API key row.
 * Returns null if OK, or { code, error, ... } if blocked.
 * May learn-bind on first use (mode=learn).
 */
export async function enforceKeyBinding(env, keyRow, request) {
  if (!keyRow || !keyRow.key_id) return null;
  let mode = (keyRow.bind_mode || "").toLowerCase().trim();
  if (!mode || mode === "none" || mode === "off") {
    // Still record last edge for visibility
    try {
      const edge = getRequestEdge(request);
      const ipHash = await hashIp(edge.ip);
      await env.DB.prepare(
        `UPDATE api_keys SET last_colo = ?2, last_ip_hash = ?3, last_used_at = datetime('now')
         WHERE id = ?1`
      )
        .bind(keyRow.key_id, edge.colo, ipHash)
        .run();
    } catch (_) {}
    return null;
  }

  const edge = getRequestEdge(request);
  const ipHash = await hashIp(edge.ip);
  let boundColo = keyRow.bound_colo ? String(keyRow.bound_colo).toUpperCase() : null;
  let boundIp = keyRow.bound_ip_hash || null;

  // Learn: pin on first successful sighting
  if (mode === "learn" && !boundColo && !boundIp) {
    try {
      await env.DB.prepare(
        `UPDATE api_keys
         SET bound_colo = ?2, bound_ip_hash = ?3, bound_at = datetime('now'),
             last_colo = ?2, last_ip_hash = ?3, last_used_at = datetime('now'),
             bind_mode = 'either'
         WHERE id = ?1`
      )
        .bind(keyRow.key_id, edge.colo, ipHash)
        .run();
      await logSafetyEvent(env, "key.edge_bound", {
        api_key_id: keyRow.key_id,
        user_id: keyRow.user_id || keyRow.id,
        reason: "learn",
        meta: { colo: edge.colo, has_ip: !!ipHash },
      });
    } catch (e) {
      console.log("key_learn_bind", e && e.message);
    }
    return null;
  }

  // If edge metadata missing (local / non-CF), allow — do not lock out operators offline
  if (!edge.colo && !ipHash) {
    return null;
  }

  const coloOk = !!(boundColo && edge.colo && boundColo === edge.colo);
  const ipOk = !!(boundIp && ipHash && boundIp === ipHash);

  let allowed = false;
  if (mode === "colo") allowed = coloOk || (!boundColo && !!edge.colo);
  else if (mode === "ip") allowed = ipOk || (!boundIp && !!ipHash);
  else if (mode === "both") allowed = (boundColo ? coloOk : true) && (boundIp ? ipOk : true) && (coloOk || ipOk || (!boundColo && !boundIp));
  else if (mode === "either" || mode === "learn") allowed = coloOk || ipOk;
  else allowed = true;

  // First-use pin for colo/ip/both when bounds empty
  if (!allowed && (mode === "colo" || mode === "ip" || mode === "both") && !boundColo && !boundIp) {
    try {
      await env.DB.prepare(
        `UPDATE api_keys
         SET bound_colo = ?2, bound_ip_hash = ?3, bound_at = datetime('now'),
             last_colo = ?2, last_ip_hash = ?3, last_used_at = datetime('now')
         WHERE id = ?1`
      )
        .bind(keyRow.key_id, edge.colo, ipHash)
        .run();
      return null;
    } catch (_) {}
  }

  if (allowed) {
    try {
      await env.DB.prepare(
        `UPDATE api_keys SET last_colo = ?2, last_ip_hash = ?3, last_used_at = datetime('now')
         WHERE id = ?1`
      )
        .bind(keyRow.key_id, edge.colo, ipHash)
        .run();
    } catch (_) {}
    return null;
  }

  // Violation
  try {
    await env.DB.prepare(
      `UPDATE api_keys
       SET bind_violations = COALESCE(bind_violations, 0) + 1,
           last_colo = ?2, last_ip_hash = ?3, last_used_at = datetime('now')
       WHERE id = ?1`
    )
      .bind(keyRow.key_id, edge.colo, ipHash)
      .run();
    await logSafetyEvent(env, "key.edge_mismatch", {
      api_key_id: keyRow.key_id,
      user_id: keyRow.user_id || keyRow.id,
      reason: "edge_mismatch",
      meta: {
        mode,
        bound_colo: boundColo,
        got_colo: edge.colo,
        ip_match: ipOk,
      },
    });
  } catch (_) {}

  return {
    code: "key_edge_mismatch",
    error:
      "API key bound to another edge (colo/IP). Stolen or off-edge use blocked.",
    bind_mode: mode,
    bound_colo: boundColo,
    got_colo: edge.colo || null,
  };
}


export async function getApiKeyUser(request, env) {
  const auth = request.headers.get("Authorization") || "";
  const m = auth.match(/^Bearer\s+(a2a_[A-Fa-f0-9]+)$/i);
  if (!m) return null;

  const raw = m[1];
  const hash = await sha256Hex(raw);

  let row;
  try {
    row = await env.DB.prepare(
      `SELECT k.id AS key_id, k.user_id, k.revoked_at, k.suspended_at, k.suspend_reason,
              k.bound_colo, k.bound_ip_hash, k.bind_mode, k.last_colo, k.bind_violations,
              u.id, u.email, u.name, u.picture, u.provider, u.default_repo
       FROM api_keys k
       JOIN users u ON u.id = k.user_id
       WHERE k.key_hash = ?1`
    )
      .bind(hash)
      .first();
  } catch (_) {
    // columns may be missing until ALTER — fall back progressively
    try {
      row = await env.DB.prepare(
        `SELECT k.id AS key_id, k.user_id, k.revoked_at, k.suspended_at, k.suspend_reason,
                u.id, u.email, u.name, u.picture, u.provider, u.default_repo
         FROM api_keys k
         JOIN users u ON u.id = k.user_id
         WHERE k.key_hash = ?1`
      )
        .bind(hash)
        .first();
    } catch (__) {
      row = await env.DB.prepare(
        `SELECT k.id AS key_id, k.user_id, k.revoked_at,
                u.id, u.email, u.name, u.picture, u.provider, u.default_repo
         FROM api_keys k
         JOIN users u ON u.id = k.user_id
         WHERE k.key_hash = ?1`
      )
        .bind(hash)
        .first();
    }
  }

  if (!row || row.revoked_at) return null;
  if (row.suspended_at) {
    row._suspended = true;
    row._suspend_reason = row.suspend_reason || "API key suspended";
    return row;
  }

  // Colo / IP binding — stolen keys fail off-edge
  try {
    const edgeBlock = await enforceKeyBinding(env, row, request);
    if (edgeBlock) {
      row._edge_blocked = true;
      row._edge_error = edgeBlock.error;
      row._edge_code = edgeBlock.code;
      row._edge_meta = edgeBlock;
      return row;
    }
  } catch (e) {
    console.log("enforce_key_binding", e && e.message);
  }

  env.DB.prepare(`UPDATE api_keys SET last_used_at = datetime('now') WHERE id = ?`)
    .bind(row.key_id)
    .run()
    .catch(() => {});

  return row;
}

export async function getAuthUser(request, env) {
  const session = await getSessionUser(request, env);
  if (session) return { ...session, auth_via: "session" };
  const keyUser = await getApiKeyUser(request, env);
  if (keyUser) {
    if (keyUser._suspended) {
      return { ...keyUser, auth_via: "api_key", suspended: true };
    }
    if (keyUser._edge_blocked) {
      return {
        ...keyUser,
        auth_via: "api_key",
        edge_blocked: true,
        _edge_error: keyUser._edge_error,
        _edge_code: keyUser._edge_code,
        _edge_meta: keyUser._edge_meta,
      };
    }
    return { ...keyUser, auth_via: "api_key" };
  }
  return null;
}

/** Return 403 Response if auth user is a suspended API key; else null. */
export function rejectIfSuspendedKey(request, authUser) {
  if (authUser && authUser.auth_via === "api_key" && (authUser.suspended || authUser._suspended)) {
    return bad(
      request,
      authUser._suspend_reason || authUser.suspend_reason || "API key suspended (kill-switch)",
      403,
      { code: "key_suspended" }
    );
  }
  if (authUser && authUser.auth_via === "api_key" && (authUser.edge_blocked || authUser._edge_blocked)) {
    const meta = authUser._edge_meta || {};
    return bad(
      request,
      authUser._edge_error || "API key bound to another edge",
      403,
      {
        code: authUser._edge_code || "key_edge_mismatch",
        bind_mode: meta.bind_mode || null,
        bound_colo: meta.bound_colo || null,
        got_colo: meta.got_colo || null,
      }
    );
  }
  return null;
}

