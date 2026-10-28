/**
 * API keys + edge binding — create/list/revoke/bind/unbind, me/key, edge info, unsuspend
 */
import { json, bad } from "./http.js";
import { randomId, sha256Hex } from "./utils.js";
import { checkRateLimit } from "./rateLimit.js";
import { getSessionUser, getAuthUser, rejectIfSuspendedKey } from "./auth.js";
import { getRequestEdge, hashIp } from "./edge.js";
import { logSafetyEvent } from "./safety.js";
import {
  MAX_KEYS_PER_USER,
  RL_KEY_CREATE_MAX,
  RL_KEY_CREATE_WINDOW_SEC,
} from "./constants.js";

/* ─── API keys ─── */

export async function handleMeKeysCreate(request, env) {
  const user = await getSessionUser(request, env);
  if (!user) return bad(request, "Sign in required", 401);

  const limited = await checkRateLimit(
    env,
    "keycreate:" + user.id,
    RL_KEY_CREATE_MAX,
    RL_KEY_CREATE_WINDOW_SEC
  );
  if (limited) {
    return bad(request, "Rate limit: max " + RL_KEY_CREATE_MAX + " keys per hour", 429, {
      retry_after_sec: limited.retry_after_sec,
    });
  }

  let body = {};
  try {
    body = await request.json();
  } catch {
    /* ok */
  }
  const label = String(body.label || "agent").slice(0, 64);

  const countRow = await env.DB.prepare(
    `SELECT COUNT(*) AS c FROM api_keys WHERE user_id = ?1 AND revoked_at IS NULL`
  )
    .bind(user.id)
    .first();
  if ((countRow?.c || 0) >= MAX_KEYS_PER_USER) {
    return bad(request, "Max " + MAX_KEYS_PER_USER + " active keys per user", 429);
  }

  const id = randomId(12);
  const secret = "a2a_" + randomId(24);
  const keyHash = await sha256Hex(secret);
  const keyPrefix = secret.slice(0, 12);

  let bindMode = body.bind_mode != null ? String(body.bind_mode).toLowerCase().trim() : "";
  if (!["", "none", "learn", "colo", "ip", "both", "either"].includes(bindMode)) {
    return bad(request, "bind_mode must be none|learn|colo|ip|both|either");
  }
  if (bindMode === "none") bindMode = "";

  const edge = getRequestEdge(request);
  let boundColo = null;
  let boundIp = null;
  if (bindMode && bindMode !== "learn") {
    boundColo = edge.colo || (body.colo ? String(body.colo).toUpperCase().slice(0, 8) : null);
    boundIp = await hashIp(edge.ip);
  }

  const pinNow = !!(bindMode && bindMode !== "learn");
  try {
    await env.DB.prepare(
      `INSERT INTO api_keys (id, user_id, key_hash, key_prefix, label, bind_mode, bound_colo, bound_ip_hash, bound_at)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)`
    )
      .bind(
        id,
        user.id,
        keyHash,
        keyPrefix,
        label,
        bindMode || null,
        pinNow ? boundColo : null,
        pinNow ? boundIp : null,
        pinNow ? new Date().toISOString().replace("T", " ").slice(0, 19) : null
      )
      .run();
  } catch (_) {
    await env.DB.prepare(
      `INSERT INTO api_keys (id, user_id, key_hash, key_prefix, label)
       VALUES (?1, ?2, ?3, ?4, ?5)`
    )
      .bind(id, user.id, keyHash, keyPrefix, label)
      .run();
    bindMode = "";
  }

  return json(request, {
    ok: true,
    id,
    label,
    key_prefix: keyPrefix,
    key: secret,
    bind_mode: bindMode || null,
    bound_colo: bindMode && bindMode !== "learn" ? boundColo : null,
    edge: { colo: edge.colo, country: edge.country },
    hint: "Copy now. The full key is never shown again." +
      (bindMode ? " Edge binding: " + bindMode + "." : ""),
  });
}

export async function handleMeKeysList(request, env) {
  const user = await getSessionUser(request, env);
  if (!user) return bad(request, "Sign in required", 401);

  let results;
  try {
    const q = await env.DB.prepare(
      `SELECT id, key_prefix, label, created_at, revoked_at, last_used_at,
              suspended_at, suspend_reason,
              bound_colo, bind_mode, last_colo, bind_violations, bound_at
       FROM api_keys WHERE user_id = ?1 ORDER BY created_at DESC LIMIT 50`
    )
      .bind(user.id)
      .all();
    results = q.results || [];
  } catch (_) {
    try {
      const q = await env.DB.prepare(
        `SELECT id, key_prefix, label, created_at, revoked_at, last_used_at, suspended_at, suspend_reason
         FROM api_keys WHERE user_id = ?1 ORDER BY created_at DESC LIMIT 50`
      )
        .bind(user.id)
        .all();
      results = q.results || [];
    } catch (__) {
      const q = await env.DB.prepare(
        `SELECT id, key_prefix, label, created_at, revoked_at, last_used_at
         FROM api_keys WHERE user_id = ?1 ORDER BY created_at DESC LIMIT 50`
      )
        .bind(user.id)
        .all();
      results = q.results || [];
    }
  }

  const edge = getRequestEdge(request);
  return json(request, {
    ok: true,
    count: results.length,
    current_edge: { colo: edge.colo, country: edge.country },
    keys: results.map((k) => ({
      id: k.id,
      key_prefix: k.key_prefix + "…",
      label: k.label,
      created_at: k.created_at,
      revoked: !!k.revoked_at,
      revoked_at: k.revoked_at,
      last_used_at: k.last_used_at,
      suspended: !!k.suspended_at,
      suspended_at: k.suspended_at || null,
      suspend_reason: k.suspend_reason || null,
      bind_mode: k.bind_mode || null,
      bound_colo: k.bound_colo || null,
      last_colo: k.last_colo || null,
      bound_at: k.bound_at || null,
      bind_violations: Number(k.bind_violations || 0),
    })),
  });
}


export async function handleMeKeysBind(request, env) {
  const user = await getSessionUser(request, env);
  if (!user) return bad(request, "Sign in required", 401);

  let body;
  try {
    body = await request.json();
  } catch {
    return bad(request, "Invalid JSON body");
  }
  const id = String(body.id || "").trim();
  if (!id) return bad(request, "id required");

  let mode = body.mode != null ? String(body.mode).toLowerCase().trim() : "either";
  if (!["learn", "colo", "ip", "both", "either"].includes(mode)) {
    return bad(request, "mode must be learn|colo|ip|both|either");
  }

  const row = await env.DB.prepare(
    `SELECT id, user_id, revoked_at FROM api_keys WHERE id = ?1`
  )
    .bind(id)
    .first();
  if (!row || row.user_id !== user.id) return bad(request, "Key not found", 404);
  if (row.revoked_at) return bad(request, "Key revoked", 400);

  const edge = getRequestEdge(request);
  const colo =
    (body.colo && String(body.colo).toUpperCase().slice(0, 8)) || edge.colo || null;
  const ipHash = await hashIp(edge.ip);

  if (mode !== "learn" && mode !== "ip" && !colo) {
    return bad(request, "No colo on this request and none provided — cannot bind", 400, {
      code: "no_colo",
    });
  }

  try {
    if (mode === "learn") {
      await env.DB.prepare(
        `UPDATE api_keys
         SET bind_mode = 'learn', bound_colo = NULL, bound_ip_hash = NULL,
             bound_at = NULL
         WHERE id = ?1`
      )
        .bind(id)
        .run();
    } else {
      await env.DB.prepare(
        `UPDATE api_keys
         SET bind_mode = ?2,
             bound_colo = ?3,
             bound_ip_hash = ?4,
             bound_at = datetime('now'),
             last_colo = COALESCE(?3, last_colo),
             last_ip_hash = COALESCE(?4, last_ip_hash)
         WHERE id = ?1`
      )
        .bind(
          id,
          mode,
          mode === "ip" ? null : colo,
          mode === "colo" ? null : ipHash
        )
        .run();
    }
  } catch (e) {
    return bad(
      request,
      "Colo columns missing — run d1-colo-migration.sql: " + (e.message || e),
      500
    );
  }

  await logSafetyEvent(env, "key.edge_bound", {
    api_key_id: id,
    user_id: user.id,
    reason: mode,
    meta: { colo, mode },
  });

  return json(request, {
    ok: true,
    id,
    bind_mode: mode,
    bound_colo: mode === "ip" || mode === "learn" ? null : colo,
    bound_ip: mode === "colo" || mode === "learn" ? false : !!ipHash,
    current_edge: { colo: edge.colo, country: edge.country },
    hint:
      mode === "learn"
        ? "First API use will pin colo + IP, then enforce either."
        : "Key locked to this edge. Off-edge requests return 403 key_edge_mismatch.",
  });
}

export async function handleMeKeysUnbind(request, env) {
  const user = await getSessionUser(request, env);
  if (!user) return bad(request, "Sign in required", 401);

  let body;
  try {
    body = await request.json();
  } catch {
    return bad(request, "Invalid JSON body");
  }
  const id = String(body.id || "").trim();
  if (!id) return bad(request, "id required");

  const row = await env.DB.prepare(
    `SELECT id, user_id FROM api_keys WHERE id = ?1`
  )
    .bind(id)
    .first();
  if (!row || row.user_id !== user.id) return bad(request, "Key not found", 404);

  try {
    await env.DB.prepare(
      `UPDATE api_keys
       SET bind_mode = NULL, bound_colo = NULL, bound_ip_hash = NULL,
           bound_at = NULL, bind_violations = 0
       WHERE id = ?1`
    )
      .bind(id)
      .run();
  } catch (e) {
    return bad(
      request,
      "Colo columns missing — run d1-colo-migration.sql: " + (e.message || e),
      500
    );
  }

  await logSafetyEvent(env, "key.edge_unbound", {
    api_key_id: id,
    user_id: user.id,
    reason: "owner_unbind",
  });

  return json(request, { ok: true, id, bind_mode: null, unbound: true });
}

/** Current API key metadata + binding (API key auth). */
export async function handleMeKeySelf(request, env) {
  const authUser = await getAuthUser(request, env);
  if (!authUser) return bad(request, "Sign in or API key required", 401);
  const sus = rejectIfSuspendedKey(request, authUser);
  if (sus) return sus;

  if (authUser.auth_via !== "api_key") {
    return bad(request, "Use an API key Bearer token for this endpoint", 400, {
      code: "api_key_required",
    });
  }

  const edge = getRequestEdge(request);
  let row = null;
  try {
    row = await env.DB.prepare(
      `SELECT id, key_prefix, label, bind_mode, bound_colo, last_colo,
              bind_violations, bound_at, last_used_at, created_at
       FROM api_keys WHERE id = ?1`
    )
      .bind(authUser.key_id)
      .first();
  } catch (_) {
    row = await env.DB.prepare(
      `SELECT id, key_prefix, label, last_used_at, created_at
       FROM api_keys WHERE id = ?1`
    )
      .bind(authUser.key_id)
      .first();
  }

  return json(request, {
    ok: true,
    key: row
      ? {
          id: row.id,
          key_prefix: (row.key_prefix || "") + "…",
          label: row.label,
          bind_mode: row.bind_mode || null,
          bound_colo: row.bound_colo || null,
          last_colo: row.last_colo || null,
          bind_violations: Number(row.bind_violations || 0),
          bound_at: row.bound_at || null,
          last_used_at: row.last_used_at || null,
        }
      : null,
    current_edge: { colo: edge.colo, country: edge.country, ray: edge.ray },
    bound_ok: !(authUser.edge_blocked || authUser._edge_blocked),
  });
}

export async function handleEdgeInfo(request, env) {
  const edge = getRequestEdge(request);
  return json(request, {
    ok: true,
    colo: edge.colo,
    country: edge.country,
    ray: edge.ray,
    has_ip: !!edge.ip,
    hint: "Bind API keys with POST /api/me/keys/bind { id, mode: 'colo'|'either'|'both'|'learn' }",
  });
}


export async function handleMeKeysRevoke(request, env) {
  const user = await getSessionUser(request, env);
  if (!user) return bad(request, "Sign in required", 401);

  let body;
  try {
    body = await request.json();
  } catch {
    return bad(request, "Invalid JSON body");
  }

  const id = String(body.id || "").trim();
  if (!id) return bad(request, "id required");

  const row = await env.DB.prepare(
    `SELECT id, revoked_at FROM api_keys WHERE id = ?1 AND user_id = ?2`
  )
    .bind(id, user.id)
    .first();

  if (!row) return bad(request, "Key not found", 404);
  if (row.revoked_at) return json(request, { ok: true, id, already_revoked: true });

  await env.DB.prepare(
    `UPDATE api_keys SET revoked_at = datetime('now') WHERE id = ?1 AND user_id = ?2`
  )
    .bind(id, user.id)
    .run();

  return json(request, { ok: true, id, revoked: true });
}

export async function handleMeKeysUnsuspend(request, env) {
  const user = await getSessionUser(request, env);
  if (!user) return bad(request, "Sign in required", 401);

  let body;
  try {
    body = await request.json();
  } catch {
    return bad(request, "Invalid JSON body");
  }
  const id = String(body.id || "").trim();
  if (!id) return bad(request, "id required");

  const row = await env.DB.prepare(
    `SELECT id, suspended_at FROM api_keys WHERE id = ?1 AND user_id = ?2`
  )
    .bind(id, user.id)
    .first();
  if (!row) return bad(request, "Key not found", 404);
  if (!row.suspended_at) {
    return json(request, { ok: true, id, already_active: true });
  }

  try {
    await env.DB.prepare(
      `UPDATE api_keys
       SET suspended_at = NULL, suspend_reason = NULL
       WHERE id = ?1 AND user_id = ?2`
    )
      .bind(id, user.id)
      .run();
  } catch (e) {
    return bad(request, "Could not unsuspend (column missing?)", 500);
  }

  await logSafetyEvent(env, "key.unsuspended", {
    api_key_id: id,
    user_id: user.id,
    reason: "dashboard",
  });

  return json(request, { ok: true, id, unsuspended: true });
}
