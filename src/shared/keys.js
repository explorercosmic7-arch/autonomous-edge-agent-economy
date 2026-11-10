/**
 * API keys + edge binding — create/list/revoke/bind/unbind, me/key, edge info,
 * unsuspend, rotate, TTL (expires_at).
 * Scoped keys: verbs, max_amount_usd, to_repo_allow (see scopes.js)
 * Security events: key.create | key.revoke | key.rotate | key.unsuspend
 */
import { json, bad } from "./http.js";
import { randomId, sha256Hex } from "./utils.js";
import { checkRateLimit } from "./rateLimit.js";
import { getSessionUser, getAuthUser, rejectIfSuspendedKey } from "./auth.js";
import { getRequestEdge, hashIp } from "./edge.js";
import { logSafetyEvent } from "./safety.js";
import { recordSecurityEvent } from "./securityLog.js";
import {
  MAX_KEYS_PER_USER,
  RL_KEY_CREATE_MAX,
  RL_KEY_CREATE_WINDOW_SEC,
  KEY_TTL_MIN_HOURS,
  KEY_TTL_MAX_HOURS,
} from "./constants.js";
import {
  scopesFromCreateBody,
  scopesToJson,
  parseScopes,
  scopesPublicView,
  SCOPE_VERBS,
} from "./scopes.js";

function parseTtlHours(body) {
  if (!body) return null;
  const raw =
    body.ttl_hours != null
      ? body.ttl_hours
      : body.ttl != null
        ? body.ttl
        : body.expires_in_hours;
  if (raw == null || raw === "" || raw === false) return null;
  const n = Math.floor(Number(raw));
  if (!Number.isFinite(n) || n <= 0) return null;
  if (n < KEY_TTL_MIN_HOURS) return KEY_TTL_MIN_HOURS;
  if (n > KEY_TTL_MAX_HOURS) return KEY_TTL_MAX_HOURS;
  return n;
}

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
  const scopes = scopesFromCreateBody(body);
  const scopesJson = scopesToJson(scopes);
  const maxAmountCol =
    scopes.max_amount_usd != null ? Number(scopes.max_amount_usd) : null;
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
  const ttlHours = parseTtlHours(body);
  const expiresAt = ttlHours
    ? new Date(Date.now() + ttlHours * 3600 * 1000)
        .toISOString()
        .replace("T", " ")
        .slice(0, 19)
    : null;

  let insertedWithScopes = false;
  let insertedWithTtl = false;
  try {
    await env.DB.prepare(
      `INSERT INTO api_keys (
         id, user_id, key_hash, key_prefix, label,
         bind_mode, bound_colo, bound_ip_hash, bound_at,
         scopes_json, max_amount_usd, scope_version, expires_at
       ) VALUES (
         ?1, ?2, ?3, ?4, ?5,
         ?6, ?7, ?8, ?9,
         ?10, ?11, 1, ?12
       )`
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
        pinNow ? new Date().toISOString().replace("T", " ").slice(0, 19) : null,
        scopesJson,
        maxAmountCol,
        expiresAt
      )
      .run();
    insertedWithScopes = true;
    insertedWithTtl = true;
  } catch (_) {
    try {
      await env.DB.prepare(
        `INSERT INTO api_keys (
           id, user_id, key_hash, key_prefix, label,
           bind_mode, bound_colo, bound_ip_hash, bound_at,
           scopes_json, max_amount_usd, scope_version
         ) VALUES (
           ?1, ?2, ?3, ?4, ?5,
           ?6, ?7, ?8, ?9,
           ?10, ?11, 1
         )`
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
          pinNow ? new Date().toISOString().replace("T", " ").slice(0, 19) : null,
          scopesJson,
          maxAmountCol
        )
        .run();
      insertedWithScopes = true;
    } catch (__) {
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
      } catch (___) {
        await env.DB.prepare(
          `INSERT INTO api_keys (id, user_id, key_hash, key_prefix, label)
           VALUES (?1, ?2, ?3, ?4, ?5)`
        )
          .bind(id, user.id, keyHash, keyPrefix, label)
          .run();
        bindMode = "";
      }
    }
  }

  await recordSecurityEvent(
    env,
    {
      kind: "key.create",
      severity: "info",
      user_id: user.id,
      key_id: id,
      reason: "dashboard_create",
      meta: {
        label,
        ttl_hours: ttlHours,
        legacy: !!scopes.legacy,
        verbs: scopes.verbs,
      },
    },
    request
  );

  const view = scopesPublicView(scopes);
  return json(request, {
    ok: true,
    id,
    label,
    key_prefix: keyPrefix,
    key: secret,
    bind_mode: bindMode || null,
    bound_colo: bindMode && bindMode !== "learn" ? boundColo : null,
    expires_at: insertedWithTtl ? expiresAt : null,
    ttl_hours: insertedWithTtl ? ttlHours : null,
    scopes: view,
    scopes_persisted: insertedWithScopes,
    available_verbs: SCOPE_VERBS,
    edge: { colo: edge.colo, country: edge.country },
    hint:
      "Copy now. The full key is never shown again." +
      (bindMode ? " Edge binding: " + bindMode + "." : "") +
      (expiresAt ? " Expires: " + expiresAt + "." : "") +
      (view.legacy
        ? " Scope: full (legacy)."
        : " Scope: " + view.label + ".") +
      (insertedWithScopes
        ? ""
        : " Run d1-key-scopes-migration.sql to persist scopes on new keys.") +
      (ttlHours && !insertedWithTtl
        ? " Run d1-security-events.sql for TTL column."
        : ""),
  });
}

export async function handleMeKeysList(request, env) {
  const user = await getSessionUser(request, env);
  if (!user) return bad(request, "Sign in required", 401);
  let results;
  try {
    const q = await env.DB.prepare(
      `SELECT id, key_prefix, label, created_at, revoked_at, last_used_at,
              suspended_at, suspend_reason, expires_at, disabled_at, disabled_reason,
              bound_colo, bind_mode, last_colo, bind_violations, bound_at,
              scopes_json, max_amount_usd, scope_version
       FROM api_keys WHERE user_id = ?1 ORDER BY created_at DESC LIMIT 50`
    )
      .bind(user.id)
      .all();
    results = q.results || [];
  } catch (_) {
    try {
      const q = await env.DB.prepare(
        `SELECT id, key_prefix, label, created_at, revoked_at, last_used_at,
                suspended_at, suspend_reason,
                bound_colo, bind_mode, last_colo, bind_violations, bound_at,
                scopes_json, max_amount_usd, scope_version
         FROM api_keys WHERE user_id = ?1 ORDER BY created_at DESC LIMIT 50`
      )
        .bind(user.id)
        .all();
      results = q.results || [];
    } catch (__) {
      try {
        const q = await env.DB.prepare(
          `SELECT id, key_prefix, label, created_at, revoked_at, last_used_at, suspended_at, suspend_reason
           FROM api_keys WHERE user_id = ?1 ORDER BY created_at DESC LIMIT 50`
        )
          .bind(user.id)
          .all();
        results = q.results || [];
      } catch (___) {
        const q = await env.DB.prepare(
          `SELECT id, key_prefix, label, created_at, revoked_at, last_used_at
           FROM api_keys WHERE user_id = ?1 ORDER BY created_at DESC LIMIT 50`
        )
          .bind(user.id)
          .all();
        results = q.results || [];
      }
    }
  }
  const edge = getRequestEdge(request);
  return json(request, {
    ok: true,
    count: results.length,
    current_edge: { colo: edge.colo, country: edge.country },
    available_verbs: SCOPE_VERBS,
    keys: results.map((k) => {
      const scopes = parseScopes(k.scopes_json);
      const view = scopesPublicView(scopes);
      return {
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
        expires_at: k.expires_at || null,
        expired: !!(k.expires_at && new Date(String(k.expires_at).replace(" ", "T") + "Z").getTime() < Date.now()),
        disabled: !!k.disabled_at,
        disabled_at: k.disabled_at || null,
        disabled_reason: k.disabled_reason || null,
        bind_mode: k.bind_mode || null,
        bound_colo: k.bound_colo || null,
        last_colo: k.last_colo || null,
        bound_at: k.bound_at || null,
        bind_violations: Number(k.bind_violations || 0),
        scopes: view,
        max_amount_usd:
          k.max_amount_usd != null ? Number(k.max_amount_usd) : view.max_amount_usd,
      };
    }),
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

/** Current API key metadata + binding + scopes (API key auth). */
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
              bind_violations, bound_at, last_used_at, created_at,
              scopes_json, max_amount_usd, expires_at, disabled_at
       FROM api_keys WHERE id = ?1`
    )
      .bind(authUser.key_id)
      .first();
  } catch (_) {
    try {
      row = await env.DB.prepare(
        `SELECT id, key_prefix, label, bind_mode, bound_colo, last_colo,
                bind_violations, bound_at, last_used_at, created_at
         FROM api_keys WHERE id = ?1`
      )
        .bind(authUser.key_id)
        .first();
    } catch (__) {
      row = await env.DB.prepare(
        `SELECT id, key_prefix, label, last_used_at, created_at
         FROM api_keys WHERE id = ?1`
      )
        .bind(authUser.key_id)
        .first();
    }
  }
  const scopes = authUser.key_scopes || parseScopes(row && row.scopes_json);
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
          expires_at: row.expires_at || null,
          disabled: !!row.disabled_at,
          scopes: scopesPublicView(scopes),
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
  await recordSecurityEvent(
    env,
    {
      kind: "key.revoke",
      severity: "info",
      user_id: user.id,
      key_id: id,
      reason: "dashboard_revoke",
    },
    request
  );
  return json(request, { ok: true, id, revoked: true });
}

/**
 * One-click rotate: revoke old key, create new with same scopes / bind / label / TTL.
 * Returns new secret once.
 */
export async function handleMeKeysRotate(request, env) {
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

  let old;
  try {
    old = await env.DB.prepare(
      `SELECT * FROM api_keys WHERE id = ?1 AND user_id = ?2`
    )
      .bind(id, user.id)
      .first();
  } catch {
    old = await env.DB.prepare(
      `SELECT id, user_id, label, revoked_at, scopes_json, max_amount_usd,
              bind_mode, bound_colo, bound_ip_hash, expires_at
       FROM api_keys WHERE id = ?1 AND user_id = ?2`
    )
      .bind(id, user.id)
      .first();
  }
  if (!old) return bad(request, "Key not found", 404);
  if (old.revoked_at) return bad(request, "Key already revoked — create a new key", 400);

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

  const newId = randomId(12);
  const secret = "a2a_" + randomId(24);
  const keyHash = await sha256Hex(secret);
  const keyPrefix = secret.slice(0, 12);
  const label = String(old.label || "agent").slice(0, 64);
  const scopesJson = old.scopes_json != null ? old.scopes_json : null;
  const maxAmountCol =
    old.max_amount_usd != null ? Number(old.max_amount_usd) : null;
  const bindMode = old.bind_mode || null;
  // New key: clear learned bounds; keep mode if any
  const expiresAt = old.expires_at || null;

  await env.DB.prepare(
    `UPDATE api_keys SET revoked_at = datetime('now') WHERE id = ?1 AND user_id = ?2`
  )
    .bind(id, user.id)
    .run();

  try {
    await env.DB.prepare(
      `INSERT INTO api_keys (
         id, user_id, key_hash, key_prefix, label,
         bind_mode, bound_colo, bound_ip_hash, bound_at,
         scopes_json, max_amount_usd, scope_version, expires_at
       ) VALUES (
         ?1, ?2, ?3, ?4, ?5,
         ?6, NULL, NULL, NULL,
         ?7, ?8, 1, ?9
       )`
    )
      .bind(
        newId,
        user.id,
        keyHash,
        keyPrefix,
        label,
        bindMode,
        scopesJson,
        maxAmountCol,
        expiresAt
      )
      .run();
  } catch (_) {
    await env.DB.prepare(
      `INSERT INTO api_keys (
         id, user_id, key_hash, key_prefix, label,
         scopes_json, max_amount_usd, scope_version
       ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1)`
    )
      .bind(newId, user.id, keyHash, keyPrefix, label, scopesJson, maxAmountCol)
      .run();
  }

  await recordSecurityEvent(
    env,
    {
      kind: "key.rotate",
      severity: "info",
      user_id: user.id,
      key_id: newId,
      reason: "dashboard_rotate",
      meta: { old_key_id: id },
    },
    request
  );
  await recordSecurityEvent(
    env,
    {
      kind: "key.revoke",
      severity: "info",
      user_id: user.id,
      key_id: id,
      reason: "rotated",
      meta: { new_key_id: newId },
    },
    request
  );

  const scopes = parseScopes(scopesJson);
  return json(request, {
    ok: true,
    rotated_from: id,
    id: newId,
    label,
    key_prefix: keyPrefix,
    key: secret,
    expires_at: expiresAt,
    scopes: scopesPublicView(scopes),
    hint: "Copy the new key now. Old key is revoked.",
  });
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
  let row;
  try {
    row = await env.DB.prepare(
      `SELECT id, suspended_at, disabled_at FROM api_keys WHERE id = ?1 AND user_id = ?2`
    )
      .bind(id, user.id)
      .first();
  } catch {
    row = await env.DB.prepare(
      `SELECT id, suspended_at FROM api_keys WHERE id = ?1 AND user_id = ?2`
    )
      .bind(id, user.id)
      .first();
  }
  if (!row) return bad(request, "Key not found", 404);
  if (row.disabled_at) {
    return bad(
      request,
      "Key permanently disabled (denial storm). Create or rotate a new key.",
      400,
      { code: "key_disabled" }
    );
  }
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
  await recordSecurityEvent(
    env,
    {
      kind: "key.unsuspend",
      severity: "info",
      user_id: user.id,
      key_id: id,
      reason: "dashboard",
    },
    request
  );
  return json(request, { ok: true, id, unsuspended: true });
}
