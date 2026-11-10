/**
 * Scoped API keys — least-privilege verbs, amount ceilings, to_repo allowlists.
 * Scope denials are recorded to security_events (immutable audit) + denial-storm check.
 */
import { afterScopeDeny } from "./securityLog.js";

export const SCOPE_VERBS = Object.freeze([
  "read",
  "pay",
  "hire",
  "escrow",
  "stream",
]);

export const READ_SAFE_HINT =
  "balance, ledger lists, passport get, security status, me/key, overview";

export function parseScopes(raw) {
  if (raw == null || raw === "") {
    return {
      v: 1,
      verbs: null,
      max_amount_usd: null,
      to_repo_allow: null,
      legacy: true,
    };
  }
  let obj = raw;
  if (typeof raw === "string") {
    try {
      obj = JSON.parse(raw);
    } catch {
      return {
        v: 1,
        verbs: null,
        max_amount_usd: null,
        to_repo_allow: null,
        legacy: true,
      };
    }
  }
  if (!obj || typeof obj !== "object") {
    return {
      v: 1,
      verbs: null,
      max_amount_usd: null,
      to_repo_allow: null,
      legacy: true,
    };
  }
  let verbs = null;
  if (Array.isArray(obj.verbs)) {
    const set = new Set();
    for (const v of obj.verbs) {
      const s = String(v || "")
        .toLowerCase()
        .trim();
      if (SCOPE_VERBS.includes(s)) set.add(s);
    }
    verbs = Array.from(set);
  } else if (obj.legacy === true || obj.full === true) {
    verbs = null;
  }
  let maxAmt = null;
  if (obj.max_amount_usd != null && obj.max_amount_usd !== "") {
    const n = Number(obj.max_amount_usd);
    if (Number.isFinite(n) && n > 0) maxAmt = n;
  }
  let allow = null;
  const rawAllow = obj.to_repo_allow ?? obj.allow_to ?? obj.to_allow;
  if (Array.isArray(rawAllow)) {
    allow = normalizeRepoAllowList(rawAllow);
  } else if (typeof rawAllow === "string" && rawAllow.trim()) {
    allow = normalizeRepoAllowList(
      rawAllow.split(/[\n,]+/).map((s) => s.trim())
    );
  }
  const legacy = verbs === null;
  return {
    v: 1,
    verbs,
    max_amount_usd: maxAmt,
    to_repo_allow: allow,
    legacy,
  };
}

function normalizeRepoAllowList(list) {
  const out = [];
  const seen = new Set();
  for (const item of list || []) {
    let s = String(item || "")
      .trim()
      .toLowerCase();
    if (!s) continue;
    s = s.replace(/\*+$/, "");
    if (!s) continue;
    if (seen.has(s)) continue;
    seen.add(s);
    out.push(s);
    if (out.length >= 64) break;
  }
  return out.length ? out : null;
}

export function scopesFromCreateBody(body) {
  body = body || {};
  if (body.full === true || body.legacy === true || body.unscoped === true) {
    return {
      v: 1,
      verbs: null,
      max_amount_usd: null,
      to_repo_allow: null,
      legacy: true,
    };
  }
  let verbs = null;
  if (Array.isArray(body.scopes)) {
    verbs = body.scopes;
  } else if (Array.isArray(body.verbs)) {
    verbs = body.verbs;
  } else if (typeof body.scope === "string") {
    verbs = body.scope.split(/[,\s]+/);
  } else if (body.preset) {
    const p = String(body.preset).toLowerCase();
    if (p === "read" || p === "readonly") verbs = ["read"];
    else if (p === "pay" || p === "agent") verbs = ["read", "pay"];
    else if (p === "hire") verbs = ["read", "hire"];
    else if (p === "money") verbs = ["read", "pay", "escrow", "stream"];
    else if (p === "full") {
      return parseScopes({ full: true });
    } else verbs = ["read"];
  } else {
    verbs = ["read"];
  }
  const parsed = parseScopes({
    verbs,
    max_amount_usd: body.max_amount_usd ?? body.max_amount ?? body.maxAmount,
    to_repo_allow: body.to_repo_allow ?? body.allow_to ?? body.to_allow,
  });
  if (!parsed.legacy && (!parsed.verbs || parsed.verbs.length === 0)) {
    parsed.verbs = ["read"];
  }
  return parsed;
}

export function scopesToJson(scopes) {
  if (!scopes || scopes.legacy || scopes.verbs === null) {
    return null;
  }
  return JSON.stringify({
    v: 1,
    verbs: scopes.verbs || [],
    max_amount_usd: scopes.max_amount_usd,
    to_repo_allow: scopes.to_repo_allow,
  });
}

export function hasVerb(scopes, verb) {
  if (!scopes || scopes.legacy || scopes.verbs === null) return true;
  const v = String(verb || "")
    .toLowerCase()
    .trim();
  return (scopes.verbs || []).includes(v);
}

export function repoAllowed(scopes, toRepo) {
  if (!scopes || scopes.legacy || !scopes.to_repo_allow || !scopes.to_repo_allow.length) {
    return true;
  }
  const target = String(toRepo || "")
    .trim()
    .toLowerCase();
  if (!target) return false;
  for (const rule of scopes.to_repo_allow) {
    const r = String(rule).toLowerCase();
    if (r.endsWith("/")) {
      if (target.startsWith(r) || target === r.slice(0, -1)) return true;
    } else if (target === r || target.startsWith(r + "/")) {
      return true;
    }
  }
  return false;
}

export function attachKeyScopes(authUser, keyRow) {
  if (!authUser) return authUser;
  const scopes = parseScopes(
    keyRow && (keyRow.scopes_json != null ? keyRow.scopes_json : keyRow.scopes)
  );
  authUser.key_scopes = scopes;
  authUser.key_scope_legacy = !!scopes.legacy;
  return authUser;
}

export function checkKeyScope(
  authUser,
  verb,
  { amount, toRepo, requireApiKeyOnly } = {}
) {
  if (!authUser) {
    return {
      error: "Sign in or API key required",
      code: "auth_required",
      status: 401,
    };
  }
  if (authUser.auth_via === "session") {
    if (requireApiKeyOnly) {
      return {
        error: "This action requires an API key Bearer token",
        code: "api_key_required",
        status: 400,
      };
    }
    return null;
  }
  if (authUser.auth_via !== "api_key") return null;
  const scopes = authUser.key_scopes || parseScopes(null);
  if (scopes.legacy) return null;
  if (verb && !hasVerb(scopes, verb)) {
    return {
      error:
        'API key missing scope "' +
        verb +
        '". Allowed: ' +
        ((scopes.verbs || []).join(", ") || "(none)"),
      code: "key_scope_denied",
      status: 403,
      required: verb,
      verbs: scopes.verbs || [],
    };
  }
  if (amount != null && scopes.max_amount_usd != null) {
    const n = Number(amount);
    if (Number.isFinite(n) && n > Number(scopes.max_amount_usd)) {
      return {
        error:
          "Amount exceeds key max_amount_usd ($" +
          scopes.max_amount_usd +
          ")",
        code: "key_amount_exceeded",
        status: 403,
        max_amount_usd: scopes.max_amount_usd,
        amount: n,
      };
    }
  }
  if (toRepo && !repoAllowed(scopes, toRepo)) {
    return {
      error: "to_repo not on this key's allowlist",
      code: "key_repo_denied",
      status: 403,
      to_repo: toRepo,
      to_repo_allow: scopes.to_repo_allow,
    };
  }
  return null;
}

/**
 * Prefer this helper from money handlers so denials hit the audit log.
 * rejectKeyScope(request, env, authUser, "pay", { amount, toRepo }, bad)
 * env is optional for backward compat: rejectKeyScope(request, authUser, verb, opts, badFn)
 */
export function rejectKeyScope(request, envOrAuth, authOrVerb, verbOrOpts, optsOrBad, badFnMaybe) {
  // Overload: (request, authUser, verb, opts, badFn)  — legacy
  //           (request, env, authUser, verb, opts, badFn) — preferred
  let env = null;
  let authUser;
  let verb;
  let opts;
  let badFn;
  if (envOrAuth && envOrAuth.DB) {
    env = envOrAuth;
    authUser = authOrVerb;
    verb = verbOrOpts;
    opts = optsOrBad || {};
    badFn = badFnMaybe;
  } else {
    authUser = envOrAuth;
    verb = authOrVerb;
    opts = verbOrOpts || {};
    badFn = optsOrBad;
  }
  const hit = checkKeyScope(authUser, verb, opts || {});
  if (!hit) return null;

  // Audit + anomaly (async fire — caller should await this function)
  // Note: callers using non-async path still get the Response; event is best-effort
  if (env && authUser && authUser.auth_via === "api_key") {
    try {
      // schedule without blocking if no await — but we return sync Response below
      // Callers that await rejectKeyScopeAsync should use the async variant.
      const p = afterScopeDeny(env, request, {
        authUser,
        verb,
        code: hit.code,
        toRepo: opts && opts.toRepo,
        amount: opts && opts.amount,
      });
      if (p && typeof p.then === "function") {
        p.catch(function () {});
      }
    } catch (_) {}
  }

  if (typeof badFn === "function") {
    return badFn(request, hit.error, hit.status || 403, {
      code: hit.code,
      required: hit.required,
      verbs: hit.verbs,
      max_amount_usd: hit.max_amount_usd,
      amount: hit.amount,
      to_repo: hit.to_repo,
      to_repo_allow: hit.to_repo_allow,
    });
  }
  return hit;
}

/** Async variant — await in handlers so denial-storm can disable before response. */
export async function rejectKeyScopeAsync(request, env, authUser, verb, opts, badFn) {
  const hit = checkKeyScope(authUser, verb, opts || {});
  if (!hit) return null;
  if (env) {
    await afterScopeDeny(env, request, {
      authUser,
      verb,
      code: hit.code,
      toRepo: opts && opts.toRepo,
      amount: opts && opts.amount,
    });
  }
  if (typeof badFn === "function") {
    return badFn(request, hit.error, hit.status || 403, {
      code: hit.code,
      required: hit.required,
      verbs: hit.verbs,
      max_amount_usd: hit.max_amount_usd,
      amount: hit.amount,
      to_repo: hit.to_repo,
      to_repo_allow: hit.to_repo_allow,
    });
  }
  return hit;
}

export function applyScopeVerb(authUser, verb, toRepo) {
  if (!authUser) return authUser;
  if (verb) authUser._scopeVerb = String(verb).toLowerCase();
  if (toRepo) {
    authUser._scopeToRepo = toRepo;
    authUser._policyCtx = Object.assign({}, authUser._policyCtx || {}, {
      to_repo: toRepo,
    });
  }
  return authUser;
}

export function scopesPublicView(scopes) {
  if (!scopes || scopes.legacy || scopes.verbs === null) {
    return {
      legacy: true,
      verbs: null,
      max_amount_usd: null,
      to_repo_allow: null,
      label: "full (legacy)",
    };
  }
  return {
    legacy: false,
    verbs: scopes.verbs || [],
    max_amount_usd: scopes.max_amount_usd,
    to_repo_allow: scopes.to_repo_allow,
    label:
      (scopes.verbs || []).join("+") +
      (scopes.max_amount_usd != null
        ? " ≤$" + scopes.max_amount_usd
        : "") +
      (scopes.to_repo_allow && scopes.to_repo_allow.length
        ? " → " + scopes.to_repo_allow.slice(0, 3).join(",")
        : ""),
  };
}
