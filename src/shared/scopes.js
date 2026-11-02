/**
 * Scoped API keys — least-privilege verbs, amount ceilings, to_repo allowlists.
 *
 * Scope object (stored as scopes_json on api_keys):
 * {
 *   v: 1,
 *   verbs: ["read","pay","hire","escrow","stream"],
 *   max_amount_usd: number|null,
 *   to_repo_allow: ["swarm/","acme/bot"]  // prefix or exact owner/repo
 * }
 *
 * Legacy keys (scopes_json NULL / empty): full access (compat until rotated).
 * Session auth: always full (owner plane).
 * New keys default: ["read"] only unless body requests more.
 */

export const SCOPE_VERBS = Object.freeze([
  "read",
  "pay",
  "hire",
  "escrow",
  "stream",
]);

/** Routes that only need read when called with an API key. */
export const READ_SAFE_HINT =
  "balance, ledger lists, passport get, security status, me/key, overview";

/**
 * Parse scopes from DB row or request body.
 * @returns {{ v:number, verbs:string[], max_amount_usd:number|null, to_repo_allow:string[]|null, legacy:boolean }}
 */
export function parseScopes(raw) {
  if (raw == null || raw === "") {
    return {
      v: 1,
      verbs: null, // null verbs = legacy full
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
    // Empty array is intentional lockdown (no verbs) — not legacy
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
    // strip trailing ** globs; we use prefix match
    s = s.replace(/\*+$/, "");
    if (!s) continue;
    if (seen.has(s)) continue;
    seen.add(s);
    out.push(s);
    if (out.length >= 64) break;
  }
  return out.length ? out : null;
}

/**
 * Build scopes from create-key body. Defaults to read-only for least privilege.
 */
export function scopesFromCreateBody(body) {
  body = body || {};
  // Explicit legacy/full opt-in (session-only create path can still request)
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
    // Secure default: read only
    verbs = ["read"];
  }

  const parsed = parseScopes({
    verbs,
    max_amount_usd: body.max_amount_usd ?? body.max_amount ?? body.maxAmount,
    to_repo_allow: body.to_repo_allow ?? body.allow_to ?? body.to_allow,
  });
  // Creating with empty verbs after filter → read
  if (!parsed.legacy && (!parsed.verbs || parsed.verbs.length === 0)) {
    parsed.verbs = ["read"];
  }
  return parsed;
}

export function scopesToJson(scopes) {
  if (!scopes || scopes.legacy || scopes.verbs === null) {
    return null; // DB NULL = legacy full
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

/**
 * Prefix or exact match against to_repo_allow.
 * "swarm/" matches swarm/bot-1; "swarm/bot-1" matches only exact.
 */
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

/**
 * Attach parsed scopes onto authUser from key row (call from getApiKeyUser).
 */
export function attachKeyScopes(authUser, keyRow) {
  if (!authUser) return authUser;
  const scopes = parseScopes(
    keyRow && (keyRow.scopes_json != null ? keyRow.scopes_json : keyRow.scopes)
  );
  authUser.key_scopes = scopes;
  authUser.key_scope_legacy = !!scopes.legacy;
  return authUser;
}

/**
 * Session = full power. API key = enforce scopes.
 * Returns null if OK, or { error, code, status, ... } for bad().
 */
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
  // Owner session bypasses key scopes (human plane)
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
 * Helper: return bad() response or null.
 * Usage: const denied = rejectKeyScope(request, authUser, "pay", { amount, toRepo }); if (denied) return denied;
 */
export function rejectKeyScope(request, authUser, verb, opts, badFn) {
  const hit = checkKeyScope(authUser, verb, opts || {});
  if (!hit) return null;
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

/**
 * Tag authUser before safetyGate so scope verb/to_repo are enforced.
 * Call from money handlers: applyScopeVerb(authUser, "pay", toRepo)
 */
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

/** Public summary for list/create responses (never secrets). */
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
