/**
 * Autonomous Edge-Agent Economy — Cloudflare Worker + D1
 * Ledger + OAuth + API keys + rate limits + escrow + auto-expire (cron)
 *
 * INVENTORY (do not delete):
 * Auth:     GET /api/auth/google, GET /api/auth/google/callback,
 *           GET /api/auth/me, POST /api/auth/logout
 * Me:       POST /api/me/agent, GET /api/me/balance
 * Keys:     POST|GET /api/me/keys, POST /api/me/keys/revoke
 * Ledger:   POST /api/pay, POST /api/fund, GET /api/balance, GET /api/ledger
 * Escrow:   POST /api/escrow/hold|release|refund, GET /api/escrow,
 *           POST /api/escrow/expire-now
 * Cron:     scheduled() → expireHeldEscrows
 */
const ALLOWED_ORIGINS = new Set([
  "https://edgerail.pages.dev",
  "https://newhorizons-beyondhorizon.pages.dev",
  "https://agentpay.pages.dev",
  "https://autonomous-edge-agent-economy.explorercosmic7.workers.dev",
]);

const DASHBOARD_URL = "https://edgerail.pages.dev/ai-agents-payment-gateway";
const COOKIE_NAME = "a2a_session";
const SESSION_DAYS = 14;

const REPO_RE = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const FAUCET_MAX_PER_CALL = 10;
const FAUCET_ACCOUNT_CAP = 100;
const SYSTEM_FAUCET = "system/faucet";
const SYSTEM_ESCROW = "system/escrow";
const MIN_AMOUNT = 0.000001;
const MAX_AMOUNT = 1_000_000;
const MAX_KEYS_PER_USER = 10;

const RL_KEY_CREATE_MAX = 3;
const RL_KEY_CREATE_WINDOW_SEC = 3600;
const RL_PAY_MAX = 60;
const RL_PAY_WINDOW_SEC = 60;
const RL_ESCROW_MAX = 30;
const RL_ESCROW_WINDOW_SEC = 60;

const ESCROW_DEFAULT_TTL_HOURS = 72;
const ESCROW_MIN_TTL_SEC = 10;
const ESCROW_MAX_TTL_SEC = 720 * 3600;
const EXPIRE_BATCH_LIMIT = 50;

function corsHeaders(request) {
  const origin = request.headers.get("Origin") || "";
  const allow = ALLOWED_ORIGINS.has(origin) ? origin : "https://edgerail.pages.dev";
  return {
    "Access-Control-Allow-Origin": allow,
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, Idempotency-Key",
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Max-Age": "86400",
    Vary: "Origin",
  };
}

function json(request, data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      ...corsHeaders(request),
      ...extraHeaders,
    },
  });
}

function bad(request, message, status = 400, extra = {}) {
  return json(request, { ok: false, error: message, ...extra }, status);
}

function parseRepo(v) {
  const s = String(v || "").trim();
  return REPO_RE.test(s) ? s : null;
}

function parseAmount(v) {
  const n = Number(v);
  if (!Number.isFinite(n) || n < MIN_AMOUNT || n > MAX_AMOUNT) return null;
  return Math.round(n * 1e6) / 1e6;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function randomId(bytes = 16) {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  return [...arr].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function parseCookies(header) {
  const out = {};
  if (!header) return out;
  header.split(";").forEach((part) => {
    const i = part.indexOf("=");
    if (i === -1) return;
    const k = part.slice(0, i).trim();
    const v = part.slice(i + 1).trim();
    out[k] = decodeURIComponent(v);
  });
  return out;
}

function sessionCookie(value, maxAgeSec) {
  return `${COOKIE_NAME}=${encodeURIComponent(value)}; Path=/; HttpOnly; Secure; SameSite=None; Max-Age=${maxAgeSec}`;
}

function clearSessionCookie() {
  return `${COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=None; Max-Age=0`;
}

async function sha256Hex(text) {
  const data = new TextEncoder().encode(text);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return [...new Uint8Array(hash)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function parseTtlSeconds(body) {
  const sec = Number(body.ttl_seconds);
  if (Number.isFinite(sec)) {
    if (sec < ESCROW_MIN_TTL_SEC || sec > ESCROW_MAX_TTL_SEC) return null;
    return Math.floor(sec);
  }
  const hours = Number(body.ttl_hours);
  const h = Number.isFinite(hours) && hours > 0 ? hours : ESCROW_DEFAULT_TTL_HOURS;
  const out = Math.floor(h * 3600);
  if (out < ESCROW_MIN_TTL_SEC || out > ESCROW_MAX_TTL_SEC) return null;
  return out;
}

/* ─── Rate limit (D1 fixed window) ─── */

async function checkRateLimit(env, bucketKey, max, windowSec) {
  const now = Date.now();
  const row = await env.DB.prepare(
    `SELECT count, window_start FROM rate_limits WHERE bucket_key = ?1`
  )
    .bind(bucketKey)
    .first();

  if (!row) {
    await env.DB.prepare(
      `INSERT INTO rate_limits (bucket_key, count, window_start, updated_at)
       VALUES (?1, 1, datetime('now'), datetime('now'))`
    )
      .bind(bucketKey)
      .run();
    return null;
  }

  const startMs = new Date(row.window_start + "Z").getTime();
  const start = Number.isFinite(startMs)
    ? startMs
    : Date.parse(String(row.window_start).replace(" ", "T") + "Z");

  if (!Number.isFinite(start) || now - start >= windowSec * 1000) {
    await env.DB.prepare(
      `UPDATE rate_limits
       SET count = 1, window_start = datetime('now'), updated_at = datetime('now')
       WHERE bucket_key = ?1`
    )
      .bind(bucketKey)
      .run();
    return null;
  }

  if (row.count >= max) {
    const retry = Math.max(1, Math.ceil((windowSec * 1000 - (now - start)) / 1000));
    return { retry_after_sec: retry };
  }

  await env.DB.prepare(
    `UPDATE rate_limits
     SET count = count + 1, updated_at = datetime('now')
     WHERE bucket_key = ?1`
  )
    .bind(bucketKey)
    .run();
  return null;
}

/* ─── Auth ─── */

async function getSessionUser(request, env) {
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

async function getApiKeyUser(request, env) {
  const auth = request.headers.get("Authorization") || "";
  const m = auth.match(/^Bearer\s+(a2a_[A-Fa-f0-9]+)$/i);
  if (!m) return null;

  const raw = m[1];
  const hash = await sha256Hex(raw);

  const row = await env.DB.prepare(
    `SELECT k.id AS key_id, k.user_id, k.revoked_at,
            u.id, u.email, u.name, u.picture, u.provider, u.default_repo
     FROM api_keys k
     JOIN users u ON u.id = k.user_id
     WHERE k.key_hash = ?1`
  )
    .bind(hash)
    .first();

  if (!row || row.revoked_at) return null;

  env.DB.prepare(`UPDATE api_keys SET last_used_at = datetime('now') WHERE id = ?`)
    .bind(row.key_id)
    .run()
    .catch(() => {});

  return row;
}

async function getAuthUser(request, env) {
  const session = await getSessionUser(request, env);
  if (session) return { ...session, auth_via: "session" };
  const keyUser = await getApiKeyUser(request, env);
  if (keyUser) return { ...keyUser, auth_via: "api_key" };
  return null;
}

/* ─── Auto-expire held escrows (cron) ─── */

/**
 * Refund from_repo for held escrows past expires_at.
 * Claim with UPDATE ... WHERE status='held' so two ticks cannot double-credit.
 * expires_at is stored as SQLite datetime so comparison with datetime('now') works.
 */
async function expireHeldEscrows(env) {
  const t0 = Date.now();
  const { results } = await env.DB.prepare(
    `SELECT id, from_repo, to_repo, amount, task
     FROM escrows
     WHERE status = 'held'
       AND expires_at IS NOT NULL
       AND expires_at < datetime('now')
     ORDER BY expires_at ASC
     LIMIT ?1`
  )
    .bind(EXPIRE_BATCH_LIMIT)
    .all();

  if (!results || results.length === 0) {
    return { expired: 0, scanned: 0, latency_ms: Date.now() - t0 };
  }

  let expired = 0;
  for (const esc of results) {
    try {
      await ensureAccount(env, esc.from_repo);
      const claim = await env.DB.prepare(
        `UPDATE escrows
         SET status = 'expired', refunded_at = datetime('now'), updated_at = datetime('now')
         WHERE id = ?1 AND status = 'held'
         RETURNING id`
      )
        .bind(esc.id)
        .first();
      if (!claim) continue;

      await env.DB.batch([
        env.DB.prepare(
          `UPDATE accounts
           SET balance = balance + ?1, updated_at = datetime('now')
           WHERE repo_id = ?2`
        ).bind(esc.amount, esc.from_repo),
        env.DB.prepare(
          `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
           VALUES (?1, ?2, ?3, ?4, 'success', ?5)`
        ).bind(
          SYSTEM_ESCROW,
          esc.from_repo,
          esc.amount,
          "escrow-expire:" + esc.id,
          Date.now() - t0
        ),
      ]);
      expired += 1;
    } catch (e) {
      console.log("expire_error", esc.id, e && e.message);
    }
  }

  return { expired, scanned: results.length, latency_ms: Date.now() - t0 };
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders(request) });
    }

    try {
      if (request.method === "GET" && url.pathname === "/api/auth/google") {
        return handleAuthGoogleStart(request, env, url);
      }
      if (request.method === "GET" && url.pathname === "/api/auth/google/callback") {
        return await handleAuthGoogleCallback(request, env, url);
      }
      if (request.method === "GET" && url.pathname === "/api/auth/me") {
        return await handleAuthMe(request, env);
      }
      if (request.method === "POST" && url.pathname === "/api/auth/logout") {
        return await handleAuthLogout(request, env);
      }

      if (request.method === "POST" && url.pathname === "/api/me/agent") {
        return await handleMeAgent(request, env);
      }
      if (request.method === "GET" && url.pathname === "/api/me/balance") {
        return await handleMeBalance(request, env);
      }

      if (request.method === "POST" && url.pathname === "/api/me/keys") {
        return await handleMeKeysCreate(request, env);
      }
      if (request.method === "GET" && url.pathname === "/api/me/keys") {
        return await handleMeKeysList(request, env);
      }
      if (request.method === "POST" && url.pathname === "/api/me/keys/revoke") {
        return await handleMeKeysRevoke(request, env);
      }

      if (request.method === "POST" && url.pathname === "/api/escrow/hold") {
        return await handleEscrowHold(request, env);
      }
      if (request.method === "POST" && url.pathname === "/api/escrow/release") {
        return await handleEscrowRelease(request, env);
      }
      if (request.method === "POST" && url.pathname === "/api/escrow/refund") {
        return await handleEscrowRefund(request, env);
      }
      if (request.method === "GET" && url.pathname === "/api/escrow") {
        return await handleEscrowList(request, url, env);
      }
      if (request.method === "POST" && url.pathname === "/api/escrow/expire-now") {
        const authUser = await getAuthUser(request, env);
        if (!authUser) return bad(request, "Sign in or API key required", 401);
        const result = await expireHeldEscrows(env);
        return json(request, { ok: true, ...result });
      }

      if (request.method === "GET" && url.pathname === "/") {
        return json(request, {
          ok: true,
          service: "a2a-ledger",
          endpoints: {
            health: "GET /health",
            pay: "POST /api/pay",
            fund: "POST /api/fund",
            balance: "GET /api/balance?repo=owner/repo",
            ledger: "GET /api/ledger",
            auth_me: "GET /api/auth/me",
            me_agent: "POST /api/me/agent",
            me_balance: "GET /api/me/balance",
            me_keys: "GET|POST /api/me/keys",
            escrow_hold: "POST /api/escrow/hold",
            escrow_release: "POST /api/escrow/release",
            escrow_refund: "POST /api/escrow/refund",
            escrow_list: "GET /api/escrow",
            escrow_expire_now: "POST /api/escrow/expire-now",
          },
        });
      }
      if (request.method === "GET" && url.pathname === "/health") {
        return json(request, { ok: true, service: "a2a-ledger", ts: Date.now() });
      }
      if (request.method === "POST" && url.pathname === "/api/pay") {
        return await handlePay(request, env);
      }
      if (request.method === "POST" && url.pathname === "/api/fund") {
        return await handleFund(request, env);
      }
      if (request.method === "GET" && url.pathname === "/api/balance") {
        return await handleBalance(request, url, env);
      }
      if (request.method === "GET" && url.pathname === "/api/ledger") {
        return await handleLedger(request, url, env);
      }

      return bad(request, "Not found", 404);
    } catch (err) {
      return bad(request, err.message || "Internal error", 500);
    }
  },

  async scheduled(event, env, ctx) {
    ctx.waitUntil(
      (async () => {
        try {
          const result = await expireHeldEscrows(env);
          console.log(
            JSON.stringify({
              cron: "escrow-expire",
              scheduledTime: event.scheduledTime,
              ...result,
            })
          );
        } catch (err) {
          console.error("escrow-expire failed:", err && err.message ? err.message : err);
        }
      })()
    );
  },
};

/* ─── Google OAuth ─── */

function handleAuthGoogleStart(request, env, url) {
  const clientId = env.GOOGLE_CLIENT_ID;
  if (!clientId) return bad(request, "GOOGLE_CLIENT_ID not configured on Worker", 500);

  const redirectUri = `${url.origin}/api/auth/google/callback`;
  const state = randomId(16);
  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: "code",
    scope: "openid email profile",
    access_type: "online",
    include_granted_scopes: "true",
    state,
    prompt: "select_account",
  });

  const headers = new Headers({
    Location: `https://accounts.google.com/o/oauth2/v2/auth?${params}`,
    "Set-Cookie": `a2a_oauth_state=${state}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600`,
  });
  return new Response(null, { status: 302, headers });
}

async function handleAuthGoogleCallback(request, env, url) {
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const err = url.searchParams.get("error");

  if (err) {
    return Response.redirect(`${DASHBOARD_URL}?auth_error=${encodeURIComponent(err)}`, 302);
  }
  if (!code || !state) {
    return Response.redirect(`${DASHBOARD_URL}?auth_error=missing_code`, 302);
  }

  const cookies = parseCookies(request.headers.get("Cookie"));
  if (!cookies.a2a_oauth_state || cookies.a2a_oauth_state !== state) {
    return Response.redirect(`${DASHBOARD_URL}?auth_error=bad_state`, 302);
  }

  const clientId = env.GOOGLE_CLIENT_ID;
  const clientSecret = env.GOOGLE_CLIENT_SECRET;
  if (!clientId || !clientSecret) {
    return Response.redirect(`${DASHBOARD_URL}?auth_error=server_config`, 302);
  }

  const redirectUri = `${url.origin}/api/auth/google/callback`;
  const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      code,
      client_id: clientId,
      client_secret: clientSecret,
      redirect_uri: redirectUri,
      grant_type: "authorization_code",
    }),
  });
  const tokenData = await tokenRes.json();
  if (!tokenRes.ok || !tokenData.access_token) {
    return Response.redirect(`${DASHBOARD_URL}?auth_error=token_exchange`, 302);
  }

  const userRes = await fetch("https://www.googleapis.com/oauth2/v3/userinfo", {
    headers: { Authorization: `Bearer ${tokenData.access_token}` },
  });
  const profile = await userRes.json();
  if (!userRes.ok || !profile.sub || !profile.email) {
    return Response.redirect(`${DASHBOARD_URL}?auth_error=userinfo`, 302);
  }

  const userId = "google:" + profile.sub;
  const email = String(profile.email);
  const name = String(profile.name || email.split("@")[0]);
  const picture = profile.picture ? String(profile.picture) : null;

  await env.DB.prepare(
    `INSERT INTO users (id, email, name, picture, provider, updated_at)
     VALUES (?1, ?2, ?3, ?4, 'google', datetime('now'))
     ON CONFLICT(id) DO UPDATE SET
       email = excluded.email,
       name = excluded.name,
       picture = excluded.picture,
       updated_at = datetime('now')`
  )
    .bind(userId, email, name, picture)
    .run();

  const sessionId = randomId(24);
  const expiresAt = new Date(Date.now() + SESSION_DAYS * 864e5).toISOString();
  await env.DB.prepare(
    `INSERT INTO sessions (id, user_id, expires_at) VALUES (?1, ?2, ?3)`
  )
    .bind(sessionId, userId, expiresAt)
    .run();

  const maxAge = SESSION_DAYS * 86400;
  const headers = new Headers({ Location: DASHBOARD_URL });
  headers.append("Set-Cookie", sessionCookie(sessionId, maxAge));
  headers.append(
    "Set-Cookie",
    "a2a_oauth_state=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0"
  );
  return new Response(null, { status: 302, headers });
}

async function handleAuthMe(request, env) {
  const user = await getSessionUser(request, env);
  if (!user) {
    return json(request, { ok: false, authenticated: false }, 200, {
      "Set-Cookie": clearSessionCookie(),
    });
  }
  return json(request, {
    ok: true,
    authenticated: true,
    user: {
      id: user.id,
      email: user.email,
      name: user.name,
      picture: user.picture,
      provider: user.provider,
      default_repo: user.default_repo || null,
    },
  });
}

async function handleAuthLogout(request, env) {
  const cookies = parseCookies(request.headers.get("Cookie"));
  const sid = cookies[COOKIE_NAME];
  if (sid) {
    await env.DB.prepare(`DELETE FROM sessions WHERE id = ?`).bind(sid).run();
  }
  return json(request, { ok: true, logged_out: true }, 200, {
    "Set-Cookie": clearSessionCookie(),
  });
}

/* ─── Me / agent ─── */

async function handleMeAgent(request, env) {
  const user = await getSessionUser(request, env);
  if (!user) return bad(request, "Sign in required", 401);

  let body;
  try {
    body = await request.json();
  } catch {
    return bad(request, "Invalid JSON body");
  }

  let repo = body.repo;
  if (repo === null || repo === "" || repo === undefined) {
    repo = null;
  } else {
    repo = parseRepo(repo);
    if (!repo) return bad(request, "repo must be owner/repo or null to clear");
  }

  await env.DB.prepare(
    `UPDATE users SET default_repo = ?1, updated_at = datetime('now') WHERE id = ?2`
  )
    .bind(repo, user.id)
    .run();

  if (repo) await ensureAccount(env, repo);
  return json(request, { ok: true, default_repo: repo, user_id: user.id });
}

async function handleMeBalance(request, env) {
  const user = await getAuthUser(request, env);
  if (!user) return bad(request, "Sign in required", 401);

  const repo = user.default_repo ? parseRepo(user.default_repo) : null;
  if (!repo) {
    return json(request, {
      ok: true,
      default_repo: null,
      balance: 0,
      exists: false,
      error: "no_default_repo",
    });
  }

  const row = await env.DB.prepare(
    `SELECT repo_id, balance, created_at, updated_at FROM accounts WHERE repo_id = ?`
  )
    .bind(repo)
    .first();

  if (!row) {
    return json(request, {
      ok: true,
      default_repo: repo,
      repo_id: repo,
      balance: 0,
      exists: false,
    });
  }
  return json(request, { ok: true, default_repo: repo, ...row, exists: true });
}

/* ─── API keys ─── */

async function handleMeKeysCreate(request, env) {
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

  await env.DB.prepare(
    `INSERT INTO api_keys (id, user_id, key_hash, key_prefix, label)
     VALUES (?1, ?2, ?3, ?4, ?5)`
  )
    .bind(id, user.id, keyHash, keyPrefix, label)
    .run();

  return json(request, {
    ok: true,
    id,
    label,
    key_prefix: keyPrefix,
    key: secret,
    hint: "Copy now. The full key is never shown again.",
  });
}

async function handleMeKeysList(request, env) {
  const user = await getSessionUser(request, env);
  if (!user) return bad(request, "Sign in required", 401);

  const { results } = await env.DB.prepare(
    `SELECT id, key_prefix, label, created_at, revoked_at, last_used_at
     FROM api_keys WHERE user_id = ?1 ORDER BY created_at DESC LIMIT 50`
  )
    .bind(user.id)
    .all();

  return json(request, {
    ok: true,
    count: results.length,
    keys: results.map((k) => ({
      id: k.id,
      key_prefix: k.key_prefix + "…",
      label: k.label,
      created_at: k.created_at,
      revoked: !!k.revoked_at,
      revoked_at: k.revoked_at,
      last_used_at: k.last_used_at,
    })),
  });
}

async function handleMeKeysRevoke(request, env) {
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

/* ─── Ledger helpers ─── */

async function ensureAccount(env, repo) {
  await env.DB.prepare(
    `INSERT INTO accounts (repo_id, balance) VALUES (?, 0) ON CONFLICT(repo_id) DO NOTHING`
  )
    .bind(repo)
    .run();
}

async function readBalances(env, fromRepo, toRepo) {
  const [fromAcc, toAcc] = await env.DB.batch([
    env.DB.prepare(`SELECT balance FROM accounts WHERE repo_id = ?`).bind(fromRepo),
    env.DB.prepare(`SELECT balance FROM accounts WHERE repo_id = ?`).bind(toRepo),
  ]);
  return {
    from: fromAcc.results?.[0]?.balance ?? 0,
    to: toAcc.results?.[0]?.balance ?? 0,
  };
}

async function waitForIdem(env, key) {
  for (let i = 0; i < 12; i++) {
    const row = await env.DB.prepare(
      `SELECT status, result_json FROM idempotency WHERE key = ?`
    )
      .bind(key)
      .first();
    if (row?.status === "success" && row.result_json) {
      const data = JSON.parse(row.result_json);
      data.replayed = true;
      return data;
    }
    if (row?.status === "failed") {
      return { ok: false, error: row.result_json || "Insufficient funds", replayed: true };
    }
    if (!row) return null;
    await sleep(25);
  }
  return { ok: false, error: "Payment still in flight", pending: true };
}

/* ─── Pay ─── */

async function handlePay(request, env) {
  const t0 = Date.now();
  let body;
  try {
    body = await request.json();
  } catch {
    return bad(request, "Invalid JSON body");
  }

  const authUser = await getAuthUser(request, env);

  const rlId = authUser
    ? authUser.auth_via === "api_key"
      ? "pay:key:" + (authUser.key_id || authUser.id)
      : "pay:user:" + authUser.id
    : "pay:anon:" + (request.headers.get("CF-Connecting-IP") || "x").slice(0, 64);

  const limited = await checkRateLimit(env, rlId, RL_PAY_MAX, RL_PAY_WINDOW_SEC);
  if (limited) {
    return bad(request, "Rate limit: too many payments", 429, {
      retry_after_sec: limited.retry_after_sec,
    });
  }

  let fromRepo = parseRepo(body.from_repo || body.fromRepo);
  if (!fromRepo && authUser?.default_repo) {
    fromRepo = parseRepo(authUser.default_repo);
  }

  const toRepo = parseRepo(body.to_repo || body.toRepo);
  const amount = parseAmount(body.amount);
  const task = String(body.task || "").slice(0, 500);
  const idem =
    String(request.headers.get("Idempotency-Key") || body.idempotency_key || "")
      .trim()
      .slice(0, 128) || null;

  if (!fromRepo) {
    return bad(
      request,
      "from_repo must be owner/repo (or authenticate and set default agent)"
    );
  }
  if (!toRepo) return bad(request, "to_repo must be owner/repo");
  if (fromRepo === toRepo) return bad(request, "from_repo and to_repo must differ");
  if (amount == null) return bad(request, "amount must be between 0.000001 and 1000000");

  let wonLock = false;
  if (idem) {
    const ins = await env.DB.prepare(
      `INSERT INTO idempotency (key, status) VALUES (?1, 'pending')
       ON CONFLICT(key) DO NOTHING`
    )
      .bind(idem)
      .run();
    wonLock = (ins.meta?.changes || 0) === 1;
    if (!wonLock) {
      const replay = await waitForIdem(env, idem);
      if (replay && replay.ok) return json(request, replay);
      if (replay && replay.pending) return json(request, replay, 202);
      if (replay && !replay.ok) return bad(request, replay.error, 402);
    }
  }

  await env.DB.batch([
    env.DB.prepare(
      `INSERT INTO accounts (repo_id, balance) VALUES (?, 0) ON CONFLICT(repo_id) DO NOTHING`
    ).bind(fromRepo),
    env.DB.prepare(
      `INSERT INTO accounts (repo_id, balance) VALUES (?, 0) ON CONFLICT(repo_id) DO NOTHING`
    ).bind(toRepo),
  ]);

  const debit = await env.DB.prepare(
    `UPDATE accounts
     SET balance = balance - ?1, updated_at = datetime('now')
     WHERE repo_id = ?2 AND balance >= ?1
     RETURNING balance`
  )
    .bind(amount, fromRepo)
    .first();

  if (!debit) {
    if (idem && wonLock) {
      await env.DB.prepare(`DELETE FROM idempotency WHERE key = ? AND status = 'pending'`)
        .bind(idem)
        .run();
    }
    await env.DB.prepare(
      `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
       VALUES (?1, ?2, ?3, ?4, 'failed', ?5)`
    )
      .bind(fromRepo, toRepo, amount, task, Date.now() - t0)
      .run();
    return bad(request, "Insufficient funds", 402);
  }

  await env.DB.batch([
    env.DB.prepare(
      `UPDATE accounts
       SET balance = balance + ?1, updated_at = datetime('now')
       WHERE repo_id = ?2`
    ).bind(amount, toRepo),
    env.DB.prepare(
      `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms, idempotency_key)
       VALUES (?1, ?2, ?3, ?4, 'success', ?5, ?6)`
    ).bind(fromRepo, toRepo, amount, task, Date.now() - t0, idem),
  ]);

  const payload = {
    ok: true,
    status: "success",
    replayed: false,
    from_repo: fromRepo,
    to_repo: toRepo,
    amount,
    task,
    latency_ms: Date.now() - t0,
    balances: await readBalances(env, fromRepo, toRepo),
  };

  if (idem && wonLock) {
    await env.DB.prepare(
      `UPDATE idempotency
       SET status = 'success', result_json = ?1, updated_at = datetime('now')
       WHERE key = ?2`
    )
      .bind(JSON.stringify(payload), idem)
      .run();
  }

  return json(request, payload);
}

/* ─── Fund ─── */

async function handleFund(request, env) {
  const t0 = Date.now();
  let body;
  try {
    body = await request.json();
  } catch {
    return bad(request, "Invalid JSON body");
  }
  const repo = parseRepo(body.repo || body.to_repo || body.toRepo);
  const amount = parseAmount(body.amount);
  const task = String(body.task || "faucet").slice(0, 500);
  if (!repo) return bad(request, "repo must be owner/repo");
  if (amount == null) return bad(request, "amount must be a positive number");
  if (amount > FAUCET_MAX_PER_CALL) {
    return bad(request, "Faucet max is $" + FAUCET_MAX_PER_CALL + " per request");
  }

  await ensureAccount(env, repo);
  const row = await env.DB.prepare(
    `UPDATE accounts
     SET balance = balance + ?1, updated_at = datetime('now')
     WHERE repo_id = ?2 AND (balance + ?1) <= ?3
     RETURNING balance`
  )
    .bind(amount, repo, FAUCET_ACCOUNT_CAP)
    .first();

  if (!row) {
    return bad(request, "Faucet cap reached ($" + FAUCET_ACCOUNT_CAP + " per agent)", 429);
  }

  await env.DB.prepare(
    `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
     VALUES (?1, ?2, ?3, ?4, 'success', ?5)`
  )
    .bind(SYSTEM_FAUCET, repo, amount, task, Date.now() - t0)
    .run();

  return json(request, {
    ok: true,
    status: "funded",
    repo,
    amount,
    balance: row.balance,
    cap: FAUCET_ACCOUNT_CAP,
    latency_ms: Date.now() - t0,
  });
}

async function handleBalance(request, url, env) {
  const repo = parseRepo(url.searchParams.get("repo"));
  if (!repo) return bad(request, "repo query must be owner/repo");
  const row = await env.DB.prepare(
    `SELECT repo_id, balance, created_at, updated_at FROM accounts WHERE repo_id = ?`
  )
    .bind(repo)
    .first();
  if (!row) return json(request, { ok: true, repo_id: repo, balance: 0, exists: false });
  return json(request, { ok: true, ...row, exists: true });
}

async function handleLedger(request, url, env) {
  const limit = Math.min(Math.max(Number(url.searchParams.get("limit") || 25), 1), 100);
  const repo = (url.searchParams.get("repo") || "").trim();
  let stmt;
  if (repo) {
    if (!parseRepo(repo)) return bad(request, "repo query must be owner/repo");
    stmt = env.DB.prepare(
      `SELECT id, from_repo, to_repo, amount, task, status, latency_ms, created_at
       FROM transactions
       WHERE from_repo = ?1 OR to_repo = ?1
       ORDER BY id DESC LIMIT ?2`
    ).bind(repo, limit);
  } else {
    stmt = env.DB.prepare(
      `SELECT id, from_repo, to_repo, amount, task, status, latency_ms, created_at
       FROM transactions ORDER BY id DESC LIMIT ?1`
    ).bind(limit);
  }
  const { results } = await stmt.all();
  return json(request, { ok: true, count: results.length, transactions: results });
}

/* ─── Escrow (agent banking) ─── */

async function handleEscrowHold(request, env) {
  const t0 = Date.now();
  const authUser = await getAuthUser(request, env);
  if (!authUser) return bad(request, "Sign in or API key required", 401);

  const rlId =
    authUser.auth_via === "api_key"
      ? "escrow:key:" + (authUser.key_id || authUser.id)
      : "escrow:user:" + authUser.id;
  const limited = await checkRateLimit(env, rlId, RL_ESCROW_MAX, RL_ESCROW_WINDOW_SEC);
  if (limited) {
    return bad(request, "Rate limit: too many escrow ops", 429, {
      retry_after_sec: limited.retry_after_sec,
    });
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return bad(request, "Invalid JSON body");
  }

  let fromRepo = parseRepo(body.from_repo || body.fromRepo);
  if (!fromRepo && authUser.default_repo) {
    fromRepo = parseRepo(authUser.default_repo);
  }
  const toRepo = parseRepo(body.to_repo || body.toRepo);
  const amount = parseAmount(body.amount);
  const task = String(body.task || "escrow").slice(0, 500);
  const ttlSec = parseTtlSeconds(body);
  const idem =
    String(request.headers.get("Idempotency-Key") || body.idempotency_key || "")
      .trim()
      .slice(0, 128) || null;

  if (!fromRepo) return bad(request, "from_repo required (or set default agent)");
  if (!toRepo) return bad(request, "to_repo required");
  if (fromRepo === toRepo) return bad(request, "from_repo and to_repo must differ");
  if (amount == null) return bad(request, "invalid amount");
  if (ttlSec == null) {
    return bad(request, "ttl_hours / ttl_seconds out of range (min 10s, max 720h)");
  }

  if (idem) {
    const existing = await env.DB.prepare(
      `SELECT * FROM escrows WHERE idempotency_key = ?1`
    )
      .bind(idem)
      .first();
    if (existing) {
      return json(request, {
        ok: true,
        replayed: true,
        escrow: existing,
      });
    }
  }

  await ensureAccount(env, fromRepo);
  await ensureAccount(env, toRepo);

  const debit = await env.DB.prepare(
    `UPDATE accounts
     SET balance = balance - ?1, updated_at = datetime('now')
     WHERE repo_id = ?2 AND balance >= ?1
     RETURNING balance`
  )
    .bind(amount, fromRepo)
    .first();

  if (!debit) return bad(request, "Insufficient funds", 402);

  const id = "esc_" + randomId(12);
  const modifier = "+" + ttlSec + " seconds";

  await env.DB.batch([
    env.DB.prepare(
      `INSERT INTO escrows (
         id, from_repo, to_repo, amount, task, status, created_by,
         idempotency_key, expires_at, created_at, updated_at
       ) VALUES (
         ?1, ?2, ?3, ?4, ?5, 'held', ?6, ?7,
         datetime('now', ?8), datetime('now'), datetime('now')
       )`
    ).bind(id, fromRepo, toRepo, amount, task, authUser.id, idem, modifier),
    env.DB.prepare(
      `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms, idempotency_key)
       VALUES (?1, ?2, ?3, ?4, 'success', ?5, ?6)`
    ).bind(fromRepo, SYSTEM_ESCROW, amount, "escrow-hold:" + id, Date.now() - t0, idem),
  ]);

  const stored = await env.DB.prepare(
    `SELECT expires_at FROM escrows WHERE id = ?1`
  )
    .bind(id)
    .first();

  return json(request, {
    ok: true,
    status: "held",
    escrow: {
      id,
      from_repo: fromRepo,
      to_repo: toRepo,
      amount,
      task,
      status: "held",
      expires_at: stored?.expires_at || null,
      ttl_seconds: ttlSec,
    },
    balance_from: debit.balance,
    latency_ms: Date.now() - t0,
  });
}

async function handleEscrowRelease(request, env) {
  const t0 = Date.now();
  const authUser = await getAuthUser(request, env);
  if (!authUser) return bad(request, "Sign in or API key required", 401);

  let body;
  try {
    body = await request.json();
  } catch {
    return bad(request, "Invalid JSON body");
  }

  const id = String(body.id || "").trim();
  if (!id) return bad(request, "id required");

  const esc = await env.DB.prepare(`SELECT * FROM escrows WHERE id = ?1`).bind(id).first();
  if (!esc) return bad(request, "Escrow not found", 404);
  if (esc.status !== "held") {
    return bad(request, "Escrow is not held (status=" + esc.status + ")");
  }

  const allowed =
    authUser.id === esc.created_by ||
    (authUser.default_repo &&
      (authUser.default_repo === esc.from_repo || authUser.default_repo === esc.to_repo));
  if (!allowed) return bad(request, "Not authorized to release this escrow", 403);

  await ensureAccount(env, esc.to_repo);

  const claim = await env.DB.prepare(
    `UPDATE escrows
     SET status = 'released', released_at = datetime('now'), updated_at = datetime('now')
     WHERE id = ?1 AND status = 'held'
     RETURNING id`
  )
    .bind(id)
    .first();
  if (!claim) return bad(request, "Escrow is not held (race)");

  await env.DB.batch([
    env.DB.prepare(
      `UPDATE accounts
       SET balance = balance + ?1, updated_at = datetime('now')
       WHERE repo_id = ?2`
    ).bind(esc.amount, esc.to_repo),
    env.DB.prepare(
      `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
       VALUES (?1, ?2, ?3, ?4, 'success', ?5)`
    ).bind(SYSTEM_ESCROW, esc.to_repo, esc.amount, "escrow-release:" + id, Date.now() - t0),
  ]);

  return json(request, {
    ok: true,
    status: "released",
    id,
    to_repo: esc.to_repo,
    amount: esc.amount,
    latency_ms: Date.now() - t0,
  });
}

async function handleEscrowRefund(request, env) {
  const t0 = Date.now();
  const authUser = await getAuthUser(request, env);
  if (!authUser) return bad(request, "Sign in or API key required", 401);

  let body;
  try {
    body = await request.json();
  } catch {
    return bad(request, "Invalid JSON body");
  }

  const id = String(body.id || "").trim();
  if (!id) return bad(request, "id required");

  const esc = await env.DB.prepare(`SELECT * FROM escrows WHERE id = ?1`).bind(id).first();
  if (!esc) return bad(request, "Escrow not found", 404);
  if (esc.status !== "held") {
    return bad(request, "Escrow is not held (status=" + esc.status + ")");
  }

  const allowed =
    authUser.id === esc.created_by ||
    (authUser.default_repo && authUser.default_repo === esc.from_repo);
  if (!allowed) return bad(request, "Not authorized to refund this escrow", 403);

  await ensureAccount(env, esc.from_repo);

  const claim = await env.DB.prepare(
    `UPDATE escrows
     SET status = 'refunded', refunded_at = datetime('now'), updated_at = datetime('now')
     WHERE id = ?1 AND status = 'held'
     RETURNING id`
  )
    .bind(id)
    .first();
  if (!claim) return bad(request, "Escrow is not held (race)");

  await env.DB.batch([
    env.DB.prepare(
      `UPDATE accounts
       SET balance = balance + ?1, updated_at = datetime('now')
       WHERE repo_id = ?2`
    ).bind(esc.amount, esc.from_repo),
    env.DB.prepare(
      `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
       VALUES (?1, ?2, ?3, ?4, 'success', ?5)`
    ).bind(SYSTEM_ESCROW, esc.from_repo, esc.amount, "escrow-refund:" + id, Date.now() - t0),
  ]);

  return json(request, {
    ok: true,
    status: "refunded",
    id,
    from_repo: esc.from_repo,
    amount: esc.amount,
    latency_ms: Date.now() - t0,
  });
}

async function handleEscrowList(request, url, env) {
  const limit = Math.min(Math.max(Number(url.searchParams.get("limit") || 25), 1), 100);
  const repo = (url.searchParams.get("repo") || "").trim();
  const status = (url.searchParams.get("status") || "").trim();

  let sql = `SELECT id, from_repo, to_repo, amount, task, status, created_by,
                    expires_at, released_at, refunded_at, created_at
             FROM escrows WHERE 1=1`;
  const binds = [];

  if (repo) {
    if (!parseRepo(repo)) return bad(request, "repo must be owner/repo");
    sql += ` AND (from_repo = ? OR to_repo = ?)`;
    binds.push(repo, repo);
  }
  if (status && ["held", "released", "refunded", "expired"].includes(status)) {
    sql += ` AND status = ?`;
    binds.push(status);
  }
  sql += ` ORDER BY created_at DESC LIMIT ?`;
  binds.push(limit);

  const { results } = await env.DB.prepare(sql).bind(...binds).all();
  return json(request, { ok: true, count: results.length, escrows: results });
}
