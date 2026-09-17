/**
 * Autonomous Edge-Agent Economy — Cloudflare Worker + D1
 * Ledger + OAuth + API keys + rate limits + escrow + auto-expire + webhooks
 *
 * INVENTORY (do not delete):
 * Auth:     GET /api/auth/google, GET /api/auth/google/callback,
 *           GET /api/auth/github, GET /api/auth/github/callback,
 *           GET /api/auth/me, POST /api/auth/logout
 * Me:       POST /api/me/agent, GET /api/me/balance,
 *           GET /api/me/github/repos
 * Keys:     POST|GET /api/me/keys, POST /api/me/keys/revoke
 * Webhook:  GET|POST /api/me/webhook, POST /api/me/webhook/clear
 *           GET /api/me/webhook/deliveries
 * Ledger:   POST /api/pay, POST /api/fund, GET /api/balance, GET /api/ledger
 * Escrow:   POST /api/escrow/hold|release|refund, GET /api/escrow,
 *           POST /api/escrow/expire-now
 * Stream:   POST /api/stream/start|meter|stop, GET /api/stream
 * Cron:     scheduled() → expireHeldEscrows (+ webhook escrow.expired)
 * D1 users: github_access_token, github_login (optional ALTER)
 * D1:       streams table (d1-stream-migration.sql)
 * D1:       agent_limits, velocity_events, safety_events; api_keys.suspended_at
 * Safety:   helpers + gate on pay / escrow hold / stream start (step 3)
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
const WEBHOOK_TIMEOUT_MS = 5000;
const RL_WEBHOOK_SET_MAX = 10;
const RL_WEBHOOK_SET_WINDOW_SEC = 3600;
const RL_GITHUB_REPOS_MAX = 12;
const RL_GITHUB_REPOS_WINDOW_SEC = 3600;
const RL_STREAM_MAX = 30;
const RL_STREAM_WINDOW_SEC = 60;
const SYSTEM_STREAM = "system/stream";
const STREAM_MIN_BUDGET = 0.000001;
const STREAM_MAX_BUDGET = 10000;

/* Safety defaults (override per-repo via agent_limits) */
const SAFETY_DEFAULT_VELOCITY_MAX_TX = 50;       // max txs in window
const SAFETY_DEFAULT_VELOCITY_TX_WINDOW_SEC = 5;
const SAFETY_DEFAULT_VELOCITY_MAX_USD = 2.0;     // max spend in window
const SAFETY_DEFAULT_VELOCITY_USD_WINDOW_SEC = 60;
const SAFETY_SPIKE_TX_PER_SEC = 100;             // instant spike threshold
const SAFETY_VELOCITY_PRUNE_HOURS = 24;


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

async function hmacSha256Hex(secret, message) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
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

/** HTTPS only public webhook URL */
function parseWebhookUrl(v) {
  try {
    const u = new URL(String(v || "").trim());
    if (u.protocol !== "https:") return null;
    if (!u.hostname || u.hostname === "localhost") return null;
    return u.toString();
  } catch {
    return null;
  }
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



/* ─── Safety helpers (budget / velocity / lock / kill-switch) ─── */

async function logSafetyEvent(env, event, { repo_id, api_key_id, user_id, reason, meta } = {}) {
  try {
    await env.DB.prepare(
      `INSERT INTO safety_events (id, event, repo_id, api_key_id, user_id, reason, meta_json, created_at)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, datetime('now'))`
    )
      .bind(
        randomId(12),
        event,
        repo_id || null,
        api_key_id || null,
        user_id || null,
        reason || null,
        meta ? JSON.stringify(meta) : null
      )
      .run();
  } catch (e) {
    console.log("safety_event_log_error", e && e.message);
  }
}

async function ensureAgentLimits(env, repoId) {
  try {
    await env.DB.prepare(
      `INSERT INTO agent_limits (repo_id, updated_at) VALUES (?1, datetime('now'))
       ON CONFLICT(repo_id) DO NOTHING`
    )
      .bind(repoId)
      .run();
  } catch (e) {
    console.log("ensure_agent_limits", e && e.message);
  }
}

async function getAgentLimits(env, repoId) {
  try {
    await ensureAgentLimits(env, repoId);
    return await env.DB.prepare(`SELECT * FROM agent_limits WHERE repo_id = ?1`)
      .bind(repoId)
      .first();
  } catch {
    return null;
  }
}

/** If wallet locked → { locked: true, reason }. Else null. */
async function checkWalletLocked(env, repoId) {
  const lim = await getAgentLimits(env, repoId);
  if (lim && Number(lim.locked) === 1) {
    return { locked: true, reason: lim.lock_reason || "Wallet locked" };
  }
  return null;
}

async function lockWallet(env, repoId, reason, { api_key_id, user_id } = {}) {
  await ensureAgentLimits(env, repoId);
  await env.DB.prepare(
    `UPDATE agent_limits
     SET locked = 1,
         locked_at = datetime('now'),
         lock_reason = ?2,
         updated_at = datetime('now')
     WHERE repo_id = ?1`
  )
    .bind(repoId, String(reason || "locked").slice(0, 500))
    .run();
  await logSafetyEvent(env, "wallet.locked", {
    repo_id: repoId,
    api_key_id,
    user_id,
    reason,
  });
}

async function unlockWallet(env, repoId, { user_id } = {}) {
  await env.DB.prepare(
    `UPDATE agent_limits
     SET locked = 0,
         locked_at = NULL,
         lock_reason = NULL,
         updated_at = datetime('now')
     WHERE repo_id = ?1`
  )
    .bind(repoId)
    .run();
  await logSafetyEvent(env, "wallet.unlocked", { repo_id: repoId, user_id });
}

async function suspendApiKey(env, keyId, reason, { repo_id, user_id } = {}) {
  if (!keyId) return;
  try {
    await env.DB.prepare(
      `UPDATE api_keys
       SET suspended_at = datetime('now'), suspend_reason = ?2
       WHERE id = ?1 AND suspended_at IS NULL`
    )
      .bind(keyId, String(reason || "suspended").slice(0, 500))
      .run();
  } catch (e) {
    console.log("suspend_key_error", e && e.message);
    return;
  }
  await logSafetyEvent(env, "key.suspended", {
    api_key_id: keyId,
    repo_id,
    user_id,
    reason,
  });
}

async function recordVelocityEvent(env, repoId, amount, apiKeyId) {
  try {
    await env.DB.prepare(
      `INSERT INTO velocity_events (id, repo_id, api_key_id, amount, created_at)
       VALUES (?1, ?2, ?3, ?4, datetime('now'))`
    )
      .bind(randomId(12), repoId, apiKeyId || null, Number(amount) || 0)
      .run();
  } catch (e) {
    console.log("velocity_record_error", e && e.message);
  }
}

/**
 * Sliding-window velocity check.
 * Returns null if OK, or { code, error, retry_after_sec?, spike? }.
 */
async function checkVelocity(env, repoId, amount, apiKeyId) {
  const lim = await getAgentLimits(env, repoId);
  const maxTx = (lim && lim.velocity_max_tx != null)
    ? Number(lim.velocity_max_tx)
    : SAFETY_DEFAULT_VELOCITY_MAX_TX;
  const txWindow = (lim && lim.velocity_tx_window_sec != null)
    ? Number(lim.velocity_tx_window_sec)
    : SAFETY_DEFAULT_VELOCITY_TX_WINDOW_SEC;
  const maxUsd = (lim && lim.velocity_max_usd != null)
    ? Number(lim.velocity_max_usd)
    : SAFETY_DEFAULT_VELOCITY_MAX_USD;
  const usdWindow = (lim && lim.velocity_window_sec != null)
    ? Number(lim.velocity_window_sec)
    : SAFETY_DEFAULT_VELOCITY_USD_WINDOW_SEC;

  try {
    // Spike: txs in last 1 second
    const spike = await env.DB.prepare(
      `SELECT COUNT(*) AS c FROM velocity_events
       WHERE repo_id = ?1 AND created_at >= datetime('now', '-1 seconds')`
    )
      .bind(repoId)
      .first();
    if (spike && Number(spike.c) >= SAFETY_SPIKE_TX_PER_SEC) {
      return {
        code: "velocity_spike",
        error:
          "Sudden spike detected (" +
          spike.c +
          " tx/sec). Edge interceptor engaged.",
        spike: true,
        retry_after_sec: 5,
      };
    }

    const txCount = await env.DB.prepare(
      `SELECT COUNT(*) AS c FROM velocity_events
       WHERE repo_id = ?1 AND created_at >= datetime('now', ?2)`
    )
      .bind(repoId, "-" + txWindow + " seconds")
      .first();
    if (txCount && Number(txCount.c) >= maxTx) {
      return {
        code: "velocity_tx",
        error:
          "Velocity limit: max " +
          maxTx +
          " transactions / " +
          txWindow +
          "s",
        retry_after_sec: txWindow,
      };
    }

    const usdSum = await env.DB.prepare(
      `SELECT COALESCE(SUM(amount), 0) AS s FROM velocity_events
       WHERE repo_id = ?1 AND created_at >= datetime('now', ?2)`
    )
      .bind(repoId, "-" + usdWindow + " seconds")
      .first();
    const spentWindow = Number(usdSum?.s || 0) + (Number(amount) || 0);
    if (spentWindow > maxUsd) {
      return {
        code: "velocity_usd",
        error:
          "Velocity limit: max $" +
          maxUsd +
          " / " +
          usdWindow +
          "s",
        retry_after_sec: usdWindow,
      };
    }
  } catch (e) {
    console.log("velocity_check_error", e && e.message);
  }
  return null;
}

/**
 * Daily budget cap. Resets when UTC day changes.
 * Returns null if OK, or { code, error }.
 */
async function checkDailyBudget(env, repoId, amount) {
  const lim = await getAgentLimits(env, repoId);
  if (!lim || lim.daily_budget == null) return null;

  const today = new Date().toISOString().slice(0, 10); // YYYY-MM-DD UTC-ish
  let dailySpent = Number(lim.daily_spent || 0);
  const windowStart = lim.daily_window_start
    ? String(lim.daily_window_start).slice(0, 10)
    : null;

  if (windowStart !== today) {
    dailySpent = 0;
    try {
      await env.DB.prepare(
        `UPDATE agent_limits
         SET daily_spent = 0, daily_window_start = ?2, updated_at = datetime('now')
         WHERE repo_id = ?1`
      )
        .bind(repoId, today)
        .run();
    } catch (_) {}
  }

  if (dailySpent + Number(amount) > Number(lim.daily_budget)) {
    return {
      code: "daily_budget",
      error:
        "Daily budget cap reached ($" +
        lim.daily_budget +
        "). Spent today: $" +
        dailySpent.toFixed(6),
    };
  }
  return null;
}

async function addDailySpent(env, repoId, amount) {
  const today = new Date().toISOString().slice(0, 10);
  try {
    await ensureAgentLimits(env, repoId);
    const lim = await env.DB.prepare(
      `SELECT daily_window_start FROM agent_limits WHERE repo_id = ?1`
    )
      .bind(repoId)
      .first();
    const windowStart = lim?.daily_window_start
      ? String(lim.daily_window_start).slice(0, 10)
      : null;
    if (windowStart !== today) {
      await env.DB.prepare(
        `UPDATE agent_limits
         SET daily_spent = ?2, daily_window_start = ?3, updated_at = datetime('now')
         WHERE repo_id = ?1`
      )
        .bind(repoId, Number(amount) || 0, today)
        .run();
    } else {
      await env.DB.prepare(
        `UPDATE agent_limits
         SET daily_spent = daily_spent + ?2, updated_at = datetime('now')
         WHERE repo_id = ?1`
      )
        .bind(repoId, Number(amount) || 0)
        .run();
    }
  } catch (e) {
    console.log("daily_spent_error", e && e.message);
  }
}

/**
 * Full pre-spend safety gate for a from_repo debit.
 * Returns null if allowed, or a bad() Response.
 */
async function safetyGate(request, env, authUser, fromRepo, amount) {
  if (!fromRepo) return null;

  const sus = rejectIfSuspendedKey(request, authUser);
  if (sus) return sus;

  const locked = await checkWalletLocked(env, fromRepo);
  if (locked) {
    return bad(request, locked.reason, 403, { code: "wallet_locked" });
  }

  const budgetHit = await checkDailyBudget(env, fromRepo, amount);
  if (budgetHit) {
    return bad(request, budgetHit.error, 429, { code: budgetHit.code });
  }

  const keyId = authUser && authUser.auth_via === "api_key" ? authUser.key_id : null;
  const vel = await checkVelocity(env, fromRepo, amount, keyId);
  if (vel) {
    // Persistent spike → kill-switch
    if (vel.spike && keyId) {
      await suspendApiKey(env, keyId, vel.error, {
        repo_id: fromRepo,
        user_id: authUser && authUser.id,
      });
      await lockWallet(env, fromRepo, vel.error, {
        api_key_id: keyId,
        user_id: authUser && authUser.id,
      });
      await logSafetyEvent(env, "agent.runaway_loop", {
        repo_id: fromRepo,
        api_key_id: keyId,
        user_id: authUser && authUser.id,
        reason: vel.error,
      });
    }
    return bad(request, vel.error, 429, {
      code: vel.code,
      retry_after_sec: vel.retry_after_sec,
    });
  }

  return null;
}

/** Call after a successful debit to update velocity + daily spent. */
async function safetyRecordSpend(env, authUser, fromRepo, amount) {
  if (!fromRepo || !amount) return;
  const keyId = authUser && authUser.auth_via === "api_key" ? authUser.key_id : null;
  await recordVelocityEvent(env, fromRepo, amount, keyId);
  await addDailySpent(env, fromRepo, amount);
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

/**
 * Security: if a valid session already exists, OAuth callbacks must not
 * silently switch identity. User must POST /api/auth/logout first, then
 * sign in with the other provider.
 * Returns Response redirect when blocked; null when OK to continue OAuth.
 */
async function rejectIfAlreadySignedIn(request, env) {
  const existing = await getSessionUser(request, env);
  if (!existing) return null;
  return Response.redirect(
    `${DASHBOARD_URL}?auth_error=${encodeURIComponent("already_signed_in")}`,
    302
  );
}

async function getApiKeyUser(request, env) {
  const auth = request.headers.get("Authorization") || "";
  const m = auth.match(/^Bearer\s+(a2a_[A-Fa-f0-9]+)$/i);
  if (!m) return null;

  const raw = m[1];
  const hash = await sha256Hex(raw);

  let row;
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
  } catch (_) {
    // suspended_at column may be missing until ALTER
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

  if (!row || row.revoked_at) return null;
  if (row.suspended_at) {
    // Mark so callers can return 403 with reason
    row._suspended = true;
    row._suspend_reason = row.suspend_reason || "API key suspended";
    return row;
  }

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
  if (keyUser) {
    if (keyUser._suspended) {
      return { ...keyUser, auth_via: "api_key", suspended: true };
    }
    return { ...keyUser, auth_via: "api_key" };
  }
  return null;
}

/** Return 403 Response if auth user is a suspended API key; else null. */
function rejectIfSuspendedKey(request, authUser) {
  if (authUser && authUser.auth_via === "api_key" && (authUser.suspended || authUser._suspended)) {
    return bad(
      request,
      authUser._suspend_reason || authUser.suspend_reason || "API key suspended (kill-switch)",
      403,
      { code: "key_suspended" }
    );
  }
  return null;
}

/* ─── Webhooks ─── */

/**
 * POST signed event to user's webhook_url.
 * webhook_secret_hash stores the raw signing secret (whsec_…) for HMAC outbound.
 * Failures are logged; never throw into ledger path.
 */
async function dispatchWebhook(env, userId, event, data) {
  if (!userId || !event) return { skipped: true, reason: "no_user" };

  let row;
  try {
    row = await env.DB.prepare(
      `SELECT webhook_url, webhook_secret_hash FROM users WHERE id = ?1`
    )
      .bind(userId)
      .first();
  } catch (e) {
    console.log("webhook_lookup_error", e && e.message);
    return { skipped: true, reason: "lookup_error" };
  }

  const url = row?.webhook_url;
  const secret = row?.webhook_secret_hash;
  if (!url || !secret) return { skipped: true, reason: "not_configured" };

  const payload = {
    id: "evt_" + randomId(12),
    event,
    created_at: new Date().toISOString(),
    data: data || {},
  };
  const body = JSON.stringify(payload);

  let statusCode = null;
  let ok = 0;
  let error = null;

  try {
    const sig = await hmacSha256Hex(secret, body);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), WEBHOOK_TIMEOUT_MS);
    try {
      const res = await fetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-AgentPay-Signature": "sha256=" + sig,
          "X-AgentPay-Event": event,
          "User-Agent": "AgentPay-Webhooks/1.0",
        },
        body,
        signal: controller.signal,
      });
      statusCode = res.status;
      ok = res.ok ? 1 : 0;
      if (!res.ok) error = "HTTP " + res.status;
    } finally {
      clearTimeout(timer);
    }
  } catch (e) {
    error =
      (e && e.name === "AbortError" ? "timeout" : null) ||
      (e && e.message) ||
      "fetch failed";
  }

  try {
    await env.DB.prepare(
      `INSERT INTO webhook_deliveries (
         id, user_id, event, escrow_id, url, payload_json,
         status_code, ok, error, attempts, created_at
       ) VALUES (
         ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 1, datetime('now')
       )`
    )
      .bind(
        randomId(12),
        userId,
        event,
        (data && (data.escrow_id || data.id)) || null,
        url,
        body,
        statusCode,
        ok,
        error
      )
      .run();
  } catch (e) {
    console.log("webhook_log_error", e && e.message);
  }

  return { ok: !!ok, status_code: statusCode, error };
}

/** Fire webhook without blocking the HTTP response when ctx is available. */
function scheduleWebhook(ctx, env, userId, event, data) {
  const p = dispatchWebhook(env, userId, event, data).catch((e) => {
    console.log("webhook_bg_error", e && e.message);
  });
  if (ctx && typeof ctx.waitUntil === "function") ctx.waitUntil(p);
  return p;
}

/* ─── Auto-expire held escrows (cron) ─── */

async function expireHeldEscrows(env, ctx) {
  const t0 = Date.now();
  const { results } = await env.DB.prepare(
    `SELECT id, from_repo, to_repo, amount, task, created_by
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

      if (esc.created_by) {
        scheduleWebhook(ctx, env, esc.created_by, "escrow.expired", {
          id: esc.id,
          escrow_id: esc.id,
          from_repo: esc.from_repo,
          to_repo: esc.to_repo,
          amount: esc.amount,
          task: esc.task,
          status: "expired",
        });
      }
    } catch (e) {
      console.log("expire_error", esc.id, e && e.message);
    }
  }

  return { expired, scanned: results.length, latency_ms: Date.now() - t0 };
}

export default {
  async fetch(request, env, ctx) {
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
      if (request.method === "GET" && url.pathname === "/api/auth/github") {
        return handleAuthGithubStart(request, env, url);
      }
      if (request.method === "GET" && url.pathname === "/api/auth/github/callback") {
        return await handleAuthGithubCallback(request, env, url);
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
      if (request.method === "GET" && url.pathname === "/api/me/github/repos") {
        return await handleMeGithubRepos(request, env);
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

      if (request.method === "GET" && url.pathname === "/api/me/webhook") {
        return await handleMeWebhookGet(request, env);
      }
      if (request.method === "POST" && url.pathname === "/api/me/webhook") {
        return await handleMeWebhookSet(request, env);
      }
      if (request.method === "POST" && url.pathname === "/api/me/webhook/clear") {
        return await handleMeWebhookClear(request, env);
      }
      if (request.method === "GET" && url.pathname === "/api/me/webhook/deliveries") {
        return await handleMeWebhookDeliveries(request, env, url);
      }

      if (request.method === "POST" && url.pathname === "/api/escrow/hold") {
        return await handleEscrowHold(request, env);
      }
      if (request.method === "POST" && url.pathname === "/api/escrow/release") {
        return await handleEscrowRelease(request, env, ctx);
      }
      if (request.method === "POST" && url.pathname === "/api/escrow/refund") {
        return await handleEscrowRefund(request, env, ctx);
      }
      if (request.method === "GET" && url.pathname === "/api/escrow") {
        return await handleEscrowList(request, url, env);
      }
      if (request.method === "POST" && url.pathname === "/api/escrow/expire-now") {
        const authUser = await getAuthUser(request, env);
        if (!authUser) return bad(request, "Sign in or API key required", 401);
        const result = await expireHeldEscrows(env, ctx);
        return json(request, { ok: true, ...result });
      }

      if (request.method === "POST" && url.pathname === "/api/stream/start") {
        return await handleStreamStart(request, env);
      }
      if (request.method === "POST" && url.pathname === "/api/stream/meter") {
        return await handleStreamMeter(request, env);
      }
      if (request.method === "POST" && url.pathname === "/api/stream/stop") {
        return await handleStreamStop(request, env);
      }
      if (request.method === "GET" && url.pathname === "/api/stream") {
        return await handleStreamList(request, url, env);
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
            auth_google: "GET /api/auth/google",
            auth_github: "GET /api/auth/github",
            me_agent: "POST /api/me/agent",
            me_balance: "GET /api/me/balance",
            me_github_repos: "GET /api/me/github/repos",
            me_keys: "GET|POST /api/me/keys",
            me_webhook: "GET|POST /api/me/webhook",
            me_webhook_clear: "POST /api/me/webhook/clear",
            me_webhook_deliveries: "GET /api/me/webhook/deliveries",
            escrow_hold: "POST /api/escrow/hold",
            escrow_release: "POST /api/escrow/release",
            escrow_refund: "POST /api/escrow/refund",
            escrow_list: "GET /api/escrow",
            escrow_expire_now: "POST /api/escrow/expire-now",
            stream_start: "POST /api/stream/start",
            stream_meter: "POST /api/stream/meter",
            stream_stop: "POST /api/stream/stop",
            stream_list: "GET /api/stream",
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
          const result = await expireHeldEscrows(env, ctx);
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

  // Must log out before switching provider / re-auth while session active
  const blocked = await rejectIfAlreadySignedIn(request, env);
  if (blocked) return blocked;

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

  const googleUserId = "google:" + profile.sub;
  const email = String(profile.email);
  const name = String(profile.name || email.split("@")[0]);
  const picture = profile.picture ? String(profile.picture) : null;

  // Same email may already exist from GitHub — link session to that row
  let sessionUserId = googleUserId;
  const byGoogle = await env.DB.prepare(`SELECT id FROM users WHERE id = ?1`)
    .bind(googleUserId)
    .first();

  if (byGoogle) {
    await env.DB.prepare(
      `UPDATE users
       SET email = ?1, name = ?2, picture = ?3, provider = 'google', updated_at = datetime('now')
       WHERE id = ?4`
    )
      .bind(email, name, picture, googleUserId)
      .run();
    sessionUserId = googleUserId;
  } else {
    const byEmail = await env.DB.prepare(`SELECT id FROM users WHERE email = ?1`)
      .bind(email)
      .first();
    if (byEmail) {
      await env.DB.prepare(
        `UPDATE users
         SET name = COALESCE(NULLIF(?1, ''), name),
             picture = COALESCE(?2, picture),
             updated_at = datetime('now')
         WHERE id = ?3`
      )
        .bind(name, picture, byEmail.id)
        .run();
      sessionUserId = byEmail.id;
    } else {
      await env.DB.prepare(
        `INSERT INTO users (id, email, name, picture, provider, updated_at)
         VALUES (?1, ?2, ?3, ?4, 'google', datetime('now'))`
      )
        .bind(googleUserId, email, name, picture)
        .run();
      sessionUserId = googleUserId;
    }
  }

  const sessionId = randomId(24);
  const expiresAt = new Date(Date.now() + SESSION_DAYS * 864e5).toISOString();
  await env.DB.prepare(
    `INSERT INTO sessions (id, user_id, expires_at) VALUES (?1, ?2, ?3)`
  )
    .bind(sessionId, sessionUserId, expiresAt)
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

/* ─── GitHub OAuth ─── */

function handleAuthGithubStart(request, env, url) {
  const clientId = env.GITHUB_CLIENT_ID;
  if (!clientId) return bad(request, "GITHUB_CLIENT_ID not configured on Worker", 500);

  const redirectUri = `${url.origin}/api/auth/github/callback`;
  const state = randomId(16);
  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    scope: "read:user user:email",
    state,
    allow_signup: "true",
  });
  const headers = new Headers({
    Location: `https://github.com/login/oauth/authorize?${params}`,
    "Set-Cookie": `a2a_oauth_state=${state}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600`,
  });
  return new Response(null, { status: 302, headers });
}

async function handleAuthGithubCallback(request, env, url) {
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const err = url.searchParams.get("error");
  if (err) {
    return Response.redirect(
      `${DASHBOARD_URL}?auth_error=${encodeURIComponent(err)}`,
      302
    );
  }
  if (!code || !state) {
    return Response.redirect(`${DASHBOARD_URL}?auth_error=missing_code`, 302);
  }

  // Must log out before switching provider / re-auth while session active
  const blocked = await rejectIfAlreadySignedIn(request, env);
  if (blocked) return blocked;

  const cookies = parseCookies(request.headers.get("Cookie"));
  if (!cookies.a2a_oauth_state || cookies.a2a_oauth_state !== state) {
    return Response.redirect(`${DASHBOARD_URL}?auth_error=bad_state`, 302);
  }

  const clientId = env.GITHUB_CLIENT_ID;
  const clientSecret = env.GITHUB_CLIENT_SECRET;
  if (!clientId || !clientSecret) {
    return Response.redirect(`${DASHBOARD_URL}?auth_error=server_config`, 302);
  }

  const redirectUri = `${url.origin}/api/auth/github/callback`;
  const tokenRes = await fetch("https://github.com/login/oauth/access_token", {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      client_id: clientId,
      client_secret: clientSecret,
      code,
      redirect_uri: redirectUri,
    }),
  });
  const tokenData = await tokenRes.json();
  if (!tokenRes.ok || !tokenData.access_token) {
    return Response.redirect(`${DASHBOARD_URL}?auth_error=token_exchange`, 302);
  }

  const accessToken = tokenData.access_token;
  const userRes = await fetch("https://api.github.com/user", {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: "application/vnd.github+json",
      "User-Agent": "AgentPay-Worker",
    },
  });
  const profile = await userRes.json();
  if (!userRes.ok || !profile.id) {
    return Response.redirect(`${DASHBOARD_URL}?auth_error=userinfo`, 302);
  }

  let email = profile.email ? String(profile.email) : null;
  if (!email) {
    try {
      const emailRes = await fetch("https://api.github.com/user/emails", {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          Accept: "application/vnd.github+json",
          "User-Agent": "AgentPay-Worker",
        },
      });
      if (emailRes.ok) {
        const emails = await emailRes.json();
        const primary =
          (Array.isArray(emails) && emails.find((e) => e.primary && e.verified)) ||
          (Array.isArray(emails) && emails.find((e) => e.verified)) ||
          (Array.isArray(emails) && emails[0]);
        if (primary && primary.email) email = String(primary.email);
      }
    } catch (_) {
      /* optional */
    }
  }
  if (!email) {
    email = `${profile.login}@users.noreply.github.com`;
  }

  const githubUserId = "github:" + profile.id;
  const name = String(profile.name || profile.login || email.split("@")[0]);
  const picture = profile.avatar_url ? String(profile.avatar_url) : null;

  // Resolve account:
  // 1) existing github:id
  // 2) same email already used (e.g. Google) → link session to that user
  // 3) else create new github user
  let sessionUserId = githubUserId;
  const byGithub = await env.DB.prepare(`SELECT id FROM users WHERE id = ?1`)
    .bind(githubUserId)
    .first();

  const ghLogin = profile.login ? String(profile.login) : null;

  if (byGithub) {
    await env.DB.prepare(
      `UPDATE users
       SET email = ?1, name = ?2, picture = ?3, provider = 'github',
           github_access_token = ?4, github_login = ?5, updated_at = datetime('now')
       WHERE id = ?6`
    )
      .bind(email, name, picture, accessToken, ghLogin, githubUserId)
      .run();
    sessionUserId = githubUserId;
  } else {
    const byEmail = await env.DB.prepare(`SELECT id FROM users WHERE email = ?1`)
      .bind(email)
      .first();
    if (byEmail) {
      // Same person logged in via Google before — reuse that row (email UNIQUE)
      await env.DB.prepare(
        `UPDATE users
         SET name = COALESCE(NULLIF(?1, ''), name),
             picture = COALESCE(?2, picture),
             github_access_token = ?3,
             github_login = ?4,
             updated_at = datetime('now')
         WHERE id = ?5`
      )
        .bind(name, picture, accessToken, ghLogin, byEmail.id)
        .run();
      sessionUserId = byEmail.id;
    } else {
      await env.DB.prepare(
        `INSERT INTO users (id, email, name, picture, provider, github_access_token, github_login, updated_at)
         VALUES (?1, ?2, ?3, ?4, 'github', ?5, ?6, datetime('now'))`
      )
        .bind(githubUserId, email, name, picture, accessToken, ghLogin)
        .run();
      sessionUserId = githubUserId;
    }
  }

  const sessionId = randomId(24);
  const expiresAt = new Date(Date.now() + SESSION_DAYS * 864e5).toISOString();
  await env.DB.prepare(
    `INSERT INTO sessions (id, user_id, expires_at) VALUES (?1, ?2, ?3)`
  )
    .bind(sessionId, sessionUserId, expiresAt)
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
  let hasGithub = false;
  let githubLogin = null;
  try {
    const g = await env.DB.prepare(
      `SELECT github_access_token, github_login FROM users WHERE id = ?1`
    )
      .bind(user.id)
      .first();
    hasGithub = !!(g && g.github_access_token);
    githubLogin = g?.github_login || null;
  } catch (_) {
    /* columns may be missing until ALTER */
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
      has_github: hasGithub,
      github_login: githubLogin,
    },
  });
}

async function handleAuthLogout(request, env) {
  const cookies = parseCookies(request.headers.get("Cookie"));
  const sid = cookies[COOKIE_NAME];
  let githubCleared = false;
  if (sid) {
    // Clear GitHub token before dropping session (security: no lingering token after logout)
    try {
      const sess = await env.DB.prepare(
        `SELECT user_id FROM sessions WHERE id = ?1`
      )
        .bind(sid)
        .first();
      if (sess && sess.user_id) {
        await env.DB.prepare(
          `UPDATE users
           SET github_access_token = NULL,
               github_login = NULL,
               updated_at = datetime('now')
           WHERE id = ?1`
        )
          .bind(sess.user_id)
          .run();
        githubCleared = true;
      }
    } catch (_) {
      /* columns optional */
    }
    await env.DB.prepare(`DELETE FROM sessions WHERE id = ?`).bind(sid).run();
  }
  return json(
    request,
    { ok: true, logged_out: true, github_token_cleared: githubCleared },
    200,
    { "Set-Cookie": clearSessionCookie() }
  );
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

/** List GitHub repos for signed-in user (requires prior GitHub OAuth with read:user). */
async function handleMeGithubRepos(request, env) {
  const user = await getSessionUser(request, env);
  if (!user) return bad(request, "Sign in required", 401);

  const limited = await checkRateLimit(
    env,
    "githubrepos:" + user.id,
    RL_GITHUB_REPOS_MAX,
    RL_GITHUB_REPOS_WINDOW_SEC
  );
  if (limited) {
    return bad(
      request,
      "Rate limit: max " +
        RL_GITHUB_REPOS_MAX +
        " GitHub repo fetches per hour",
      429,
      {
        code: "rate_limited",
        retry_after_sec: limited.retry_after_sec,
      }
    );
  }

  let row;
  try {
    row = await env.DB.prepare(
      `SELECT github_access_token, github_login FROM users WHERE id = ?1`
    )
      .bind(user.id)
      .first();
  } catch (e) {
    return bad(
      request,
      "D1 missing github_access_token / github_login — run ALTER TABLE",
      500
    );
  }

  const token = row?.github_access_token;
  if (!token) {
    return bad(
      request,
      "GitHub not linked. Log out, then Sign in with GitHub once to enable repo picker.",
      400,
      { code: "github_not_linked" }
    );
  }

  const all = [];
  let page = 1;
  const maxPages = 3;
  while (page <= maxPages) {
    const res = await fetch(
      `https://api.github.com/user/repos?per_page=100&page=${page}&sort=updated&affiliation=owner,collaborator,organization_member`,
      {
        headers: {
          Authorization: `Bearer ${token}`,
          Accept: "application/vnd.github+json",
          "User-Agent": "AgentPay-Worker",
        },
      }
    );
    if (res.status === 401 || res.status === 403) {
      return bad(
        request,
        "GitHub token expired or revoked. Log out and Sign in with GitHub again.",
        401,
        { code: "github_token_invalid" }
      );
    }
    if (!res.ok) {
      return bad(request, "GitHub API error HTTP " + res.status, 502);
    }
    const batch = await res.json();
    if (!Array.isArray(batch) || batch.length === 0) break;
    for (const r of batch) {
      if (r && r.full_name) {
        all.push({
          full_name: String(r.full_name),
          private: !!r.private,
          description: r.description ? String(r.description).slice(0, 120) : null,
          updated_at: r.updated_at || null,
        });
      }
    }
    if (batch.length < 100) break;
    page += 1;
  }

  return json(request, {
    ok: true,
    github_login: row.github_login || null,
    count: all.length,
    repos: all,
  });
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

/* ─── Me / webhook ─── */

async function handleMeWebhookGet(request, env) {
  const user = await getSessionUser(request, env);
  if (!user) return bad(request, "Sign in required", 401);

  const row = await env.DB.prepare(
    `SELECT webhook_url, webhook_secret_prefix FROM users WHERE id = ?1`
  )
    .bind(user.id)
    .first();

  return json(request, {
    ok: true,
    configured: !!(row && row.webhook_url),
    url: row?.webhook_url || null,
    secret_prefix: row?.webhook_secret_prefix ? row.webhook_secret_prefix + "…" : null,
    events: ["escrow.released", "escrow.refunded", "escrow.expired"],
  });
}

async function handleMeWebhookSet(request, env) {
  const user = await getSessionUser(request, env);
  if (!user) return bad(request, "Sign in required", 401);

  const limited = await checkRateLimit(
    env,
    "webhookset:" + user.id,
    RL_WEBHOOK_SET_MAX,
    RL_WEBHOOK_SET_WINDOW_SEC
  );
  if (limited) {
    return bad(
      request,
      "Rate limit: max " + RL_WEBHOOK_SET_MAX + " webhook updates per hour",
      429,
      { retry_after_sec: limited.retry_after_sec }
    );
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return bad(request, "Invalid JSON body");
  }

  const url = parseWebhookUrl(body.url || body.webhook_url);
  if (!url) {
    return bad(request, "url must be a public https:// endpoint");
  }

  // Raw secret for HMAC signing stored in webhook_secret_hash column.
  // Shown once — copy offline.
  const secret = "whsec_" + randomId(24);
  const prefix = secret.slice(0, 12);

  await env.DB.prepare(
    `UPDATE users
     SET webhook_url = ?1,
         webhook_secret_hash = ?2,
         webhook_secret_prefix = ?3,
         updated_at = datetime('now')
     WHERE id = ?4`
  )
    .bind(url, secret, prefix, user.id)
    .run();

  return json(request, {
    ok: true,
    url,
    secret_prefix: prefix + "…",
    secret,
    events: ["escrow.released", "escrow.refunded", "escrow.expired"],
    hint: "Copy secret now. Verify X-AgentPay-Signature: sha256=<hmac-sha256(secret, rawBody)>.",
  });
}

async function handleMeWebhookClear(request, env) {
  const user = await getSessionUser(request, env);
  if (!user) return bad(request, "Sign in required", 401);

  await env.DB.prepare(
    `UPDATE users
     SET webhook_url = NULL,
         webhook_secret_hash = NULL,
         webhook_secret_prefix = NULL,
         updated_at = datetime('now')
     WHERE id = ?1`
  )
    .bind(user.id)
    .run();

  return json(request, { ok: true, cleared: true });
}

async function handleMeWebhookDeliveries(request, env, url) {
  const user = await getSessionUser(request, env);
  if (!user) return bad(request, "Sign in required", 401);

  const limit = Math.min(Math.max(Number(url.searchParams.get("limit") || 25), 1), 100);
  const { results } = await env.DB.prepare(
    `SELECT id, event, escrow_id, url, status_code, ok, error, attempts, created_at
     FROM webhook_deliveries
     WHERE user_id = ?1
     ORDER BY created_at DESC
     LIMIT ?2`
  )
    .bind(user.id, limit)
    .all();

  return json(request, {
    ok: true,
    count: results.length,
    deliveries: results,
  });
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

  // Safety: suspended key / wallet lock / daily budget / velocity
  if (authUser) {
    const blocked = await safetyGate(request, env, authUser, fromRepo, amount);
    if (blocked) return blocked;
  } else {
    // Anonymous pay: still enforce wallet lock + velocity defaults
    const locked = await checkWalletLocked(env, fromRepo);
    if (locked) return bad(request, locked.reason, 403, { code: "wallet_locked" });
    const vel = await checkVelocity(env, fromRepo, amount, null);
    if (vel) {
      return bad(request, vel.error, 429, {
        code: vel.code,
        retry_after_sec: vel.retry_after_sec,
      });
    }
  }

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

  await safetyRecordSpend(env, authUser, fromRepo, amount);

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

  {
    const blocked = await safetyGate(request, env, authUser, fromRepo, amount);
    if (blocked) return blocked;
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

  await safetyRecordSpend(env, authUser, fromRepo, amount);

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

async function handleEscrowRelease(request, env, ctx) {
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

  if (esc.created_by) {
    scheduleWebhook(ctx, env, esc.created_by, "escrow.released", {
      id: esc.id,
      escrow_id: esc.id,
      from_repo: esc.from_repo,
      to_repo: esc.to_repo,
      amount: esc.amount,
      task: esc.task,
      status: "released",
      released_by: authUser.id,
    });
  }

  return json(request, {
    ok: true,
    status: "released",
    id,
    to_repo: esc.to_repo,
    amount: esc.amount,
    latency_ms: Date.now() - t0,
  });
}

async function handleEscrowRefund(request, env, ctx) {
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

  if (esc.created_by) {
    scheduleWebhook(ctx, env, esc.created_by, "escrow.refunded", {
      id: esc.id,
      escrow_id: esc.id,
      from_repo: esc.from_repo,
      to_repo: esc.to_repo,
      amount: esc.amount,
      task: esc.task,
      status: "refunded",
      refunded_by: authUser.id,
    });
  }

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


/* ─── Streaming micro-pay ───
 * Start: debit budget from from_repo → system/stream (held)
 * Meter: move rate*units from held spent tracking → to_repo
 * Stop:  refund (budget - spent) to from_repo
 */

async function handleStreamStart(request, env) {
  const t0 = Date.now();
  const authUser = await getAuthUser(request, env);
  if (!authUser) return bad(request, "Sign in or API key required", 401);

  const rlId =
    authUser.auth_via === "api_key"
      ? "stream:key:" + (authUser.key_id || authUser.id)
      : "stream:user:" + authUser.id;
  const limited = await checkRateLimit(env, rlId, RL_STREAM_MAX, RL_STREAM_WINDOW_SEC);
  if (limited) {
    return bad(request, "Rate limit: too many stream ops", 429, {
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
  const budget = parseAmount(body.budget ?? body.amount);
  const rate = parseAmount(body.rate_per_unit ?? body.rate);
  const unitLabel = String(body.unit_label || body.unit || "token").slice(0, 32);
  const task = String(body.task || "stream").slice(0, 500);
  const idem =
    String(request.headers.get("Idempotency-Key") || body.idempotency_key || "")
      .trim()
      .slice(0, 128) || null;

  if (!fromRepo) return bad(request, "from_repo required (or set default agent)");
  if (!toRepo) return bad(request, "to_repo required");
  if (fromRepo === toRepo) return bad(request, "from_repo and to_repo must differ");
  if (budget == null || budget < STREAM_MIN_BUDGET || budget > STREAM_MAX_BUDGET) {
    return bad(request, "budget must be between " + STREAM_MIN_BUDGET + " and " + STREAM_MAX_BUDGET);
  }
  if (rate == null || rate <= 0) return bad(request, "rate_per_unit must be > 0");
  if (rate > budget) return bad(request, "rate_per_unit cannot exceed budget");

  {
    const blocked = await safetyGate(request, env, authUser, fromRepo, budget);
    if (blocked) return blocked;
  }

  if (idem) {
    try {
      const existing = await env.DB.prepare(
        `SELECT * FROM streams WHERE idempotency_key = ?1`
      )
        .bind(idem)
        .first();
      if (existing) {
        return json(request, { ok: true, replayed: true, stream: existing });
      }
    } catch (e) {
      return bad(request, "streams table missing — run d1-stream-migration.sql", 500);
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
    .bind(budget, fromRepo)
    .first();

  if (!debit) return bad(request, "Insufficient funds", 402);

  const id = "str_" + randomId(12);

  try {
    await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO streams (
           id, from_repo, to_repo, task, status, budget, rate_per_unit, unit_label,
           spent, units_metered, created_by, idempotency_key, created_at, updated_at
         ) VALUES (
           ?1, ?2, ?3, ?4, 'open', ?5, ?6, ?7, 0, 0, ?8, ?9, datetime('now'), datetime('now')
         )`
      ).bind(
        id,
        fromRepo,
        toRepo,
        task,
        budget,
        rate,
        unitLabel,
        authUser.id,
        idem
      ),
      env.DB.prepare(
        `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms, idempotency_key)
         VALUES (?1, ?2, ?3, ?4, 'success', ?5, ?6)`
      ).bind(
        fromRepo,
        SYSTEM_STREAM,
        budget,
        "stream-start:" + id,
        Date.now() - t0,
        idem
      ),
    ]);
  } catch (e) {
    // refund on insert failure
    await env.DB.prepare(
      `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
    )
      .bind(budget, fromRepo)
      .run();
    return bad(request, "Stream create failed: " + (e.message || e), 500);
  }

  await safetyRecordSpend(env, authUser, fromRepo, budget);

  return json(request, {
    ok: true,
    status: "open",
    stream: {
      id,
      from_repo: fromRepo,
      to_repo: toRepo,
      budget,
      rate_per_unit: rate,
      unit_label: unitLabel,
      spent: 0,
      remaining: budget,
      units_metered: 0,
      task,
      status: "open",
    },
    balance_from: debit.balance,
    latency_ms: Date.now() - t0,
    hint: "Call POST /api/stream/meter with { id, units } as work progresses. Stop refunds remainder.",
  });
}

async function handleStreamMeter(request, env) {
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
  const units = Number(body.units);
  if (!id) return bad(request, "id required");
  if (!Number.isFinite(units) || units <= 0) return bad(request, "units must be > 0");

  let row;
  try {
    row = await env.DB.prepare(`SELECT * FROM streams WHERE id = ?1`).bind(id).first();
  } catch {
    return bad(request, "streams table missing — run d1-stream-migration.sql", 500);
  }
  if (!row) return bad(request, "Stream not found", 404);
  if (row.status !== "open") {
    return bad(request, "Stream is not open (status=" + row.status + ")");
  }

  const allowed =
    authUser.id === row.created_by ||
    (authUser.default_repo &&
      (authUser.default_repo === row.from_repo || authUser.default_repo === row.to_repo));
  if (!allowed) return bad(request, "Not authorized to meter this stream", 403);

  const remaining = Number(row.budget) - Number(row.spent);
  if (remaining <= 0) {
    await env.DB.prepare(
      `UPDATE streams SET status = 'exhausted', updated_at = datetime('now') WHERE id = ?1`
    )
      .bind(id)
      .run();
    return bad(request, "Stream budget exhausted", 402);
  }

  let cost = Math.round(units * Number(row.rate_per_unit) * 1e6) / 1e6;
  let unitsApplied = units;
  if (cost > remaining) {
    cost = remaining;
    unitsApplied = Math.round((remaining / Number(row.rate_per_unit)) * 1e6) / 1e6;
  }

  await ensureAccount(env, row.to_repo);

  await env.DB.batch([
    env.DB.prepare(
      `UPDATE streams
       SET spent = spent + ?1,
           units_metered = units_metered + ?2,
           status = CASE WHEN spent + ?1 >= budget THEN 'exhausted' ELSE 'open' END,
           updated_at = datetime('now')
       WHERE id = ?3 AND status = 'open'`
    ).bind(cost, unitsApplied, id),
    env.DB.prepare(
      `UPDATE accounts
       SET balance = balance + ?1, updated_at = datetime('now')
       WHERE repo_id = ?2`
    ).bind(cost, row.to_repo),
    env.DB.prepare(
      `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
       VALUES (?1, ?2, ?3, ?4, 'success', ?5)`
    ).bind(
      SYSTEM_STREAM,
      row.to_repo,
      cost,
      "stream-meter:" + id,
      Date.now() - t0
    ),
  ]);

  const updated = await env.DB.prepare(`SELECT * FROM streams WHERE id = ?1`).bind(id).first();
  const rem = Number(updated.budget) - Number(updated.spent);

  return json(request, {
    ok: true,
    id,
    units_applied: unitsApplied,
    amount: cost,
    spent: updated.spent,
    remaining: Math.max(0, rem),
    units_metered: updated.units_metered,
    status: updated.status,
    latency_ms: Date.now() - t0,
  });
}

async function handleStreamStop(request, env) {
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

  let row;
  try {
    row = await env.DB.prepare(`SELECT * FROM streams WHERE id = ?1`).bind(id).first();
  } catch {
    return bad(request, "streams table missing — run d1-stream-migration.sql", 500);
  }
  if (!row) return bad(request, "Stream not found", 404);
  if (row.status !== "open" && row.status !== "exhausted") {
    return bad(request, "Stream already stopped (status=" + row.status + ")");
  }

  const allowed =
    authUser.id === row.created_by ||
    (authUser.default_repo && authUser.default_repo === row.from_repo);
  if (!allowed) return bad(request, "Not authorized to stop this stream", 403);

  const claim = await env.DB.prepare(
    `UPDATE streams
     SET status = 'stopped', stopped_at = datetime('now'), updated_at = datetime('now')
     WHERE id = ?1 AND status IN ('open', 'exhausted')
     RETURNING id, budget, spent, from_repo`
  )
    .bind(id)
    .first();
  if (!claim) return bad(request, "Stream not stoppable (race)");

  const refund = Math.max(0, Math.round((Number(claim.budget) - Number(claim.spent)) * 1e6) / 1e6);
  if (refund > 0) {
    await ensureAccount(env, claim.from_repo);
    await env.DB.batch([
      env.DB.prepare(
        `UPDATE accounts
         SET balance = balance + ?1, updated_at = datetime('now')
         WHERE repo_id = ?2`
      ).bind(refund, claim.from_repo),
      env.DB.prepare(
        `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
         VALUES (?1, ?2, ?3, ?4, 'success', ?5)`
      ).bind(
        SYSTEM_STREAM,
        claim.from_repo,
        refund,
        "stream-stop-refund:" + id,
        Date.now() - t0
      ),
    ]);
  }

  return json(request, {
    ok: true,
    status: "stopped",
    id,
    spent: Number(row.spent),
    refunded: refund,
    latency_ms: Date.now() - t0,
  });
}

async function handleStreamList(request, url, env) {
  const limit = Math.min(Math.max(Number(url.searchParams.get("limit") || 25), 1), 100);
  const repo = (url.searchParams.get("repo") || "").trim();
  const status = (url.searchParams.get("status") || "").trim();

  let sql = `SELECT id, from_repo, to_repo, task, status, budget, rate_per_unit, unit_label,
                    spent, units_metered, created_by, created_at, stopped_at
             FROM streams WHERE 1=1`;
  const binds = [];

  if (repo) {
    if (!parseRepo(repo)) return bad(request, "repo must be owner/repo");
    sql += ` AND (from_repo = ? OR to_repo = ?)`;
    binds.push(repo, repo);
  }
  if (status && ["open", "stopped", "exhausted"].includes(status)) {
    sql += ` AND status = ?`;
    binds.push(status);
  }
  sql += ` ORDER BY created_at DESC LIMIT ?`;
  binds.push(limit);

  try {
    const { results } = await env.DB.prepare(sql).bind(...binds).all();
    return json(request, { ok: true, count: results.length, streams: results });
  } catch (e) {
    return bad(request, "streams table missing — run d1-stream-migration.sql", 500);
  }
}
