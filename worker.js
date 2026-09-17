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
 * Safety:   gate + /api/me/safety + webhooks wallet.locked/agent.runaway_loop
 * Cron:     expireHeldEscrows + pruneTelemetry + expireSubWallets
 * Sub-wallets: POST /api/subwallet/open|spend|close, GET /api/subwallet
 * D1:       sub_wallets (d1-subwallet-migration.sql)
 * Receipts: GET /api/receipt/:id, POST /api/receipt/verify; auto on pay
 * D1:       payment_receipts (d1-receipts-migration.sql)
 * Policy:   GET|POST /api/me/policy — allow/deny to, max_amount, task prefix
 * D1:       agent_policies (d1-policy-migration.sql)
 * Netting:  POST /api/netting/run, GET /api/netting
 * D1:       netting_runs + netting_settlements (d1-netting-migration.sql)
 * Traces:   GET /api/trace/:id ; optional trace_id on pay
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

const SYSTEM_SUBWALLET = "system/subwallet";
const SUBWALLET_MIN_BUDGET = 0.000001;
const SUBWALLET_MAX_BUDGET = 10000;
const SUBWALLET_DEFAULT_TTL_SEC = 3600; // 1h
const SUBWALLET_MIN_TTL_SEC = 30;
const SUBWALLET_MAX_TTL_SEC = 72 * 3600; // 72h
const RL_SUBWALLET_MAX = 40;
const RL_SUBWALLET_WINDOW_SEC = 60;
const EXPIRE_SUBWALLET_BATCH = 50;

const SYSTEM_NETTING = "system/netting";
const NETTING_DEFAULT_WINDOW_HOURS = 24;
const NETTING_MIN_WINDOW_HOURS = 1;
const NETTING_MAX_WINDOW_HOURS = 168;
const NETTING_MAX_PAIRS = 200;
const RL_NETTING_MAX = 5;
const RL_NETTING_WINDOW_SEC = 3600;

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

async function lockWallet(env, repoId, reason, { api_key_id, user_id, ctx } = {}) {
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
  if (user_id) {
    scheduleWebhook(ctx, env, user_id, "wallet.locked", {
      repo_id: repoId,
      reason: reason || "Wallet locked",
      api_key_id: api_key_id || null,
    });
  }
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

  // Policy-as-code (allow/deny, max_amount, task prefix) — optional toRepo/task via authUser._policyCtx
  const pctx = (authUser && authUser._policyCtx) || {};
  const polHit = await checkSpendPolicy(env, fromRepo, amount, pctx.to_repo, pctx.task);
  if (polHit) {
    return bad(request, polHit.error, 403, { code: polHit.code || "policy_denied" });
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
      const uid = authUser && authUser.id;
      await suspendApiKey(env, keyId, vel.error, {
        repo_id: fromRepo,
        user_id: uid,
      });
      await lockWallet(env, fromRepo, vel.error, {
        api_key_id: keyId,
        user_id: uid,
      });
      await logSafetyEvent(env, "agent.runaway_loop", {
        repo_id: fromRepo,
        api_key_id: keyId,
        user_id: uid,
        reason: vel.error,
      });
      if (uid) {
        // fire-and-forget (no ctx in gate path)
        scheduleWebhook(null, env, uid, "agent.runaway_loop", {
          repo_id: fromRepo,
          reason: vel.error,
          api_key_id: keyId,
        });
      }
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



/* ─── Telemetry prune (non-critical only; never touch balances/users/ledger core) ───
 * Safe to delete:
 *   velocity_events > 24h
 *   safety_events > 90d
 *   webhook_deliveries > 30d
 *   rate_limits updated > 7d ago
 *   idempotency success/failed > 7d
 * NEVER delete: accounts, transactions, users, sessions, api_keys, escrows, streams, agent_limits
 */
const PRUNE_VELOCITY_HOURS = 24;
const PRUNE_SAFETY_DAYS = 90;
const PRUNE_WEBHOOK_DAYS = 30;
const PRUNE_RATE_LIMIT_DAYS = 7;
const PRUNE_IDEM_DAYS = 7;

async function pruneTelemetry(env) {
  const t0 = Date.now();
  const out = {
    velocity: 0,
    safety: 0,
    webhook_deliveries: 0,
    rate_limits: 0,
    idempotency: 0,
  };

  async function del(sql, label) {
    try {
      const r = await env.DB.prepare(sql).run();
      out[label] = r.meta?.changes || 0;
    } catch (e) {
      console.log("prune_" + label, e && e.message);
    }
  }

  await del(
    `DELETE FROM velocity_events
     WHERE created_at < datetime('now', '-${PRUNE_VELOCITY_HOURS} hours')`,
    "velocity"
  );
  await del(
    `DELETE FROM safety_events
     WHERE created_at < datetime('now', '-${PRUNE_SAFETY_DAYS} days')`,
    "safety"
  );
  await del(
    `DELETE FROM webhook_deliveries
     WHERE created_at < datetime('now', '-${PRUNE_WEBHOOK_DAYS} days')`,
    "webhook_deliveries"
  );
  await del(
    `DELETE FROM rate_limits
     WHERE updated_at < datetime('now', '-${PRUNE_RATE_LIMIT_DAYS} days')`,
    "rate_limits"
  );
  await del(
    `DELETE FROM idempotency
     WHERE status IN ('success', 'failed')
       AND updated_at < datetime('now', '-${PRUNE_IDEM_DAYS} days')`,
    "idempotency"
  );

  out.latency_ms = Date.now() - t0;
  return out;
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

      if (request.method === "POST" && url.pathname === "/api/subwallet/open") {
        return await handleSubWalletOpen(request, env);
      }
      if (request.method === "POST" && url.pathname === "/api/subwallet/spend") {
        return await handleSubWalletSpend(request, env);
      }
      if (request.method === "POST" && url.pathname === "/api/subwallet/close") {
        return await handleSubWalletClose(request, env);
      }
      if (request.method === "GET" && url.pathname === "/api/subwallet") {
        return await handleSubWalletList(request, url, env);
      }

      if (request.method === "GET" && url.pathname.startsWith("/api/receipt/")) {
        const rid = url.pathname.slice("/api/receipt/".length).replace(/\/$/, "");
        if (rid === "verify") {
          /* fall through — POST only */
        } else if (rid) {
          return await handleReceiptGet(request, env, rid);
        }
      }
      if (request.method === "POST" && url.pathname === "/api/receipt/verify") {
        return await handleReceiptVerify(request, env);
      }

      if (request.method === "GET" && url.pathname === "/api/me/policy") {
        return await handleMePolicyGet(request, env);
      }
      if (request.method === "POST" && url.pathname === "/api/me/policy") {
        return await handleMePolicySet(request, env);
      }

      if (request.method === "POST" && url.pathname === "/api/netting/run") {
        return await handleNettingRun(request, env);
      }
      if (request.method === "GET" && url.pathname === "/api/netting") {
        return await handleNettingList(request, url, env);
      }

      if (request.method === "GET" && url.pathname === "/api/me/safety") {
        return await handleMeSafetyGet(request, env);
      }
      if (request.method === "POST" && url.pathname === "/api/me/safety") {
        return await handleMeSafetySet(request, env);
      }
      if (request.method === "POST" && url.pathname === "/api/me/safety/unlock") {
        return await handleMeSafetyUnlock(request, env);
      }
      if (request.method === "POST" && url.pathname === "/api/me/keys/unsuspend") {
        return await handleMeKeysUnsuspend(request, env);
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
            me_safety: "GET|POST /api/me/safety",
            me_safety_unlock: "POST /api/me/safety/unlock",
            me_keys_unsuspend: "POST /api/me/keys/unsuspend",
            subwallet_open: "POST /api/subwallet/open",
            subwallet_spend: "POST /api/subwallet/spend",
            subwallet_close: "POST /api/subwallet/close",
            subwallet_list: "GET /api/subwallet",
            receipt_get: "GET /api/receipt/:id",
            receipt_verify: "POST /api/receipt/verify",
            me_policy: "GET|POST /api/me/policy",
            netting_run: "POST /api/netting/run",
            netting_list: "GET /api/netting",
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
        try {
          const pruned = await pruneTelemetry(env);
          console.log(
            JSON.stringify({
              cron: "telemetry-prune",
              scheduledTime: event.scheduledTime,
              ...pruned,
            })
          );
        } catch (err) {
          console.error("telemetry-prune failed:", err && err.message ? err.message : err);
        }
        try {
          const sw = await expireSubWallets(env);
          console.log(
            JSON.stringify({
              cron: "subwallet-expire",
              scheduledTime: event.scheduledTime,
              ...sw,
            })
          );
        } catch (err) {
          console.error("subwallet-expire failed:", err && err.message ? err.message : err);
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

  let results;
  try {
    const q = await env.DB.prepare(
      `SELECT id, key_prefix, label, created_at, revoked_at, last_used_at, suspended_at, suspend_reason
       FROM api_keys WHERE user_id = ?1 ORDER BY created_at DESC LIMIT 50`
    )
      .bind(user.id)
      .all();
    results = q.results || [];
  } catch (_) {
    const q = await env.DB.prepare(
      `SELECT id, key_prefix, label, created_at, revoked_at, last_used_at
       FROM api_keys WHERE user_id = ?1 ORDER BY created_at DESC LIMIT 50`
    )
      .bind(user.id)
      .all();
    results = q.results || [];
  }

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
      suspended: !!k.suspended_at,
      suspended_at: k.suspended_at || null,
      suspend_reason: k.suspend_reason || null,
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
    events: ["escrow.released", "escrow.refunded", "escrow.expired", "wallet.locked", "agent.runaway_loop"],
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
    events: ["escrow.released", "escrow.refunded", "escrow.expired", "wallet.locked", "agent.runaway_loop"],
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
  const traceId = parseTraceId(body.trace_id || body.traceId || request.headers.get("X-Trace-Id"));

  if (!fromRepo) {
    return bad(
      request,
      "from_repo must be owner/repo (or authenticate and set default agent)"
    );
  }
  if (!toRepo) return bad(request, "to_repo must be owner/repo");
  if (fromRepo === toRepo) return bad(request, "from_repo and to_repo must differ");
  if (amount == null) return bad(request, "amount must be between 0.000001 and 1000000");

  // Safety: suspended key / wallet lock / policy / daily budget / velocity
  if (authUser) {
    authUser._policyCtx = { to_repo: toRepo, task };
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

  if (traceId) {
    await ensureTrace(env, traceId, {
      label: task || "pay",
      created_by: authUser && authUser.id,
    });
  }

  try {
    await env.DB.batch([
      env.DB.prepare(
        `UPDATE accounts
         SET balance = balance + ?1, updated_at = datetime('now')
         WHERE repo_id = ?2`
      ).bind(amount, toRepo),
      env.DB.prepare(
        `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms, idempotency_key, trace_id)
         VALUES (?1, ?2, ?3, ?4, 'success', ?5, ?6, ?7)`
      ).bind(fromRepo, toRepo, amount, task, Date.now() - t0, idem, traceId),
    ]);
  } catch (e) {
    // Fallback if trace_id column missing
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
  }

  const payload = {
    ok: true,
    status: "success",
    replayed: false,
    from_repo: fromRepo,
    to_repo: toRepo,
    amount,
    task,
    trace_id: traceId || undefined,
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

  const rcpt = await issuePayReceipt(env, {
    from_repo: fromRepo,
    to_repo: toRepo,
    amount,
    task,
    status: "success",
  });
  if (rcpt) {
    payload.receipt_id = rcpt.id;
    payload.receipt_signature = rcpt.signature;
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
      `SELECT id, from_repo, to_repo, amount, task, status, latency_ms, created_at, trace_id
       FROM transactions
       WHERE from_repo = ?1 OR to_repo = ?1
       ORDER BY id DESC LIMIT ?2`
    ).bind(repo, limit);
  } else {
    stmt = env.DB.prepare(
      `SELECT id, from_repo, to_repo, amount, task, status, latency_ms, created_at, trace_id
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
    authUser._policyCtx = { to_repo: toRepo, task };
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
    authUser._policyCtx = { to_repo: toRepo, task };
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




/* ─── Ephemeral sub-wallets (task wallets) ───
 * Parent debits budget → held in system/subwallet.
 * Child spends only via POST /api/subwallet/spend { id, to_repo, amount }.
 * Close / TTL expire → refund remaining to parent. Blast radius = budget only.
 */

function parseSubWalletTtl(body) {
  const sec = Number(body.ttl_seconds ?? body.ttl);
  if (Number.isFinite(sec)) {
    if (sec < SUBWALLET_MIN_TTL_SEC || sec > SUBWALLET_MAX_TTL_SEC) return null;
    return Math.floor(sec);
  }
  return SUBWALLET_DEFAULT_TTL_SEC;
}

async function loadSubWallet(env, id) {
  try {
    return await env.DB.prepare(`SELECT * FROM sub_wallets WHERE id = ?1`).bind(id).first();
  } catch (e) {
    return null;
  }
}

async function handleSubWalletOpen(request, env) {
  const t0 = Date.now();
  const authUser = await getAuthUser(request, env);
  if (!authUser) return bad(request, "Sign in or API key required", 401);

  const rlId =
    authUser.auth_via === "api_key"
      ? "sw:key:" + (authUser.key_id || authUser.id)
      : "sw:user:" + authUser.id;
  const limited = await checkRateLimit(env, rlId, RL_SUBWALLET_MAX, RL_SUBWALLET_WINDOW_SEC);
  if (limited) {
    return bad(request, "Rate limit: too many sub-wallet ops", 429, {
      retry_after_sec: limited.retry_after_sec,
    });
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return bad(request, "Invalid JSON body");
  }

  let parentRepo = parseRepo(body.parent_repo || body.from_repo || body.fromRepo);
  if (!parentRepo && authUser.default_repo) {
    parentRepo = parseRepo(authUser.default_repo);
  }
  const budget = parseAmount(body.budget ?? body.amount);
  const label = String(body.label || body.name || "task").slice(0, 64);
  const task = String(body.task || "sub-task").slice(0, 500);
  const ttlSec = parseSubWalletTtl(body);
  const idem =
    String(request.headers.get("Idempotency-Key") || body.idempotency_key || "")
      .trim()
      .slice(0, 128) || null;

  if (!parentRepo) return bad(request, "parent_repo required (or set default agent)");
  if (budget == null || budget < SUBWALLET_MIN_BUDGET || budget > SUBWALLET_MAX_BUDGET) {
    return bad(
      request,
      "budget must be between " + SUBWALLET_MIN_BUDGET + " and " + SUBWALLET_MAX_BUDGET
    );
  }
  if (ttlSec == null) {
    return bad(
      request,
      "ttl_seconds out of range (min " +
        SUBWALLET_MIN_TTL_SEC +
        "s, max " +
        SUBWALLET_MAX_TTL_SEC +
        "s)"
    );
  }

  {
    authUser._policyCtx = { to_repo: null, task };
    const blocked = await safetyGate(request, env, authUser, parentRepo, budget);
    if (blocked) return blocked;
  }

  if (idem) {
    try {
      const existing = await env.DB.prepare(
        `SELECT * FROM sub_wallets WHERE idempotency_key = ?1`
      )
        .bind(idem)
        .first();
      if (existing) {
        return json(request, { ok: true, replayed: true, sub_wallet: existing });
      }
    } catch (e) {
      return bad(request, "sub_wallets table missing — run d1-subwallet-migration.sql", 500);
    }
  }

  await ensureAccount(env, parentRepo);

  const debit = await env.DB.prepare(
    `UPDATE accounts
     SET balance = balance - ?1, updated_at = datetime('now')
     WHERE repo_id = ?2 AND balance >= ?1
     RETURNING balance`
  )
    .bind(budget, parentRepo)
    .first();

  if (!debit) return bad(request, "Insufficient funds on parent", 402);

  const id = "sw_" + randomId(12);
  const modifier = "+" + ttlSec + " seconds";

  try {
    await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO sub_wallets (
           id, parent_repo, label, task, status, budget, spent, remaining,
           created_by, expires_at, idempotency_key, created_at, updated_at
         ) VALUES (
           ?1, ?2, ?3, ?4, 'open', ?5, 0, ?5, ?6,
           datetime('now', ?7), ?8, datetime('now'), datetime('now')
         )`
      ).bind(id, parentRepo, label, task, budget, authUser.id, modifier, idem),
      env.DB.prepare(
        `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms, idempotency_key)
         VALUES (?1, ?2, ?3, ?4, 'success', ?5, ?6)`
      ).bind(
        parentRepo,
        SYSTEM_SUBWALLET,
        budget,
        "subwallet-open:" + id,
        Date.now() - t0,
        idem
      ),
    ]);
  } catch (e) {
    await env.DB.prepare(
      `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
    )
      .bind(budget, parentRepo)
      .run();
    return bad(request, "Sub-wallet create failed: " + (e.message || e), 500);
  }

  await safetyRecordSpend(env, authUser, parentRepo, budget);

  const row = await loadSubWallet(env, id);
  return json(request, {
    ok: true,
    status: "open",
    sub_wallet: {
      id,
      parent_repo: parentRepo,
      label,
      task,
      budget,
      spent: 0,
      remaining: budget,
      status: "open",
      expires_at: row?.expires_at || null,
      ttl_seconds: ttlSec,
    },
    balance_parent: debit.balance,
    latency_ms: Date.now() - t0,
    hint: "Child spends only via POST /api/subwallet/spend { id, to_repo, amount }. Close or wait for TTL to refund remainder.",
  });
}

async function handleSubWalletSpend(request, env) {
  const t0 = Date.now();
  const authUser = await getAuthUser(request, env);
  if (!authUser) return bad(request, "Sign in or API key required", 401);

  const sus = rejectIfSuspendedKey(request, authUser);
  if (sus) return sus;

  let body;
  try {
    body = await request.json();
  } catch {
    return bad(request, "Invalid JSON body");
  }

  const id = String(body.id || "").trim();
  const toRepo = parseRepo(body.to_repo || body.toRepo);
  const amount = parseAmount(body.amount);
  const task = String(body.task || "subwallet-spend").slice(0, 500);

  if (!id) return bad(request, "id required");
  if (!toRepo) return bad(request, "to_repo required");
  if (amount == null) return bad(request, "invalid amount");

  let row;
  try {
    row = await env.DB.prepare(`SELECT * FROM sub_wallets WHERE id = ?1`).bind(id).first();
  } catch {
    return bad(request, "sub_wallets table missing — run d1-subwallet-migration.sql", 500);
  }
  if (!row) return bad(request, "Sub-wallet not found", 404);
  if (row.status !== "open") {
    return bad(request, "Sub-wallet not open (status=" + row.status + ")", 400, {
      code: "subwallet_closed",
    });
  }

  // TTL check
  if (row.expires_at) {
    const expMs = Date.parse(String(row.expires_at).replace(" ", "T") + "Z");
    if (Number.isFinite(expMs) && expMs < Date.now()) {
      return bad(request, "Sub-wallet expired — close or wait for cron refund", 400, {
        code: "subwallet_expired",
      });
    }
  }

  // Authorization: creator or parent default agent
  const allowed =
    authUser.id === row.created_by ||
    (authUser.default_repo && authUser.default_repo === row.parent_repo);
  if (!allowed) return bad(request, "Not authorized to spend this sub-wallet", 403);

  const remaining = Number(row.remaining != null ? row.remaining : row.budget - row.spent);
  if (amount > remaining) {
    return bad(request, "Insufficient sub-wallet remaining ($" + remaining.toFixed(6) + ")", 402, {
      code: "subwallet_insufficient",
      remaining,
    });
  }

  await ensureAccount(env, toRepo);

  const claim = await env.DB.prepare(
    `UPDATE sub_wallets
     SET spent = spent + ?1,
         remaining = remaining - ?1,
         status = CASE WHEN remaining - ?1 <= 0.0000005 THEN 'exhausted' ELSE 'open' END,
         updated_at = datetime('now')
     WHERE id = ?2 AND status = 'open' AND remaining >= ?1
     RETURNING id, spent, remaining, status, parent_repo`
  )
    .bind(amount, id)
    .first();

  if (!claim) {
    return bad(request, "Spend failed (race or insufficient remaining)", 409);
  }

  await env.DB.batch([
    env.DB.prepare(
      `UPDATE accounts
       SET balance = balance + ?1, updated_at = datetime('now')
       WHERE repo_id = ?2`
    ).bind(amount, toRepo),
    env.DB.prepare(
      `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
       VALUES (?1, ?2, ?3, ?4, 'success', ?5)`
    ).bind(
      SYSTEM_SUBWALLET,
      toRepo,
      amount,
      "subwallet-spend:" + id + ":" + task.slice(0, 40),
      Date.now() - t0
    ),
  ]);

  return json(request, {
    ok: true,
    id,
    to_repo: toRepo,
    amount,
    spent: claim.spent,
    remaining: Math.max(0, Number(claim.remaining)),
    status: claim.status,
    parent_repo: claim.parent_repo,
    latency_ms: Date.now() - t0,
  });
}

async function handleSubWalletClose(request, env) {
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
    row = await env.DB.prepare(`SELECT * FROM sub_wallets WHERE id = ?1`).bind(id).first();
  } catch {
    return bad(request, "sub_wallets table missing — run d1-subwallet-migration.sql", 500);
  }
  if (!row) return bad(request, "Sub-wallet not found", 404);
  if (row.status !== "open" && row.status !== "exhausted") {
    return bad(request, "Sub-wallet already closed (status=" + row.status + ")");
  }

  const allowed =
    authUser.id === row.created_by ||
    (authUser.default_repo && authUser.default_repo === row.parent_repo);
  if (!allowed) return bad(request, "Not authorized to close this sub-wallet", 403);

  const refund = await closeSubWalletInternal(env, row, "closed", t0);
  return json(request, {
    ok: true,
    status: "closed",
    id,
    spent: Number(row.spent),
    refunded: refund,
    parent_repo: row.parent_repo,
    latency_ms: Date.now() - t0,
  });
}

async function closeSubWalletInternal(env, row, reason, t0) {
  const id = row.id;
  const claim = await env.DB.prepare(
    `UPDATE sub_wallets
     SET status = ?2,
         closed_at = datetime('now'),
         close_reason = ?3,
         remaining = 0,
         updated_at = datetime('now')
     WHERE id = ?1 AND status IN ('open', 'exhausted')
     RETURNING id, remaining, parent_repo, spent, budget`
  )
    .bind(id, reason === "expired" ? "expired" : "closed", reason || "closed")
    .first();

  if (!claim) return 0;

  // Use pre-update remaining from row (claim.remaining already 0)
  const refund = Math.max(
    0,
    Math.round(Number(row.remaining != null ? row.remaining : row.budget - row.spent) * 1e6) / 1e6
  );

  if (refund > 0) {
    await ensureAccount(env, row.parent_repo);
    await env.DB.batch([
      env.DB.prepare(
        `UPDATE accounts
         SET balance = balance + ?1, updated_at = datetime('now')
         WHERE repo_id = ?2`
      ).bind(refund, row.parent_repo),
      env.DB.prepare(
        `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
         VALUES (?1, ?2, ?3, ?4, 'success', ?5)`
      ).bind(
        SYSTEM_SUBWALLET,
        row.parent_repo,
        refund,
        "subwallet-" + (reason || "close") + "-refund:" + id,
        typeof t0 === "number" ? Date.now() - t0 : 0
      ),
    ]);
  }
  return refund;
}

async function handleSubWalletList(request, url, env) {
  const limit = Math.min(Math.max(Number(url.searchParams.get("limit") || 25), 1), 100);
  const repo = (url.searchParams.get("repo") || "").trim();
  const status = (url.searchParams.get("status") || "").trim();

  let sql = `SELECT id, parent_repo, label, task, status, budget, spent, remaining,
                    created_by, expires_at, closed_at, close_reason, created_at
             FROM sub_wallets WHERE 1=1`;
  const binds = [];

  if (repo) {
    if (!parseRepo(repo)) return bad(request, "repo must be owner/repo");
    sql += ` AND parent_repo = ?`;
    binds.push(repo);
  }
  if (status && ["open", "closed", "expired", "exhausted"].includes(status)) {
    sql += ` AND status = ?`;
    binds.push(status);
  }
  sql += ` ORDER BY created_at DESC LIMIT ?`;
  binds.push(limit);

  try {
    const { results } = await env.DB.prepare(sql).bind(...binds).all();
    return json(request, { ok: true, count: results.length, sub_wallets: results });
  } catch (e) {
    return bad(request, "sub_wallets table missing — run d1-subwallet-migration.sql", 500);
  }
}

async function expireSubWallets(env) {
  const t0 = Date.now();
  let results;
  try {
    const q = await env.DB.prepare(
      `SELECT * FROM sub_wallets
       WHERE status = 'open'
         AND expires_at IS NOT NULL
         AND expires_at < datetime('now')
       ORDER BY expires_at ASC
       LIMIT ?1`
    )
      .bind(EXPIRE_SUBWALLET_BATCH)
      .all();
    results = q.results || [];
  } catch (e) {
    return { expired: 0, scanned: 0, error: e.message, latency_ms: Date.now() - t0 };
  }

  let expired = 0;
  let refundedTotal = 0;
  for (const row of results) {
    try {
      const refund = await closeSubWalletInternal(env, row, "expired", t0);
      expired += 1;
      refundedTotal += refund;
    } catch (e) {
      console.log("subwallet_expire_error", row.id, e && e.message);
    }
  }
  return {
    expired,
    scanned: results.length,
    refunded_total: refundedTotal,
    latency_ms: Date.now() - t0,
  };
}



/* ─── Signed payment receipts ───
 * HMAC-SHA256 over canonical JSON using env.RECEIPT_SECRET (or SESSION cookie secret fallback).
 * Agents store receipt_id + signature offline and verify later without trusting the UI.
 */
function receiptSecret(env) {
  return env.RECEIPT_SECRET || env.SESSION_SECRET || env.GOOGLE_CLIENT_SECRET || "a2a-dev-receipt-secret";
}

function canonicalReceiptPayload(p) {
  // stable field order for HMAC
  return JSON.stringify({
    v: 1,
    id: p.id,
    from_repo: p.from_repo,
    to_repo: p.to_repo,
    amount: p.amount,
    task: p.task || "",
    status: p.status || "success",
    created_at: p.created_at,
  });
}

async function issuePayReceipt(env, { from_repo, to_repo, amount, task, status, tx_id }) {
  try {
    const id = "rcpt_" + randomId(12);
    const created_at = new Date().toISOString();
    const body = {
      id,
      from_repo,
      to_repo,
      amount: Number(amount),
      task: task || "",
      status: status || "success",
      created_at,
    };
    const canon = canonicalReceiptPayload(body);
    const signature = await hmacSha256Hex(receiptSecret(env), canon);
    await env.DB.prepare(
      `INSERT INTO payment_receipts (
         id, tx_id, from_repo, to_repo, amount, task, status, payload_json, signature, created_at
       ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, datetime('now'))`
    )
      .bind(
        id,
        tx_id || null,
        from_repo,
        to_repo,
        Number(amount),
        task || "",
        status || "success",
        canon,
        signature
      )
      .run();
    return { id, signature, created_at, v: 1 };
  } catch (e) {
    console.log("receipt_issue_error", e && e.message);
    return null;
  }
}

async function handleReceiptGet(request, env, id) {
  id = String(id || "").trim();
  if (!id || id.length > 64) return bad(request, "invalid receipt id", 400);
  let row;
  try {
    row = await env.DB.prepare(
      `SELECT id, tx_id, from_repo, to_repo, amount, task, status, payload_json, signature, created_at
       FROM payment_receipts WHERE id = ?1`
    )
      .bind(id)
      .first();
  } catch (e) {
    return bad(request, "payment_receipts table missing — run d1-receipts-migration.sql", 500);
  }
  if (!row) return bad(request, "Receipt not found", 404);
  return json(request, {
    ok: true,
    receipt: {
      id: row.id,
      tx_id: row.tx_id,
      from_repo: row.from_repo,
      to_repo: row.to_repo,
      amount: row.amount,
      task: row.task,
      status: row.status,
      created_at: row.created_at,
      signature: row.signature,
      payload: row.payload_json,
    },
    verify: "POST /api/receipt/verify with { id } or { payload, signature }",
  });
}

async function handleReceiptVerify(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return bad(request, "Invalid JSON body");
  }

  let payloadStr = body.payload;
  let signature = body.signature;
  const id = body.id ? String(body.id).trim() : null;

  if (id && (!payloadStr || !signature)) {
    let row;
    try {
      row = await env.DB.prepare(
        `SELECT payload_json, signature FROM payment_receipts WHERE id = ?1`
      )
        .bind(id)
        .first();
    } catch {
      return bad(request, "payment_receipts table missing — run d1-receipts-migration.sql", 500);
    }
    if (!row) return bad(request, "Receipt not found", 404);
    payloadStr = row.payload_json;
    signature = row.signature;
  }

  if (!payloadStr || !signature) {
    return bad(request, "payload + signature required (or id)");
  }

  const expected = await hmacSha256Hex(receiptSecret(env), String(payloadStr));
  const ok = expected === String(signature).toLowerCase() || expected === String(signature);
  return json(request, {
    ok: true,
    valid: ok,
    id: id || null,
  });
}




/* ─── Obligation netting (bilateral batch settlement) ───
 * For each unordered pair (A,B) with success pays in the window:
 *   gross_ab = sum(A→B), gross_ba = sum(B→A)
 *   net = gross_ab - gross_ba
 * If |net| >= MIN_AMOUNT: one settlement ledger line via system/netting
 *   (informational + optional real balance move is OFF by default — report only).
 * Algorithm is O(pairs) after a single group-by query; caps pairs for safety.
 */
async function handleNettingRun(request, env) {
  const t0 = Date.now();
  const authUser = await getAuthUser(request, env);
  if (!authUser) return bad(request, "Sign in or API key required", 401);

  const rlId =
    authUser.auth_via === "api_key"
      ? "net:key:" + (authUser.key_id || authUser.id)
      : "net:user:" + authUser.id;
  const limited = await checkRateLimit(env, rlId, RL_NETTING_MAX, RL_NETTING_WINDOW_SEC);
  if (limited) {
    return bad(request, "Rate limit: netting runs", 429, {
      retry_after_sec: limited.retry_after_sec,
    });
  }

  let body = {};
  try {
    if (request.headers.get("Content-Type")?.includes("json")) {
      body = await request.json();
    }
  } catch {
    body = {};
  }

  let windowHours = Number(body.window_hours ?? body.window ?? NETTING_DEFAULT_WINDOW_HOURS);
  if (!Number.isFinite(windowHours)) windowHours = NETTING_DEFAULT_WINDOW_HOURS;
  windowHours = Math.max(NETTING_MIN_WINDOW_HOURS, Math.min(NETTING_MAX_WINDOW_HOURS, Math.floor(windowHours)));
  const applyBalances = !!body.apply_balances; // default false: soft net (report + ledger annotation)
  const repoFilter = body.repo ? parseRepo(body.repo) : (authUser.default_repo ? parseRepo(authUser.default_repo) : null);

  // Aggregate bilateral success flows in window
  let rows;
  try {
    let sql = `
      SELECT from_repo, to_repo, SUM(amount) AS gross, COUNT(*) AS n
      FROM transactions
      WHERE status = 'success'
        AND created_at >= datetime('now', ?)
        AND from_repo NOT LIKE 'system/%'
        AND to_repo NOT LIKE 'system/%'
        AND from_repo != to_repo
    `;
    const binds = ["-" + windowHours + " hours"];
    if (repoFilter) {
      sql += ` AND (from_repo = ? OR to_repo = ?)`;
      binds.push(repoFilter, repoFilter);
    }
    sql += ` GROUP BY from_repo, to_repo`;
    const q = await env.DB.prepare(sql).bind(...binds).all();
    rows = q.results || [];
  } catch (e) {
    return bad(request, "ledger query failed: " + (e.message || e), 500);
  }

  // Build undirected pair map: key = sorted(a|b)
  const pairMap = new Map();
  for (const r of rows) {
    const a = r.from_repo;
    const b = r.to_repo;
    const gross = Number(r.gross) || 0;
    const n = Number(r.n) || 0;
    if (!a || !b || gross <= 0) continue;
    const [lo, hi] = a < b ? [a, b] : [b, a];
    const key = lo + "\0" + hi;
    let p = pairMap.get(key);
    if (!p) {
      p = {
        party_a: lo,
        party_b: hi,
        gross_a_to_b: 0,
        gross_b_to_a: 0,
        tx_count_a_to_b: 0,
        tx_count_b_to_a: 0,
      };
      pairMap.set(key, p);
    }
    if (a === lo && b === hi) {
      p.gross_a_to_b += gross;
      p.tx_count_a_to_b += n;
    } else {
      p.gross_b_to_a += gross;
      p.tx_count_b_to_a += n;
    }
  }

  const pairs = [...pairMap.values()].slice(0, NETTING_MAX_PAIRS);
  const runId = "net_" + randomId(12);
  let pairsNetted = 0;
  let volumeGross = 0;
  let volumeNetted = 0;
  const settlements = [];

  for (const p of pairs) {
    const gab = Math.round(p.gross_a_to_b * 1e6) / 1e6;
    const gba = Math.round(p.gross_b_to_a * 1e6) / 1e6;
    volumeGross += gab + gba;
    const net = Math.round((gab - gba) * 1e6) / 1e6;
    if (Math.abs(net) < MIN_AMOUNT) continue;
    // Only net when both directions had flow (true bilateral obligation)
    if (gab < MIN_AMOUNT || gba < MIN_AMOUNT) continue;

    const netFrom = net > 0 ? p.party_a : p.party_b;
    const netTo = net > 0 ? p.party_b : p.party_a;
    const netAmt = Math.abs(net);
    volumeNetted += netAmt;
    pairsNetted += 1;

    const sid = "ns_" + randomId(10);
    settlements.push({
      id: sid,
      party_a: p.party_a,
      party_b: p.party_b,
      gross_a_to_b: gab,
      gross_b_to_a: gba,
      net_amount: netAmt,
      net_from: netFrom,
      net_to: netTo,
      tx_count_a_to_b: p.tx_count_a_to_b,
      tx_count_b_to_a: p.tx_count_b_to_a,
    });

    try {
      await env.DB.prepare(
        `INSERT INTO netting_settlements (
           id, run_id, party_a, party_b, gross_a_to_b, gross_b_to_a,
           net_amount, net_from, net_to, tx_count_a_to_b, tx_count_b_to_a,
           status, created_at
         ) VALUES (
           ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 'settled', datetime('now')
         )`
      )
        .bind(
          sid,
          runId,
          p.party_a,
          p.party_b,
          gab,
          gba,
          netAmt,
          netFrom,
          netTo,
          p.tx_count_a_to_b,
          p.tx_count_b_to_a
        )
        .run();
    } catch (e) {
      return bad(
        request,
        "netting tables missing — run d1-netting-migration.sql: " + (e.message || e),
        500
      );
    }

    // Ledger annotation (always)
    await env.DB.prepare(
      `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
       VALUES (?1, ?2, ?3, ?4, 'success', ?5)`
    )
      .bind(
        SYSTEM_NETTING,
        netTo,
        netAmt,
        "net:" + sid + ":" + netFrom + "→" + netTo,
        Date.now() - t0
      )
      .run()
      .catch(() => {});

    // Optional hard settle: move balances (off by default — safe for demo)
    if (applyBalances) {
      try {
        await ensureAccount(env, netFrom);
        await ensureAccount(env, netTo);
        const debit = await env.DB.prepare(
          `UPDATE accounts SET balance = balance - ?1, updated_at = datetime('now')
           WHERE repo_id = ?2 AND balance >= ?1 RETURNING balance`
        )
          .bind(netAmt, netFrom)
          .first();
        if (debit) {
          await env.DB.prepare(
            `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now')
             WHERE repo_id = ?2`
          )
            .bind(netAmt, netTo)
            .run();
        }
      } catch (_) {}
    }
  }

  try {
    await env.DB.prepare(
      `INSERT INTO netting_runs (
         id, window_hours, pairs_scanned, pairs_netted,
         volume_gross, volume_netted, status, created_by, created_at
       ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'done', ?7, datetime('now'))`
    )
      .bind(
        runId,
        windowHours,
        pairs.length,
        pairsNetted,
        Math.round(volumeGross * 1e6) / 1e6,
        Math.round(volumeNetted * 1e6) / 1e6,
        authUser.id
      )
      .run();
  } catch (e) {
    return bad(
      request,
      "netting tables missing — run d1-netting-migration.sql: " + (e.message || e),
      500
    );
  }

  const saved = Math.round((volumeGross - volumeNetted) * 1e6) / 1e6;
  return json(request, {
    ok: true,
    run_id: runId,
    window_hours: windowHours,
    pairs_scanned: pairs.length,
    pairs_netted: pairsNetted,
    volume_gross: Math.round(volumeGross * 1e6) / 1e6,
    volume_net: Math.round(volumeNetted * 1e6) / 1e6,
    volume_saved: saved,
    apply_balances: applyBalances,
    settlements: settlements.slice(0, 50),
    latency_ms: Date.now() - t0,
    hint: applyBalances
      ? "Hard settle applied (balances moved)."
      : "Soft net: report + ledger annotation only. Pass apply_balances:true to move funds.",
  });
}

async function handleNettingList(request, url, env) {
  const limit = Math.min(Math.max(Number(url.searchParams.get("limit") || 10), 1), 50);
  try {
    const { results: runs } = await env.DB.prepare(
      `SELECT id, window_hours, pairs_scanned, pairs_netted, volume_gross, volume_netted, status, created_at
       FROM netting_runs ORDER BY created_at DESC LIMIT ?1`
    )
      .bind(limit)
      .all();
    const runIds = (runs || []).map((r) => r.id);
    let settlements = [];
    if (runIds.length) {
      const placeholders = runIds.map(() => "?").join(",");
      const q = await env.DB.prepare(
        `SELECT id, run_id, party_a, party_b, gross_a_to_b, gross_b_to_a, net_amount, net_from, net_to, created_at
         FROM netting_settlements WHERE run_id IN (${placeholders})
         ORDER BY created_at DESC LIMIT 100`
      )
        .bind(...runIds)
        .all();
      settlements = q.results || [];
    }
    return json(request, {
      ok: true,
      runs: runs || [],
      settlements,
    });
  } catch (e) {
    return bad(
      request,
      "netting tables missing — run d1-netting-migration.sql: " + (e.message || e),
      500
    );
  }
}

/* ─── Policy-as-code spend rules ───
 * JSON policy on agent_policies.repo_id:
 * {
 *   version: 1,
 *   blocked: false,
 *   max_amount: 5.0,           // per tx (null = no cap beyond safety)
 *   allow_to: ["acme/*", "bob/tool"],  // empty = allow all (unless deny)
 *   deny_to: ["scam/*"],
 *   require_task_prefix: ["job-", "task-"],  // empty = any task
 *   notes: "..."
 * }
 * Glob: * matches any segment remainder (owner/* or */name or *).
 */
function matchRepoGlob(pattern, repo) {
  if (!pattern || !repo) return false;
  const p = String(pattern).trim();
  const r = String(repo).trim();
  if (p === "*") return true;
  if (p === r) return true;
  // prefix*
  if (p.endsWith("*") && !p.slice(0, -1).includes("*")) {
    return r.startsWith(p.slice(0, -1));
  }
  // owner/*
  if (p.includes("/*")) {
    const owner = p.split("/")[0];
    return r.startsWith(owner + "/");
  }
  return false;
}

function normalizePolicy(raw) {
  let p = raw;
  if (typeof raw === "string") {
    try { p = JSON.parse(raw); } catch { p = {}; }
  }
  if (!p || typeof p !== "object") p = {};
  const arr = (v) => (Array.isArray(v) ? v.map((x) => String(x).trim()).filter(Boolean) : []);
  return {
    version: Number(p.version) || 1,
    blocked: !!p.blocked,
    max_amount: p.max_amount == null || p.max_amount === "" ? null : Number(p.max_amount),
    allow_to: arr(p.allow_to),
    deny_to: arr(p.deny_to),
    require_task_prefix: arr(p.require_task_prefix),
    notes: p.notes ? String(p.notes).slice(0, 500) : "",
  };
}

async function getAgentPolicy(env, repoId) {
  if (!repoId) return normalizePolicy({});
  try {
    const row = await env.DB.prepare(
      `SELECT policy_json, version, updated_at, updated_by FROM agent_policies WHERE repo_id = ?1`
    )
      .bind(repoId)
      .first();
    if (!row) return normalizePolicy({});
    const pol = normalizePolicy(row.policy_json);
    pol._version = row.version;
    pol._updated_at = row.updated_at;
    pol._updated_by = row.updated_by;
    return pol;
  } catch (e) {
    console.log("policy_load_error", e && e.message);
    return normalizePolicy({});
  }
}

/** Returns null if allowed, or { code, error }. */
async function checkSpendPolicy(env, fromRepo, amount, toRepo, task) {
  const pol = await getAgentPolicy(env, fromRepo);
  if (pol.blocked) {
    return { code: "policy_blocked", error: "Spend policy: agent is blocked by policy-as-code" };
  }
  if (pol.max_amount != null && Number.isFinite(pol.max_amount) && Number(amount) > pol.max_amount) {
    return {
      code: "policy_max_amount",
      error: "Spend policy: amount $" + Number(amount).toFixed(6) + " exceeds max_amount $" + pol.max_amount,
    };
  }
  if (toRepo) {
    if (pol.deny_to.length) {
      for (const g of pol.deny_to) {
        if (matchRepoGlob(g, toRepo)) {
          return {
            code: "policy_deny_to",
            error: "Spend policy: to_repo denied by rule " + g,
          };
        }
      }
    }
    if (pol.allow_to.length) {
      let ok = false;
      for (const g of pol.allow_to) {
        if (matchRepoGlob(g, toRepo)) {
          ok = true;
          break;
        }
      }
      if (!ok) {
        return {
          code: "policy_allow_to",
          error: "Spend policy: to_repo not in allow_to list",
        };
      }
    }
  }
  if (pol.require_task_prefix.length) {
    const t = String(task || "");
    const ok = pol.require_task_prefix.some((pref) => t.startsWith(pref));
    if (!ok) {
      return {
        code: "policy_task_prefix",
        error:
          "Spend policy: task must start with one of: " +
          pol.require_task_prefix.join(", "),
      };
    }
  }
  return null;
}

async function handleMePolicyGet(request, env) {
  const user = await getSessionUser(request, env);
  if (!user) return bad(request, "Sign in required", 401);
  const repo = user.default_repo ? parseRepo(user.default_repo) : null;
  if (!repo) {
    return json(request, {
      ok: true,
      default_repo: null,
      policy: normalizePolicy({}),
      hint: "Bind a default agent first",
    });
  }
  const pol = await getAgentPolicy(env, repo);
  return json(request, {
    ok: true,
    default_repo: repo,
    policy: {
      version: pol.version,
      blocked: pol.blocked,
      max_amount: pol.max_amount,
      allow_to: pol.allow_to,
      deny_to: pol.deny_to,
      require_task_prefix: pol.require_task_prefix,
      notes: pol.notes,
    },
    meta: {
      stored_version: pol._version || null,
      updated_at: pol._updated_at || null,
      updated_by: pol._updated_by || null,
    },
    schema: {
      blocked: "boolean — hard stop all spends",
      max_amount: "number|null — max USD per operation",
      allow_to: "string[] — globs e.g. acme/* ; empty = all allowed",
      deny_to: "string[] — globs denied even if allow matches",
      require_task_prefix: "string[] — task must start with one",
      notes: "string",
    },
  });
}

async function handleMePolicySet(request, env) {
  const user = await getSessionUser(request, env);
  if (!user) return bad(request, "Sign in required", 401);
  const repo = user.default_repo ? parseRepo(user.default_repo) : null;
  if (!repo) return bad(request, "Bind a default agent first");

  let body;
  try {
    body = await request.json();
  } catch {
    return bad(request, "Invalid JSON body");
  }

  // Accept nested policy or flat body
  const src = body.policy && typeof body.policy === "object" ? body.policy : body;
  const pol = normalizePolicy(src);

  if (pol.max_amount != null && (!Number.isFinite(pol.max_amount) || pol.max_amount < 0)) {
    return bad(request, "max_amount invalid");
  }

  const jsonStr = JSON.stringify({
    version: 1,
    blocked: pol.blocked,
    max_amount: pol.max_amount,
    allow_to: pol.allow_to,
    deny_to: pol.deny_to,
    require_task_prefix: pol.require_task_prefix,
    notes: pol.notes,
  });

  try {
    await env.DB.prepare(
      `INSERT INTO agent_policies (repo_id, policy_json, version, updated_by, updated_at)
       VALUES (?1, ?2, 1, ?3, datetime('now'))
       ON CONFLICT(repo_id) DO UPDATE SET
         policy_json = excluded.policy_json,
         version = agent_policies.version + 1,
         updated_by = excluded.updated_by,
         updated_at = datetime('now')`
    )
      .bind(repo, jsonStr, user.id)
      .run();
  } catch (e) {
    return bad(
      request,
      "agent_policies table missing — run d1-policy-migration.sql: " + (e.message || e),
      500
    );
  }

  await logSafetyEvent(env, "policy.updated", {
    repo_id: repo,
    user_id: user.id,
    reason: "dashboard",
    meta: pol,
  });

  const saved = await getAgentPolicy(env, repo);
  return json(request, {
    ok: true,
    default_repo: repo,
    policy: {
      version: saved.version,
      blocked: saved.blocked,
      max_amount: saved.max_amount,
      allow_to: saved.allow_to,
      deny_to: saved.deny_to,
      require_task_prefix: saved.require_task_prefix,
      notes: saved.notes,
    },
  });
}

/* ─── Safety controls (dashboard / API) ─── */

async function handleMeSafetyGet(request, env) {
  const user = await getSessionUser(request, env);
  if (!user) return bad(request, "Sign in required", 401);

  const repo = user.default_repo ? parseRepo(user.default_repo) : null;
  if (!repo) {
    return json(request, {
      ok: true,
      default_repo: null,
      limits: null,
      defaults: {
        velocity_max_tx: SAFETY_DEFAULT_VELOCITY_MAX_TX,
        velocity_tx_window_sec: SAFETY_DEFAULT_VELOCITY_TX_WINDOW_SEC,
        velocity_max_usd: SAFETY_DEFAULT_VELOCITY_MAX_USD,
        velocity_window_sec: SAFETY_DEFAULT_VELOCITY_USD_WINDOW_SEC,
        spike_tx_per_sec: SAFETY_SPIKE_TX_PER_SEC,
      },
    });
  }

  const lim = await getAgentLimits(env, repo);
  let recent = [];
  try {
    const { results } = await env.DB.prepare(
      `SELECT event, reason, created_at FROM safety_events
       WHERE repo_id = ?1 ORDER BY created_at DESC LIMIT 10`
    )
      .bind(repo)
      .all();
    recent = results || [];
  } catch (_) {}

  return json(request, {
    ok: true,
    default_repo: repo,
    limits: lim
      ? {
          repo_id: lim.repo_id,
          daily_budget: lim.daily_budget,
          daily_spent: lim.daily_spent,
          daily_window_start: lim.daily_window_start,
          velocity_max_usd: lim.velocity_max_usd,
          velocity_window_sec: lim.velocity_window_sec,
          velocity_max_tx: lim.velocity_max_tx,
          velocity_tx_window_sec: lim.velocity_tx_window_sec,
          locked: Number(lim.locked) === 1,
          locked_at: lim.locked_at,
          lock_reason: lim.lock_reason,
          updated_at: lim.updated_at,
        }
      : null,
    defaults: {
      velocity_max_tx: SAFETY_DEFAULT_VELOCITY_MAX_TX,
      velocity_tx_window_sec: SAFETY_DEFAULT_VELOCITY_TX_WINDOW_SEC,
      velocity_max_usd: SAFETY_DEFAULT_VELOCITY_MAX_USD,
      velocity_window_sec: SAFETY_DEFAULT_VELOCITY_USD_WINDOW_SEC,
      spike_tx_per_sec: SAFETY_SPIKE_TX_PER_SEC,
    },
    recent_events: recent,
  });
}

async function handleMeSafetySet(request, env) {
  const user = await getSessionUser(request, env);
  if (!user) return bad(request, "Sign in required", 401);

  const repo = user.default_repo ? parseRepo(user.default_repo) : null;
  if (!repo) return bad(request, "Bind a default agent first");

  let body;
  try {
    body = await request.json();
  } catch {
    return bad(request, "Invalid JSON body");
  }

  await ensureAgentLimits(env, repo);

  // null / "" clears optional caps
  const parseOpt = (v) => {
    if (v === null || v === "" || v === undefined) return null;
    const n = Number(v);
    if (!Number.isFinite(n) || n < 0) return undefined; // invalid
    return n;
  };

  const daily = parseOpt(body.daily_budget);
  const vmaxUsd = parseOpt(body.velocity_max_usd);
  const vwinUsd = parseOpt(body.velocity_window_sec);
  const vmaxTx = parseOpt(body.velocity_max_tx);
  const vwinTx = parseOpt(body.velocity_tx_window_sec);

  if (daily === undefined) return bad(request, "daily_budget invalid");
  if (vmaxUsd === undefined) return bad(request, "velocity_max_usd invalid");
  if (vwinUsd === undefined) return bad(request, "velocity_window_sec invalid");
  if (vmaxTx === undefined) return bad(request, "velocity_max_tx invalid");
  if (vwinTx === undefined) return bad(request, "velocity_tx_window_sec invalid");

  // Only update fields present in body
  const sets = [];
  const binds = [];
  const add = (col, val, present) => {
    if (!present) return;
    sets.push(col + " = ?" + (binds.length + 1));
    binds.push(val);
  };

  add("daily_budget", daily, "daily_budget" in body);
  add("velocity_max_usd", vmaxUsd, "velocity_max_usd" in body);
  add(
    "velocity_window_sec",
    vwinUsd != null ? Math.floor(vwinUsd) : null,
    "velocity_window_sec" in body
  );
  add(
    "velocity_max_tx",
    vmaxTx != null ? Math.floor(vmaxTx) : null,
    "velocity_max_tx" in body
  );
  add(
    "velocity_tx_window_sec",
    vwinTx != null ? Math.floor(vwinTx) : null,
    "velocity_tx_window_sec" in body
  );

  if (!sets.length) return bad(request, "No fields to update");

  sets.push("updated_at = datetime('now')");
  binds.push(repo);

  await env.DB.prepare(
    `UPDATE agent_limits SET ${sets.join(", ")} WHERE repo_id = ?${binds.length}`
  )
    .bind(...binds)
    .run();

  await logSafetyEvent(env, "limits.updated", {
    repo_id: repo,
    user_id: user.id,
    reason: "dashboard",
    meta: body,
  });

  const lim = await getAgentLimits(env, repo);
  return json(request, {
    ok: true,
    repo_id: repo,
    limits: lim,
  });
}

async function handleMeSafetyUnlock(request, env) {
  const user = await getSessionUser(request, env);
  if (!user) return bad(request, "Sign in required", 401);

  const repo = user.default_repo ? parseRepo(user.default_repo) : null;
  if (!repo) return bad(request, "Bind a default agent first");

  await unlockWallet(env, repo, { user_id: user.id });
  return json(request, { ok: true, unlocked: true, repo_id: repo });
}

async function handleMeKeysUnsuspend(request, env) {
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

