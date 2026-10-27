/**
 * Shared Standing Orders — recurring micro-pays + processStandingOrders cron.
 */
import { json, bad } from "./http.js";
import {
  parseRepo,
  parseAmount,
  randomId,
} from "./utils.js";
import { checkRateLimit } from "./rateLimit.js";
import { getAuthUser } from "./auth.js";
import { ensureAccount } from "./accounts.js";
import { debitWithCredit, adjustRep } from "./credit.js";
import { scheduleWebhook } from "./webhooks.js";
import { safetyGate, safetyRecordSpend } from "./gate.js";
import {
  STANDING_MIN,
  STANDING_MAX,
  STANDING_MIN_INTERVAL_SEC,
  STANDING_MAX_INTERVAL_SEC,
  STANDING_DEFAULT_INTERVAL_SEC,
  STANDING_MIN_TTL_SEC,
  STANDING_MAX_TTL_SEC,
  STANDING_DEFAULT_TTL_SEC,
  RL_STANDING_MAX,
  RL_STANDING_WINDOW_SEC,
  STANDING_RUN_BATCH,
  CREDIT_REP_SUCCESS_BONUS,
} from "./constants.js";

/* ─── Standing Orders (recurring micro-pays) ───
 * POST /api/standing/open   { from_repo?, to_repo, amount, interval_sec, max_runs?, budget_usd?, ttl_seconds?, task?, label? }
 * POST /api/standing/cancel { id }
 * POST /api/standing/pause  { id }
 * POST /api/standing/resume { id }
 * GET  /api/standing        ?repo=&status=
 * GET  /api/standing/:id
 * Cron: processStandingOrders — debit + pay when next_run_at due
 */

export function parseStandingInterval(body) {
  const sec = Number(body.interval_sec ?? body.interval);
  if (!Number.isFinite(sec)) return STANDING_DEFAULT_INTERVAL_SEC;
  if (sec < STANDING_MIN_INTERVAL_SEC || sec > STANDING_MAX_INTERVAL_SEC) return null;
  return Math.floor(sec);
}

export function parseStandingTtl(body) {
  const sec = Number(body.ttl_seconds ?? body.ttl);
  if (!Number.isFinite(sec)) return STANDING_DEFAULT_TTL_SEC;
  if (sec < STANDING_MIN_TTL_SEC || sec > STANDING_MAX_TTL_SEC) return null;
  return Math.floor(sec);
}

export async function logStandingEvent(env, orderId, event, { amount, note } = {}) {
  try {
    await env.DB.prepare(
      `INSERT INTO standing_events (id, order_id, event, amount, note, created_at)
       VALUES (?1, ?2, ?3, ?4, ?5, datetime('now'))`
    )
      .bind(
        randomId(10),
        orderId,
        event,
        amount != null ? Number(amount) : null,
        note ? String(note).slice(0, 500) : null
      )
      .run();
  } catch (e) {
    console.log("standing_event_err", e && e.message);
  }
}

export async function loadStanding(env, id) {
  try {
    return await env.DB.prepare(`SELECT * FROM standing_orders WHERE id = ?1`).bind(id).first();
  } catch {
    return null;
  }
}

export async function handleStandingOpen(request, env, ctx) {
  const t0 = Date.now();
  const authUser = await getAuthUser(request, env);
  if (!authUser) return bad(request, "Sign in or API key required", 401);

  const rlId =
    authUser.auth_via === "api_key"
      ? "st:key:" + (authUser.key_id || authUser.id)
      : "st:user:" + authUser.id;
  const limited = await checkRateLimit(env, rlId, RL_STANDING_MAX, RL_STANDING_WINDOW_SEC);
  if (limited) {
    return bad(request, "Rate limit: standing orders", 429, { retry_after_sec: limited.retry_after_sec });
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return bad(request, "Invalid JSON body");
  }

  let fromRepo = parseRepo(body.from_repo || body.from);
  if (!fromRepo && authUser.default_repo) fromRepo = parseRepo(authUser.default_repo);
  const toRepo = parseRepo(body.to_repo || body.to);
  const amount = parseAmount(body.amount);
  const intervalSec = parseStandingInterval(body);
  const ttlSec = parseStandingTtl(body);
  const task = String(body.task || "standing-order").slice(0, 500);
  const label = body.label ? String(body.label).slice(0, 200) : null;
  let maxRuns = body.max_runs != null ? Math.floor(Number(body.max_runs)) : null;
  if (maxRuns != null && (!Number.isFinite(maxRuns) || maxRuns < 1)) maxRuns = null;
  let budget = body.budget_usd != null ? parseAmount(body.budget_usd) : null;
  if (budget != null && budget < amount) return bad(request, "budget_usd must be >= amount");

  if (!fromRepo) return bad(request, "from_repo required (or set default agent)");
  if (!toRepo) return bad(request, "to_repo required");
  if (amount == null || amount < STANDING_MIN || amount > STANDING_MAX) return bad(request, "amount invalid");
  if (intervalSec == null) return bad(request, "interval_sec out of range (30s–30d)");
  if (ttlSec == null) return bad(request, "ttl_seconds out of range");

  // Soft pre-check: safety gate for first potential debit (does not debit yet)
  authUser._policyCtx = { to_repo: toRepo, task: "standing:" + task };
  const blocked = await safetyGate(request, env, authUser, fromRepo, amount);
  if (blocked) return blocked;

  const id = "so_" + randomId(12);
  const modInterval = "+" + intervalSec + " seconds";
  const modTtl = "+" + ttlSec + " seconds";

  try {
    await env.DB.prepare(
      `INSERT INTO standing_orders (
         id, from_repo, to_repo, amount, interval_sec, task, label, status,
         max_runs, runs_done, budget_usd, spent_usd,
         next_run_at, ttl_seconds, expires_at,
         created_by, created_at, updated_at
       ) VALUES (
         ?1, ?2, ?3, ?4, ?5, ?6, ?7, 'active',
         ?8, 0, ?9, 0,
         datetime('now', ?10), ?11, datetime('now', ?12),
         ?13, datetime('now'), datetime('now')
       )`
    )
      .bind(
        id,
        fromRepo,
        toRepo,
        amount,
        intervalSec,
        task,
        label,
        maxRuns,
        budget,
        modInterval, // first run after one interval (or use 'now' for immediate — use interval)
        ttlSec,
        modTtl,
        authUser.id
      )
      .run();
  } catch (e) {
    return bad(
      request,
      "standing_orders table missing — run d1-standing-migration.sql: " + (e.message || e),
      500
    );
  }

  await logStandingEvent(env, id, "opened", { amount, note: label || task });

  if (authUser.id) {
    scheduleWebhook(ctx, env, authUser.id, "standing.opened", {
      id,
      from_repo: fromRepo,
      to_repo: toRepo,
      amount,
      interval_sec: intervalSec,
      max_runs: maxRuns,
      budget_usd: budget,
      status: "active",
    });
  }

  return json(request, {
    ok: true,
    order: {
      id,
      from_repo: fromRepo,
      to_repo: toRepo,
      amount,
      interval_sec: intervalSec,
      task,
      label,
      status: "active",
      max_runs: maxRuns,
      runs_done: 0,
      budget_usd: budget,
      spent_usd: 0,
      ttl_seconds: ttlSec,
    },
    latency_ms: Date.now() - t0,
    hint: "Cron debits every interval_sec until max_runs, budget, TTL, or cancel.",
  });
}

export async function handleStandingCancel(request, env, ctx) {
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

  const row = await loadStanding(env, id);
  if (!row) {
    try {
      await env.DB.prepare(`SELECT 1 FROM standing_orders LIMIT 1`).first();
    } catch {
      return bad(request, "standing_orders table missing — run d1-standing-migration.sql", 500);
    }
    return bad(request, "Order not found", 404);
  }
  if (!["active", "paused"].includes(row.status)) {
    return bad(request, "Order not cancellable (status=" + row.status + ")", 400);
  }

  const allowed =
    authUser.id === row.created_by ||
    (authUser.default_repo && authUser.default_repo === row.from_repo);
  if (!allowed) return bad(request, "Not authorized", 403);

  const claim = await env.DB.prepare(
    `UPDATE standing_orders
     SET status = 'cancelled', cancelled_at = datetime('now'), closed_at = datetime('now'),
         updated_at = datetime('now')
     WHERE id = ?1 AND status IN ('active', 'paused')
     RETURNING *`
  )
    .bind(id)
    .first();
  if (!claim) return bad(request, "Cancel race", 409);

  await logStandingEvent(env, id, "cancelled", {
    note: "spent $" + Number(row.spent_usd || 0).toFixed(6),
  });

  if (row.created_by) {
    scheduleWebhook(ctx, env, row.created_by, "standing.cancelled", {
      id,
      from_repo: row.from_repo,
      to_repo: row.to_repo,
      runs_done: Number(row.runs_done || 0),
      spent_usd: Number(row.spent_usd || 0),
      status: "cancelled",
    });
  }

  return json(request, {
    ok: true,
    id,
    status: "cancelled",
    runs_done: Number(row.runs_done || 0),
    spent_usd: Number(row.spent_usd || 0),
    latency_ms: Date.now() - t0,
  });
}

export async function handleStandingPause(request, env, ctx) {
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
  const row = await loadStanding(env, id);
  if (!row) return bad(request, "Order not found", 404);
  if (row.status !== "active") return bad(request, "Only active orders can be paused", 400);
  const allowed =
    authUser.id === row.created_by ||
    (authUser.default_repo && authUser.default_repo === row.from_repo);
  if (!allowed) return bad(request, "Not authorized", 403);
  await env.DB.prepare(
    `UPDATE standing_orders SET status = 'paused', updated_at = datetime('now') WHERE id = ?1`
  )
    .bind(id)
    .run();
  await logStandingEvent(env, id, "paused");
  return json(request, { ok: true, id, status: "paused" });
}

export async function handleStandingResume(request, env, ctx) {
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
  const row = await loadStanding(env, id);
  if (!row) return bad(request, "Order not found", 404);
  if (row.status !== "paused") return bad(request, "Only paused orders can be resumed", 400);
  const allowed =
    authUser.id === row.created_by ||
    (authUser.default_repo && authUser.default_repo === row.from_repo);
  if (!allowed) return bad(request, "Not authorized", 403);
  const intervalSec = Number(row.interval_sec) || STANDING_DEFAULT_INTERVAL_SEC;
  const mod = "+" + intervalSec + " seconds";
  await env.DB.prepare(
    `UPDATE standing_orders
     SET status = 'active', next_run_at = datetime('now', ?2), updated_at = datetime('now')
     WHERE id = ?1`
  )
    .bind(id, mod)
    .run();
  await logStandingEvent(env, id, "resumed");
  return json(request, { ok: true, id, status: "active" });
}

export async function handleStandingGet(request, env, id) {
  id = String(id || "").trim();
  if (!id) return bad(request, "id required");
  const row = await loadStanding(env, id);
  if (!row) {
    try {
      await env.DB.prepare(`SELECT 1 FROM standing_orders LIMIT 1`).first();
    } catch {
      return bad(request, "standing_orders table missing — run d1-standing-migration.sql", 500);
    }
    return bad(request, "Order not found", 404);
  }
  let events = [];
  try {
    const q = await env.DB.prepare(
      `SELECT event, amount, note, created_at
       FROM standing_events WHERE order_id = ?1 ORDER BY created_at DESC LIMIT 40`
    )
      .bind(id)
      .all();
    events = q.results || [];
  } catch (_) {}
  return json(request, { ok: true, order: row, events });
}

export async function handleStandingList(request, url, env) {
  const limit = Math.min(Math.max(Number(url.searchParams.get("limit") || 20), 1), 100);
  const repo = (url.searchParams.get("repo") || "").trim();
  const status = (url.searchParams.get("status") || "").trim();

  let sql = `SELECT id, from_repo, to_repo, amount, interval_sec, task, label, status,
                    max_runs, runs_done, budget_usd, spent_usd,
                    next_run_at, expires_at, last_run_at, last_error, created_at
             FROM standing_orders WHERE 1=1`;
  const binds = [];
  if (repo) {
    if (!parseRepo(repo)) return bad(request, "repo must be owner/repo");
    sql += ` AND (from_repo = ? OR to_repo = ?)`;
    binds.push(repo, repo);
  }
  if (status && ["active", "paused", "cancelled", "completed", "expired"].includes(status)) {
    sql += ` AND status = ?`;
    binds.push(status);
  }
  sql += ` ORDER BY created_at DESC LIMIT ?`;
  binds.push(limit);

  try {
    const { results } = await env.DB.prepare(sql).bind(...binds).all();
    return json(request, { ok: true, count: results.length, orders: results });
  } catch (e) {
    return bad(
      request,
      "standing_orders table missing — run d1-standing-migration.sql: " + (e.message || e),
      500
    );
  }
}

/**
 * Execute one standing debit+pay. Returns { ok, amount?, error?, code? }.
 */
export async function runStandingOnce(env, row, ctx) {
  const amount = Number(row.amount);
  const fromRepo = row.from_repo;
  const toRepo = row.to_repo;
  const task = "standing:" + (row.task || row.id);

  // Synthetic auth for safety gate
  const authUser = {
    id: row.created_by,
    default_repo: fromRepo,
    auth_via: "session",
    _policyCtx: { to_repo: toRepo, task },
  };

  const blocked = await safetyGate(
    new Request("https://standing.internal/run", { method: "POST" }),
    env,
    authUser,
    fromRepo,
    amount
  );
  if (blocked) {
    let msg = "safety blocked";
    try {
      const j = await blocked.json();
      msg = j.error || msg;
    } catch (_) {}
    return { ok: false, error: msg, code: "safety" };
  }

  const debitRes = await debitWithCredit(env, fromRepo, amount);
  if (!debitRes.ok) {
    return { ok: false, error: debitRes.error || "Insufficient funds", code: debitRes.code || "insufficient" };
  }

  await ensureAccount(env, toRepo);
  const t0 = Date.now();
  try {
    await env.DB.batch([
      env.DB.prepare(
        `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
      ).bind(amount, toRepo),
      env.DB.prepare(
        `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
         VALUES (?1, ?2, ?3, ?4, 'success', ?5)`
      ).bind(fromRepo, toRepo, amount, task.slice(0, 200), Date.now() - t0),
    ]);
  } catch (e) {
    // refund debit
    await env.DB.prepare(
      `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
    )
      .bind(amount, fromRepo)
      .run()
      .catch(() => {});
    return { ok: false, error: e.message || "pay failed", code: "pay_fail" };
  }

  await safetyRecordSpend(env, authUser, fromRepo, amount);
  try {
    await adjustRep(env, fromRepo, CREDIT_REP_SUCCESS_BONUS, "standing_run", row.id);
    await adjustRep(env, toRepo, CREDIT_REP_SUCCESS_BONUS, "standing_recv", row.id);
  } catch (_) {}

  return { ok: true, amount };
}

export async function processStandingOrders(env, ctx) {
  const t0 = Date.now();
  let ran = 0;
  let failed = 0;
  let completed = 0;
  let expired = 0;
  try {
    // Expire by TTL first
    const expQ = await env.DB.prepare(
      `SELECT id FROM standing_orders
       WHERE status = 'active'
         AND expires_at IS NOT NULL
         AND expires_at < datetime('now')
       LIMIT ?1`
    )
      .bind(STANDING_RUN_BATCH)
      .all();
    for (const r of expQ.results || []) {
      await env.DB.prepare(
        `UPDATE standing_orders
         SET status = 'expired', closed_at = datetime('now'), updated_at = datetime('now')
         WHERE id = ?1 AND status = 'active'`
      )
        .bind(r.id)
        .run();
      await logStandingEvent(env, r.id, "expired", { note: "ttl" });
      expired += 1;
    }

    const q = await env.DB.prepare(
      `SELECT * FROM standing_orders
       WHERE status = 'active'
         AND next_run_at IS NOT NULL
         AND next_run_at <= datetime('now')
         AND (expires_at IS NULL OR expires_at >= datetime('now'))
       ORDER BY next_run_at ASC LIMIT ?1`
    )
      .bind(STANDING_RUN_BATCH)
      .all();

    for (const row of q.results || []) {
      try {
        // Budget / max_runs pre-check
        const spent = Number(row.spent_usd || 0);
        const runs = Number(row.runs_done || 0);
        const amount = Number(row.amount);
        if (row.budget_usd != null && spent + amount > Number(row.budget_usd) + 1e-9) {
          await env.DB.prepare(
            `UPDATE standing_orders
             SET status = 'completed', closed_at = datetime('now'), updated_at = datetime('now'),
                 last_error = 'budget exhausted'
             WHERE id = ?1`
          )
            .bind(row.id)
            .run();
          await logStandingEvent(env, row.id, "completed", { note: "budget" });
          completed += 1;
          continue;
        }
        if (row.max_runs != null && runs >= Number(row.max_runs)) {
          await env.DB.prepare(
            `UPDATE standing_orders
             SET status = 'completed', closed_at = datetime('now'), updated_at = datetime('now')
             WHERE id = ?1`
          )
            .bind(row.id)
            .run();
          await logStandingEvent(env, row.id, "completed", { note: "max_runs" });
          completed += 1;
          continue;
        }

        const result = await runStandingOnce(env, row, ctx);
        const intervalSec = Number(row.interval_sec) || STANDING_DEFAULT_INTERVAL_SEC;
        const mod = "+" + intervalSec + " seconds";

        if (result.ok) {
          const newRuns = runs + 1;
          const newSpent = Math.round((spent + amount) * 1e6) / 1e6;
          let status = "active";
          let close = false;
          if (row.max_runs != null && newRuns >= Number(row.max_runs)) {
            status = "completed";
            close = true;
          }
          if (row.budget_usd != null && newSpent + amount > Number(row.budget_usd) + 1e-9) {
            // next would exceed — mark complete after this run
            status = "completed";
            close = true;
          }
          await env.DB.prepare(
            `UPDATE standing_orders
             SET runs_done = ?2,
                 spent_usd = ?3,
                 last_run_at = datetime('now'),
                 next_run_at = datetime('now', ?4),
                 last_error = NULL,
                 status = ?5,
                 closed_at = CASE WHEN ?6 = 1 THEN datetime('now') ELSE closed_at END,
                 updated_at = datetime('now')
             WHERE id = ?1`
          )
            .bind(row.id, newRuns, newSpent, mod, status, close ? 1 : 0)
            .run();
          await logStandingEvent(env, row.id, "ran", { amount, note: "run " + newRuns });
          ran += 1;
          if (close) {
            completed += 1;
            await logStandingEvent(env, row.id, "completed", { note: status });
          }
          if (row.created_by) {
            scheduleWebhook(ctx, env, row.created_by, "standing.ran", {
              id: row.id,
              from_repo: row.from_repo,
              to_repo: row.to_repo,
              amount,
              runs_done: newRuns,
              spent_usd: newSpent,
              status,
            });
          }
        } else {
          // On insufficient / lock — stop order so it doesn't spin
          const stop =
            result.code === "insufficient" ||
            result.code === "insufficient_credit" ||
            result.code === "wallet_locked" ||
            result.code === "safety";
          await env.DB.prepare(
            `UPDATE standing_orders
             SET last_error = ?2,
                 next_run_at = datetime('now', ?3),
                 status = CASE WHEN ?4 = 1 THEN 'paused' ELSE status END,
                 updated_at = datetime('now')
             WHERE id = ?1`
          )
            .bind(
              row.id,
              String(result.error || "error").slice(0, 500),
              mod,
              stop ? 1 : 0
            )
            .run();
          await logStandingEvent(env, row.id, "error", { note: result.error });
          failed += 1;
        }
      } catch (e) {
        console.log("standing_run", row.id, e && e.message);
        failed += 1;
      }
    }
  } catch (e) {
    return { ran: 0, error: e.message, latency_ms: Date.now() - t0 };
  }
  return { ran, failed, completed, expired, latency_ms: Date.now() - t0 };
}


