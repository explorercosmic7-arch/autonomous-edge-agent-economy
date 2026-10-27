/**
 * Shared Saga — multi-step payment graphs + compensate/cancel + expireSagas cron.
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
import { adjustRep } from "./credit.js";
import { scheduleWebhook } from "./webhooks.js";
import { safetyGate, safetyRecordSpend } from "./gate.js";
import {
  SYSTEM_SAGA,
  SAGA_MIN_BUDGET,
  SAGA_MAX_BUDGET,
  SAGA_MAX_STEPS,
  SAGA_DEFAULT_TTL_SEC,
  SAGA_MIN_TTL_SEC,
  SAGA_MAX_TTL_SEC,
  RL_SAGA_MAX,
  RL_SAGA_WINDOW_SEC,
  EXPIRE_SAGA_BATCH,
  CREDIT_REP_FAIL_PENALTY,
} from "./constants.js";

/* ─── Multi-agent atomic graphs (saga with money) ───
 * Owner locks total_budget into system/saga.
 * Steps run in order via advance: debit reserved → credit step.to_repo.
 * On failure: compensate walks completed steps reverse and refunds to owner.
 * Cancel (open, no spent): full refund of reserved.
 * Expire open/running past TTL: auto-compensate.
 */
export function parseSagaTtl(body) {
  const sec = Number(body.ttl_seconds ?? body.ttl);
  if (Number.isFinite(sec)) {
    if (sec < SAGA_MIN_TTL_SEC || sec > SAGA_MAX_TTL_SEC) return null;
    return Math.floor(sec);
  }
  return SAGA_DEFAULT_TTL_SEC;
}

export async function logSagaEvent(env, sagaId, event, { step_index, amount, note } = {}) {
  try {
    await env.DB.prepare(
      `INSERT INTO saga_events (id, saga_id, event, step_index, amount, note, created_at)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, datetime('now'))`
    )
      .bind(
        randomId(10),
        sagaId,
        event,
        step_index != null ? Number(step_index) : null,
        amount != null ? Number(amount) : null,
        note ? String(note).slice(0, 500) : null
      )
      .run();
  } catch (e) {
    console.log("saga_event_err", e && e.message);
  }
}

export async function loadSaga(env, id) {
  try {
    return await env.DB.prepare(`SELECT * FROM payment_sagas WHERE id = ?1`).bind(id).first();
  } catch {
    return null;
  }
}

export async function loadSagaSteps(env, sagaId) {
  try {
    const q = await env.DB.prepare(
      `SELECT * FROM saga_steps WHERE saga_id = ?1 ORDER BY step_index ASC`
    )
      .bind(sagaId)
      .all();
    return q.results || [];
  } catch {
    return [];
  }
}

export async function handleSagaStart(request, env, ctx) {
  const t0 = Date.now();
  const authUser = await getAuthUser(request, env);
  if (!authUser) return bad(request, "Sign in or API key required", 401);

  const rlId =
    authUser.auth_via === "api_key"
      ? "sg:key:" + (authUser.key_id || authUser.id)
      : "sg:user:" + authUser.id;
  const limited = await checkRateLimit(env, rlId, RL_SAGA_MAX, RL_SAGA_WINDOW_SEC);
  if (limited) {
    return bad(request, "Rate limit: saga ops", 429, { retry_after_sec: limited.retry_after_sec });
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return bad(request, "Invalid JSON body");
  }

  let owner = parseRepo(body.owner_repo || body.from_repo || body.fromRepo);
  if (!owner && authUser.default_repo) owner = parseRepo(authUser.default_repo);
  const label = String(body.label || body.name || "saga").slice(0, 120);
  const ttlSec = parseSagaTtl(body);
  const stepsIn = Array.isArray(body.steps) ? body.steps : [];

  if (!owner) return bad(request, "owner_repo required (or set default agent)");
  if (ttlSec == null) return bad(request, "ttl_seconds out of range");
  if (!stepsIn.length) return bad(request, "steps[] required (at least one)");
  if (stepsIn.length > SAGA_MAX_STEPS) {
    return bad(request, "max " + SAGA_MAX_STEPS + " steps per saga");
  }

  const parsedSteps = [];
  let total = 0;
  for (let i = 0; i < stepsIn.length; i++) {
    const s = stepsIn[i] || {};
    const from_repo = parseRepo(s.from_repo || s.from) || owner;
    const to_repo = parseRepo(s.to_repo || s.to);
    const amount = parseAmount(s.amount);
    const task = String(s.task || "saga-step-" + i).slice(0, 500);
    if (!to_repo) return bad(request, "steps[" + i + "].to_repo required");
    if (amount == null || amount < SAGA_MIN_BUDGET) {
      return bad(request, "steps[" + i + "].amount invalid");
    }
    total += amount;
    parsedSteps.push({ from_repo, to_repo, amount, task, step_index: i });
  }
  total = Math.round(total * 1e6) / 1e6;
  if (total > SAGA_MAX_BUDGET) return bad(request, "total budget exceeds max");

  // Optional explicit budget override (must cover steps)
  if (body.total_budget != null) {
    const tb = parseAmount(body.total_budget);
    if (tb == null || tb < total) {
      return bad(request, "total_budget must be >= sum of step amounts");
    }
    total = tb;
  }

  authUser._policyCtx = { to_repo: SYSTEM_SAGA, task: "saga:" + label };
  const blocked = await safetyGate(request, env, authUser, owner, total);
  if (blocked) return blocked;

  await ensureAccount(env, owner);
  const debit = await env.DB.prepare(
    `UPDATE accounts SET balance = balance - ?1, updated_at = datetime('now')
     WHERE repo_id = ?2 AND balance >= ?1 RETURNING balance`
  )
    .bind(total, owner)
    .first();
  if (!debit) return bad(request, "Insufficient funds for saga budget", 402);

  const id = "sg_" + randomId(12);
  const modifier = "+" + ttlSec + " seconds";
  const meta = body.meta && typeof body.meta === "object" ? JSON.stringify(body.meta).slice(0, 2000) : null;

  try {
    const stmts = [
      env.DB.prepare(
        `INSERT INTO payment_sagas (
           id, owner_repo, label, status, total_budget, reserved, spent,
           current_step, step_count, created_by, expires_at, meta_json,
           created_at, updated_at
         ) VALUES (
           ?1, ?2, ?3, 'open', ?4, ?4, 0, 0, ?5, ?6,
           datetime('now', ?7), ?8, datetime('now'), datetime('now')
         )`
      ).bind(id, owner, label, total, parsedSteps.length, authUser.id, modifier, meta),
      env.DB.prepare(
        `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
         VALUES (?1, ?2, ?3, ?4, 'success', ?5)`
      ).bind(owner, SYSTEM_SAGA, total, "saga-reserve:" + id, Date.now() - t0),
    ];
    for (const st of parsedSteps) {
      stmts.push(
        env.DB.prepare(
          `INSERT INTO saga_steps (
             id, saga_id, step_index, from_repo, to_repo, amount, task, status, created_at
           ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'pending', datetime('now'))`
        ).bind(
          "ss_" + randomId(8),
          id,
          st.step_index,
          st.from_repo,
          st.to_repo,
          st.amount,
          st.task
        )
      );
    }
    await env.DB.batch(stmts);
  } catch (e) {
    await env.DB.prepare(
      `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
    )
      .bind(total, owner)
      .run();
    return bad(
      request,
      "payment_sagas table missing — run d1-saga-migration.sql: " + (e.message || e),
      500
    );
  }

  await safetyRecordSpend(env, authUser, owner, total);
  await logSagaEvent(env, id, "started", { amount: total, note: label });

  if (authUser.id) {
    scheduleWebhook(ctx, env, authUser.id, "saga.started", {
      id,
      owner_repo: owner,
      label,
      total_budget: total,
      step_count: parsedSteps.length,
      status: "open",
    });
  }

  const steps = await loadSagaSteps(env, id);
  return json(request, {
    ok: true,
    saga: {
      id,
      owner_repo: owner,
      label,
      status: "open",
      total_budget: total,
      reserved: total,
      spent: 0,
      current_step: 0,
      step_count: parsedSteps.length,
      ttl_seconds: ttlSec,
    },
    steps,
    balance_owner: debit.balance,
    latency_ms: Date.now() - t0,
    hint: "POST /api/saga/advance { id } to execute next step. Compensate on failure.",
  });
}

export async function handleSagaAdvance(request, env, ctx) {
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
    row = await env.DB.prepare(`SELECT * FROM payment_sagas WHERE id = ?1`).bind(id).first();
  } catch {
    return bad(request, "payment_sagas table missing — run d1-saga-migration.sql", 500);
  }
  if (!row) return bad(request, "Saga not found", 404);
  if (row.status !== "open" && row.status !== "running") {
    return bad(request, "Saga not advanceable (status=" + row.status + ")", 400, {
      code: "saga_closed",
    });
  }
  if (row.expires_at) {
    const expMs = Date.parse(String(row.expires_at).replace(" ", "T") + "Z");
    if (Number.isFinite(expMs) && expMs < Date.now()) {
      return bad(request, "Saga expired — compensate or wait for cron", 400, {
        code: "saga_expired",
      });
    }
  }

  const allowed =
    authUser.id === row.created_by ||
    (authUser.default_repo && authUser.default_repo === row.owner_repo);
  if (!allowed) return bad(request, "Not authorized to advance this saga", 403);

  const stepIdx = Number(row.current_step);
  const step = await env.DB.prepare(
    `SELECT * FROM saga_steps WHERE saga_id = ?1 AND step_index = ?2`
  )
    .bind(id, stepIdx)
    .first();
  if (!step) return bad(request, "No pending step at index " + stepIdx, 404);
  if (step.status !== "pending") {
    return bad(request, "Step already " + step.status, 409);
  }

  const amount = Number(step.amount);
  // Move value from system/saga pool → to_repo (budget already reserved from owner)
  await ensureAccount(env, step.to_repo);
  await ensureAccount(env, SYSTEM_SAGA);

  const claim = await env.DB.prepare(
    `UPDATE saga_steps
     SET status = 'done', executed_at = datetime('now')
     WHERE id = ?1 AND status = 'pending'
     RETURNING *`
  )
    .bind(step.id)
    .first();
  if (!claim) return bad(request, "Step race", 409);

  const nextIdx = stepIdx + 1;
  const done = nextIdx >= Number(row.step_count);
  const newStatus = done ? "completed" : "running";

  await env.DB.batch([
    env.DB.prepare(
      `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
    ).bind(amount, step.to_repo),
    env.DB.prepare(
      `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
       VALUES (?1, ?2, ?3, ?4, 'success', ?5)`
    ).bind(
      SYSTEM_SAGA,
      step.to_repo,
      amount,
      "saga-step:" + id + ":" + stepIdx + ":" + (step.task || "").slice(0, 40),
      Date.now() - t0
    ),
    env.DB.prepare(
      `UPDATE payment_sagas
       SET spent = spent + ?1,
           current_step = ?2,
           status = ?3,
           completed_at = CASE WHEN ?3 = 'completed' THEN datetime('now') ELSE completed_at END,
           closed_at = CASE WHEN ?3 = 'completed' THEN datetime('now') ELSE closed_at END,
           close_reason = CASE WHEN ?3 = 'completed' THEN 'completed' ELSE close_reason END,
           updated_at = datetime('now')
       WHERE id = ?4`
    ).bind(amount, nextIdx, newStatus, id),
  ]);

  await logSagaEvent(env, id, "step_done", {
    step_index: stepIdx,
    amount,
    note: step.to_repo,
  });
  if (done) {
    await logSagaEvent(env, id, "completed", { amount: Number(row.spent) + amount });
  }

  if (row.created_by) {
    scheduleWebhook(ctx, env, row.created_by, done ? "saga.completed" : "saga.step", {
      id,
      step_index: stepIdx,
      to_repo: step.to_repo,
      amount,
      status: newStatus,
    });
  }

  const steps = await loadSagaSteps(env, id);
  return json(request, {
    ok: true,
    id,
    status: newStatus,
    step_index: stepIdx,
    paid_to: step.to_repo,
    amount,
    current_step: nextIdx,
    completed: done,
    steps,
    latency_ms: Date.now() - t0,
  });
}

export async function compensateSagaInternal(env, row, reason, t0, ctx) {
  const steps = await loadSagaSteps(env, row.id);
  const doneSteps = steps
    .filter((s) => s.status === "done")
    .sort((a, b) => Number(b.step_index) - Number(a.step_index));

  let refunded = 0;
  for (const st of doneSteps) {
    const amt = Number(st.amount);
    // Reverse: debit to_repo if possible, credit owner; else credit owner from system pool
    await ensureAccount(env, st.to_repo);
    await ensureAccount(env, row.owner_repo);
    const took = await env.DB.prepare(
      `UPDATE accounts SET balance = balance - ?1, updated_at = datetime('now')
       WHERE repo_id = ?2 AND balance >= ?1 RETURNING balance`
    )
      .bind(amt, st.to_repo)
      .first();
    const fromRepo = took ? st.to_repo : SYSTEM_SAGA;
    if (!took) {
      // system/saga already held remaining reserved; use accounting credit only
    }
    await env.DB.batch([
      env.DB.prepare(
        `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
      ).bind(amt, row.owner_repo),
      env.DB.prepare(
        `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
         VALUES (?1, ?2, ?3, ?4, 'success', ?5)`
      ).bind(
        fromRepo,
        row.owner_repo,
        amt,
        "saga-compensate:" + row.id + ":" + st.step_index,
        typeof t0 === "number" ? Date.now() - t0 : 0
      ),
      env.DB.prepare(
        `UPDATE saga_steps
         SET status = 'compensated', compensated_at = datetime('now'),
             compensated_amount = ?2
         WHERE id = ?1`
      ).bind(st.id, amt),
    ]);
    refunded += amt;
  }

  // Unspent reserved still in system/saga → owner
  const unspent = Math.max(
    0,
    Math.round((Number(row.reserved) - Number(row.spent)) * 1e6) / 1e6
  );
  if (unspent > 0) {
    await ensureAccount(env, row.owner_repo);
    await env.DB.batch([
      env.DB.prepare(
        `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
      ).bind(unspent, row.owner_repo),
      env.DB.prepare(
        `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
         VALUES (?1, ?2, ?3, ?4, 'success', 0)`
      ).bind(SYSTEM_SAGA, row.owner_repo, unspent, "saga-unspent-refund:" + row.id),
    ]);
    refunded += unspent;
  }

  await env.DB.prepare(
    `UPDATE payment_sagas
     SET status = 'compensated',
         compensated_at = datetime('now'),
         closed_at = datetime('now'),
         close_reason = ?2,
         updated_at = datetime('now')
     WHERE id = ?1`
  )
    .bind(row.id, reason || "compensated")
    .run();

  await adjustRep(env, row.owner_repo, -CREDIT_REP_FAIL_PENALTY, "saga_compensated", row.id);
  await logSagaEvent(env, row.id, "compensated", {
    amount: refunded,
    note: reason || "compensated",
  });

  if (row.created_by && ctx) {
    scheduleWebhook(ctx, env, row.created_by, "saga.compensated", {
      id: row.id,
      refunded,
      reason: reason || "compensated",
      status: "compensated",
    });
  }
  return refunded;
}

export async function handleSagaCompensate(request, env, ctx) {
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
  const reason = String(body.reason || "compensate").slice(0, 500);
  if (!id) return bad(request, "id required");

  let row;
  try {
    row = await env.DB.prepare(`SELECT * FROM payment_sagas WHERE id = ?1`).bind(id).first();
  } catch {
    return bad(request, "payment_sagas table missing — run d1-saga-migration.sql", 500);
  }
  if (!row) return bad(request, "Saga not found", 404);
  if (!["open", "running"].includes(row.status)) {
    return bad(request, "Saga not compensatable (status=" + row.status + ")");
  }

  const allowed =
    authUser.id === row.created_by ||
    (authUser.default_repo && authUser.default_repo === row.owner_repo);
  if (!allowed) return bad(request, "Not authorized to compensate", 403);

  const claim = await env.DB.prepare(
    `UPDATE payment_sagas SET status = 'compensating', updated_at = datetime('now')
     WHERE id = ?1 AND status IN ('open', 'running') RETURNING *`
  )
    .bind(id)
    .first();
  if (!claim) return bad(request, "Compensate race", 409);

  const refunded = await compensateSagaInternal(env, claim, reason, t0, ctx);
  const steps = await loadSagaSteps(env, id);
  return json(request, {
    ok: true,
    id,
    status: "compensated",
    refunded,
    steps,
    latency_ms: Date.now() - t0,
  });
}

export async function handleSagaCancel(request, env, ctx) {
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
    row = await env.DB.prepare(`SELECT * FROM payment_sagas WHERE id = ?1`).bind(id).first();
  } catch {
    return bad(request, "payment_sagas table missing — run d1-saga-migration.sql", 500);
  }
  if (!row) return bad(request, "Saga not found", 404);
  if (row.status !== "open" || Number(row.spent) > 0) {
    return bad(
      request,
      "Cancel only before any step runs (use compensate after advance)",
      400
    );
  }

  const allowed =
    authUser.id === row.created_by ||
    (authUser.default_repo && authUser.default_repo === row.owner_repo);
  if (!allowed) return bad(request, "Not authorized to cancel", 403);

  const claim = await env.DB.prepare(
    `UPDATE payment_sagas
     SET status = 'cancelled', closed_at = datetime('now'), close_reason = 'cancelled',
         updated_at = datetime('now')
     WHERE id = ?1 AND status = 'open' AND spent = 0
     RETURNING *`
  )
    .bind(id)
    .first();
  if (!claim) return bad(request, "Cancel race or already advanced", 409);

  const refund = Number(row.reserved);
  await ensureAccount(env, row.owner_repo);
  await env.DB.batch([
    env.DB.prepare(
      `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
    ).bind(refund, row.owner_repo),
    env.DB.prepare(
      `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
       VALUES (?1, ?2, ?3, ?4, 'success', ?5)`
    ).bind(SYSTEM_SAGA, row.owner_repo, refund, "saga-cancel-refund:" + id, Date.now() - t0),
    env.DB.prepare(
      `UPDATE saga_steps SET status = 'cancelled' WHERE saga_id = ?1 AND status = 'pending'`
    ).bind(id),
  ]);

  await logSagaEvent(env, id, "cancelled", { amount: refund });
  return json(request, {
    ok: true,
    id,
    status: "cancelled",
    refunded: refund,
    latency_ms: Date.now() - t0,
  });
}

export async function handleSagaGet(request, env, id) {
  id = String(id || "").trim();
  if (!id) return bad(request, "id required");
  const row = await loadSaga(env, id);
  if (!row) {
    try {
      await env.DB.prepare(`SELECT 1 FROM payment_sagas LIMIT 1`).first();
    } catch {
      return bad(request, "payment_sagas table missing — run d1-saga-migration.sql", 500);
    }
    return bad(request, "Saga not found", 404);
  }
  const steps = await loadSagaSteps(env, id);
  let events = [];
  try {
    const q = await env.DB.prepare(
      `SELECT event, step_index, amount, note, created_at
       FROM saga_events WHERE saga_id = ?1 ORDER BY created_at DESC LIMIT 40`
    )
      .bind(id)
      .all();
    events = q.results || [];
  } catch (_) {}
  return json(request, { ok: true, saga: row, steps, events });
}

export async function handleSagaList(request, url, env) {
  const limit = Math.min(Math.max(Number(url.searchParams.get("limit") || 20), 1), 100);
  const repo = (url.searchParams.get("repo") || "").trim();
  const status = (url.searchParams.get("status") || "").trim();

  let sql = `SELECT id, owner_repo, label, status, total_budget, reserved, spent,
                    current_step, step_count, expires_at, created_at
             FROM payment_sagas WHERE 1=1`;
  const binds = [];
  if (repo) {
    if (!parseRepo(repo)) return bad(request, "repo must be owner/repo");
    sql += ` AND owner_repo = ?`;
    binds.push(repo);
  }
  if (
    status &&
    ["open", "running", "completed", "compensated", "cancelled", "expired"].includes(status)
  ) {
    sql += ` AND status = ?`;
    binds.push(status);
  }
  sql += ` ORDER BY created_at DESC LIMIT ?`;
  binds.push(limit);

  try {
    const { results } = await env.DB.prepare(sql).bind(...binds).all();
    return json(request, { ok: true, count: results.length, sagas: results });
  } catch (e) {
    return bad(
      request,
      "payment_sagas table missing — run d1-saga-migration.sql: " + (e.message || e),
      500
    );
  }
}

export async function expireSagas(env, ctx) {
  const t0 = Date.now();
  let expired = 0;
  let refundedTotal = 0;
  try {
    const q = await env.DB.prepare(
      `SELECT * FROM payment_sagas
       WHERE status IN ('open', 'running')
         AND expires_at IS NOT NULL
         AND expires_at < datetime('now')
       ORDER BY expires_at ASC LIMIT ?1`
    )
      .bind(EXPIRE_SAGA_BATCH)
      .all();
    for (const row of q.results || []) {
      try {
        const claim = await env.DB.prepare(
          `UPDATE payment_sagas SET status = 'compensating', updated_at = datetime('now')
           WHERE id = ?1 AND status IN ('open', 'running') RETURNING *`
        )
          .bind(row.id)
          .first();
        if (!claim) continue;
        const r = await compensateSagaInternal(env, claim, "expired", t0, ctx);
        await env.DB.prepare(
          `UPDATE payment_sagas SET close_reason = 'expired' WHERE id = ?1`
        )
          .bind(row.id)
          .run();
        expired += 1;
        refundedTotal += r;
      } catch (e) {
        console.log("saga_expire", row.id, e && e.message);
      }
    }
  } catch (e) {
    return { expired: 0, error: e.message, latency_ms: Date.now() - t0 };
  }
  return { expired, refunded_total: refundedTotal, latency_ms: Date.now() - t0 };
}

