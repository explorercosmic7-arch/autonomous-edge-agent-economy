/**
 * Streaming micro-pay — start / meter / stop / list
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
import { safetyGate, safetyRecordSpend } from "./gate.js";
import {
  RL_STREAM_MAX,
  RL_STREAM_WINDOW_SEC,
  SYSTEM_STREAM,
  STREAM_MIN_BUDGET,
  STREAM_MAX_BUDGET,
} from "./constants.js";

/* ─── Streaming micro-pay ───
 * Start: debit budget from from_repo → system/stream (held)
 * Meter: move rate*units from held spent tracking → to_repo
 * Stop:  refund (budget - spent) to from_repo
 */

export async function handleStreamStart(request, env) {
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

export async function handleStreamMeter(request, env) {
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

export async function handleStreamStop(request, env) {
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

export async function handleStreamList(request, url, env) {
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
