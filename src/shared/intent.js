/**
 * Shared Intent Capsules — create / spend / cancel / list / expire.
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
  SYSTEM_INTENT,
  INTENT_MIN,
  INTENT_MAX,
  INTENT_DEFAULT_TTL_SEC,
  INTENT_MIN_TTL_SEC,
  INTENT_MAX_TTL_SEC,
  RL_INTENT_MAX,
  RL_INTENT_WINDOW_SEC,
  EXPIRE_INTENT_BATCH,
  CREDIT_REP_SUCCESS_BONUS,
} from "./constants.js";

/* ─── Spend Intent Capsules ───
 * Pre-authorize a time-boxed, amount-capped spend envelope.
 * Create locks budget into system/intent; spend draws remaining under allowlist;
 * cancel/expire refunds remainder to from_repo.
 *
 * POST /api/intent/create  { from_repo?, budget, allow_to?, task_prefix?, max_per_spend?, ttl_seconds?, label? }
 * POST /api/intent/spend   { id, to_repo, amount, task? }
 * POST /api/intent/cancel  { id }
 * GET  /api/intent         ?repo=&status=
 * GET  /api/intent/:id
 */

export function parseIntentTtl(body) {
  const sec = Number(body.ttl_seconds ?? body.ttl);
  if (Number.isFinite(sec)) {
    if (sec < INTENT_MIN_TTL_SEC || sec > INTENT_MAX_TTL_SEC) return null;
    return Math.floor(sec);
  }
  return INTENT_DEFAULT_TTL_SEC;
}

export function parseAllowTo(v) {
  if (v == null || v === "") return null;
  if (Array.isArray(v)) {
    const list = v.map((x) => parseRepo(x)).filter(Boolean);
    return list.length ? JSON.stringify(list) : null;
  }
  const s = String(v).trim();
  if (!s) return null;
  if (s.startsWith("[")) {
    try {
      const arr = JSON.parse(s);
      if (Array.isArray(arr)) {
        const list = arr.map((x) => parseRepo(x)).filter(Boolean);
        return list.length ? JSON.stringify(list) : null;
      }
    } catch (_) {}
  }
  // comma-separated
  const list = s.split(",").map((x) => parseRepo(x.trim())).filter(Boolean);
  return list.length ? JSON.stringify(list) : null;
}

export function allowToList(raw) {
  if (!raw) return null;
  try {
    const arr = typeof raw === "string" ? JSON.parse(raw) : raw;
    return Array.isArray(arr) ? arr : null;
  } catch {
    return null;
  }
}

export async function logIntentEvent(env, intentId, event, { actor_repo, amount, to_repo, note } = {}) {
  try {
    await env.DB.prepare(
      `INSERT INTO intent_events (id, intent_id, event, actor_repo, amount, to_repo, note, created_at)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, datetime('now'))`
    )
      .bind(
        randomId(10),
        intentId,
        event,
        actor_repo || null,
        amount != null ? Number(amount) : null,
        to_repo || null,
        note ? String(note).slice(0, 500) : null
      )
      .run();
  } catch (e) {
    console.log("intent_event_err", e && e.message);
  }
}

export async function loadIntent(env, id) {
  try {
    return await env.DB.prepare(`SELECT * FROM intent_capsules WHERE id = ?1`).bind(id).first();
  } catch {
    return null;
  }
}

export async function handleIntentCreate(request, env, ctx) {
  const t0 = Date.now();
  const authUser = await getAuthUser(request, env);
  if (!authUser) return bad(request, "Sign in or API key required", 401);

  const rlId =
    authUser.auth_via === "api_key"
      ? "intent:key:" + (authUser.key_id || authUser.id)
      : "intent:user:" + authUser.id;
  const limited = await checkRateLimit(env, rlId, RL_INTENT_MAX, RL_INTENT_WINDOW_SEC);
  if (limited) {
    return bad(request, "Rate limit: intent ops", 429, { retry_after_sec: limited.retry_after_sec });
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return bad(request, "Invalid JSON body");
  }

  let fromRepo = parseRepo(body.from_repo || body.fromRepo);
  if (!fromRepo && authUser.default_repo) fromRepo = parseRepo(authUser.default_repo);
  const budget = parseAmount(body.budget ?? body.amount ?? body.budget_usd);
  const ttlSec = parseIntentTtl(body);
  const allowTo = parseAllowTo(body.allow_to ?? body.allowTo ?? body.to_allow);
  const taskPrefix = body.task_prefix != null ? String(body.task_prefix).slice(0, 120) : (body.taskPrefix != null ? String(body.taskPrefix).slice(0, 120) : null);
  let maxPer = body.max_per_spend != null ? parseAmount(body.max_per_spend) : (body.maxPerSpend != null ? parseAmount(body.maxPerSpend) : null);
  if (body.max_per_spend === "" || body.max_per_spend === null) maxPer = null;
  const label = body.label ? String(body.label).slice(0, 200) : null;

  if (!fromRepo) return bad(request, "from_repo required (or set default agent)");
  if (budget == null || budget < INTENT_MIN || budget > INTENT_MAX) return bad(request, "budget invalid");
  if (ttlSec == null) return bad(request, "ttl_seconds out of range");
  if (maxPer != null && (maxPer < INTENT_MIN || maxPer > budget)) {
    return bad(request, "max_per_spend must be between min amount and budget");
  }

  authUser._policyCtx = { to_repo: SYSTEM_INTENT, task: "intent:create" };
  const blocked = await safetyGate(request, env, authUser, fromRepo, budget);
  if (blocked) return blocked;

  const debitRes = await debitWithCredit(env, fromRepo, budget);
  if (!debitRes.ok) {
    return bad(request, debitRes.error || "Insufficient funds", debitRes.code === "wallet_locked" ? 403 : 402, {
      code: debitRes.code || "insufficient",
      available_credit: debitRes.available_credit,
    });
  }

  const id = "ic_" + randomId(12);
  const modifier = "+" + ttlSec + " seconds";

  try {
    await ensureAccount(env, SYSTEM_INTENT);
    await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO intent_capsules (
           id, from_repo, budget_usd, remaining_usd, allow_to, task_prefix, max_per_spend,
           status, ttl_seconds, expires_at, label, created_by, created_at, updated_at
         ) VALUES (
           ?1, ?2, ?3, ?3, ?4, ?5, ?6,
           'open', ?7, datetime('now', ?8), ?9, ?10, datetime('now'), datetime('now')
         )`
      ).bind(
        id,
        fromRepo,
        budget,
        allowTo,
        taskPrefix,
        maxPer,
        ttlSec,
        modifier,
        label,
        authUser.id
      ),
      env.DB.prepare(
        `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
         VALUES (?1, ?2, ?3, ?4, 'success', ?5)`
      ).bind(fromRepo, SYSTEM_INTENT, budget, "intent-create:" + id, Date.now() - t0),
    ]);
  } catch (e) {
    await env.DB.prepare(
      `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
    )
      .bind(budget, fromRepo)
      .run()
      .catch(() => {});
    if (debitRes.credit_drawn > 0) {
      await env.DB.prepare(
        `UPDATE agent_limits
         SET outstanding_credit = MAX(0, COALESCE(outstanding_credit, 0) - ?2),
             updated_at = datetime('now')
         WHERE repo_id = ?1`
      )
        .bind(fromRepo, debitRes.credit_drawn)
        .run()
        .catch(() => {});
    }
    return bad(
      request,
      "intent_capsules table missing — run d1-intent-migration.sql: " + (e.message || e),
      500
    );
  }

  await safetyRecordSpend(env, authUser, fromRepo, budget);
  await logIntentEvent(env, id, "created", {
    actor_repo: fromRepo,
    amount: budget,
    note: label || "capsule",
  });

  if (authUser.id) {
    scheduleWebhook(ctx, env, authUser.id, "intent.created", {
      id,
      from_repo: fromRepo,
      budget_usd: budget,
      remaining_usd: budget,
      allow_to: allowToList(allowTo),
      task_prefix: taskPrefix,
      max_per_spend: maxPer,
      ttl_seconds: ttlSec,
      status: "open",
    });
  }

  return json(request, {
    ok: true,
    intent: {
      id,
      from_repo: fromRepo,
      budget_usd: budget,
      remaining_usd: budget,
      allow_to: allowToList(allowTo),
      task_prefix: taskPrefix,
      max_per_spend: maxPer,
      status: "open",
      ttl_seconds: ttlSec,
      label,
    },
    latency_ms: Date.now() - t0,
    hint: "Spend via POST /api/intent/spend { id, to_repo, amount }. Cancel refunds remainder.",
  });
}

export async function handleIntentSpend(request, env, ctx) {
  const t0 = Date.now();
  const authUser = await getAuthUser(request, env);
  if (!authUser) return bad(request, "Sign in or API key required", 401);

  const rlId =
    authUser.auth_via === "api_key"
      ? "intent:key:" + (authUser.key_id || authUser.id)
      : "intent:user:" + authUser.id;
  const limited = await checkRateLimit(env, rlId, RL_INTENT_MAX, RL_INTENT_WINDOW_SEC);
  if (limited) {
    return bad(request, "Rate limit: intent ops", 429, { retry_after_sec: limited.retry_after_sec });
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return bad(request, "Invalid JSON body");
  }

  const id = String(body.id || "").trim();
  const toRepo = parseRepo(body.to_repo || body.toRepo);
  const amount = parseAmount(body.amount);
  const task = String(body.task || "intent-spend").slice(0, 500);

  if (!id) return bad(request, "id required");
  if (!toRepo) return bad(request, "to_repo required");
  if (amount == null) return bad(request, "amount invalid");

  const row = await loadIntent(env, id);
  if (!row) {
    try {
      await env.DB.prepare(`SELECT 1 FROM intent_capsules LIMIT 1`).first();
    } catch {
      return bad(request, "intent_capsules table missing — run d1-intent-migration.sql", 500);
    }
    return bad(request, "Intent not found", 404);
  }
  if (row.status !== "open") {
    return bad(request, "Intent not open (status=" + row.status + ")", 400, { code: "intent_closed" });
  }
  if (row.expires_at) {
    const expMs = Date.parse(String(row.expires_at).replace(" ", "T") + "Z");
    if (Number.isFinite(expMs) && expMs < Date.now()) {
      return bad(request, "Intent expired — cancel or wait for cron refund", 400, { code: "intent_expired" });
    }
  }

  // Authz: creator session or matching default_repo / from_repo
  const allowed =
    authUser.id === row.created_by ||
    (authUser.default_repo && authUser.default_repo === row.from_repo);
  if (!allowed) return bad(request, "Not authorized to spend this intent", 403);

  const allow = allowToList(row.allow_to);
  if (allow && allow.length && !allow.includes(toRepo)) {
    return bad(request, "to_repo not in allow_to list", 403, { code: "intent_allow_to", allow_to: allow });
  }
  if (row.task_prefix) {
    const pref = String(row.task_prefix);
    if (!task.startsWith(pref)) {
      return bad(request, "task must start with prefix \"" + pref + "\"", 403, { code: "intent_task_prefix" });
    }
  }
  if (row.max_per_spend != null && amount > Number(row.max_per_spend)) {
    return bad(request, "amount exceeds max_per_spend ($" + row.max_per_spend + ")", 400, {
      code: "intent_max_per_spend",
    });
  }

  const remaining = Number(row.remaining_usd || 0);
  if (amount > remaining) {
    return bad(request, "Insufficient intent remaining ($" + remaining.toFixed(6) + ")", 402, {
      code: "intent_insufficient",
      remaining_usd: remaining,
    });
  }

  // Claim remaining atomically
  const claim = await env.DB.prepare(
    `UPDATE intent_capsules
     SET remaining_usd = remaining_usd - ?2,
         status = CASE WHEN remaining_usd - ?2 <= 0.0000005 THEN 'depleted' ELSE status END,
         updated_at = datetime('now'),
         closed_at = CASE WHEN remaining_usd - ?2 <= 0.0000005 THEN datetime('now') ELSE closed_at END
     WHERE id = ?1 AND status = 'open' AND remaining_usd >= ?2
     RETURNING *`
  )
    .bind(id, amount)
    .first();
  if (!claim) {
    return bad(request, "Intent spend race or insufficient remaining", 409, { code: "intent_race" });
  }

  try {
    await ensureAccount(env, toRepo);
    await ensureAccount(env, SYSTEM_INTENT);
    await env.DB.batch([
      env.DB.prepare(
        `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
      ).bind(amount, toRepo),
      env.DB.prepare(
        `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
         VALUES (?1, ?2, ?3, ?4, 'success', ?5)`
      ).bind(
        SYSTEM_INTENT,
        toRepo,
        amount,
        "intent-spend:" + id + ":" + task.slice(0, 40),
        Date.now() - t0
      ),
    ]);
  } catch (e) {
    // rollback remaining
    await env.DB.prepare(
      `UPDATE intent_capsules
       SET remaining_usd = remaining_usd + ?2, status = 'open', closed_at = NULL, updated_at = datetime('now')
       WHERE id = ?1`
    )
      .bind(id, amount)
      .run()
      .catch(() => {});
    return bad(request, "Spend settle failed: " + (e.message || e), 500);
  }

  await logIntentEvent(env, id, "spent", {
    actor_repo: row.from_repo,
    amount,
    to_repo: toRepo,
    note: task,
  });
  await adjustRep(env, row.from_repo, CREDIT_REP_SUCCESS_BONUS, "intent_spend", id);

  if (row.created_by) {
    scheduleWebhook(ctx, env, row.created_by, "intent.spent", {
      id,
      from_repo: row.from_repo,
      to_repo: toRepo,
      amount,
      remaining_usd: Number(claim.remaining_usd),
      status: claim.status,
      task,
    });
  }

  return json(request, {
    ok: true,
    id,
    to_repo: toRepo,
    amount,
    remaining_usd: Number(claim.remaining_usd),
    status: claim.status,
    latency_ms: Date.now() - t0,
  });
}

export async function handleIntentCancel(request, env, ctx) {
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

  const row = await loadIntent(env, id);
  if (!row) return bad(request, "Intent not found", 404);
  if (row.status !== "open") {
    return bad(request, "Intent not open (status=" + row.status + ")", 400);
  }

  const allowed =
    authUser.id === row.created_by ||
    (authUser.default_repo && authUser.default_repo === row.from_repo);
  if (!allowed) return bad(request, "Not authorized to cancel", 403);

  const claim = await env.DB.prepare(
    `UPDATE intent_capsules
     SET status = 'cancelled', cancelled_at = datetime('now'), closed_at = datetime('now'), updated_at = datetime('now')
     WHERE id = ?1 AND status = 'open'
     RETURNING *`
  )
    .bind(id)
    .first();
  if (!claim) return bad(request, "Cancel race", 409);

  const refund = Number(claim.remaining_usd || 0);
  if (refund > 0) {
    await ensureAccount(env, row.from_repo);
    await ensureAccount(env, SYSTEM_INTENT);
    await env.DB.batch([
      env.DB.prepare(
        `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
      ).bind(refund, row.from_repo),
      env.DB.prepare(
        `UPDATE intent_capsules SET remaining_usd = 0, updated_at = datetime('now') WHERE id = ?1`
      ).bind(id),
      env.DB.prepare(
        `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
         VALUES (?1, ?2, ?3, ?4, 'success', ?5)`
      ).bind(SYSTEM_INTENT, row.from_repo, refund, "intent-cancel-refund:" + id, Date.now() - t0),
    ]);
  }

  await logIntentEvent(env, id, "cancelled", {
    actor_repo: row.from_repo,
    amount: refund,
    note: "owner_cancel",
  });

  if (row.created_by) {
    scheduleWebhook(ctx, env, row.created_by, "intent.cancelled", {
      id,
      from_repo: row.from_repo,
      refunded: refund,
      status: "cancelled",
    });
  }

  return json(request, {
    ok: true,
    id,
    status: "cancelled",
    refunded: refund,
    latency_ms: Date.now() - t0,
  });
}

export async function handleIntentGet(request, env, id) {
  id = String(id || "").trim();
  if (!id) return bad(request, "id required");
  const row = await loadIntent(env, id);
  if (!row) {
    try {
      await env.DB.prepare(`SELECT 1 FROM intent_capsules LIMIT 1`).first();
    } catch {
      return bad(request, "intent_capsules table missing — run d1-intent-migration.sql", 500);
    }
    return bad(request, "Intent not found", 404);
  }
  let events = [];
  try {
    const q = await env.DB.prepare(
      `SELECT event, actor_repo, amount, to_repo, note, created_at
       FROM intent_events WHERE intent_id = ?1 ORDER BY created_at DESC LIMIT 40`
    )
      .bind(id)
      .all();
    events = q.results || [];
  } catch (_) {}
  return json(request, {
    ok: true,
    intent: {
      ...row,
      allow_to: allowToList(row.allow_to),
    },
    events,
  });
}

export async function handleIntentList(request, url, env) {
  const limit = Math.min(Math.max(Number(url.searchParams.get("limit") || 20), 1), 100);
  const repo = (url.searchParams.get("repo") || "").trim();
  const status = (url.searchParams.get("status") || "").trim();

  let sql = `SELECT id, from_repo, budget_usd, remaining_usd, allow_to, task_prefix, max_per_spend,
                    status, ttl_seconds, expires_at, label, created_at
             FROM intent_capsules WHERE 1=1`;
  const binds = [];
  if (repo) {
    if (!parseRepo(repo)) return bad(request, "repo must be owner/repo");
    sql += ` AND from_repo = ?`;
    binds.push(repo);
  }
  if (status && ["open", "depleted", "cancelled", "expired"].includes(status)) {
    sql += ` AND status = ?`;
    binds.push(status);
  }
  sql += ` ORDER BY created_at DESC LIMIT ?`;
  binds.push(limit);

  try {
    const { results } = await env.DB.prepare(sql).bind(...binds).all();
    const rows = (results || []).map((r) => ({
      ...r,
      allow_to: allowToList(r.allow_to),
    }));
    return json(request, { ok: true, count: rows.length, intents: rows });
  } catch (e) {
    return bad(
      request,
      "intent_capsules table missing — run d1-intent-migration.sql: " + (e.message || e),
      500
    );
  }
}

export async function expireIntentCapsules(env, ctx) {
  const t0 = Date.now();
  let expired = 0;
  let refundedTotal = 0;
  try {
    const q = await env.DB.prepare(
      `SELECT * FROM intent_capsules
       WHERE status = 'open'
         AND expires_at IS NOT NULL
         AND expires_at < datetime('now')
       ORDER BY expires_at ASC LIMIT ?1`
    )
      .bind(EXPIRE_INTENT_BATCH)
      .all();
    for (const row of q.results || []) {
      try {
        const claim = await env.DB.prepare(
          `UPDATE intent_capsules
           SET status = 'expired', closed_at = datetime('now'), updated_at = datetime('now')
           WHERE id = ?1 AND status = 'open' RETURNING *`
        )
          .bind(row.id)
          .first();
        if (!claim) continue;
        const refund = Number(claim.remaining_usd || 0);
        if (refund > 0) {
          await ensureAccount(env, row.from_repo);
          await env.DB.batch([
            env.DB.prepare(
              `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
            ).bind(refund, row.from_repo),
            env.DB.prepare(
              `UPDATE intent_capsules SET remaining_usd = 0, updated_at = datetime('now') WHERE id = ?1`
            ).bind(row.id),
            env.DB.prepare(
              `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
               VALUES (?1, ?2, ?3, ?4, 'success', 0)`
            ).bind(SYSTEM_INTENT, row.from_repo, refund, "intent-expire-refund:" + row.id),
          ]);
          refundedTotal += refund;
        }
        await logIntentEvent(env, row.id, "expired", {
          actor_repo: row.from_repo,
          amount: refund,
          note: "ttl",
        });
        expired += 1;
        if (row.created_by) {
          scheduleWebhook(ctx, env, row.created_by, "intent.expired", {
            id: row.id,
            from_repo: row.from_repo,
            refunded: refund,
            status: "expired",
          });
        }
      } catch (e) {
        console.log("intent_expire", row.id, e && e.message);
      }
    }
  } catch (e) {
    return { expired: 0, error: e.message, latency_ms: Date.now() - t0 };
  }
  return { expired, refunded_total: refundedTotal, latency_ms: Date.now() - t0 };
}


