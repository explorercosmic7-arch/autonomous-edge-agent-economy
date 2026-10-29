/**
 * Shared Hire Protocol — RFQ → Quote → Accept → Complete / Cancel + expire.
 *
 * Passport gate on Accept:
 *   - Always attaches provider passport claims on success (soft).
 *   - require_passport=true or passport_strict=true → hard block when:
 *       dispute_rate > max_dispute_rate (default 0.25)
 *       OR (require_history && settled_tx_band === "0")
 *   - Body override: max_dispute_rate (0..1), require_history (bool)
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
import { getPassportClaims } from "./passport.js";
import {
  SYSTEM_HIRE,
  HIRE_MIN,
  HIRE_MAX,
  HIRE_DEFAULT_TTL_SEC,
  HIRE_MIN_TTL_SEC,
  HIRE_MAX_TTL_SEC,
  RL_HIRE_MAX,
  RL_HIRE_WINDOW_SEC,
  EXPIRE_HIRE_BATCH,
  CREDIT_REP_SUCCESS_BONUS,
} from "./constants.js";

const DEFAULT_MAX_DISPUTE_RATE = 0.25;

/* ─── Hire Protocol (RFQ → Quote → Accept → Complete / Cancel) ───
 * POST /api/hire/rfq       { task, budget_usd, capability?, ttl_seconds?, buyer_repo? }
 * POST /api/hire/quote     { rfq_id, amount_usd, eta_seconds?, note?, provider_repo? }
 * POST /api/hire/accept    { quote_id, require_passport?, passport_strict?, max_dispute_rate?, require_history? }
 * POST /api/hire/complete  { job_id }    — pay provider
 * POST /api/hire/cancel    { rfq_id? | job_id? }
 * GET  /api/hire           ?repo=&status=
 * GET  /api/hire/:id
 */

export function parseHireTtl(body) {
  const sec = Number(body.ttl_seconds ?? body.ttl);
  if (Number.isFinite(sec)) {
    if (sec < HIRE_MIN_TTL_SEC || sec > HIRE_MAX_TTL_SEC) return null;
    return Math.floor(sec);
  }
  return HIRE_DEFAULT_TTL_SEC;
}

/**
 * Evaluate provider passport for hire accept.
 * Returns { claims, warnings[], blocked, block_reason }.
 */
export async function evaluateHirePassport(env, providerRepo, opts = {}) {
  const strict = !!(opts.require_passport || opts.passport_strict || opts.strict);
  let maxRate = Number(opts.max_dispute_rate);
  if (!Number.isFinite(maxRate) || maxRate < 0 || maxRate > 1) {
    maxRate = DEFAULT_MAX_DISPUTE_RATE;
  }
  const requireHistory = !!opts.require_history;

  const claims = await getPassportClaims(env, providerRepo);
  const warnings = [];
  let blocked = false;
  let block_reason = null;

  if (!claims) {
    warnings.push("passport_unavailable");
    if (strict) {
      blocked = true;
      block_reason = "provider_passport_unavailable";
    }
    return { claims: null, warnings, blocked, block_reason, max_dispute_rate: maxRate };
  }

  const rate = Number(claims.dispute_rate) || 0;
  if (rate > maxRate) {
    warnings.push("high_dispute_rate");
    if (strict) {
      blocked = true;
      block_reason = "provider_dispute_rate_exceeded";
    }
  }

  if (requireHistory && (claims.settled_tx_band === "0" || !claims.settled_tx_band)) {
    warnings.push("no_settlement_history");
    if (strict) {
      blocked = true;
      block_reason = "provider_no_settlement_history";
    }
  }

  if ((Number(claims.rep_score) || 0) < 0) {
    warnings.push("negative_rep");
  }

  return { claims, warnings, blocked, block_reason, max_dispute_rate: maxRate };
}

export async function logHireEvent(env, { rfq_id, quote_id, job_id, event, actor_repo, amount, note } = {}) {
  try {
    await env.DB.prepare(
      `INSERT INTO hire_events (id, rfq_id, quote_id, job_id, event, actor_repo, amount, note, created_at)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, datetime('now'))`
    )
      .bind(
        randomId(10),
        rfq_id || null,
        quote_id || null,
        job_id || null,
        event,
        actor_repo || null,
        amount != null ? Number(amount) : null,
        note ? String(note).slice(0, 500) : null
      )
      .run();
  } catch (e) {
    console.log("hire_event_err", e && e.message);
  }
}

export async function loadHireRfq(env, id) {
  try {
    return await env.DB.prepare(`SELECT * FROM hire_rfqs WHERE id = ?1`).bind(id).first();
  } catch {
    return null;
  }
}

export async function loadHireQuote(env, id) {
  try {
    return await env.DB.prepare(`SELECT * FROM hire_quotes WHERE id = ?1`).bind(id).first();
  } catch {
    return null;
  }
}

export async function loadHireJob(env, id) {
  try {
    return await env.DB.prepare(`SELECT * FROM hire_jobs WHERE id = ?1`).bind(id).first();
  } catch {
    return null;
  }
}

export async function handleHireRfq(request, env, ctx) {
  const t0 = Date.now();
  const authUser = await getAuthUser(request, env);
  if (!authUser) return bad(request, "Sign in or API key required", 401);

  const rlId =
    authUser.auth_via === "api_key"
      ? "hire:key:" + (authUser.key_id || authUser.id)
      : "hire:user:" + authUser.id;
  const limited = await checkRateLimit(env, rlId, RL_HIRE_MAX, RL_HIRE_WINDOW_SEC);
  if (limited) {
    return bad(request, "Rate limit: hire ops", 429, { retry_after_sec: limited.retry_after_sec });
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return bad(request, "Invalid JSON body");
  }

  let buyer = parseRepo(body.buyer_repo || body.from_repo);
  if (!buyer && authUser.default_repo) buyer = parseRepo(authUser.default_repo);

  const task = String(body.task || "").trim().slice(0, 500);
  const budget = parseAmount(body.budget_usd ?? body.budget ?? body.amount);
  const capability = body.capability ? String(body.capability).slice(0, 200) : null;
  const label = body.label ? String(body.label).slice(0, 120) : null;
  const minQuotes = Math.max(1, Math.min(20, Math.floor(Number(body.min_quotes) || 1)));
  const ttlSec = parseHireTtl(body || {});

  if (!buyer) return bad(request, "buyer_repo required (or set default agent)");
  if (!task) return bad(request, "task required");
  if (budget == null || budget < HIRE_MIN || budget > HIRE_MAX) {
    return bad(request, "budget_usd invalid");
  }
  if (ttlSec == null) return bad(request, "ttl_seconds out of range");

  const id = "hr_" + randomId(12);
  const modifier = "+" + ttlSec + " seconds";

  try {
    await env.DB.prepare(
      `INSERT INTO hire_rfqs (
         id, buyer_repo, capability, task, budget_usd, min_quotes, status,
         ttl_seconds, expires_at, label, created_by, created_at, updated_at
       ) VALUES (
         ?1, ?2, ?3, ?4, ?5, ?6, 'open',
         ?7, datetime('now', ?8), ?9, ?10, datetime('now'), datetime('now')
       )`
    )
      .bind(id, buyer, capability, task, budget, minQuotes, ttlSec, modifier, label, authUser.id)
      .run();
  } catch (e) {
    return bad(
      request,
      "hire_rfqs table missing — run d1-hire-migration.sql: " + (e.message || e),
      500
    );
  }

  await logHireEvent(env, {
    rfq_id: id,
    event: "rfq_opened",
    actor_repo: buyer,
    amount: budget,
    note: task,
  });

  if (authUser.id) {
    scheduleWebhook(ctx, env, authUser.id, "hire.rfq_opened", {
      id,
      buyer_repo: buyer,
      task,
      budget_usd: budget,
      capability,
      status: "open",
    });
  }

  return json(request, {
    ok: true,
    rfq: {
      id,
      buyer_repo: buyer,
      capability,
      task,
      budget_usd: budget,
      min_quotes: minQuotes,
      status: "open",
      ttl_seconds: ttlSec,
      label,
    },
    latency_ms: Date.now() - t0,
    hint: "Providers POST /api/hire/quote { rfq_id, amount_usd }. Buyer accepts with /api/hire/accept.",
  });
}

export async function handleHireQuote(request, env, ctx) {
  const t0 = Date.now();
  const authUser = await getAuthUser(request, env);
  if (!authUser) return bad(request, "Sign in or API key required", 401);

  const rlId =
    authUser.auth_via === "api_key"
      ? "hire:key:" + (authUser.key_id || authUser.id)
      : "hire:user:" + authUser.id;
  const limited = await checkRateLimit(env, rlId, RL_HIRE_MAX, RL_HIRE_WINDOW_SEC);
  if (limited) {
    return bad(request, "Rate limit: hire ops", 429, { retry_after_sec: limited.retry_after_sec });
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return bad(request, "Invalid JSON body");
  }

  const rfqId = String(body.rfq_id || body.id || "").trim();
  let provider = parseRepo(body.provider_repo || body.from_repo);
  if (!provider && authUser.default_repo) provider = parseRepo(authUser.default_repo);

  const amount = parseAmount(body.amount_usd ?? body.amount);
  const eta = body.eta_seconds != null ? Math.floor(Number(body.eta_seconds)) : null;
  const note = body.note ? String(body.note).slice(0, 500) : null;

  if (!rfqId) return bad(request, "rfq_id required");
  if (!provider) return bad(request, "provider_repo required (or set default agent)");
  if (amount == null || amount < HIRE_MIN || amount > HIRE_MAX) {
    return bad(request, "amount_usd invalid");
  }

  const rfq = await loadHireRfq(env, rfqId);
  if (!rfq) {
    try {
      await env.DB.prepare(`SELECT 1 FROM hire_rfqs LIMIT 1`).first();
    } catch {
      return bad(request, "hire_rfqs table missing — run d1-hire-migration.sql", 500);
    }
    return bad(request, "RFQ not found", 404);
  }
  if (rfq.status !== "open") {
    return bad(request, "RFQ not open (status=" + rfq.status + ")", 400, { code: "rfq_closed" });
  }
  if (rfq.expires_at) {
    const expMs = Date.parse(String(rfq.expires_at).replace(" ", "T") + "Z");
    if (Number.isFinite(expMs) && expMs < Date.now()) {
      return bad(request, "RFQ expired", 400, { code: "rfq_expired" });
    }
  }
  if (provider === rfq.buyer_repo) {
    return bad(request, "Buyer cannot quote their own RFQ", 400, { code: "self_quote" });
  }
  if (amount > Number(rfq.budget_usd)) {
    return bad(request, "Quote exceeds RFQ budget ($" + rfq.budget_usd + ")", 400, {
      code: "over_budget",
    });
  }

  try {
    const existing = await env.DB.prepare(
      `SELECT id FROM hire_quotes
       WHERE rfq_id = ?1 AND provider_repo = ?2 AND status = 'open' LIMIT 1`
    )
      .bind(rfqId, provider)
      .first();
    if (existing) {
      return bad(request, "Provider already has an open quote on this RFQ", 409, {
        code: "duplicate_quote",
        quote_id: existing.id,
      });
    }
  } catch (_) {}

  // Soft: attach provider passport on quote response (agents can filter before accept)
  let provider_passport = null;
  try {
    provider_passport = await getPassportClaims(env, provider);
  } catch (_) {}

  const qid = "hq_" + randomId(12);
  try {
    await env.DB.prepare(
      `INSERT INTO hire_quotes (
         id, rfq_id, provider_repo, amount_usd, eta_seconds, note, status,
         created_by, created_at, updated_at
       ) VALUES (
         ?1, ?2, ?3, ?4, ?5, ?6, 'open',
         ?7, datetime('now'), datetime('now')
       )`
    )
      .bind(qid, rfqId, provider, amount, eta, note, authUser.id)
      .run();
  } catch (e) {
    return bad(request, "Quote insert failed: " + (e.message || e), 500);
  }

  await logHireEvent(env, {
    rfq_id: rfqId,
    quote_id: qid,
    event: "quote_posted",
    actor_repo: provider,
    amount,
    note,
  });

  if (rfq.created_by) {
    scheduleWebhook(ctx, env, rfq.created_by, "hire.quote_posted", {
      rfq_id: rfqId,
      quote_id: qid,
      provider_repo: provider,
      amount_usd: amount,
      eta_seconds: eta,
    });
  }

  return json(request, {
    ok: true,
    quote: {
      id: qid,
      rfq_id: rfqId,
      provider_repo: provider,
      amount_usd: amount,
      eta_seconds: eta,
      note,
      status: "open",
    },
    provider_passport,
    latency_ms: Date.now() - t0,
  });
}

export async function handleHireAccept(request, env, ctx) {
  const t0 = Date.now();
  const authUser = await getAuthUser(request, env);
  if (!authUser) return bad(request, "Sign in or API key required", 401);

  let body;
  try {
    body = await request.json();
  } catch {
    return bad(request, "Invalid JSON body");
  }

  const quoteId = String(body.quote_id || body.id || "").trim();
  if (!quoteId) return bad(request, "quote_id required");

  const quote = await loadHireQuote(env, quoteId);
  if (!quote) return bad(request, "Quote not found", 404);
  if (quote.status !== "open") {
    return bad(request, "Quote not open (status=" + quote.status + ")", 400);
  }

  const rfq = await loadHireRfq(env, quote.rfq_id);
  if (!rfq) return bad(request, "RFQ not found", 404);
  if (rfq.status !== "open") {
    return bad(request, "RFQ not open (status=" + rfq.status + ")", 400);
  }

  const allowed =
    authUser.id === rfq.created_by ||
    (authUser.default_repo && authUser.default_repo === rfq.buyer_repo);
  if (!allowed) return bad(request, "Not authorized to accept on this RFQ", 403);

  const amount = Number(quote.amount_usd);
  const buyer = rfq.buyer_repo;
  const provider = quote.provider_repo;

  /* ── Passport gate (soft by default; strict when requested) ── */
  const passportEval = await evaluateHirePassport(env, provider, {
    require_passport: body.require_passport,
    passport_strict: body.passport_strict,
    strict: body.strict,
    max_dispute_rate: body.max_dispute_rate,
    require_history: body.require_history,
  });

  if (passportEval.blocked) {
    return bad(
      request,
      "Hire blocked by passport policy: " + (passportEval.block_reason || "provider_risk"),
      403,
      {
        code: passportEval.block_reason || "passport_gate",
        provider_repo: provider,
        provider_passport: passportEval.claims,
        passport_warnings: passportEval.warnings,
        max_dispute_rate: passportEval.max_dispute_rate,
        hint: "Omit require_passport / passport_strict for soft mode (accept + warnings only)",
      }
    );
  }

  authUser._policyCtx = { to_repo: provider, task: "hire:" + (rfq.task || "").slice(0, 80) };
  const blocked = await safetyGate(request, env, authUser, buyer, amount);
  if (blocked) return blocked;

  const debitRes = await debitWithCredit(env, buyer, amount);
  if (!debitRes.ok) {
    return bad(request, debitRes.error || "Insufficient funds", debitRes.code === "wallet_locked" ? 403 : 402, {
      code: debitRes.code || "insufficient",
      available_credit: debitRes.available_credit,
    });
  }

  const jobId = "hj_" + randomId(12);

  try {
    await ensureAccount(env, SYSTEM_HIRE);
    await env.DB.batch([
      env.DB.prepare(
        `UPDATE hire_rfqs
         SET status = 'matched', accepted_quote_id = ?2, job_id = ?3,
             updated_at = datetime('now'), closed_at = datetime('now')
         WHERE id = ?1 AND status = 'open'`
      ).bind(rfq.id, quoteId, jobId),
      env.DB.prepare(
        `UPDATE hire_quotes SET status = 'accepted', updated_at = datetime('now') WHERE id = ?1`
      ).bind(quoteId),
      env.DB.prepare(
        `UPDATE hire_quotes SET status = 'rejected', updated_at = datetime('now')
         WHERE rfq_id = ?1 AND id != ?2 AND status = 'open'`
      ).bind(rfq.id, quoteId),
      env.DB.prepare(
        `INSERT INTO hire_jobs (
           id, rfq_id, quote_id, buyer_repo, provider_repo, amount_usd, task,
           status, created_by, created_at, updated_at
         ) VALUES (
           ?1, ?2, ?3, ?4, ?5, ?6, ?7,
           'held', ?8, datetime('now'), datetime('now')
         )`
      ).bind(jobId, rfq.id, quoteId, buyer, provider, amount, rfq.task, authUser.id),
      env.DB.prepare(
        `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
         VALUES (?1, ?2, ?3, ?4, 'success', ?5)`
      ).bind(buyer, SYSTEM_HIRE, amount, "hire-hold:" + jobId, Date.now() - t0),
    ]);
  } catch (e) {
    await env.DB.prepare(
      `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
    )
      .bind(amount, buyer)
      .run()
      .catch(() => {});
    if (debitRes.credit_drawn > 0) {
      await env.DB.prepare(
        `UPDATE agent_limits
         SET outstanding_credit = MAX(0, COALESCE(outstanding_credit, 0) - ?2),
             updated_at = datetime('now')
         WHERE repo_id = ?1`
      )
        .bind(buyer, debitRes.credit_drawn)
        .run()
        .catch(() => {});
    }
    return bad(request, "Accept failed: " + (e.message || e), 500);
  }

  await safetyRecordSpend(env, authUser, buyer, amount);
  await logHireEvent(env, {
    rfq_id: rfq.id,
    quote_id: quoteId,
    job_id: jobId,
    event: "accepted",
    actor_repo: buyer,
    amount,
  });

  if (rfq.created_by) {
    scheduleWebhook(ctx, env, rfq.created_by, "hire.accepted", {
      rfq_id: rfq.id,
      quote_id: quoteId,
      job_id: jobId,
      buyer_repo: buyer,
      provider_repo: provider,
      amount_usd: amount,
      status: "held",
      passport_warnings: passportEval.warnings,
    });
  }

  return json(request, {
    ok: true,
    job: {
      id: jobId,
      rfq_id: rfq.id,
      quote_id: quoteId,
      buyer_repo: buyer,
      provider_repo: provider,
      amount_usd: amount,
      task: rfq.task,
      status: "held",
    },
    provider_passport: passportEval.claims,
    passport_warnings: passportEval.warnings,
    passport_gate: passportEval.warnings.length ? "soft_warn" : "clear",
    latency_ms: Date.now() - t0,
    hint: "Provider delivers work. Buyer POST /api/hire/complete { job_id } to pay out.",
  });
}

export async function handleHireComplete(request, env, ctx) {
  const t0 = Date.now();
  const authUser = await getAuthUser(request, env);
  if (!authUser) return bad(request, "Sign in or API key required", 401);

  let body;
  try {
    body = await request.json();
  } catch {
    return bad(request, "Invalid JSON body");
  }

  const jobId = String(body.job_id || body.id || "").trim();
  if (!jobId) return bad(request, "job_id required");

  const job = await loadHireJob(env, jobId);
  if (!job) return bad(request, "Job not found", 404);
  if (job.status !== "held") {
    return bad(request, "Job not held (status=" + job.status + ")", 400);
  }

  const isBuyer =
    authUser.id === job.created_by ||
    (authUser.default_repo && authUser.default_repo === job.buyer_repo);
  if (!isBuyer) return bad(request, "Only the buyer can complete / release this job", 403);

  const amount = Number(job.amount_usd);

  const claim = await env.DB.prepare(
    `UPDATE hire_jobs
     SET status = 'completed', completed_at = datetime('now'), updated_at = datetime('now')
     WHERE id = ?1 AND status = 'held'
     RETURNING *`
  )
    .bind(jobId)
    .first();
  if (!claim) return bad(request, "Complete race", 409);

  await ensureAccount(env, job.provider_repo);
  await ensureAccount(env, SYSTEM_HIRE);

  await env.DB.batch([
    env.DB.prepare(
      `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
    ).bind(amount, job.provider_repo),
    env.DB.prepare(
      `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
       VALUES (?1, ?2, ?3, ?4, 'success', ?5)`
    ).bind(
      SYSTEM_HIRE,
      job.provider_repo,
      amount,
      "hire-complete:" + jobId + ":" + (job.task || "").slice(0, 40),
      Date.now() - t0
    ),
  ]);

  await logHireEvent(env, {
    rfq_id: job.rfq_id,
    quote_id: job.quote_id,
    job_id: jobId,
    event: "completed",
    actor_repo: job.buyer_repo,
    amount,
  });

  await adjustRep(env, job.provider_repo, CREDIT_REP_SUCCESS_BONUS, "hire_complete", jobId);
  await adjustRep(env, job.buyer_repo, CREDIT_REP_SUCCESS_BONUS, "hire_buyer", jobId);

  if (job.created_by) {
    scheduleWebhook(ctx, env, job.created_by, "hire.completed", {
      job_id: jobId,
      provider_repo: job.provider_repo,
      amount_usd: amount,
      status: "completed",
    });
  }

  return json(request, {
    ok: true,
    job_id: jobId,
    status: "completed",
    paid_to: job.provider_repo,
    amount_usd: amount,
    latency_ms: Date.now() - t0,
  });
}

export async function handleHireCancel(request, env, ctx) {
  const t0 = Date.now();
  const authUser = await getAuthUser(request, env);
  if (!authUser) return bad(request, "Sign in or API key required", 401);

  let body;
  try {
    body = await request.json();
  } catch {
    return bad(request, "Invalid JSON body");
  }

  const jobId = body.job_id ? String(body.job_id).trim() : "";
  const rfqId = body.rfq_id ? String(body.rfq_id).trim() : "";

  if (jobId) {
    const job = await loadHireJob(env, jobId);
    if (!job) return bad(request, "Job not found", 404);
    if (job.status !== "held") {
      return bad(request, "Job not cancellable (status=" + job.status + ")", 400);
    }
    const allowed =
      authUser.id === job.created_by ||
      (authUser.default_repo && authUser.default_repo === job.buyer_repo);
    if (!allowed) return bad(request, "Not authorized", 403);

    const claim = await env.DB.prepare(
      `UPDATE hire_jobs
       SET status = 'cancelled', cancelled_at = datetime('now'), updated_at = datetime('now')
       WHERE id = ?1 AND status = 'held' RETURNING *`
    )
      .bind(jobId)
      .first();
    if (!claim) return bad(request, "Cancel race", 409);

    const amount = Number(job.amount_usd);
    await ensureAccount(env, job.buyer_repo);
    await env.DB.batch([
      env.DB.prepare(
        `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
      ).bind(amount, job.buyer_repo),
      env.DB.prepare(
        `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
         VALUES (?1, ?2, ?3, ?4, 'success', ?5)`
      ).bind(SYSTEM_HIRE, job.buyer_repo, amount, "hire-cancel-refund:" + jobId, Date.now() - t0),
    ]);

    await logHireEvent(env, {
      rfq_id: job.rfq_id,
      job_id: jobId,
      event: "job_cancelled",
      actor_repo: job.buyer_repo,
      amount,
    });

    return json(request, {
      ok: true,
      job_id: jobId,
      status: "cancelled",
      refunded: amount,
      latency_ms: Date.now() - t0,
    });
  }

  if (!rfqId) return bad(request, "rfq_id or job_id required");
  const rfq = await loadHireRfq(env, rfqId);
  if (!rfq) return bad(request, "RFQ not found", 404);
  if (rfq.status !== "open") {
    return bad(request, "RFQ not open (status=" + rfq.status + ")", 400);
  }
  const allowed =
    authUser.id === rfq.created_by ||
    (authUser.default_repo && authUser.default_repo === rfq.buyer_repo);
  if (!allowed) return bad(request, "Not authorized", 403);

  await env.DB.prepare(
    `UPDATE hire_rfqs
     SET status = 'cancelled', closed_at = datetime('now'), updated_at = datetime('now')
     WHERE id = ?1 AND status = 'open'`
  )
    .bind(rfqId)
    .run();
  await env.DB.prepare(
    `UPDATE hire_quotes SET status = 'rejected', updated_at = datetime('now')
     WHERE rfq_id = ?1 AND status = 'open'`
  )
    .bind(rfqId)
    .run();

  await logHireEvent(env, {
    rfq_id: rfqId,
    event: "rfq_cancelled",
    actor_repo: rfq.buyer_repo,
  });

  return json(request, {
    ok: true,
    rfq_id: rfqId,
    status: "cancelled",
    latency_ms: Date.now() - t0,
  });
}

export async function handleHireGet(request, env, id) {
  id = String(id || "").trim();
  if (!id) return bad(request, "id required");

  const rfq = await loadHireRfq(env, id);
  if (rfq) {
    let quotes = [];
    let events = [];
    try {
      const q = await env.DB.prepare(
        `SELECT id, provider_repo, amount_usd, eta_seconds, note, status, created_at
         FROM hire_quotes WHERE rfq_id = ?1 ORDER BY created_at ASC`
      )
        .bind(id)
        .all();
      quotes = q.results || [];
    } catch (_) {}
    try {
      const q = await env.DB.prepare(
        `SELECT event, actor_repo, amount, note, created_at
         FROM hire_events WHERE rfq_id = ?1 ORDER BY created_at DESC LIMIT 40`
      )
        .bind(id)
        .all();
      events = q.results || [];
    } catch (_) {}
    let job = null;
    if (rfq.job_id) job = await loadHireJob(env, rfq.job_id);
    return json(request, { ok: true, type: "rfq", rfq, quotes, job, events });
  }

  const job = await loadHireJob(env, id);
  if (job) {
    return json(request, { ok: true, type: "job", job });
  }

  try {
    await env.DB.prepare(`SELECT 1 FROM hire_rfqs LIMIT 1`).first();
  } catch {
    return bad(request, "hire tables missing — run d1-hire-migration.sql", 500);
  }
  return bad(request, "Not found", 404);
}

export async function handleHireList(request, url, env) {
  const limit = Math.min(Math.max(Number(url.searchParams.get("limit") || 20), 1), 100);
  const repo = (url.searchParams.get("repo") || "").trim();
  const status = (url.searchParams.get("status") || "").trim();
  const kind = (url.searchParams.get("kind") || "rfq").toLowerCase();

  if (kind === "job") {
    let sql = `SELECT id, rfq_id, quote_id, buyer_repo, provider_repo, amount_usd, task, status, created_at
               FROM hire_jobs WHERE 1=1`;
    const binds = [];
    if (repo) {
      if (!parseRepo(repo)) return bad(request, "repo must be owner/repo");
      sql += ` AND (buyer_repo = ? OR provider_repo = ?)`;
      binds.push(repo, repo);
    }
    if (status && ["held", "completed", "cancelled", "expired"].includes(status)) {
      sql += ` AND status = ?`;
      binds.push(status);
    }
    sql += ` ORDER BY created_at DESC LIMIT ?`;
    binds.push(limit);
    try {
      const { results } = await env.DB.prepare(sql).bind(...binds).all();
      return json(request, { ok: true, kind: "job", count: results.length, jobs: results });
    } catch (e) {
      return bad(request, "hire_jobs missing — run d1-hire-migration.sql: " + (e.message || e), 500);
    }
  }

  let sql = `SELECT id, buyer_repo, capability, task, budget_usd, min_quotes, status,
                    expires_at, accepted_quote_id, job_id, label, created_at
             FROM hire_rfqs WHERE 1=1`;
  const binds = [];
  if (repo) {
    if (!parseRepo(repo)) return bad(request, "repo must be owner/repo");
    sql += ` AND buyer_repo = ?`;
    binds.push(repo);
  }
  if (status && ["open", "matched", "cancelled", "expired"].includes(status)) {
    sql += ` AND status = ?`;
    binds.push(status);
  }
  sql += ` ORDER BY created_at DESC LIMIT ?`;
  binds.push(limit);

  try {
    const { results } = await env.DB.prepare(sql).bind(...binds).all();
    return json(request, { ok: true, kind: "rfq", count: results.length, rfqs: results });
  } catch (e) {
    return bad(request, "hire_rfqs missing — run d1-hire-migration.sql: " + (e.message || e), 500);
  }
}

export async function expireHireRfqs(env, ctx) {
  const t0 = Date.now();
  let expired = 0;
  let refundedJobs = 0;
  try {
    const q = await env.DB.prepare(
      `SELECT id, created_by FROM hire_rfqs
       WHERE status = 'open'
         AND expires_at IS NOT NULL
         AND expires_at < datetime('now')
       ORDER BY expires_at ASC LIMIT ?1`
    )
      .bind(EXPIRE_HIRE_BATCH)
      .all();
    for (const row of q.results || []) {
      try {
        await env.DB.prepare(
          `UPDATE hire_rfqs
           SET status = 'expired', closed_at = datetime('now'), updated_at = datetime('now')
           WHERE id = ?1 AND status = 'open'`
        )
          .bind(row.id)
          .run();
        await env.DB.prepare(
          `UPDATE hire_quotes SET status = 'expired', updated_at = datetime('now')
           WHERE rfq_id = ?1 AND status = 'open'`
        )
          .bind(row.id)
          .run();
        await logHireEvent(env, { rfq_id: row.id, event: "rfq_expired" });
        expired += 1;
        if (row.created_by) {
          scheduleWebhook(ctx, env, row.created_by, "hire.rfq_expired", {
            id: row.id,
            status: "expired",
          });
        }
      } catch (e) {
        console.log("hire_rfq_expire", row.id, e && e.message);
      }
    }
  } catch (e) {
    return { expired: 0, error: e.message, latency_ms: Date.now() - t0 };
  }
  return { expired, refunded_jobs: refundedJobs, latency_ms: Date.now() - t0 };
}
