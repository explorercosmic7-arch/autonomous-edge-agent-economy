/**
 * Shared Work — verifiable work claims, lock/attest/settle/refund + expireWorkClaims cron.
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
  SYSTEM_WORK,
  WORK_MIN,
  WORK_MAX,
  WORK_DEFAULT_TTL_SEC,
  WORK_MIN_TTL_SEC,
  WORK_MAX_TTL_SEC,
  RL_WORK_MAX,
  RL_WORK_WINDOW_SEC,
  EXPIRE_WORK_BATCH,
  WORK_BLOCK_SELF_ATTEST,
  WORK_REQUIRE_DISTINCT_ATTESTORS,
  CREDIT_REP_SUCCESS_BONUS,
  CREDIT_REP_FAIL_PENALTY,
} from "./constants.js";

/* ─── Verifiable Work Settlement (VWS) ───
 * 1) Provider POST /api/work/claim  { task, amount, expected_hash?, output_hash?, min_attestations? }
 * 2) Buyer     POST /api/work/lock   { id }  — locks amount from buyer → system/work
 * 3) Anyone    POST /api/work/attest { id, output_hash, note? }
 * 4) Settle    POST /api/work/settle { id }  — when attestations >= min and hash matches → pay provider
 * 5) Refund    POST /api/work/refund { id }  — buyer or timeout path
 * Receipt includes work proof + payment (HMAC).
 */

export function parseWorkTtl(body) {
  const sec = Number(body.ttl_seconds ?? body.ttl);
  if (Number.isFinite(sec)) {
    if (sec < WORK_MIN_TTL_SEC || sec > WORK_MAX_TTL_SEC) return null;
    return Math.floor(sec);
  }
  return WORK_DEFAULT_TTL_SEC;
}

export function isHexHash(s) {
  return typeof s === "string" && /^[a-fA-F0-9]{16,128}$/.test(s.trim());
}

export async function logWorkEvent(env, claimId, event, { actor_repo, note } = {}) {
  try {
    await env.DB.prepare(
      `INSERT INTO work_events (id, claim_id, event, actor_repo, note, created_at)
       VALUES (?1, ?2, ?3, ?4, ?5, datetime('now'))`
    )
      .bind(randomId(10), claimId, event, actor_repo || null, note ? String(note).slice(0, 500) : null)
      .run();
  } catch (e) {
    console.log("work_event_err", e && e.message);
  }
}

export async function loadWorkClaim(env, id) {
  try {
    return await env.DB.prepare(`SELECT * FROM work_claims WHERE id = ?1`).bind(id).first();
  } catch {
    return null;
  }
}

export async function handleWorkClaim(request, env, ctx) {
  const t0 = Date.now();
  const authUser = await getAuthUser(request, env);
  if (!authUser) return bad(request, "Sign in or API key required", 401);

  const rlId =
    authUser.auth_via === "api_key"
      ? "wk:key:" + (authUser.key_id || authUser.id)
      : "wk:user:" + authUser.id;
  const limited = await checkRateLimit(env, rlId, RL_WORK_MAX, RL_WORK_WINDOW_SEC);
  if (limited) {
    return bad(request, "Rate limit: work ops", 429, { retry_after_sec: limited.retry_after_sec });
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return bad(request, "Invalid JSON body");
  }

  let providerRepo = parseRepo(body.provider_repo || body.providerRepo);
  if (!providerRepo && authUser.default_repo) providerRepo = parseRepo(authUser.default_repo);
  const buyerRepo = parseRepo(body.buyer_repo || body.buyerRepo) || null;
  const task = String(body.task || "").trim().slice(0, 500);
  const amount = parseAmount(body.amount);
  const expectedHash = body.expected_hash ? String(body.expected_hash).trim().toLowerCase() : null;
  const outputHash = body.output_hash ? String(body.output_hash).trim().toLowerCase() : null;
  const outputUri = body.output_uri ? String(body.output_uri).slice(0, 1000) : null;
  const minAtt = Math.max(1, Math.min(10, Number(body.min_attestations) || 1));
  const ttlSec = parseWorkTtl(body);

  if (!providerRepo) return bad(request, "provider_repo required (or set default agent)");
  if (!task) return bad(request, "task required");
  if (amount == null || amount < WORK_MIN || amount > WORK_MAX) return bad(request, "amount invalid");
  if (ttlSec == null) return bad(request, "ttl_seconds out of range");
  if (expectedHash && !isHexHash(expectedHash)) return bad(request, "expected_hash must be hex (16-128 chars)");
  if (outputHash && !isHexHash(outputHash)) return bad(request, "output_hash must be hex (16-128 chars)");

  const id = "wk_" + randomId(12);
  const modifier = "+" + ttlSec + " seconds";

  try {
    await env.DB.prepare(
      `INSERT INTO work_claims (
         id, provider_repo, buyer_repo, task, expected_hash, output_hash, output_uri,
         amount, status, locked_amount, attestation_count, min_attestations,
         ttl_seconds, expires_at, created_by, created_at, updated_at
       ) VALUES (
         ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'open', 0, 0, ?9, ?10,
         datetime('now', ?11), ?12, datetime('now'), datetime('now')
       )`
    )
      .bind(
        id, providerRepo, buyerRepo, task, expectedHash, outputHash, outputUri,
        amount, minAtt, ttlSec, modifier, authUser.id || null
      )
      .run();
  } catch (e) {
    return bad(
      request,
      "work_claims table missing — run d1-work-migration.sql: " + (e.message || e),
      500
    );
  }

  await logWorkEvent(env, id, "claimed", { actor_repo: providerRepo, note: task });

  if (authUser.id) {
    scheduleWebhook(ctx, env, authUser.id, "work.claimed", {
      id, provider_repo: providerRepo, buyer_repo: buyerRepo, amount, task, status: "open",
    });
  }

  return json(request, {
    ok: true,
    claim: {
      id,
      provider_repo: providerRepo,
      buyer_repo: buyerRepo,
      task,
      amount,
      expected_hash: expectedHash,
      output_hash: outputHash,
      min_attestations: minAtt,
      status: "open",
      ttl_seconds: ttlSec,
    },
    latency_ms: Date.now() - t0,
    hint: "Buyer locks with POST /api/work/lock { id }. Attest then settle.",
  });
}

export async function handleWorkLock(request, env, ctx) {
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

  let row = await loadWorkClaim(env, id);
  if (!row) {
    try {
      await env.DB.prepare(`SELECT 1 FROM work_claims LIMIT 1`).first();
    } catch {
      return bad(request, "work_claims table missing — run d1-work-migration.sql", 500);
    }
    return bad(request, "Claim not found", 404);
  }
  if (row.status !== "open") {
    return bad(request, "Claim not lockable (status=" + row.status + ")", 400);
  }

  let buyerRepo = parseRepo(body.buyer_repo || body.from_repo);
  if (!buyerRepo && authUser.default_repo) buyerRepo = parseRepo(authUser.default_repo);
  if (!buyerRepo) return bad(request, "buyer_repo required (or set default agent)");
  if (row.buyer_repo && row.buyer_repo !== buyerRepo) {
    return bad(request, "buyer_repo does not match claim reservation", 403);
  }

  const amount = Number(row.amount);
  authUser._policyCtx = { to_repo: row.provider_repo, task: "work:" + (row.task || "") };
  const blocked = await safetyGate(request, env, authUser, buyerRepo, amount);
  if (blocked) return blocked;

  const debitRes = await debitWithCredit(env, buyerRepo, amount);
  if (!debitRes.ok) {
    return bad(request, debitRes.error || "Insufficient funds", debitRes.code === "wallet_locked" ? 403 : 402, {
      code: debitRes.code || "insufficient",
    });
  }

  await ensureAccount(env, SYSTEM_WORK);
  const claim = await env.DB.prepare(
    `UPDATE work_claims
     SET status = 'locked',
         buyer_repo = ?2,
         locked_amount = ?3,
         updated_at = datetime('now')
     WHERE id = ?1 AND status = 'open'
     RETURNING *`
  )
    .bind(id, buyerRepo, amount)
    .first();

  if (!claim) {
    // refund
    await env.DB.prepare(
      `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
    )
      .bind(amount, buyerRepo)
      .run()
      .catch(() => {});
    return bad(request, "Lock race", 409);
  }

  await env.DB.prepare(
    `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
     VALUES (?1, ?2, ?3, ?4, 'success', ?5)`
  )
    .bind(buyerRepo, SYSTEM_WORK, amount, "work-lock:" + id, Date.now() - t0)
    .run();

  await safetyRecordSpend(env, authUser, buyerRepo, amount);
  await logWorkEvent(env, id, "locked", { actor_repo: buyerRepo, note: "$" + amount });

  if (authUser.id) {
    scheduleWebhook(ctx, env, authUser.id, "work.locked", {
      id, buyer_repo: buyerRepo, provider_repo: row.provider_repo, amount, status: "locked",
    });
  }

  return json(request, {
    ok: true,
    claim: {
      id,
      status: "locked",
      buyer_repo: buyerRepo,
      provider_repo: row.provider_repo,
      amount,
      locked_amount: amount,
      credit_drawn: debitRes.credit_drawn || 0,
    },
    balance_buyer: debitRes.balance,
    latency_ms: Date.now() - t0,
  });
}

export async function handleWorkAttest(request, env, ctx) {
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
  const outputHash = String(body.output_hash || body.hash || "").trim().toLowerCase();
  const note = body.note ? String(body.note).slice(0, 500) : null;
  if (!id) return bad(request, "id required");
  if (!isHexHash(outputHash)) return bad(request, "output_hash must be hex (16-128 chars)");

  let attestor = parseRepo(body.attestor_repo || body.attestorRepo);
  if (!attestor && authUser.default_repo) attestor = parseRepo(authUser.default_repo);
  if (!attestor) return bad(request, "attestor_repo required (or set default agent)");

  const row = await loadWorkClaim(env, id);
  if (!row) return bad(request, "Claim not found", 404);
  if (!["open", "locked", "attested"].includes(row.status)) {
    return bad(request, "Claim not attestable (status=" + row.status + ")", 400);
  }

  // ── Attestation diversity: no self-attest (provider / buyer) ──
  if (WORK_BLOCK_SELF_ATTEST) {
    if (row.provider_repo && attestor === row.provider_repo) {
      await logWorkEvent(env, id, "attest_rejected", {
        actor_repo: attestor,
        note: "self_attest_provider",
      });
      return bad(request, "Provider cannot attest their own claim", 403, {
        code: "self_attest_forbidden",
      });
    }
    if (row.buyer_repo && attestor === row.buyer_repo) {
      await logWorkEvent(env, id, "attest_rejected", {
        actor_repo: attestor,
        note: "self_attest_buyer",
      });
      return bad(request, "Buyer cannot attest a claim they funded", 403, {
        code: "self_attest_forbidden",
      });
    }
  }

  // ── Distinct attestors only (one vote per repo) ──
  if (WORK_REQUIRE_DISTINCT_ATTESTORS) {
    try {
      const prior = await env.DB.prepare(
        `SELECT id FROM work_attestations
         WHERE claim_id = ?1 AND attestor_repo = ?2 LIMIT 1`
      )
        .bind(id, attestor)
        .first();
      if (prior) {
        return bad(request, "This attestor already attested this claim", 409, {
          code: "duplicate_attestor",
          attestor_repo: attestor,
        });
      }
    } catch (e) {
      // table missing handled on insert
    }
  }

  // If expected_hash set, attestation must match
  if (row.expected_hash && row.expected_hash.toLowerCase() !== outputHash) {
    await logWorkEvent(env, id, "attest_mismatch", { actor_repo: attestor, note: outputHash.slice(0, 16) });
    return bad(request, "output_hash does not match expected_hash", 403, { code: "hash_mismatch" });
  }

  // If claim already has output_hash from provider, require match
  if (row.output_hash && row.output_hash.toLowerCase() !== outputHash) {
    return bad(request, "output_hash conflicts with existing claim hash", 409, { code: "hash_conflict" });
  }

  const attId = "wa_" + randomId(10);
  try {
    await env.DB.prepare(
      `INSERT INTO work_attestations (id, claim_id, attestor_repo, output_hash, note, created_at)
       VALUES (?1, ?2, ?3, ?4, ?5, datetime('now'))`
    )
      .bind(attId, id, attestor, outputHash, note)
      .run();
  } catch (e) {
    const msg = (e && e.message) || String(e);
    if (/UNIQUE|unique|constraint/i.test(msg)) {
      return bad(request, "This attestor already attested this claim", 409, {
        code: "duplicate_attestor",
        attestor_repo: attestor,
      });
    }
    return bad(request, "work_attestations missing — run d1-work-migration.sql: " + msg, 500);
  }

  // Recount distinct attestors (source of truth for diversity)
  let distinctCount = 1;
  try {
    const dist = await env.DB.prepare(
      `SELECT COUNT(DISTINCT attestor_repo) AS c FROM work_attestations WHERE claim_id = ?1`
    )
      .bind(id)
      .first();
    distinctCount = Number(dist?.c || 1);
  } catch (_) {
    distinctCount = Number(row.attestation_count || 0) + 1;
  }

  const newStatus =
    row.status === "locked" || row.status === "attested"
      ? "attested"
      : row.status === "open"
        ? "open"
        : row.status;

  await env.DB.prepare(
    `UPDATE work_claims
     SET output_hash = COALESCE(output_hash, ?2),
         attestation_count = ?3,
         status = CASE WHEN status IN ('locked', 'attested') THEN 'attested' ELSE status END,
         updated_at = datetime('now')
     WHERE id = ?1`
  )
    .bind(id, outputHash, distinctCount)
    .run();

  await logWorkEvent(env, id, "attested", {
    actor_repo: attestor,
    note: outputHash.slice(0, 16) + " distinct=" + distinctCount,
  });

  if (row.created_by) {
    scheduleWebhook(ctx, env, row.created_by, "work.attested", {
      id,
      attestor_repo: attestor,
      output_hash: outputHash,
      attestation_count: distinctCount,
      distinct_attestors: distinctCount,
      min_attestations: Number(row.min_attestations || 1),
    });
  }

  const minAtt = Number(row.min_attestations || 1);
  return json(request, {
    ok: true,
    claim_id: id,
    attestation_id: attId,
    attestor_repo: attestor,
    attestation_count: distinctCount,
    distinct_attestors: distinctCount,
    min_attestations: minAtt,
    output_hash: outputHash,
    status: newStatus === "open" && row.status === "open" ? "open" : "attested",
    diversity: {
      self_attest_blocked: WORK_BLOCK_SELF_ATTEST,
      distinct_required: WORK_REQUIRE_DISTINCT_ATTESTORS,
    },
    ready_to_settle:
      (row.status === "locked" || row.status === "attested") && distinctCount >= minAtt,
    latency_ms: Date.now() - t0,
  });
}

export async function handleWorkSettle(request, env, ctx) {
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

  const row = await loadWorkClaim(env, id);
  if (!row) return bad(request, "Claim not found", 404);
  if (!["locked", "attested"].includes(row.status)) {
    return bad(request, "Claim not settleable (status=" + row.status + ")", 400);
  }
  if (Number(row.locked_amount || 0) <= 0) {
    return bad(request, "No funds locked on claim", 400);
  }
  // Diversity: require distinct attestors (re-count; ignore inflated row counters)
  let distinctAtt = Number(row.attestation_count || 0);
  try {
    const dist = await env.DB.prepare(
      `SELECT COUNT(DISTINCT attestor_repo) AS c FROM work_attestations WHERE claim_id = ?1`
    )
      .bind(id)
      .first();
    if (dist && dist.c != null) distinctAtt = Number(dist.c);
  } catch (_) {}
  const minAtt = Number(row.min_attestations || 1);
  if (distinctAtt < minAtt) {
    return bad(
      request,
      "Need " + minAtt + " distinct attestation(s), have " + distinctAtt,
      400,
      {
        code: "insufficient_attestations",
        distinct_attestors: distinctAtt,
        min_attestations: minAtt,
      }
    );
  }
  if (!row.output_hash) return bad(request, "No output_hash on claim — attest first", 400);

  const claim = await env.DB.prepare(
    `UPDATE work_claims
     SET status = 'settled', settled_at = datetime('now'), updated_at = datetime('now')
     WHERE id = ?1 AND status IN ('locked', 'attested')
     RETURNING *`
  )
    .bind(id)
    .first();
  if (!claim) return bad(request, "Settle race", 409);

  const amount = Number(row.locked_amount || row.amount);
  await ensureAccount(env, row.provider_repo);
  await ensureAccount(env, SYSTEM_WORK);
  await env.DB.batch([
    env.DB.prepare(
      `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
    ).bind(amount, row.provider_repo),
    env.DB.prepare(
      `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
       VALUES (?1, ?2, ?3, ?4, 'success', ?5)`
    ).bind(
      SYSTEM_WORK,
      row.provider_repo,
      amount,
      "work-settle:" + id + ":" + (row.output_hash || "").slice(0, 12),
      Date.now() - t0
    ),
  ]);

  await logWorkEvent(env, id, "settled", { actor_repo: authUser.default_repo || row.buyer_repo });
  await adjustRep(env, row.provider_repo, CREDIT_REP_SUCCESS_BONUS, "work_settle", id);
  if (row.buyer_repo) {
    await adjustRep(env, row.buyer_repo, CREDIT_REP_SUCCESS_BONUS, "work_settle_buyer", id);
  }

  // HMAC receipt with work proof
  let receiptId = null;
  let receiptSig = null;
  try {
    receiptId = "rcpt_wk_" + randomId(10);
    const rPayload = {
      id: receiptId,
      type: "work_settlement",
      claim_id: id,
      provider_repo: row.provider_repo,
      buyer_repo: row.buyer_repo,
      amount,
      task: row.task,
      output_hash: row.output_hash,
      attestation_count: row.attestation_count,
      settled_at: new Date().toISOString(),
    };
    const rJson = JSON.stringify(rPayload);
    receiptSig = await hmacSha256Hex(
      env.RECEIPT_SECRET || env.SESSION_SECRET || env.GOOGLE_CLIENT_SECRET || "a2a-dev-receipt-secret",
      rJson
    );
    await env.DB.prepare(
      `INSERT INTO payment_receipts (id, payload_json, signature, from_repo, to_repo, amount, created_at)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, datetime('now'))`
    )
      .bind(receiptId, rJson, receiptSig, row.buyer_repo || SYSTEM_WORK, row.provider_repo, amount)
      .run();
  } catch (e) {
    console.log("work_receipt_skip", e && e.message);
  }

  if (row.created_by) {
    scheduleWebhook(ctx, env, row.created_by, "work.settled", {
      id, amount, provider_repo: row.provider_repo, output_hash: row.output_hash, receipt_id: receiptId,
    });
  }

  return json(request, {
    ok: true,
    claim: {
      id,
      status: "settled",
      amount,
      provider_repo: row.provider_repo,
      buyer_repo: row.buyer_repo,
      output_hash: row.output_hash,
    },
    receipt_id: receiptId,
    receipt_signature: receiptSig,
    latency_ms: Date.now() - t0,
  });
}

export async function handleWorkRefund(request, env, ctx) {
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

  const row = await loadWorkClaim(env, id);
  if (!row) return bad(request, "Claim not found", 404);
  if (!["locked", "attested", "open"].includes(row.status)) {
    return bad(request, "Claim not refundable (status=" + row.status + ")", 400);
  }

  const allowed =
    authUser.id === row.created_by ||
    (authUser.default_repo &&
      (authUser.default_repo === row.buyer_repo || authUser.default_repo === row.provider_repo));
  if (!allowed) return bad(request, "Not authorized to refund", 403);

  // open with no lock — just cancel
  if (row.status === "open" || Number(row.locked_amount || 0) <= 0) {
    await env.DB.prepare(
      `UPDATE work_claims SET status = 'refunded', refunded_at = datetime('now'), updated_at = datetime('now')
       WHERE id = ?1 AND status = 'open'`
    )
      .bind(id)
      .run();
    await logWorkEvent(env, id, "cancelled", { actor_repo: authUser.default_repo });
    return json(request, { ok: true, id, status: "refunded", refunded: 0, latency_ms: Date.now() - t0 });
  }

  const claim = await env.DB.prepare(
    `UPDATE work_claims
     SET status = 'refunded', refunded_at = datetime('now'), updated_at = datetime('now')
     WHERE id = ?1 AND status IN ('locked', 'attested')
     RETURNING *`
  )
    .bind(id)
    .first();
  if (!claim) return bad(request, "Refund race", 409);

  const refund = Number(row.locked_amount);
  await ensureAccount(env, row.buyer_repo);
  await env.DB.batch([
    env.DB.prepare(
      `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
    ).bind(refund, row.buyer_repo),
    env.DB.prepare(
      `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
       VALUES (?1, ?2, ?3, ?4, 'success', ?5)`
    ).bind(SYSTEM_WORK, row.buyer_repo, refund, "work-refund:" + id, Date.now() - t0),
  ]);

  await logWorkEvent(env, id, "refunded", { actor_repo: authUser.default_repo || row.buyer_repo });
  if (row.created_by) {
    scheduleWebhook(ctx, env, row.created_by, "work.refunded", {
      id, refunded: refund, buyer_repo: row.buyer_repo,
    });
  }

  return json(request, {
    ok: true,
    id,
    status: "refunded",
    refunded: refund,
    latency_ms: Date.now() - t0,
  });
}

export async function handleWorkGet(request, env, id) {
  id = String(id || "").trim();
  if (!id) return bad(request, "id required");
  const row = await loadWorkClaim(env, id);
  if (!row) {
    try {
      await env.DB.prepare(`SELECT 1 FROM work_claims LIMIT 1`).first();
    } catch {
      return bad(request, "work_claims table missing — run d1-work-migration.sql", 500);
    }
    return bad(request, "Claim not found", 404);
  }
  let attestations = [];
  let events = [];
  try {
    const a = await env.DB.prepare(
      `SELECT id, attestor_repo, output_hash, note, created_at
       FROM work_attestations WHERE claim_id = ?1 ORDER BY created_at ASC`
    )
      .bind(id)
      .all();
    attestations = a.results || [];
  } catch (_) {}
  try {
    const e = await env.DB.prepare(
      `SELECT event, actor_repo, note, created_at
       FROM work_events WHERE claim_id = ?1 ORDER BY created_at DESC LIMIT 40`
    )
      .bind(id)
      .all();
    events = e.results || [];
  } catch (_) {}
  return json(request, { ok: true, claim: row, attestations, events });
}

export async function handleWorkList(request, url, env) {
  const limit = Math.min(Math.max(Number(url.searchParams.get("limit") || 20), 1), 100);
  const repo = (url.searchParams.get("repo") || "").trim();
  const status = (url.searchParams.get("status") || "").trim();

  let sql = `SELECT id, provider_repo, buyer_repo, task, amount, status, output_hash,
                    locked_amount, attestation_count, min_attestations, expires_at, created_at
             FROM work_claims WHERE 1=1`;
  const binds = [];
  if (repo) {
    if (!parseRepo(repo)) return bad(request, "repo must be owner/repo");
    sql += ` AND (provider_repo = ? OR buyer_repo = ?)`;
    binds.push(repo, repo);
  }
  if (
    status &&
    ["open", "locked", "attested", "settled", "refunded", "expired", "disputed"].includes(status)
  ) {
    sql += ` AND status = ?`;
    binds.push(status);
  }
  sql += ` ORDER BY created_at DESC LIMIT ?`;
  binds.push(limit);

  try {
    const { results } = await env.DB.prepare(sql).bind(...binds).all();
    return json(request, { ok: true, count: results.length, claims: results });
  } catch (e) {
    return bad(
      request,
      "work_claims table missing — run d1-work-migration.sql: " + (e.message || e),
      500
    );
  }
}

export async function expireWorkClaims(env, ctx) {
  const t0 = Date.now();
  let expired = 0;
  let refundedTotal = 0;
  try {
    const q = await env.DB.prepare(
      `SELECT * FROM work_claims
       WHERE status IN ('open', 'locked', 'attested')
         AND expires_at IS NOT NULL
         AND expires_at < datetime('now')
       ORDER BY expires_at ASC LIMIT ?1`
    )
      .bind(EXPIRE_WORK_BATCH)
      .all();
    for (const row of q.results || []) {
      try {
        if (row.status === "open" || Number(row.locked_amount || 0) <= 0) {
          await env.DB.prepare(
            `UPDATE work_claims SET status = 'expired', updated_at = datetime('now')
             WHERE id = ?1 AND status = 'open'`
          )
            .bind(row.id)
            .run();
          expired += 1;
          continue;
        }
        const claim = await env.DB.prepare(
          `UPDATE work_claims SET status = 'expired', refunded_at = datetime('now'), updated_at = datetime('now')
           WHERE id = ?1 AND status IN ('locked', 'attested') RETURNING id`
        )
          .bind(row.id)
          .first();
        if (!claim) continue;
        const refund = Number(row.locked_amount);
        if (row.buyer_repo && refund > 0) {
          await ensureAccount(env, row.buyer_repo);
          await env.DB.batch([
            env.DB.prepare(
              `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
            ).bind(refund, row.buyer_repo),
            env.DB.prepare(
              `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
               VALUES (?1, ?2, ?3, ?4, 'success', 0)`
            ).bind(SYSTEM_WORK, row.buyer_repo, refund, "work-expire-refund:" + row.id),
          ]);
          refundedTotal += refund;
        }
        await logWorkEvent(env, row.id, "expired", { note: "ttl" });
        expired += 1;
        if (row.created_by) {
          scheduleWebhook(ctx, env, row.created_by, "work.expired", {
            id: row.id, refunded: refund, status: "expired",
          });
        }
      } catch (e) {
        console.log("work_expire", row.id, e && e.message);
      }
    }
  } catch (e) {
    return { expired: 0, error: e.message, latency_ms: Date.now() - t0 };
  }
  return { expired, refunded_total: refundedTotal, latency_ms: Date.now() - t0 };
}


