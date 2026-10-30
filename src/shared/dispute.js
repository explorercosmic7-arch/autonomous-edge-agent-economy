/**
 * Shared Dispute — bonded arbitration over work claims + expireDisputes cron.
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
import { loadWorkClaim, isHexHash } from "./work.js";
import { adjustRep, debitWithCredit } from "./credit.js";
import { scheduleWebhook } from "./webhooks.js";
import { safetyGate, safetyRecordSpend } from "./gate.js";
import {
  SYSTEM_DISPUTE,
  SYSTEM_SLASH_POOL,
  SYSTEM_WORK,
  DISPUTE_MIN,
  DISPUTE_MAX,
  DISPUTE_DEFAULT_TTL_SEC,
  DISPUTE_MIN_TTL_SEC,
  DISPUTE_MAX_TTL_SEC,
  DISPUTE_DEFAULT_COMPLAINANT_BOND_BPS,
  DISPUTE_DEFAULT_ARBITER_BOND_BPS,
  DISPUTE_MIN_ARBITERS,
  DISPUTE_MAX_ARBITERS,
  RL_DISPUTE_MAX,
  RL_DISPUTE_WINDOW_SEC,
  EXPIRE_DISPUTE_BATCH,
  CREDIT_REP_SUCCESS_BONUS,
  CREDIT_REP_FAIL_PENALTY,
} from "./constants.js";

/* ─── Dispute / Arbitration (Supreme Court) ───
 * Closes the work trust loop when attestation / parties disagree.
 *
 * POST /api/dispute/open    { claim_id, reason, evidence_uri?, evidence_hash?, complainant_bond?,
 *                             arbiter_bond_required?, min_arbiters?, ttl_seconds? }
 *   Buyer (or locked payer) opens court. Optional complainant bond locked to system/dispute.
 *   Claim must be locked (funds in system/work). Claim marked disputed.
 *
 * POST /api/dispute/accept  { id, arbiter_repo?, bond_usd? }
 *   Bonded arbiter joins the panel (stake required).
 *
 * POST /api/dispute/vote    { id, decision: release|slash|split, split_bps?, note? }
 *   Arbiter casts vote. When quorum met → auto-execute.
 *
 * POST /api/dispute/execute { id }  — force execute if quorum already reached
 * POST /api/dispute/cancel  { id }  — complainant cancels before ruling (bonds return)
 * GET  /api/dispute         ?repo=&status=&claim_id=
 * GET  /api/dispute/:id
 * Cron: expireDisputes — timeout → default release-to-provider with bond penalties
 *
 * Decisions:
 *   release — pay locked amount to provider (buyer loses dispute)
 *   slash   — refund buyer; provider may lose respondent bond to slash pool
 *   split   — split locked amount by split_bps (bps to provider)
 */

export function parseDisputeTtl(body) {
  const sec = Number(body.ttl_seconds ?? body.ttl);
  if (Number.isFinite(sec)) {
    if (sec < DISPUTE_MIN_TTL_SEC || sec > DISPUTE_MAX_TTL_SEC) return null;
    return Math.floor(sec);
  }
  return DISPUTE_DEFAULT_TTL_SEC;
}

export async function logDisputeEvent(env, disputeId, event, { actor_repo, amount, note, meta } = {}) {
  try {
    await env.DB.prepare(
      `INSERT INTO dispute_events (id, dispute_id, event, actor_repo, amount, note, meta_json, created_at)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, datetime('now'))`
    )
      .bind(
        randomId(10),
        disputeId,
        event,
        actor_repo || null,
        amount != null ? Number(amount) : null,
        note ? String(note).slice(0, 500) : null,
        meta ? JSON.stringify(meta) : null
      )
      .run();
  } catch (e) {
    console.log("dispute_event_err", e && e.message);
  }
}

export async function loadDispute(env, id) {
  try {
    return await env.DB.prepare(`SELECT * FROM work_disputes WHERE id = ?1`).bind(id).first();
  } catch {
    return null;
  }
}

export async function countOpenDisputeForClaim(env, claimId) {
  try {
    const row = await env.DB.prepare(
      `SELECT COUNT(*) AS c FROM work_disputes
       WHERE claim_id = ?1 AND status IN ('open', 'accepted')`
    )
      .bind(claimId)
      .first();
    return Number(row?.c || 0);
  } catch {
    return 0;
  }
}

/**
 * Execute a ruled dispute: move work lock + bonds according to decision.
 * Idempotent on status=executed.
 */
export async function executeDisputeRuling(env, dispute, t0, ctx) {
  if (!dispute || !["ruled", "open", "accepted"].includes(dispute.status)) {
    return { ok: false, error: "not executable" };
  }
  const id = dispute.id;
  const claim = await loadWorkClaim(env, dispute.claim_id);
  const amount = Number(dispute.amount_usd || 0);
  const decision = String(dispute.decision || "release").toLowerCase();
  let splitBps = Math.min(10000, Math.max(0, Number(dispute.split_bps != null ? dispute.split_bps : 5000)));

  let toProvider = 0;
  let toBuyer = 0;
  let toSlash = 0;

  if (decision === "release") {
    toProvider = amount;
    toBuyer = 0;
  } else if (decision === "slash") {
    toProvider = 0;
    toBuyer = amount;
  } else if (decision === "split") {
    toProvider = Math.round(((amount * splitBps) / 10000) * 1e6) / 1e6;
    toBuyer = Math.round((amount - toProvider) * 1e6) / 1e6;
  } else {
    return { ok: false, error: "unknown decision" };
  }

  // Mark executed first (race guard)
  const claimExec = await env.DB.prepare(
    `UPDATE work_disputes
     SET status = 'executed', executed_at = datetime('now'), updated_at = datetime('now'),
         paid_to_provider = ?2, refunded_to_buyer = ?3, slashed_to_pool = ?4
     WHERE id = ?1 AND status IN ('ruled', 'accepted', 'open')
     RETURNING *`
  )
    .bind(id, toProvider, toBuyer, toSlash)
    .first();
  if (!claimExec) return { ok: false, error: "execute race" };

  await ensureAccount(env, SYSTEM_WORK);
  await ensureAccount(env, SYSTEM_DISPUTE);
  await ensureAccount(env, dispute.provider_repo);
  await ensureAccount(env, dispute.buyer_repo);

  const stmts = [];
  // Work funds: system/work holds the lock
  if (toProvider > 0) {
    stmts.push(
      env.DB.prepare(
        `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
      ).bind(toProvider, dispute.provider_repo),
      env.DB.prepare(
        `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
         VALUES (?1, ?2, ?3, ?4, 'success', ?5)`
      ).bind(SYSTEM_WORK, dispute.provider_repo, toProvider, "dispute-release:" + id, typeof t0 === "number" ? Date.now() - t0 : 0)
    );
  }
  if (toBuyer > 0) {
    stmts.push(
      env.DB.prepare(
        `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
      ).bind(toBuyer, dispute.buyer_repo),
      env.DB.prepare(
        `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
         VALUES (?1, ?2, ?3, ?4, 'success', 0)`
      ).bind(SYSTEM_WORK, dispute.buyer_repo, toBuyer, "dispute-refund:" + id)
    );
  }

  // Bonds: return winners, slash losers (simplified: complainant loses bond on release, respondent loses on slash)
  const cBond = Number(dispute.complainant_bond_usd || 0);
  const rBond = Number(dispute.respondent_bond_usd || 0);
  let cRet = 0, rRet = 0, bondSlash = 0;

  if (decision === "release") {
    // Buyer lost — complainant bond → slash pool; respondent bond returns
    if (cBond > 0) {
      bondSlash += cBond;
      await ensureAccount(env, SYSTEM_SLASH_POOL);
      stmts.push(
        env.DB.prepare(
          `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
        ).bind(cBond, SYSTEM_SLASH_POOL),
        env.DB.prepare(
          `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
           VALUES (?1, ?2, ?3, ?4, 'success', 0)`
        ).bind(SYSTEM_DISPUTE, SYSTEM_SLASH_POOL, cBond, "dispute-bond-slash-complainant:" + id)
      );
    }
    if (rBond > 0) {
      rRet = rBond;
      stmts.push(
        env.DB.prepare(
          `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
        ).bind(rBond, dispute.provider_repo),
        env.DB.prepare(
          `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
           VALUES (?1, ?2, ?3, ?4, 'success', 0)`
        ).bind(SYSTEM_DISPUTE, dispute.provider_repo, rBond, "dispute-bond-return-respondent:" + id)
      );
    }
  } else if (decision === "slash") {
    // Provider lost — respondent bond → slash; complainant returns
    if (rBond > 0) {
      bondSlash += rBond;
      await ensureAccount(env, SYSTEM_SLASH_POOL);
      stmts.push(
        env.DB.prepare(
          `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
        ).bind(rBond, SYSTEM_SLASH_POOL),
        env.DB.prepare(
          `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
           VALUES (?1, ?2, ?3, ?4, 'success', 0)`
        ).bind(SYSTEM_DISPUTE, SYSTEM_SLASH_POOL, rBond, "dispute-bond-slash-respondent:" + id)
      );
    }
    if (cBond > 0) {
      cRet = cBond;
      stmts.push(
        env.DB.prepare(
          `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
        ).bind(cBond, dispute.buyer_repo),
        env.DB.prepare(
          `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
           VALUES (?1, ?2, ?3, ?4, 'success', 0)`
        ).bind(SYSTEM_DISPUTE, dispute.buyer_repo, cBond, "dispute-bond-return-complainant:" + id)
      );
    }
  } else {
    // split — return both bonds (good-faith disagreement)
    if (cBond > 0) {
      cRet = cBond;
      stmts.push(
        env.DB.prepare(
          `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
        ).bind(cBond, dispute.buyer_repo),
        env.DB.prepare(
          `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
           VALUES (?1, ?2, ?3, ?4, 'success', 0)`
        ).bind(SYSTEM_DISPUTE, dispute.buyer_repo, cBond, "dispute-bond-return-complainant:" + id)
      );
    }
    if (rBond > 0) {
      rRet = rBond;
      stmts.push(
        env.DB.prepare(
          `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
        ).bind(rBond, dispute.provider_repo),
        env.DB.prepare(
          `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
           VALUES (?1, ?2, ?3, ?4, 'success', 0)`
        ).bind(SYSTEM_DISPUTE, dispute.provider_repo, rBond, "dispute-bond-return-respondent:" + id)
      );
    }
  }

  // Return arbiter bonds
  try {
    const aq = await env.DB.prepare(
      `SELECT id, arbiter_repo, bond_usd FROM dispute_arbiters
       WHERE dispute_id = ?1 AND status IN ('bonded', 'voted')`
    )
      .bind(id)
      .all();
    for (const a of aq.results || []) {
      const b = Number(a.bond_usd || 0);
      if (b > 0) {
        await ensureAccount(env, a.arbiter_repo);
        stmts.push(
          env.DB.prepare(
            `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
          ).bind(b, a.arbiter_repo),
          env.DB.prepare(
            `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
             VALUES (?1, ?2, ?3, ?4, 'success', 0)`
          ).bind(SYSTEM_DISPUTE, a.arbiter_repo, b, "dispute-arbiter-bond-return:" + id)
        );
      }
      stmts.push(
        env.DB.prepare(
          `UPDATE dispute_arbiters SET status = 'refunded' WHERE id = ?1`
        ).bind(a.id)
      );
    }
  } catch (e) {
    console.log("dispute_arbiter_return", e && e.message);
  }

  if (stmts.length) await env.DB.batch(stmts);

  // Close claim
  if (claim && ["locked", "disputed", "attested"].includes(claim.status)) {
    try {
      await env.DB.prepare(
        `UPDATE work_claims
         SET status = ?2, locked_amount = 0, updated_at = datetime('now'),
             settled_at = datetime('now')
         WHERE id = ?1`
      )
        .bind(claim.id, decision === "release" ? "settled" : decision === "slash" ? "refunded" : "settled")
        .run();
    } catch (_) {}
  }

  await env.DB.prepare(
    `UPDATE work_disputes
     SET complainant_bond_returned = ?2, respondent_bond_returned = ?3,
         slashed_to_pool = ?4, updated_at = datetime('now')
     WHERE id = ?1`
  )
    .bind(id, cRet, rRet, bondSlash)
    .run();

  await logDisputeEvent(env, id, "executed", {
    actor_repo: dispute.ruled_by || null,
    amount: amount,
    note: decision + " provider=" + toProvider + " buyer=" + toBuyer,
    meta: { decision, toProvider, toBuyer, bondSlash },
  });

  // Reputation
  if (decision === "release") {
    await adjustRep(env, dispute.provider_repo, CREDIT_REP_SUCCESS_BONUS * 2, "dispute_won", id);
    await adjustRep(env, dispute.buyer_repo, -CREDIT_REP_FAIL_PENALTY, "dispute_lost", id);
  } else if (decision === "slash") {
    await adjustRep(env, dispute.buyer_repo, CREDIT_REP_SUCCESS_BONUS * 2, "dispute_won", id);
    await adjustRep(env, dispute.provider_repo, -CREDIT_REP_FAIL_PENALTY, "dispute_lost", id);
  }

  if (dispute.created_by) {
    scheduleWebhook(ctx, env, dispute.created_by, "dispute.executed", {
      id,
      claim_id: dispute.claim_id,
      decision,
      paid_to_provider: toProvider,
      refunded_to_buyer: toBuyer,
      slashed_bonds: bondSlash,
      status: "executed",
    });
  }

  return {
    ok: true,
    decision,
    paid_to_provider: toProvider,
    refunded_to_buyer: toBuyer,
    slashed_bonds: bondSlash,
    complainant_bond_returned: cRet,
    respondent_bond_returned: rRet,
  };
}

export async function tryQuorumAndExecute(env, disputeId, ctx) {
  const d = await loadDispute(env, disputeId);
  if (!d || !["open", "accepted"].includes(d.status)) return null;
  const minA = Number(d.min_arbiters || 1);
  const votes = Number(d.votes_release || 0) + Number(d.votes_slash || 0) + Number(d.votes_split || 0);
  if (votes < minA) return null;

  // Majority decision
  const tallies = [
    { k: "release", n: Number(d.votes_release || 0) },
    { k: "slash", n: Number(d.votes_slash || 0) },
    { k: "split", n: Number(d.votes_split || 0) },
  ].sort((a, b) => b.n - a.n);
  const winner = tallies[0];
  if (winner.n <= 0) return null;
  // Require strict majority of min_arbiters
  if (winner.n < Math.ceil(minA / 2) && winner.n < minA) {
    // if all min_arbiters voted and there's a unique top — accept
    if (votes < minA) return null;
  }

  let splitBps = Number(d.split_bps != null ? d.split_bps : 5000);
  if (winner.k === "split") {
    // average split_bps from split voters
    try {
      const q = await env.DB.prepare(
        `SELECT AVG(split_bps) AS a FROM dispute_arbiters
         WHERE dispute_id = ?1 AND vote = 'split' AND split_bps IS NOT NULL`
      )
        .bind(disputeId)
        .first();
      if (q && q.a != null) splitBps = Math.round(Number(q.a));
    } catch (_) {}
  }

  await env.DB.prepare(
    `UPDATE work_disputes
     SET status = 'ruled', decision = ?2, split_bps = ?3, ruled_by = 'quorum',
         ruled_at = datetime('now'), updated_at = datetime('now')
     WHERE id = ?1 AND status IN ('open', 'accepted')`
  )
    .bind(disputeId, winner.k, splitBps)
    .run();

  await logDisputeEvent(env, disputeId, "ruled", {
    note: "quorum:" + winner.k,
    meta: { votes_release: d.votes_release, votes_slash: d.votes_slash, votes_split: d.votes_split },
  });

  const fresh = await loadDispute(env, disputeId);
  return executeDisputeRuling(env, fresh, Date.now(), ctx);
}

export async function handleDisputeOpen(request, env, ctx) {
  const t0 = Date.now();
  const authUser = await getAuthUser(request, env);
  if (!authUser) return bad(request, "Sign in or API key required", 401);

  const rlId =
    authUser.auth_via === "api_key"
      ? "dsp:key:" + (authUser.key_id || authUser.id)
      : "dsp:user:" + authUser.id;
  const limited = await checkRateLimit(env, rlId, RL_DISPUTE_MAX, RL_DISPUTE_WINDOW_SEC);
  if (limited) {
    return bad(request, "Rate limit: dispute ops", 429, { retry_after_sec: limited.retry_after_sec });
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return bad(request, "Invalid JSON body");
  }

  const claimId = String(body.claim_id || body.work_id || "").trim();
  const reason = String(body.reason || "").trim().slice(0, 1000);
  const evidenceUri = body.evidence_uri ? String(body.evidence_uri).slice(0, 1000) : null;
  const evidenceHash = body.evidence_hash ? String(body.evidence_hash).trim().toLowerCase() : null;
  const ttlSec = parseDisputeTtl(body);
  const minArbiters = Math.min(
    DISPUTE_MAX_ARBITERS,
    Math.max(DISPUTE_MIN_ARBITERS, Math.floor(Number(body.min_arbiters) || DISPUTE_MIN_ARBITERS))
  );

  if (!claimId) return bad(request, "claim_id required");
  if (!reason || reason.length < 8) return bad(request, "reason required (min 8 chars) — court needs grounds");
  if (ttlSec == null) return bad(request, "ttl_seconds out of range");
  if (evidenceHash && !isHexHash(evidenceHash)) return bad(request, "evidence_hash must be hex");

  const claim = await loadWorkClaim(env, claimId);
  if (!claim) {
    try {
      await env.DB.prepare(`SELECT 1 FROM work_claims LIMIT 1`).first();
    } catch {
      return bad(request, "work_claims table missing", 500);
    }
    return bad(request, "Work claim not found", 404);
  }
  if (!["locked", "attested"].includes(claim.status)) {
    return bad(request, "Claim must be locked or attested to open dispute (status=" + claim.status + ")", 400, {
      code: "claim_not_disputable",
    });
  }

  const buyerRepo = parseRepo(claim.buyer_repo);
  const providerRepo = parseRepo(claim.provider_repo);
  if (!buyerRepo || !providerRepo) return bad(request, "Claim missing buyer/provider", 400);

  // Only buyer (complainant) may open.
  // Allow when:
  //  - default_repo is the claim buyer, OR
  //  - same account that created the claim (API key / session — Lab multi-agent keys), OR
  //  - same account that locked the claim (locked_by), if column present
  const isBuyerRepo =
    !!(authUser.default_repo && authUser.default_repo === buyerRepo);
  const isClaimCreator =
    !!(authUser.id && claim.created_by && authUser.id === claim.created_by);
  const isLocker =
    !!(authUser.id && claim.locked_by && authUser.id === claim.locked_by);
  if (!isBuyerRepo && !isClaimCreator && !isLocker) {
    return bad(request, "Only the buyer may open a dispute on this claim", 403, {
      code: "not_buyer",
      buyer_repo: buyerRepo,
      default_repo: authUser.default_repo || null,
    });
  }

  const openCount = await countOpenDisputeForClaim(env, claimId);
  if (openCount > 0) {
    return bad(request, "An open dispute already exists for this claim", 409, { code: "dispute_exists" });
  }

  const amount = Number(claim.locked_amount || claim.amount || 0);
  if (!(amount > 0)) return bad(request, "Claim has no locked amount to dispute", 400);

  // Complainant bond (default 5% of claim)
  let cBond = body.complainant_bond != null ? parseAmount(body.complainant_bond) : null;
  if (cBond == null) {
    cBond = Math.round(((amount * DISPUTE_DEFAULT_COMPLAINANT_BOND_BPS) / 10000) * 1e6) / 1e6;
    if (cBond < DISPUTE_MIN) cBond = DISPUTE_MIN;
  }
  if (cBond < 0 || cBond > DISPUTE_MAX) return bad(request, "complainant_bond invalid");

  let arbBondReq = body.arbiter_bond_required != null ? parseAmount(body.arbiter_bond_required) : null;
  if (arbBondReq == null) {
    arbBondReq = Math.round(((amount * DISPUTE_DEFAULT_ARBITER_BOND_BPS) / 10000) * 1e6) / 1e6;
  }
  if (arbBondReq == null || arbBondReq < 0) arbBondReq = 0;

  // Optional respondent bond deposit at open (provider may add later via accept-style)
  let rBond = body.respondent_bond != null ? parseAmount(body.respondent_bond) : 0;
  if (rBond == null) rBond = 0;

  if (cBond > 0) {
    authUser._policyCtx = { to_repo: SYSTEM_DISPUTE, task: "dispute:open" };
    const blocked = await safetyGate(request, env, authUser, buyerRepo, cBond);
    if (blocked) return blocked;
    const debitRes = await debitWithCredit(env, buyerRepo, cBond);
    if (!debitRes.ok) {
      return bad(request, debitRes.error || "Insufficient funds for complainant bond", 402, {
        code: debitRes.code || "insufficient",
      });
    }
  }

  const id = "dsp_" + randomId(12);
  const modifier = "+" + ttlSec + " seconds";

  try {
    await ensureAccount(env, SYSTEM_DISPUTE);
    const stmts = [
      env.DB.prepare(
        `INSERT INTO work_disputes (
           id, claim_id, buyer_repo, provider_repo, amount_usd, status, reason,
           evidence_uri, evidence_hash,
           complainant_bond_usd, respondent_bond_usd, arbiter_bond_required,
           min_arbiters, arbiter_count, votes_release, votes_slash, votes_split,
           ttl_seconds, expires_at, created_by, created_at, updated_at
         ) VALUES (
           ?1, ?2, ?3, ?4, ?5, 'open', ?6,
           ?7, ?8,
           ?9, ?10, ?11,
           ?12, 0, 0, 0, 0,
           ?13, datetime('now', ?14), ?15, datetime('now'), datetime('now')
         )`
      ).bind(
        id, claimId, buyerRepo, providerRepo, amount, reason,
        evidenceUri, evidenceHash,
        cBond, rBond, arbBondReq,
        minArbiters, ttlSec, modifier, authUser.id
      ),
      env.DB.prepare(
        `UPDATE work_claims SET status = 'disputed', updated_at = datetime('now') WHERE id = ?1`
      ).bind(claimId),
    ];
    if (cBond > 0) {
      stmts.push(
        env.DB.prepare(
          `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
           VALUES (?1, ?2, ?3, ?4, 'success', ?5)`
        ).bind(buyerRepo, SYSTEM_DISPUTE, cBond, "dispute-complainant-bond:" + id, Date.now() - t0)
      );
    }
    await env.DB.batch(stmts);
  } catch (e) {
    if (cBond > 0) {
      await env.DB.prepare(
        `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
      )
        .bind(cBond, buyerRepo)
        .run()
        .catch(() => {});
    }
    return bad(
      request,
      "work_disputes table missing — run d1-dispute-migration.sql: " + (e.message || e),
      500
    );
  }

  if (cBond > 0) await safetyRecordSpend(env, authUser, buyerRepo, cBond);
  await logDisputeEvent(env, id, "opened", {
    actor_repo: buyerRepo,
    amount: cBond,
    note: reason.slice(0, 200),
    meta: { claim_id: claimId, amount_usd: amount },
  });

  if (authUser.id) {
    scheduleWebhook(ctx, env, authUser.id, "dispute.opened", {
      id, claim_id: claimId, buyer_repo: buyerRepo, provider_repo: providerRepo,
      amount_usd: amount, complainant_bond: cBond, status: "open",
    });
  }

  return json(request, {
    ok: true,
    dispute: {
      id,
      claim_id: claimId,
      buyer_repo: buyerRepo,
      provider_repo: providerRepo,
      amount_usd: amount,
      reason,
      complainant_bond_usd: cBond,
      arbiter_bond_required: arbBondReq,
      min_arbiters: minArbiters,
      status: "open",
      ttl_seconds: ttlSec,
    },
    latency_ms: Date.now() - t0,
    hint: "Arbiters POST /api/dispute/accept { id } then /api/dispute/vote { id, decision }. Quorum auto-executes.",
  });
}

export async function handleDisputeAccept(request, env, ctx) {
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

  let arbiterRepo = parseRepo(body.arbiter_repo || body.from_repo);
  if (!arbiterRepo && authUser.default_repo) arbiterRepo = parseRepo(authUser.default_repo);
  if (!arbiterRepo) return bad(request, "arbiter_repo required (or set default agent)");

  const d = await loadDispute(env, id);
  if (!d) return bad(request, "Dispute not found", 404);
  if (!["open", "accepted"].includes(d.status)) {
    return bad(request, "Dispute not open for arbiters (status=" + d.status + ")", 400);
  }
  // Arbiters cannot be buyer or provider (impartiality)
  if (arbiterRepo === d.buyer_repo || arbiterRepo === d.provider_repo) {
    return bad(request, "Buyer and provider cannot serve as arbiters on their own case", 403, {
      code: "not_impartial",
    });
  }

  let bond = body.bond_usd != null ? parseAmount(body.bond_usd) : Number(d.arbiter_bond_required || 0);
  if (bond == null) bond = Number(d.arbiter_bond_required || 0);
  if (bond < Number(d.arbiter_bond_required || 0)) {
    return bad(request, "bond_usd below required arbiter bond ($" + d.arbiter_bond_required + ")", 400);
  }

  if (bond > 0) {
    authUser._policyCtx = { to_repo: SYSTEM_DISPUTE, task: "dispute:accept" };
    const blocked = await safetyGate(request, env, authUser, arbiterRepo, bond);
    if (blocked) return blocked;
    const debitRes = await debitWithCredit(env, arbiterRepo, bond);
    if (!debitRes.ok) {
      return bad(request, debitRes.error || "Insufficient funds for arbiter bond", 402, {
        code: debitRes.code || "insufficient",
      });
    }
  }

  const aid = "da_" + randomId(10);
  try {
    await ensureAccount(env, SYSTEM_DISPUTE);
    await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO dispute_arbiters (
           id, dispute_id, arbiter_repo, bond_usd, status, created_by, created_at
         ) VALUES (?1, ?2, ?3, ?4, 'bonded', ?5, datetime('now'))`
      ).bind(aid, id, arbiterRepo, bond, authUser.id),
      env.DB.prepare(
        `UPDATE work_disputes
         SET status = CASE WHEN status = 'open' THEN 'accepted' ELSE status END,
             arbiter_count = arbiter_count + 1,
             accepted_at = COALESCE(accepted_at, datetime('now')),
             updated_at = datetime('now')
         WHERE id = ?1`
      ).bind(id),
    ]);
    if (bond > 0) {
      await env.DB.prepare(
        `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
         VALUES (?1, ?2, ?3, ?4, 'success', ?5)`
      )
        .bind(arbiterRepo, SYSTEM_DISPUTE, bond, "dispute-arbiter-bond:" + id, Date.now() - t0)
        .run();
      await safetyRecordSpend(env, authUser, arbiterRepo, bond);
    }
  } catch (e) {
    if (bond > 0) {
      await env.DB.prepare(
        `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
      )
        .bind(bond, arbiterRepo)
        .run()
        .catch(() => {});
    }
    if (String(e.message || e).includes("UNIQUE")) {
      return bad(request, "Already accepted as arbiter on this dispute", 409);
    }
    return bad(request, "Accept failed: " + (e.message || e), 500);
  }

  await logDisputeEvent(env, id, "arbiter_accepted", {
    actor_repo: arbiterRepo,
    amount: bond,
  });

  return json(request, {
    ok: true,
    dispute_id: id,
    arbiter_id: aid,
    arbiter_repo: arbiterRepo,
    bond_usd: bond,
    status: "accepted",
    latency_ms: Date.now() - t0,
    hint: "POST /api/dispute/vote { id, decision: release|slash|split }",
  });
}

export async function handleDisputeVote(request, env, ctx) {
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
  const decision = String(body.decision || "").toLowerCase().trim();
  const note = body.note ? String(body.note).slice(0, 500) : null;
  let splitBps = body.split_bps != null ? Math.floor(Number(body.split_bps)) : null;
  if (splitBps != null) splitBps = Math.min(10000, Math.max(0, splitBps));

  if (!id) return bad(request, "id required");
  if (!["release", "slash", "split"].includes(decision)) {
    return bad(request, "decision must be release | slash | split", 400);
  }
  if (decision === "split" && splitBps == null) splitBps = 5000;

  let arbiterRepo = parseRepo(body.arbiter_repo || body.from_repo);
  if (!arbiterRepo && authUser.default_repo) arbiterRepo = parseRepo(authUser.default_repo);
  if (!arbiterRepo) return bad(request, "arbiter_repo required");

  const d = await loadDispute(env, id);
  if (!d) return bad(request, "Dispute not found", 404);
  if (!["open", "accepted"].includes(d.status)) {
    return bad(request, "Dispute not votable (status=" + d.status + ")", 400);
  }

  let arb;
  try {
    arb = await env.DB.prepare(
      `SELECT * FROM dispute_arbiters WHERE dispute_id = ?1 AND arbiter_repo = ?2`
    )
      .bind(id, arbiterRepo)
      .first();
  } catch {
    return bad(request, "dispute_arbiters missing — run d1-dispute-migration.sql", 500);
  }
  if (!arb || arb.status === "refunded") {
    return bad(request, "Not a bonded arbiter on this dispute — POST /api/dispute/accept first", 403);
  }
  if (arb.vote) {
    return bad(request, "Already voted (" + arb.vote + ")", 409);
  }

  const col =
    decision === "release" ? "votes_release" :
    decision === "slash" ? "votes_slash" : "votes_split";

  await env.DB.batch([
    env.DB.prepare(
      `UPDATE dispute_arbiters
       SET vote = ?2, split_bps = ?3, note = ?4, status = 'voted', voted_at = datetime('now')
       WHERE id = ?1`
    ).bind(arb.id, decision, splitBps, note),
    env.DB.prepare(
      `UPDATE work_disputes
       SET ${col} = ${col} + 1, updated_at = datetime('now')
       WHERE id = ?1`
    ).bind(id),
  ]);

  await logDisputeEvent(env, id, "voted", {
    actor_repo: arbiterRepo,
    note: decision + (splitBps != null ? " bps=" + splitBps : ""),
  });

  // Quorum check
  const exec = await tryQuorumAndExecute(env, id, ctx);

  return json(request, {
    ok: true,
    dispute_id: id,
    vote: decision,
    split_bps: splitBps,
    executed: !!(exec && exec.ok),
    execution: exec && exec.ok ? exec : null,
    latency_ms: Date.now() - t0,
  });
}

export async function handleDisputeExecute(request, env, ctx) {
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

  const d = await loadDispute(env, id);
  if (!d) return bad(request, "Dispute not found", 404);

  if (d.status === "executed") {
    return json(request, { ok: true, already: true, id, status: "executed" });
  }

  if (d.status === "ruled") {
    const result = await executeDisputeRuling(env, d, t0, ctx);
    if (!result.ok) return bad(request, result.error || "Execute failed", 400);
    return json(request, { ok: true, id, ...result, latency_ms: Date.now() - t0 });
  }

  // Try quorum
  const exec = await tryQuorumAndExecute(env, id, ctx);
  if (exec && exec.ok) {
    return json(request, { ok: true, id, ...exec, latency_ms: Date.now() - t0 });
  }
  return bad(request, "Quorum not reached yet — need more arbiter votes", 400, {
    code: "no_quorum",
    min_arbiters: d.min_arbiters,
    votes: {
      release: d.votes_release,
      slash: d.votes_slash,
      split: d.votes_split,
    },
  });
}

export async function handleDisputeCancel(request, env, ctx) {
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

  const d = await loadDispute(env, id);
  if (!d) return bad(request, "Dispute not found", 404);
  if (!["open", "accepted"].includes(d.status)) {
    return bad(request, "Cannot cancel (status=" + d.status + ")", 400);
  }
  const allowed =
    authUser.id === d.created_by ||
    (authUser.default_repo && authUser.default_repo === d.buyer_repo);
  if (!allowed) return bad(request, "Only complainant may cancel", 403);

  // Block cancel if any votes already cast
  const votes = Number(d.votes_release || 0) + Number(d.votes_slash || 0) + Number(d.votes_split || 0);
  if (votes > 0) {
    return bad(request, "Cannot cancel after votes have been cast", 400, { code: "votes_exist" });
  }

  const claim = await env.DB.prepare(
    `UPDATE work_disputes
     SET status = 'cancelled', cancelled_at = datetime('now'), updated_at = datetime('now')
     WHERE id = ?1 AND status IN ('open', 'accepted')
     RETURNING *`
  )
    .bind(id)
    .first();
  if (!claim) return bad(request, "Cancel race", 409);

  // Return bonds; restore claim to locked
  const cBond = Number(d.complainant_bond_usd || 0);
  const stmts = [];
  if (cBond > 0) {
    await ensureAccount(env, d.buyer_repo);
    stmts.push(
      env.DB.prepare(
        `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
      ).bind(cBond, d.buyer_repo),
      env.DB.prepare(
        `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
         VALUES (?1, ?2, ?3, ?4, 'success', 0)`
      ).bind(SYSTEM_DISPUTE, d.buyer_repo, cBond, "dispute-cancel-bond-return:" + id)
    );
  }
  try {
    const aq = await env.DB.prepare(
      `SELECT id, arbiter_repo, bond_usd FROM dispute_arbiters WHERE dispute_id = ?1 AND status = 'bonded'`
    )
      .bind(id)
      .all();
    for (const a of aq.results || []) {
      const b = Number(a.bond_usd || 0);
      if (b > 0) {
        await ensureAccount(env, a.arbiter_repo);
        stmts.push(
          env.DB.prepare(
            `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
          ).bind(b, a.arbiter_repo),
          env.DB.prepare(
            `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
             VALUES (?1, ?2, ?3, ?4, 'success', 0)`
          ).bind(SYSTEM_DISPUTE, a.arbiter_repo, b, "dispute-cancel-arbiter-return:" + id)
        );
      }
      stmts.push(env.DB.prepare(`UPDATE dispute_arbiters SET status = 'refunded' WHERE id = ?1`).bind(a.id));
    }
  } catch (_) {}

  stmts.push(
    env.DB.prepare(
      `UPDATE work_claims SET status = 'locked', updated_at = datetime('now')
       WHERE id = ?1 AND status = 'disputed'`
    ).bind(d.claim_id)
  );
  if (stmts.length) await env.DB.batch(stmts);

  await logDisputeEvent(env, id, "cancelled", { actor_repo: d.buyer_repo, amount: cBond });

  return json(request, {
    ok: true,
    id,
    status: "cancelled",
    complainant_bond_returned: cBond,
    latency_ms: Date.now() - t0,
  });
}

export async function handleDisputeGet(request, env, id) {
  id = String(id || "").trim();
  if (!id) return bad(request, "id required");
  const d = await loadDispute(env, id);
  if (!d) {
    try {
      await env.DB.prepare(`SELECT 1 FROM work_disputes LIMIT 1`).first();
    } catch {
      return bad(request, "work_disputes table missing — run d1-dispute-migration.sql", 500);
    }
    return bad(request, "Dispute not found", 404);
  }
  let arbiters = [];
  let events = [];
  try {
    const q = await env.DB.prepare(
      `SELECT id, arbiter_repo, bond_usd, vote, split_bps, note, status, voted_at, created_at
       FROM dispute_arbiters WHERE dispute_id = ?1 ORDER BY created_at ASC`
    )
      .bind(id)
      .all();
    arbiters = q.results || [];
  } catch (_) {}
  try {
    const q = await env.DB.prepare(
      `SELECT event, actor_repo, amount, note, created_at
       FROM dispute_events WHERE dispute_id = ?1 ORDER BY created_at DESC LIMIT 50`
    )
      .bind(id)
      .all();
    events = q.results || [];
  } catch (_) {}
  return json(request, { ok: true, dispute: d, arbiters, events });
}

export async function handleDisputeList(request, url, env) {
  const limit = Math.min(Math.max(Number(url.searchParams.get("limit") || 20), 1), 100);
  const repo = (url.searchParams.get("repo") || "").trim();
  const status = (url.searchParams.get("status") || "").trim();
  const claimId = (url.searchParams.get("claim_id") || "").trim();

  let sql = `SELECT id, claim_id, buyer_repo, provider_repo, amount_usd, status, reason,
                    decision, split_bps, min_arbiters, arbiter_count,
                    votes_release, votes_slash, votes_split,
                    complainant_bond_usd, expires_at, created_at
             FROM work_disputes WHERE 1=1`;
  const binds = [];
  if (repo) {
    if (!parseRepo(repo)) return bad(request, "repo must be owner/repo");
    sql += ` AND (buyer_repo = ? OR provider_repo = ?)`;
    binds.push(repo, repo);
  }
  if (status && ["open", "accepted", "ruled", "executed", "cancelled", "expired"].includes(status)) {
    sql += ` AND status = ?`;
    binds.push(status);
  }
  if (claimId) {
    sql += ` AND claim_id = ?`;
    binds.push(claimId);
  }
  sql += ` ORDER BY created_at DESC LIMIT ?`;
  binds.push(limit);

  try {
    const { results } = await env.DB.prepare(sql).bind(...binds).all();
    return json(request, { ok: true, count: (results || []).length, disputes: results || [] });
  } catch (e) {
    return bad(
      request,
      "work_disputes table missing — run d1-dispute-migration.sql: " + (e.message || e),
      500
    );
  }
}

export async function expireDisputes(env, ctx) {
  const t0 = Date.now();
  let expired = 0;
  try {
    const q = await env.DB.prepare(
      `SELECT * FROM work_disputes
       WHERE status IN ('open', 'accepted')
         AND expires_at IS NOT NULL
         AND expires_at < datetime('now')
       ORDER BY expires_at ASC LIMIT ?1`
    )
      .bind(EXPIRE_DISPUTE_BATCH)
      .all();
    for (const row of q.results || []) {
      try {
        // Timeout default: release to provider (buyer failed to prove) if no votes;
        // if votes exist, execute majority.
        const votes =
          Number(row.votes_release || 0) +
          Number(row.votes_slash || 0) +
          Number(row.votes_split || 0);
        if (votes > 0) {
          const exec = await tryQuorumAndExecute(env, row.id, ctx);
          if (exec && exec.ok) {
            expired += 1;
            continue;
          }
        }
        // Default timeout ruling: release (provider wins) — complainant failed to prosecute
        await env.DB.prepare(
          `UPDATE work_disputes
           SET status = 'ruled', decision = 'release', ruled_by = 'timeout',
               ruled_at = datetime('now'), updated_at = datetime('now')
           WHERE id = ?1 AND status IN ('open', 'accepted')`
        )
          .bind(row.id)
          .run();
        const fresh = await loadDispute(env, row.id);
        await executeDisputeRuling(env, fresh, t0, ctx);
        await logDisputeEvent(env, row.id, "expired", { note: "ttl_default_release" });
        expired += 1;
      } catch (e) {
        console.log("dispute_expire", row.id, e && e.message);
      }
    }
  } catch (e) {
    return { expired: 0, error: e.message, latency_ms: Date.now() - t0 };
  }
  return { expired, latency_ms: Date.now() - t0 };
}


