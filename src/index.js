import {
  securityHeaders,
  corsHeaders,
  json,
  bad,
  timingSafeEqualString,
  rejectOversizedBody,
  clientIp,
  MAX_JSON_BODY_BYTES,
} from "./shared/http.js";


import {
  parseRepo,
  parseAmount,
  sleep,
  randomId,
  parseCookies,
  sessionCookie,
  clearSessionCookie,
  sha256Hex,
  hmacSha256Hex,
  parseTtlSeconds,
  parseWebhookUrl,
  REPO_RE,
  MIN_AMOUNT,
  MAX_AMOUNT,
  COOKIE_NAME,
} from "./shared/utils.js";


import { checkRateLimit } from "./shared/rateLimit.js";


import { assertAdminSecret } from "./shared/admin.js";


import { getRequestEdge, hashIp } from "./shared/edge.js";

import {
  logSafetyEvent,
  ensureAgentLimits,
  getAgentLimits,
  checkWalletLocked,
  unlockWallet,
  suspendApiKey,
  recordVelocityEvent,
  checkVelocity,
  checkDailyBudget,
  addDailySpent,
} from "./shared/safety.js";

import {
  logShieldEvent,
  ensureShieldRow,
  getShield,
  setShieldLevel,
  countRecentWalletLocks,
  checkShieldGate,
  maybeAutoTripGlobalShield,
} from "./shared/shield.js";





import {
  DASHBOARD_URL,
  SESSION_DAYS,
  FAUCET_MAX_PER_CALL,
  FAUCET_ACCOUNT_CAP,
  SYSTEM_FAUCET,
  SYSTEM_ESCROW,
  MAX_KEYS_PER_USER,
  RL_KEY_CREATE_MAX,
  RL_KEY_CREATE_WINDOW_SEC,
  RL_PAY_MAX,
  RL_PAY_WINDOW_SEC,
  RL_ESCROW_MAX,
  RL_ESCROW_WINDOW_SEC,
  ESCROW_DEFAULT_TTL_HOURS,
  ESCROW_MIN_TTL_SEC,
  ESCROW_MAX_TTL_SEC,
  EXPIRE_BATCH_LIMIT,
  WEBHOOK_TIMEOUT_MS,
  RL_WEBHOOK_SET_MAX,
  RL_WEBHOOK_SET_WINDOW_SEC,
  RL_GITHUB_REPOS_MAX,
  RL_GITHUB_REPOS_WINDOW_SEC,
  RL_STREAM_MAX,
  RL_STREAM_WINDOW_SEC,
  SYSTEM_STREAM,
  STREAM_MIN_BUDGET,
  STREAM_MAX_BUDGET,
  SYSTEM_SUBWALLET,
  SUBWALLET_MIN_BUDGET,
  SUBWALLET_MAX_BUDGET,
  SUBWALLET_DEFAULT_TTL_SEC,
  SUBWALLET_MIN_TTL_SEC,
  SUBWALLET_MAX_TTL_SEC,
  RL_SUBWALLET_MAX,
  RL_SUBWALLET_WINDOW_SEC,
  EXPIRE_SUBWALLET_BATCH,
  SYSTEM_NETTING,
  NETTING_DEFAULT_WINDOW_HOURS,
  NETTING_MIN_WINDOW_HOURS,
  NETTING_MAX_WINDOW_HOURS,
  NETTING_MAX_PAIRS,
  RL_NETTING_MAX,
  RL_NETTING_WINDOW_SEC,
  SYSTEM_TICKET,
  TICKET_MIN_UNITS,
  TICKET_MAX_UNITS,
  TICKET_DEFAULT_TTL_SEC,
  TICKET_MIN_TTL_SEC,
  TICKET_MAX_TTL_SEC,
  RL_TICKET_MAX,
  RL_TICKET_WINDOW_SEC,
  EXPIRE_TICKET_BATCH,
  SYSTEM_BOND,
  SYSTEM_SLASH_POOL,
  BOND_MIN,
  BOND_MAX,
  BOND_DEFAULT_TTL_SEC,
  BOND_MIN_TTL_SEC,
  BOND_MAX_TTL_SEC,
  BOND_DEFAULT_MATCH_TTL_SEC,
  BOND_DEFAULT_SLASH_BPS,
  RL_BOND_MAX,
  RL_BOND_WINDOW_SEC,
  EXPIRE_BOND_BATCH,
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
  SAFETY_DEFAULT_VELOCITY_MAX_TX,
  SAFETY_DEFAULT_VELOCITY_TX_WINDOW_SEC,
  SAFETY_DEFAULT_VELOCITY_MAX_USD,
  SAFETY_DEFAULT_VELOCITY_USD_WINDOW_SEC,
  SAFETY_SPIKE_TX_PER_SEC,
  SAFETY_VELOCITY_PRUNE_HOURS,
  CREDIT_DEFAULT_LIMIT,
  CREDIT_MAX_LIMIT,
  CREDIT_REP_PER_USD,
  CREDIT_REP_SUCCESS_BONUS,
  CREDIT_REP_FAIL_PENALTY,
  CREDIT_REP_TO_LIMIT_RATIO,
  CREDIT_AUTO_LIMIT,
  RL_CREDIT_MAX,
  RL_CREDIT_WINDOW_SEC,
  SYSTEM_COMMIT,
  COMMIT_MIN,
  COMMIT_MAX,
  COMMIT_DEFAULT_TTL_SEC,
  COMMIT_MIN_TTL_SEC,
  COMMIT_MAX_TTL_SEC,
  RL_COMMIT_MAX,
  RL_COMMIT_WINDOW_SEC,
  EXPIRE_COMMIT_BATCH,
  SYSTEM_CLEARING,
  CLEARING_DEFAULT_WINDOW_HOURS,
  CLEARING_MIN_WINDOW_HOURS,
  CLEARING_MAX_WINDOW_HOURS,
  CLEARING_MAX_REPOS,
  RL_CLEARING_MAX,
  RL_CLEARING_WINDOW_SEC,
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
  SYSTEM_CONTINUITY,
  CONT_MIN_BOND,
  CONT_MAX_BOND,
  CONT_DEFAULT_INTERVAL_SEC,
  CONT_MIN_INTERVAL_SEC,
  CONT_MAX_INTERVAL_SEC,
  CONT_DEFAULT_GRACE_SEC,
  CONT_MIN_GRACE_SEC,
  CONT_MAX_GRACE_SEC,
  CONT_DEFAULT_MISS_LIMIT,
  CONT_MAX_MISS_LIMIT,
  RL_CONT_MAX,
  RL_CONT_WINDOW_SEC,
  EXPIRE_CONT_BATCH,
  SYSTEM_POOL,
  POOL_MIN,
  POOL_MAX,
  POOL_DEFAULT_TTL_SEC,
  POOL_MIN_TTL_SEC,
  POOL_MAX_TTL_SEC,
  RL_POOL_MAX,
  RL_POOL_WINDOW_SEC,
  EXPIRE_POOL_BATCH,
  SHIELD_LEVEL_NORMAL,
  SHIELD_LEVEL_WATCH,
  SHIELD_LEVEL_THROTTLE,
  SHIELD_LEVEL_FREEZE,
  SHIELD_LEVEL_EMERGENCY,
  SHIELD_AUTO_LOCKS_TRIP,
  SHIELD_AUTO_WINDOW_SEC,
  SHIELD_COOLDOWN_SEC,
  SHIELD_MAX_LEVEL,
  RL_SHIELD_MAX,
  RL_SHIELD_WINDOW_SEC,
  SYSTEM_INTENT,
  INTENT_MIN,
  INTENT_MAX,
  INTENT_DEFAULT_TTL_SEC,
  INTENT_MIN_TTL_SEC,
  INTENT_MAX_TTL_SEC,
  RL_INTENT_MAX,
  RL_INTENT_WINDOW_SEC,
  EXPIRE_INTENT_BATCH,
  SYSTEM_HIRE,
  HIRE_MIN,
  HIRE_MAX,
  HIRE_DEFAULT_TTL_SEC,
  HIRE_MIN_TTL_SEC,
  HIRE_MAX_TTL_SEC,
  RL_HIRE_MAX,
  RL_HIRE_WINDOW_SEC,
  EXPIRE_HIRE_BATCH,
  SYSTEM_STANDING,
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
  SYSTEM_DELEGATE,
  DELEGATE_MIN,
  DELEGATE_MAX,
  DELEGATE_DEFAULT_TTL_SEC,
  DELEGATE_MIN_TTL_SEC,
  DELEGATE_MAX_TTL_SEC,
  RL_DELEGATE_MAX,
  RL_DELEGATE_WINDOW_SEC,
  EXPIRE_DELEGATE_BATCH,
  SYSTEM_DISPUTE,
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
  RL_IP_POST_MAX,
  RL_IP_POST_WINDOW_SEC,
  INTEGRITY_SAMPLE_LIMIT,
} from "./shared/constants.js";

/***
 * Autonomous Edge-Agent Economy — Cloudflare Worker + D1
 * Ledger + OAuth + API keys + rate limits + escrow + auto-expire + webhooks
 *
 * INVENTORY (do not delete):
 * Auth:     GET /api/auth/google, GET /api/auth/google/callback,
 *           GET /api/auth/github, GET /api/auth/github/callback,
 *           GET /api/auth/gitlab, GET /api/auth/gitlab/callback, 
 *           GET /api/auth/me, POST /api/auth/logout
 * Me:       POST /api/me/agent, GET /api/me/balance,
 *           GET /api/me/github/repos, GET /api/me/gitlab/repos, GET /api/me/repos
 * Agents:   GET /api/agents, GET /api/agents/search, GET /api/agents/rank, POST /api/agents/scan
 *           Capabilities-aware index (AP-Capabilities / wrangler.toml)
 * Keys:     POST|GET /api/me/keys, POST /api/me/keys/revoke
 * Webhook:  GET|POST /api/me/webhook, POST /api/me/webhook/clear
 *           GET /api/me/webhook/deliveries
 * Ledger:   POST /api/pay (fast cash path + batched settle + waitUntil post-commit),
 *           POST /api/fund, GET /api/balance, GET /api/ledger
 * Escrow:   POST /api/escrow/hold|release|refund (hold: waitUntil post-commit like pay),
 *           GET /api/escrow, POST /api/escrow/expire-now
 * Stream:   POST /api/stream/start|meter|stop, GET /api/stream
 * Cron:     scheduled() → expireHeldEscrows (+ webhook escrow.expired)
 * D1 users: github_access_token, github_login; gitlab_access_token, gitlab_username (optional ALTER)
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
 * Tickets:  POST /api/ticket/mint|transfer|redeem, GET /api/ticket
 * D1:       capability_tickets + ticket_events (d1-tickets-migration.sql)
 * Bonds:    POST /api/bond/post|match|fulfill|slash|cancel, GET /api/bond
 * D1:       intent_bonds + bond_events (d1-bonds-migration.sql)
 * Sagas:    POST /api/saga/start|advance|compensate|cancel, GET /api/saga
 * D1:       payment_sagas + saga_steps + saga_events (d1-saga-migration.sql)
 * Credit:   rep-backed limits on agent_limits; GET|POST /api/me/credit
 * D1:       agent_limits credit_* + rep_events (d1-credit-migration.sql)
 * Commit:   POST /api/commit|reveal|cancel, GET /api/commit
 * D1:       payment_commits + commit_events (d1-commit-migration.sql)
 * Clearing: POST /api/clearing/run, GET /api/clearing, GET /api/clearing/:id
 * D1:       clearing_batches + clearing_positions (d1-clearing-migration.sql)
 * Receipts: HMAC-SHA256 via env.RECEIPT_SECRET (pay + clearing settlements)
 * Work:     POST /api/work/claim|lock|attest|settle|refund, GET /api/work
 *           Attestation diversity: no self-attest (provider/buyer), distinct attestors only
 * D1:       work_claims + work_attestations + work_events (d1-work-migration.sql)
 *           Optional: UNIQUE(claim_id, attestor_repo) — d1-work-attest-diversity.sql
 * Continuity: POST /api/continuity/open|beat|close|recover, GET /api/continuity
 * D1:       continuity_sessions + continuity_events (d1-continuity-migration.sql)
 * Cron:     expireContinuitySessions
 * Pools:    POST /api/pool/open|contribute|release|refund, GET /api/pool, GET /api/pool/:id
 *           Collaborative / swarm co-funding — multi-agent target fill then release
 * D1:       collaborative_pools + pool_contributions + pool_events (d1-pool-migration.sql)
 * Cron:     expireCollaborativePools
 * Admin:    POST /api/admin/sandbox-cleanup (ADMIN_CLEANUP_SECRET + confirm)
 * Shield:   GET /api/shield, GET|POST /api/me/shield, POST /api/me/shield/release
 *           Adaptive circuit-breaker + agent quarantine (bot flood / key compromise)
 * D1:       edge_shield + shield_events (d1-shield-migration.sql)
 * Admin:    POST /api/admin/shield (ADMIN_CLEANUP_SECRET)
 * Intent:   POST /api/intent/create|spend|cancel, GET /api/intent, GET /api/intent/:id
 *           Spend Intent Capsules — time-boxed amount-capped pre-auth envelopes
 * D1:       intent_capsules + intent_events (d1-intent-migration.sql)
 * Cron:     expireIntentCapsules
 * Colo:     POST /api/me/keys/bind|unbind, GET /api/me/key, GET /api/edge
 *           Bind API keys to Cloudflare colo and/or IP fingerprint — stolen keys fail off-edge
 * D1:       api_keys.bound_colo, bound_ip_hash, bind_mode, last_colo, last_ip_hash,
 *           bind_violations, bound_at (d1-colo-migration.sql)
 * Delegate: POST /api/delegate/open|revoke, GET /api/delegate, GET /api/delegate/:id
 *           Parent authority → child API key; pay with Bearer child_key + X-Delegate-Id
 * D1:       delegations + delegation_events (d1-delegate-migration.sql)
 * Cron:     expireDelegations
 * Dispute:  POST /api/dispute/open|accept|vote|execute|cancel, GET /api/dispute, GET /api/dispute/:id
 *           Bonded arbitration over work claims — slash / release / split (supreme court)
 * D1:       work_disputes + dispute_arbiters + dispute_events (d1-dispute-migration.sql)
 * Cron:     expireDisputes
 * Security: response security headers on all JSON; Content-Length body cap;
 *           timing-safe admin secret compare; per-IP POST rate limit;
 *           GET /api/security/status (public defense map);
 *           POST /api/admin/integrity (ADMIN_CLEANUP_SECRET — ledger balance audit)
 */



/* ─── Safety: lockWallet (needs adjustRep + scheduleWebhook); rest in shared/safety.js ─── */

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
  await adjustRep(env, repoId, -CREDIT_REP_FAIL_PENALTY, "wallet_locked");
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


async function safetyGate(request, env, authUser, fromRepo, amount) {
  if (!fromRepo) return null;

  const sus = rejectIfSuspendedKey(request, authUser);
  if (sus) return sus;

  // Edge Shield: global freeze / agent quarantine
  const shieldBlock = await checkShieldGate(request, env, fromRepo);
  if (shieldBlock) return shieldBlock;

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
      // Quarantine agent under Edge Shield (auto cool-down)
      try {
        await setShieldLevel(env, fromRepo, SHIELD_LEVEL_FREEZE, "runaway_loop: " + vel.error, {
          cooldownSec: SHIELD_COOLDOWN_SEC,
        });
        await maybeAutoTripGlobalShield(env);
      } catch (e) {
        console.log("shield_trip_on_spike", e && e.message);
      }
      if (uid) {
        // fire-and-forget (no ctx in gate path)
        scheduleWebhook(null, env, uid, "agent.runaway_loop", {
          repo_id: fromRepo,
          reason: vel.error,
          api_key_id: keyId,
        });
        scheduleWebhook(null, env, uid, "shield.quarantine", {
          repo_id: fromRepo,
          reason: vel.error,
          level: SHIELD_LEVEL_FREEZE,
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


/* ─── Reputation-backed credit ───
 * agent_limits.credit_limit  — max outstanding draw (null/0 = cash only)
 * agent_limits.outstanding_credit — current borrowed
 * agent_limits.rep_score — reputation points
 * Spend path: if balance < amount, draw min(shortfall, available_credit).
 * Repay: POST /api/me/credit/repay reduces outstanding from free balance.
 * Auto-limit: suggested = min(CREDIT_MAX_LIMIT, rep_score * CREDIT_REP_TO_LIMIT_RATIO)
 */

async function getCreditState(env, repoId) {
  const lim = await getAgentLimits(env, repoId);
  if (!lim) {
    return {
      credit_limit: CREDIT_DEFAULT_LIMIT,
      outstanding_credit: 0,
      available_credit: CREDIT_DEFAULT_LIMIT,
      rep_score: 0,
      rep_events: 0,
      suggested_limit: 0,
    };
  }
  const limit = lim.credit_limit != null ? Number(lim.credit_limit) : CREDIT_DEFAULT_LIMIT;
  const outstanding = Number(lim.outstanding_credit || 0);
  const rep = Number(lim.rep_score || 0);
  const suggested = Math.min(
    CREDIT_MAX_LIMIT,
    Math.round(rep * CREDIT_REP_TO_LIMIT_RATIO * 1e6) / 1e6
  );
  const effectiveLimit = Math.max(limit, 0);
  const available = Math.max(0, Math.round((effectiveLimit - outstanding) * 1e6) / 1e6);
  return {
    credit_limit: effectiveLimit,
    outstanding_credit: outstanding,
    available_credit: available,
    rep_score: rep,
    rep_events: Number(lim.rep_events || 0),
    suggested_limit: suggested,
    locked: Number(lim.locked) === 1,
  };
}

async function adjustRep(env, repoId, delta, reason, refId) {
  if (!repoId || !delta) return null;
  try {
    await ensureAgentLimits(env, repoId);
    const row = await env.DB.prepare(
      `UPDATE agent_limits
       SET rep_score = MAX(0, COALESCE(rep_score, 0) + ?2),
           rep_events = COALESCE(rep_events, 0) + 1,
           updated_at = datetime('now')
       WHERE repo_id = ?1
       RETURNING rep_score, credit_limit`
    )
      .bind(repoId, Number(delta))
      .first();
    if (!row) return null;
    const score = Number(row.rep_score || 0);
    // Soft auto-raise: only if credit_limit is null/0 and AUTO on
    if (CREDIT_AUTO_LIMIT) {
      const curLim = row.credit_limit != null ? Number(row.credit_limit) : 0;
      const suggested = Math.min(
        CREDIT_MAX_LIMIT,
        Math.round(score * CREDIT_REP_TO_LIMIT_RATIO * 1e6) / 1e6
      );
      if (suggested > curLim && curLim === 0) {
        await env.DB.prepare(
          `UPDATE agent_limits SET credit_limit = ?2, updated_at = datetime('now') WHERE repo_id = ?1`
        )
          .bind(repoId, suggested)
          .run();
      }
    }
    try {
      await env.DB.prepare(
        `INSERT INTO rep_events (id, repo_id, delta, score_after, reason, ref_id, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, datetime('now'))`
      )
        .bind(randomId(10), repoId, Number(delta), score, String(reason || "").slice(0, 200), refId || null)
        .run();
    } catch (_) {}
    return score;
  } catch (e) {
    console.log("adjust_rep_error", e && e.message);
    return null;
  }
}

/**
 * Debit with optional credit draw.
 * Returns { ok, balance, credit_drawn, outstanding } or { ok:false, error, code }.
 * Does NOT run safety gate — caller must.
 */
async function debitWithCredit(env, repoId, amount) {
  amount = Number(amount);
  await ensureAccount(env, repoId);
  const acc = await env.DB.prepare(`SELECT balance FROM accounts WHERE repo_id = ?1`)
    .bind(repoId)
    .first();
  const bal = Number(acc?.balance || 0);
  if (bal >= amount) {
    const row = await env.DB.prepare(
      `UPDATE accounts SET balance = balance - ?1, updated_at = datetime('now')
       WHERE repo_id = ?2 AND balance >= ?1 RETURNING balance`
    )
      .bind(amount, repoId)
      .first();
    if (!row) return { ok: false, error: "Insufficient funds", code: "insufficient" };
    return { ok: true, balance: Number(row.balance), credit_drawn: 0, outstanding: 0 };
  }

  const shortfall = Math.round((amount - bal) * 1e6) / 1e6;
  const credit = await getCreditState(env, repoId);
  if (credit.locked) {
    return { ok: false, error: "Wallet locked", code: "wallet_locked" };
  }
  if (credit.available_credit < shortfall) {
    return {
      ok: false,
      error:
        "Insufficient funds + credit (need $" +
        amount.toFixed(6) +
        ", cash $" +
        bal.toFixed(6) +
        ", credit available $" +
        credit.available_credit.toFixed(6) +
        ")",
      code: "insufficient_credit",
      balance: bal,
      available_credit: credit.available_credit,
    };
  }

  // Draw credit: set balance to 0 (use all cash), increase outstanding
  await ensureAgentLimits(env, repoId);
  const updLim = await env.DB.prepare(
    `UPDATE agent_limits
     SET outstanding_credit = COALESCE(outstanding_credit, 0) + ?2,
         updated_at = datetime('now')
     WHERE repo_id = ?1
       AND COALESCE(credit_limit, 0) >= COALESCE(outstanding_credit, 0) + ?2
     RETURNING outstanding_credit, credit_limit`
  )
    .bind(repoId, shortfall)
    .first();
  if (!updLim) {
    return { ok: false, error: "Credit draw race or limit exceeded", code: "credit_race" };
  }

  // Cash goes to 0 (or stays if already 0); we "spent" amount via cash+credit
  if (bal > 0) {
    await env.DB.prepare(
      `UPDATE accounts SET balance = 0, updated_at = datetime('now') WHERE repo_id = ?1`
    )
      .bind(repoId)
      .run();
  }

  return {
    ok: true,
    balance: 0,
    credit_drawn: shortfall,
    outstanding: Number(updLim.outstanding_credit),
  };
}

async function repayCredit(env, repoId, amount) {
  amount = Number(amount);
  if (!(amount > 0)) return { ok: false, error: "amount required" };
  const lim = await getAgentLimits(env, repoId);
  const outstanding = Number(lim?.outstanding_credit || 0);
  if (outstanding <= 0) return { ok: true, repaid: 0, outstanding: 0, already_clear: true };
  const pay = Math.min(amount, outstanding);
  await ensureAccount(env, repoId);
  const deb = await env.DB.prepare(
    `UPDATE accounts SET balance = balance - ?1, updated_at = datetime('now')
     WHERE repo_id = ?2 AND balance >= ?1 RETURNING balance`
  )
    .bind(pay, repoId)
    .first();
  if (!deb) return { ok: false, error: "Insufficient balance to repay credit", code: "insufficient" };
  await env.DB.prepare(
    `UPDATE agent_limits
     SET outstanding_credit = MAX(0, COALESCE(outstanding_credit, 0) - ?2),
         updated_at = datetime('now')
     WHERE repo_id = ?1`
  )
    .bind(repoId, pay)
    .run();
  const after = await getCreditState(env, repoId);
  return {
    ok: true,
    repaid: pay,
    outstanding: after.outstanding_credit,
    balance: Number(deb.balance),
  };
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


/**
 * Enforce colo/IP binding on an API key row.
 * Returns null if OK, or { code, error, ... } if blocked.
 * May learn-bind on first use (mode=learn).
 */
async function enforceKeyBinding(env, keyRow, request) {
  if (!keyRow || !keyRow.key_id) return null;
  let mode = (keyRow.bind_mode || "").toLowerCase().trim();
  if (!mode || mode === "none" || mode === "off") {
    // Still record last edge for visibility
    try {
      const edge = getRequestEdge(request);
      const ipHash = await hashIp(edge.ip);
      await env.DB.prepare(
        `UPDATE api_keys SET last_colo = ?2, last_ip_hash = ?3, last_used_at = datetime('now')
         WHERE id = ?1`
      )
        .bind(keyRow.key_id, edge.colo, ipHash)
        .run();
    } catch (_) {}
    return null;
  }

  const edge = getRequestEdge(request);
  const ipHash = await hashIp(edge.ip);
  let boundColo = keyRow.bound_colo ? String(keyRow.bound_colo).toUpperCase() : null;
  let boundIp = keyRow.bound_ip_hash || null;

  // Learn: pin on first successful sighting
  if (mode === "learn" && !boundColo && !boundIp) {
    try {
      await env.DB.prepare(
        `UPDATE api_keys
         SET bound_colo = ?2, bound_ip_hash = ?3, bound_at = datetime('now'),
             last_colo = ?2, last_ip_hash = ?3, last_used_at = datetime('now'),
             bind_mode = 'either'
         WHERE id = ?1`
      )
        .bind(keyRow.key_id, edge.colo, ipHash)
        .run();
      await logSafetyEvent(env, "key.edge_bound", {
        api_key_id: keyRow.key_id,
        user_id: keyRow.user_id || keyRow.id,
        reason: "learn",
        meta: { colo: edge.colo, has_ip: !!ipHash },
      });
    } catch (e) {
      console.log("key_learn_bind", e && e.message);
    }
    return null;
  }

  // If edge metadata missing (local / non-CF), allow — do not lock out operators offline
  if (!edge.colo && !ipHash) {
    return null;
  }

  const coloOk = !!(boundColo && edge.colo && boundColo === edge.colo);
  const ipOk = !!(boundIp && ipHash && boundIp === ipHash);

  let allowed = false;
  if (mode === "colo") allowed = coloOk || (!boundColo && !!edge.colo);
  else if (mode === "ip") allowed = ipOk || (!boundIp && !!ipHash);
  else if (mode === "both") allowed = (boundColo ? coloOk : true) && (boundIp ? ipOk : true) && (coloOk || ipOk || (!boundColo && !boundIp));
  else if (mode === "either" || mode === "learn") allowed = coloOk || ipOk;
  else allowed = true;

  // First-use pin for colo/ip/both when bounds empty
  if (!allowed && (mode === "colo" || mode === "ip" || mode === "both") && !boundColo && !boundIp) {
    try {
      await env.DB.prepare(
        `UPDATE api_keys
         SET bound_colo = ?2, bound_ip_hash = ?3, bound_at = datetime('now'),
             last_colo = ?2, last_ip_hash = ?3, last_used_at = datetime('now')
         WHERE id = ?1`
      )
        .bind(keyRow.key_id, edge.colo, ipHash)
        .run();
      return null;
    } catch (_) {}
  }

  if (allowed) {
    try {
      await env.DB.prepare(
        `UPDATE api_keys SET last_colo = ?2, last_ip_hash = ?3, last_used_at = datetime('now')
         WHERE id = ?1`
      )
        .bind(keyRow.key_id, edge.colo, ipHash)
        .run();
    } catch (_) {}
    return null;
  }

  // Violation
  try {
    await env.DB.prepare(
      `UPDATE api_keys
       SET bind_violations = COALESCE(bind_violations, 0) + 1,
           last_colo = ?2, last_ip_hash = ?3, last_used_at = datetime('now')
       WHERE id = ?1`
    )
      .bind(keyRow.key_id, edge.colo, ipHash)
      .run();
    await logSafetyEvent(env, "key.edge_mismatch", {
      api_key_id: keyRow.key_id,
      user_id: keyRow.user_id || keyRow.id,
      reason: "edge_mismatch",
      meta: {
        mode,
        bound_colo: boundColo,
        got_colo: edge.colo,
        ip_match: ipOk,
      },
    });
  } catch (_) {}

  return {
    code: "key_edge_mismatch",
    error:
      "API key bound to another edge (colo/IP). Stolen or off-edge use blocked.",
    bind_mode: mode,
    bound_colo: boundColo,
    got_colo: edge.colo || null,
  };
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
              k.bound_colo, k.bound_ip_hash, k.bind_mode, k.last_colo, k.bind_violations,
              u.id, u.email, u.name, u.picture, u.provider, u.default_repo
       FROM api_keys k
       JOIN users u ON u.id = k.user_id
       WHERE k.key_hash = ?1`
    )
      .bind(hash)
      .first();
  } catch (_) {
    // columns may be missing until ALTER — fall back progressively
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
    } catch (__) {
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
  }

  if (!row || row.revoked_at) return null;
  if (row.suspended_at) {
    row._suspended = true;
    row._suspend_reason = row.suspend_reason || "API key suspended";
    return row;
  }

  // Colo / IP binding — stolen keys fail off-edge
  try {
    const edgeBlock = await enforceKeyBinding(env, row, request);
    if (edgeBlock) {
      row._edge_blocked = true;
      row._edge_error = edgeBlock.error;
      row._edge_code = edgeBlock.code;
      row._edge_meta = edgeBlock;
      return row;
    }
  } catch (e) {
    console.log("enforce_key_binding", e && e.message);
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
    if (keyUser._edge_blocked) {
      return {
        ...keyUser,
        auth_via: "api_key",
        edge_blocked: true,
        _edge_error: keyUser._edge_error,
        _edge_code: keyUser._edge_code,
        _edge_meta: keyUser._edge_meta,
      };
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
  if (authUser && authUser.auth_via === "api_key" && (authUser.edge_blocked || authUser._edge_blocked)) {
    const meta = authUser._edge_meta || {};
    return bad(
      request,
      authUser._edge_error || "API key bound to another edge",
      403,
      {
        code: authUser._edge_code || "key_edge_mismatch",
        bind_mode: meta.bind_mode || null,
        bound_colo: meta.bound_colo || null,
        got_colo: meta.got_colo || null,
      }
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


/* ─── Security status (public, read-only defense map) ─── */
async function handleSecurityStatus(request, env) {
  let globalShield = { level: 0, reason: null, cools_at: null };
  try {
    globalShield = await getShield(env, "global");
  } catch (_) {}

  return json(request, {
    ok: true,
    product: "AgentPay Secure Gateway",
    security_tier: "bank-grade-v1",
    as_of: new Date().toISOString(),
    network: {
      global_shield_level: Number(globalShield.level || 0),
      global_shield_reason: globalShield.reason || null,
      global_shield_cools_at: globalShield.cools_at || null,
    },
    controls: {
      body_max_bytes: MAX_JSON_BODY_BYTES,
      ip_post_rate_limit: { max: RL_IP_POST_MAX, window_sec: RL_IP_POST_WINDOW_SEC },
      pay_rate_limit: { max: RL_PAY_MAX, window_sec: RL_PAY_WINDOW_SEC },
      security_headers: true,
      timing_safe_admin: true,
      idempotency_on_pay: true,
      safety_gate: [
        "wallet_lock",
        "edge_shield",
        "policy_as_code",
        "daily_budget",
        "velocity_tx",
        "velocity_usd",
        "spike_kill_switch",
        "rep_credit_draw",
      ],
      key_binding: ["colo", "ip", "either", "both", "learn"],
      work_attestation_diversity: {
        block_self_attest: WORK_BLOCK_SELF_ATTEST,
        require_distinct_attestors: WORK_REQUIRE_DISTINCT_ATTESTORS,
      },
      dispute_court: true,
      zero_loss_instruments: [
        "escrow",
        "stream",
        "subwallet",
        "intent_capsule",
        "commit_reveal",
        "work_settlement",
        "dispute_bonds",
      ],
    },
    admin: {
      integrity: "POST /api/admin/integrity (X-Admin-Cleanup-Key)",
      shield: "POST /api/admin/shield",
      sandbox_cleanup: "POST /api/admin/sandbox-cleanup",
    },
    hint: "Public map only — no balances or secrets exposed.",
  });
}

/**
 * Ledger integrity audit (admin-only).
 * Checks: non-negative balances, locked+spendable consistency signals,
 * orphaned held instruments sample, system account presence.
 * Does NOT mutate ledger.
 */
async function handleAdminIntegrity(request, env) {
  const t0 = Date.now();
  let body = {};
  try {
    body = await request.json();
  } catch {
    body = {};
  }
  const admin = await assertAdminSecret(request, env, body);
  if (!admin.ok) return admin.response;

  const rl = await checkRateLimit(env, "admin:integrity", 10, 3600);
  if (rl) {
    return bad(request, "Integrity rate limit: max 10/hour", 429, {
      code: "integrity_rate_limited",
      retry_after_sec: rl.retry_after_sec,
    });
  }

  const findings = [];
  const stats = {
    accounts_scanned: 0,
    negative_balances: 0,
    locked_wallets: 0,
    system_accounts_ok: 0,
    held_escrows: 0,
    open_disputes: 0,
  };

  // System accounts must exist (create if missing for audit readiness)
  const systemRepos = [
    SYSTEM_FAUCET,
    SYSTEM_ESCROW,
    SYSTEM_STREAM,
    SYSTEM_SUBWALLET,
    SYSTEM_DISPUTE,
  ];
  for (const repo of systemRepos) {
    try {
      await ensureAccount(env, repo);
      stats.system_accounts_ok += 1;
    } catch (e) {
      findings.push({ severity: "high", code: "system_account", repo, error: e.message });
    }
  }

  // Sample accounts for negative balance
  try {
    const { results } = await env.DB.prepare(
      `SELECT repo_id, balance FROM accounts
       ORDER BY updated_at DESC LIMIT ?1`
    )
      .bind(INTEGRITY_SAMPLE_LIMIT)
      .all();
    for (const row of results || []) {
      stats.accounts_scanned += 1;
      if (Number(row.balance) < -0.0000005) {
        stats.negative_balances += 1;
        findings.push({
          severity: "critical",
          code: "negative_balance",
          repo_id: row.repo_id,
          balance: Number(row.balance),
        });
      }
    }
  } catch (e) {
    findings.push({ severity: "high", code: "accounts_scan_failed", error: e.message });
  }

  try {
    const lockRow = await env.DB.prepare(
      `SELECT COUNT(*) AS c FROM agent_limits WHERE locked = 1`
    ).first();
    stats.locked_wallets = Number(lockRow?.c || 0);
  } catch (_) {}

  try {
    const esc = await env.DB.prepare(
      `SELECT COUNT(*) AS c FROM escrows WHERE status = 'held'`
    ).first();
    stats.held_escrows = Number(esc?.c || 0);
  } catch (_) {}

  try {
    const dsp = await env.DB.prepare(
      `SELECT COUNT(*) AS c FROM work_disputes WHERE status IN ('open', 'voting', 'accepted')`
    ).first();
    stats.open_disputes = Number(dsp?.c || 0);
  } catch (_) {}

  // Outstanding credit vs limit sanity
  try {
    const badCredit = await env.DB.prepare(
      `SELECT repo_id, credit_limit, outstanding_credit FROM agent_limits
       WHERE COALESCE(outstanding_credit, 0) > COALESCE(credit_limit, 0) + 0.000001
       LIMIT 20`
    ).all();
    for (const row of badCredit.results || []) {
      findings.push({
        severity: "high",
        code: "credit_overdraw",
        repo_id: row.repo_id,
        credit_limit: Number(row.credit_limit),
        outstanding_credit: Number(row.outstanding_credit),
      });
    }
  } catch (_) {}

  const critical = findings.filter((f) => f.severity === "critical").length;
  const high = findings.filter((f) => f.severity === "high").length;

  try {
    await logSafetyEvent(env, "integrity.scan", {
      reason: critical > 0 ? "findings_critical" : "ok",
      meta: { critical, high, accounts_scanned: stats.accounts_scanned },
    });
  } catch (_) {}

  return json(request, {
    ok: critical === 0,
    integrity: critical === 0 ? "pass" : "fail",
    stats,
    findings,
    summary: {
      critical,
      high,
      message:
        critical === 0
          ? "No critical ledger anomalies in sample."
          : "Critical findings — investigate before increasing limits.",
    },
    latency_ms: Date.now() - t0,
  });
}


/* ─── Sandbox D1 cleanup (ADMIN_CLEANUP_SECRET required) ───
 * Temporary while AgentPay is in testing. Remove before real-user production.
 * Does NOT drop schema. Does NOT delete users / sessions / api_keys by default.
 * Clears ledger noise, held instruments, telemetry. Resets non-system balances to 0.
 */
async function handleAdminSandboxCleanup(request, env) {
  const t0 = Date.now();
  let body = {};
  try {
    body = await request.json();
  } catch {
    body = {};
  }

  const admin = await assertAdminSecret(request, env, body);
  if (!admin.ok) return admin.response;

  if (body.confirm !== true && body.confirm !== "SANDBOX_RESET") {
    return bad(
      request,
      'Send JSON { "secret":"…", "confirm": true } or confirm: "SANDBOX_RESET"',
      400,
      { code: "confirm_required" }
    );
  }

  // Anti-loop: max 3 cleanups / hour
  const rl = await checkRateLimit(env, "admin:sandbox-cleanup", 3, 3600);
  if (rl) {
    return bad(request, "Cleanup rate limit: max 3 per hour (anti-loop protection)", 429, {
      code: "cleanup_rate_limited",
      retry_after_sec: rl.retry_after_sec,
    });
  }

  const results = {};
  let wiped = 0;
  let skipped = 0;
  let failed = 0;

  async function wipe(label, sql) {
    try {
      const r = await env.DB.prepare(sql).run();
      const changes = (r.meta && r.meta.changes) || 0;
      results[label] = { ok: true, status: "wiped", changes };
      wiped += 1;
    } catch (e) {
      const msg = (e && e.message) || String(e);
      if (/no such table/i.test(msg)) {
        results[label] = { ok: true, status: "skipped", reason: "table_not_present" };
        skipped += 1;
      } else {
        results[label] = { ok: false, status: "error", error: msg };
        failed += 1;
      }
    }
  }

  await wipe("velocity_events", `DELETE FROM velocity_events`);
  await wipe("safety_events", `DELETE FROM safety_events`);
  await wipe("rate_limits", `DELETE FROM rate_limits WHERE bucket_key != 'admin:sandbox-cleanup'`);
  await wipe("webhook_deliveries", `DELETE FROM webhook_deliveries`);
  await wipe("idempotency", `DELETE FROM idempotency`);
  await wipe("rep_events", `DELETE FROM rep_events`);

  await wipe("transactions", `DELETE FROM transactions`);
  await wipe("escrows", `DELETE FROM escrows`);
  await wipe("streams", `DELETE FROM streams`);
  await wipe("sub_wallets", `DELETE FROM sub_wallets`);
  await wipe("payment_receipts", `DELETE FROM payment_receipts`);
  await wipe("payment_commits", `DELETE FROM payment_commits`);
  await wipe("commit_events", `DELETE FROM commit_events`);
  await wipe("capability_tickets", `DELETE FROM capability_tickets`);
  await wipe("ticket_events", `DELETE FROM ticket_events`);
  await wipe("intent_bonds", `DELETE FROM intent_bonds`);
  await wipe("bond_events", `DELETE FROM bond_events`);
  await wipe("payment_sagas", `DELETE FROM payment_sagas`);
  await wipe("saga_steps", `DELETE FROM saga_steps`);
  await wipe("saga_events", `DELETE FROM saga_events`);
  await wipe("netting_runs", `DELETE FROM netting_runs`);
  await wipe("netting_settlements", `DELETE FROM netting_settlements`);
  await wipe("clearing_batches", `DELETE FROM clearing_batches`);
  await wipe("clearing_positions", `DELETE FROM clearing_positions`);
  await wipe("work_claims", `DELETE FROM work_claims`);
  await wipe("work_attestations", `DELETE FROM work_attestations`);
  await wipe("work_events", `DELETE FROM work_events`);
  await wipe("continuity_sessions", `DELETE FROM continuity_sessions`);
  await wipe("continuity_events", `DELETE FROM continuity_events`);
  await wipe("pool_events", `DELETE FROM pool_events`);
  await wipe("pool_contributions", `DELETE FROM pool_contributions`);
  await wipe("collaborative_pools", `DELETE FROM collaborative_pools`);
  await wipe("shield_events", `DELETE FROM shield_events`);
  await wipe("edge_shield", `DELETE FROM edge_shield`);
  await wipe("agent_index", `DELETE FROM agent_index`);
  await wipe("delegation_events", `DELETE FROM delegation_events`);
  await wipe("delegations", `DELETE FROM delegations`);
  await wipe("dispute_events", `DELETE FROM dispute_events`);
  await wipe("dispute_arbiters", `DELETE FROM dispute_arbiters`);
  await wipe("work_disputes", `DELETE FROM work_disputes`);

  await wipe(
    "agent_limits_reset",
    `UPDATE agent_limits SET
       daily_spent = 0,
       daily_window_start = NULL,
       outstanding_credit = 0,
       locked = 0,
       locked_at = NULL,
       lock_reason = NULL,
       updated_at = datetime('now')`
  );

  await wipe(
    "accounts_zero",
    `UPDATE accounts SET balance = 0, updated_at = datetime('now')
     WHERE repo_id NOT LIKE 'system/%'`
  );

  if (body.wipe_keys === true) {
    await wipe(
      "api_keys_revoke",
      `UPDATE api_keys SET revoked_at = datetime('now')
       WHERE revoked_at IS NULL`
    );
  }

  try {
    await env.DB.prepare(
      `INSERT INTO safety_events (id, event, repo_id, api_key_id, user_id, reason, meta_json, created_at)
       VALUES (?1, 'sandbox.cleanup', NULL, NULL, NULL, ?2, ?3, datetime('now'))`
    )
      .bind(
        randomId(12),
        "operator_cleanup",
        JSON.stringify({ wiped, skipped, failed, wipe_keys: !!body.wipe_keys })
      )
      .run();
  } catch (_) {}

  return json(request, {
    ok: failed === 0,
    sandbox: true,
    message:
      failed === 0
        ? "Sandbox ledger cleaned. Users/sessions kept. Re-fund via Faucet. Max 3 cleanups/hour."
        : "Cleanup finished with some real errors (see results).",
    summary: {
      wiped,
      skipped_missing_tables: skipped,
      failed,
      note:
        skipped > 0
          ? "Skipped tables were never migrated — normal, not a problem."
          : undefined,
    },
    results,
    latency_ms: Date.now() - t0,
  });
}


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

function parseIntentTtl(body) {
  const sec = Number(body.ttl_seconds ?? body.ttl);
  if (Number.isFinite(sec)) {
    if (sec < INTENT_MIN_TTL_SEC || sec > INTENT_MAX_TTL_SEC) return null;
    return Math.floor(sec);
  }
  return INTENT_DEFAULT_TTL_SEC;
}

function parseAllowTo(v) {
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

function allowToList(raw) {
  if (!raw) return null;
  try {
    const arr = typeof raw === "string" ? JSON.parse(raw) : raw;
    return Array.isArray(arr) ? arr : null;
  } catch {
    return null;
  }
}

async function logIntentEvent(env, intentId, event, { actor_repo, amount, to_repo, note } = {}) {
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

async function loadIntent(env, id) {
  try {
    return await env.DB.prepare(`SELECT * FROM intent_capsules WHERE id = ?1`).bind(id).first();
  } catch {
    return null;
  }
}

async function handleIntentCreate(request, env, ctx) {
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

async function handleIntentSpend(request, env, ctx) {
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

async function handleIntentCancel(request, env, ctx) {
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

async function handleIntentGet(request, env, id) {
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

async function handleIntentList(request, url, env) {
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

async function expireIntentCapsules(env, ctx) {
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


/* ─── Hire Protocol (RFQ → Quote → Accept → Complete / Cancel) ───
 * POST /api/hire/rfq       { task, budget_usd, capability?, ttl_seconds?, buyer_repo? }
 * POST /api/hire/quote     { rfq_id, amount_usd, eta_seconds?, note?, provider_repo? }
 * POST /api/hire/accept    { quote_id }  — hold funds, open job
 * POST /api/hire/complete  { job_id }    — pay provider
 * POST /api/hire/cancel    { rfq_id? | job_id? }
 * GET  /api/hire           ?repo=&status=
 * GET  /api/hire/:id
 */

function parseHireTtl(body) {
  const sec = Number(body.ttl_seconds ?? body.ttl);
  if (Number.isFinite(sec)) {
    if (sec < HIRE_MIN_TTL_SEC || sec > HIRE_MAX_TTL_SEC) return null;
    return Math.floor(sec);
  }
  return HIRE_DEFAULT_TTL_SEC;
}

async function logHireEvent(env, { rfq_id, quote_id, job_id, event, actor_repo, amount, note } = {}) {
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

async function loadHireRfq(env, id) {
  try {
    return await env.DB.prepare(`SELECT * FROM hire_rfqs WHERE id = ?1`).bind(id).first();
  } catch {
    return null;
  }
}

async function loadHireQuote(env, id) {
  try {
    return await env.DB.prepare(`SELECT * FROM hire_quotes WHERE id = ?1`).bind(id).first();
  } catch {
    return null;
  }
}

async function loadHireJob(env, id) {
  try {
    return await env.DB.prepare(`SELECT * FROM hire_jobs WHERE id = ?1`).bind(id).first();
  } catch {
    return null;
  }
}

async function handleHireRfq(request, env, ctx) {
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

async function handleHireQuote(request, env, ctx) {
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

  // One open quote per provider per RFQ
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
    latency_ms: Date.now() - t0,
  });
}

async function handleHireAccept(request, env, ctx) {
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
    latency_ms: Date.now() - t0,
    hint: "Provider delivers work. Buyer POST /api/hire/complete { job_id } to pay out.",
  });
}

async function handleHireComplete(request, env, ctx) {
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

  const allowed =
    authUser.id === job.created_by ||
    (authUser.default_repo &&
      (authUser.default_repo === job.buyer_repo || authUser.default_repo === job.provider_repo));
  // Only buyer completes (pays out) — provider cannot self-release
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

async function handleHireCancel(request, env, ctx) {
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

  // Cancel held job → refund buyer
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

  // Cancel open RFQ
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

async function handleHireGet(request, env, id) {
  id = String(id || "").trim();
  if (!id) return bad(request, "id required");

  // Try RFQ first, then job
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

async function handleHireList(request, url, env) {
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

async function expireHireRfqs(env, ctx) {
  const t0 = Date.now();
  let expired = 0;
  let refundedJobs = 0;
  try {
    // Expire open RFQs
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

    // Note: held jobs are not auto-expired here (buyer must complete/cancel).
    // Optional future: TTL on jobs.
  } catch (e) {
    return { expired: 0, error: e.message, latency_ms: Date.now() - t0 };
  }
  return { expired, refunded_jobs: refundedJobs, latency_ms: Date.now() - t0 };
}


/* ─── Standing Orders (recurring micro-pays) ───
 * POST /api/standing/open   { from_repo?, to_repo, amount, interval_sec, max_runs?, budget_usd?, ttl_seconds?, task?, label? }
 * POST /api/standing/cancel { id }
 * POST /api/standing/pause  { id }
 * POST /api/standing/resume { id }
 * GET  /api/standing        ?repo=&status=
 * GET  /api/standing/:id
 * Cron: processStandingOrders — debit + pay when next_run_at due
 */

function parseStandingInterval(body) {
  const sec = Number(body.interval_sec ?? body.interval);
  if (!Number.isFinite(sec)) return STANDING_DEFAULT_INTERVAL_SEC;
  if (sec < STANDING_MIN_INTERVAL_SEC || sec > STANDING_MAX_INTERVAL_SEC) return null;
  return Math.floor(sec);
}

function parseStandingTtl(body) {
  const sec = Number(body.ttl_seconds ?? body.ttl);
  if (!Number.isFinite(sec)) return STANDING_DEFAULT_TTL_SEC;
  if (sec < STANDING_MIN_TTL_SEC || sec > STANDING_MAX_TTL_SEC) return null;
  return Math.floor(sec);
}

async function logStandingEvent(env, orderId, event, { amount, note } = {}) {
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

async function loadStanding(env, id) {
  try {
    return await env.DB.prepare(`SELECT * FROM standing_orders WHERE id = ?1`).bind(id).first();
  } catch {
    return null;
  }
}

async function handleStandingOpen(request, env, ctx) {
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

async function handleStandingCancel(request, env, ctx) {
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

async function handleStandingPause(request, env, ctx) {
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

async function handleStandingResume(request, env, ctx) {
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

async function handleStandingGet(request, env, id) {
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

async function handleStandingList(request, url, env) {
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
async function runStandingOnce(env, row, ctx) {
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

async function processStandingOrders(env, ctx) {
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


/* ─── Delegation chains (parent authority / child pocket money) ───
 * Parent locks budget → system/delegate. Child API key spends with:
 *   Authorization: Bearer a2a_…child_key
 *   X-Delegate-Id: dg_…
 * Constraints: allow_to, task_prefix, max_per_spend, remaining, TTL.
 * Parent revokes instantly. Extends intent + policy + colo bind on the key.
 *
 * POST /api/delegate/open   { parent_repo?, child_key_id, budget, allow_to?, task_prefix?, max_per_spend?, ttl_seconds?, label?, child_repo? }
 * POST /api/delegate/revoke { id }
 * GET  /api/delegate        ?repo=&status=
 * GET  /api/delegate/:id
 * Cron: expireDelegations
 */

function parseDelegateTtl(body) {
  const sec = Number(body.ttl_seconds ?? body.ttl);
  if (Number.isFinite(sec)) {
    if (sec < DELEGATE_MIN_TTL_SEC || sec > DELEGATE_MAX_TTL_SEC) return null;
    return Math.floor(sec);
  }
  return DELEGATE_DEFAULT_TTL_SEC;
}

function parseDelegateAllowTo(v) {
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
  const list = s.split(",").map((x) => parseRepo(x.trim())).filter(Boolean);
  return list.length ? JSON.stringify(list) : null;
}

function delegateAllowToList(raw) {
  if (!raw) return null;
  try {
    const arr = typeof raw === "string" ? JSON.parse(raw) : raw;
    return Array.isArray(arr) ? arr : null;
  } catch {
    return null;
  }
}

async function logDelegateEvent(env, delegationId, event, { actor_repo, amount, to_repo, note } = {}) {
  try {
    await env.DB.prepare(
      `INSERT INTO delegation_events (id, delegation_id, event, actor_repo, amount, to_repo, note, created_at)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, datetime('now'))`
    )
      .bind(
        randomId(10),
        delegationId,
        event,
        actor_repo || null,
        amount != null ? Number(amount) : null,
        to_repo || null,
        note ? String(note).slice(0, 500) : null
      )
      .run();
  } catch (e) {
    console.log("delegate_event_err", e && e.message);
  }
}

async function loadDelegation(env, id) {
  try {
    return await env.DB.prepare(`SELECT * FROM delegations WHERE id = ?1`).bind(id).first();
  } catch {
    return null;
  }
}

/**
 * Resolve and claim a spend against a delegation.
 * Returns { ok, delegation, remaining } or { ok:false, error, code, status? }.
 */
async function claimDelegationSpend(env, { id, childKeyId, toRepo, amount, task }) {
  const row = await loadDelegation(env, id);
  if (!row) {
    try {
      await env.DB.prepare(`SELECT 1 FROM delegations LIMIT 1`).first();
    } catch {
      return { ok: false, error: "delegations table missing — run d1-delegate-migration.sql", code: "table_missing" };
    }
    return { ok: false, error: "Delegation not found", code: "not_found" };
  }
  if (row.status !== "open") {
    return { ok: false, error: "Delegation not open (status=" + row.status + ")", code: "delegate_closed", status: row.status };
  }
  if (String(row.child_key_id) !== String(childKeyId)) {
    return { ok: false, error: "API key is not the delegated child key", code: "delegate_key_mismatch" };
  }
  if (row.expires_at) {
    const expMs = Date.parse(String(row.expires_at).replace(" ", "T") + "Z");
    if (Number.isFinite(expMs) && expMs < Date.now()) {
      return { ok: false, error: "Delegation expired", code: "delegate_expired" };
    }
  }
  const allow = delegateAllowToList(row.allow_to);
  if (allow && allow.length && !allow.includes(toRepo)) {
    return { ok: false, error: "to_repo not in delegation allow_to", code: "delegate_allow_to", allow_to: allow };
  }
  if (row.task_prefix) {
    const pref = String(row.task_prefix);
    if (!String(task || "").startsWith(pref)) {
      return { ok: false, error: 'task must start with prefix "' + pref + '"', code: "delegate_task_prefix" };
    }
  }
  if (row.max_per_spend != null && amount > Number(row.max_per_spend)) {
    return {
      ok: false,
      error: "amount exceeds max_per_spend ($" + row.max_per_spend + ")",
      code: "delegate_max_per_spend",
    };
  }
  const remaining = Number(row.remaining_usd || 0);
  if (amount > remaining) {
    return {
      ok: false,
      error: "Insufficient delegation remaining ($" + remaining.toFixed(6) + ")",
      code: "delegate_insufficient",
      remaining_usd: remaining,
    };
  }

  const claim = await env.DB.prepare(
    `UPDATE delegations
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
    return { ok: false, error: "Delegation spend race or insufficient remaining", code: "delegate_race" };
  }
  return { ok: true, delegation: claim, remaining: Number(claim.remaining_usd) };
}

async function handleDelegateOpen(request, env, ctx) {
  const t0 = Date.now();
  const authUser = await getAuthUser(request, env);
  if (!authUser) return bad(request, "Sign in or API key required", 401);

  const rlId =
    authUser.auth_via === "api_key"
      ? "dg:key:" + (authUser.key_id || authUser.id)
      : "dg:user:" + authUser.id;
  const limited = await checkRateLimit(env, rlId, RL_DELEGATE_MAX, RL_DELEGATE_WINDOW_SEC);
  if (limited) {
    return bad(request, "Rate limit: delegate ops", 429, { retry_after_sec: limited.retry_after_sec });
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return bad(request, "Invalid JSON body");
  }

  let parentRepo = parseRepo(body.parent_repo || body.from_repo || body.parent);
  if (!parentRepo && authUser.default_repo) parentRepo = parseRepo(authUser.default_repo);
  const childKeyId = String(body.child_key_id || body.key_id || body.child_key || "").trim();
  const childRepo = body.child_repo ? parseRepo(body.child_repo) : null;
  const budget = parseAmount(body.budget ?? body.amount ?? body.budget_usd);
  const ttlSec = parseDelegateTtl(body);
  const allowTo = parseDelegateAllowTo(body.allow_to ?? body.allowTo ?? body.to_allow);
  const taskPrefix =
    body.task_prefix != null
      ? String(body.task_prefix).slice(0, 120)
      : body.taskPrefix != null
        ? String(body.taskPrefix).slice(0, 120)
        : null;
  let maxPer =
    body.max_per_spend != null
      ? parseAmount(body.max_per_spend)
      : body.maxPerSpend != null
        ? parseAmount(body.maxPerSpend)
        : null;
  if (body.max_per_spend === "" || body.max_per_spend === null) maxPer = null;
  const label = body.label ? String(body.label).slice(0, 200) : null;

  if (!parentRepo) return bad(request, "parent_repo required (or set default agent)");
  if (!childKeyId) return bad(request, "child_key_id required (API key id from /api/me/keys)");
  if (budget == null || budget < DELEGATE_MIN || budget > DELEGATE_MAX) {
    return bad(request, "budget invalid");
  }
  if (ttlSec == null) return bad(request, "ttl_seconds out of range");
  if (maxPer != null && (maxPer < DELEGATE_MIN || maxPer > budget)) {
    return bad(request, "max_per_spend must be between min amount and budget");
  }

  // Child key must exist, active, and belong to same user (family of keys)
  let keyRow;
  try {
    keyRow = await env.DB.prepare(
      `SELECT id, user_id, revoked_at, suspended_at, label, key_prefix
       FROM api_keys WHERE id = ?1`
    )
      .bind(childKeyId)
      .first();
  } catch {
    return bad(request, "api_keys lookup failed", 500);
  }
  if (!keyRow || keyRow.revoked_at) {
    return bad(request, "child_key_id not found or revoked", 404, { code: "child_key_missing" });
  }
  if (keyRow.suspended_at) {
    return bad(request, "child API key is suspended", 403, { code: "child_key_suspended" });
  }
  if (String(keyRow.user_id) !== String(authUser.id)) {
    return bad(request, "child_key_id must belong to your account (same family)", 403, {
      code: "child_key_not_yours",
    });
  }

  authUser._policyCtx = { to_repo: SYSTEM_DELEGATE, task: "delegate:open" };
  const blocked = await safetyGate(request, env, authUser, parentRepo, budget);
  if (blocked) return blocked;

  const debitRes = await debitWithCredit(env, parentRepo, budget);
  if (!debitRes.ok) {
    return bad(request, debitRes.error || "Insufficient funds", debitRes.code === "wallet_locked" ? 403 : 402, {
      code: debitRes.code || "insufficient",
      available_credit: debitRes.available_credit,
    });
  }

  const id = "dg_" + randomId(12);
  const modifier = "+" + ttlSec + " seconds";

  try {
    await ensureAccount(env, SYSTEM_DELEGATE);
    await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO delegations (
           id, parent_repo, child_key_id, child_repo, budget_usd, remaining_usd,
           allow_to, task_prefix, max_per_spend, status, ttl_seconds, expires_at,
           label, created_by, created_at, updated_at
         ) VALUES (
           ?1, ?2, ?3, ?4, ?5, ?5,
           ?6, ?7, ?8, 'open', ?9, datetime('now', ?10),
           ?11, ?12, datetime('now'), datetime('now')
         )`
      ).bind(
        id,
        parentRepo,
        childKeyId,
        childRepo,
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
      ).bind(parentRepo, SYSTEM_DELEGATE, budget, "delegate-open:" + id, Date.now() - t0),
    ]);
  } catch (e) {
    await env.DB.prepare(
      `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
    )
      .bind(budget, parentRepo)
      .run()
      .catch(() => {});
    if (debitRes.credit_drawn > 0) {
      await env.DB.prepare(
        `UPDATE agent_limits
         SET outstanding_credit = MAX(0, COALESCE(outstanding_credit, 0) - ?2),
             updated_at = datetime('now')
         WHERE repo_id = ?1`
      )
        .bind(parentRepo, debitRes.credit_drawn)
        .run()
        .catch(() => {});
    }
    return bad(
      request,
      "delegations table missing — run d1-delegate-migration.sql: " + (e.message || e),
      500
    );
  }

  await safetyRecordSpend(env, authUser, parentRepo, budget);
  await logDelegateEvent(env, id, "opened", {
    actor_repo: parentRepo,
    amount: budget,
    note: label || ("key:" + (keyRow.key_prefix || childKeyId)),
  });

  if (authUser.id) {
    scheduleWebhook(ctx, env, authUser.id, "delegate.opened", {
      id,
      parent_repo: parentRepo,
      child_key_id: childKeyId,
      child_repo: childRepo,
      budget_usd: budget,
      remaining_usd: budget,
      allow_to: delegateAllowToList(allowTo),
      task_prefix: taskPrefix,
      max_per_spend: maxPer,
      ttl_seconds: ttlSec,
      status: "open",
    });
  }

  return json(request, {
    ok: true,
    delegation: {
      id,
      parent_repo: parentRepo,
      child_key_id: childKeyId,
      child_key_prefix: keyRow.key_prefix || null,
      child_repo: childRepo,
      budget_usd: budget,
      remaining_usd: budget,
      allow_to: delegateAllowToList(allowTo),
      task_prefix: taskPrefix,
      max_per_spend: maxPer,
      status: "open",
      ttl_seconds: ttlSec,
      label,
    },
    latency_ms: Date.now() - t0,
    hint:
      "Child pays with Authorization: Bearer <child_key> and header X-Delegate-Id: " +
      id +
      ". Revoke anytime via POST /api/delegate/revoke.",
  });
}

async function handleDelegateRevoke(request, env, ctx) {
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

  const row = await loadDelegation(env, id);
  if (!row) return bad(request, "Delegation not found", 404);
  if (row.status !== "open") {
    return bad(request, "Delegation not open (status=" + row.status + ")", 400);
  }

  const allowed =
    authUser.id === row.created_by ||
    (authUser.default_repo && authUser.default_repo === row.parent_repo);
  if (!allowed) return bad(request, "Not authorized to revoke this delegation", 403);

  const claim = await env.DB.prepare(
    `UPDATE delegations
     SET status = 'revoked', revoked_at = datetime('now'), closed_at = datetime('now'), updated_at = datetime('now')
     WHERE id = ?1 AND status = 'open'
     RETURNING *`
  )
    .bind(id)
    .first();
  if (!claim) return bad(request, "Revoke race", 409);

  const refund = Number(claim.remaining_usd || 0);
  if (refund > 0) {
    await ensureAccount(env, row.parent_repo);
    await ensureAccount(env, SYSTEM_DELEGATE);
    await env.DB.batch([
      env.DB.prepare(
        `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
      ).bind(refund, row.parent_repo),
      env.DB.prepare(
        `UPDATE delegations SET remaining_usd = 0, updated_at = datetime('now') WHERE id = ?1`
      ).bind(id),
      env.DB.prepare(
        `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
         VALUES (?1, ?2, ?3, ?4, 'success', ?5)`
      ).bind(SYSTEM_DELEGATE, row.parent_repo, refund, "delegate-revoke-refund:" + id, Date.now() - t0),
    ]);
  }

  await logDelegateEvent(env, id, "revoked", {
    actor_repo: row.parent_repo,
    amount: refund,
    note: "parent_revoke",
  });

  if (row.created_by) {
    scheduleWebhook(ctx, env, row.created_by, "delegate.revoked", {
      id,
      parent_repo: row.parent_repo,
      child_key_id: row.child_key_id,
      refunded: refund,
      status: "revoked",
    });
  }

  return json(request, {
    ok: true,
    id,
    status: "revoked",
    refunded: refund,
    latency_ms: Date.now() - t0,
  });
}

async function handleDelegateGet(request, env, id) {
  id = String(id || "").trim();
  if (!id) return bad(request, "id required");
  const row = await loadDelegation(env, id);
  if (!row) {
    try {
      await env.DB.prepare(`SELECT 1 FROM delegations LIMIT 1`).first();
    } catch {
      return bad(request, "delegations table missing — run d1-delegate-migration.sql", 500);
    }
    return bad(request, "Delegation not found", 404);
  }
  let events = [];
  try {
    const q = await env.DB.prepare(
      `SELECT event, actor_repo, amount, to_repo, note, created_at
       FROM delegation_events WHERE delegation_id = ?1 ORDER BY created_at DESC LIMIT 40`
    )
      .bind(id)
      .all();
    events = q.results || [];
  } catch (_) {}
  return json(request, {
    ok: true,
    delegation: {
      ...row,
      allow_to: delegateAllowToList(row.allow_to),
    },
    events,
  });
}

async function handleDelegateList(request, url, env) {
  const limit = Math.min(Math.max(Number(url.searchParams.get("limit") || 20), 1), 100);
  const repo = (url.searchParams.get("repo") || "").trim();
  const status = (url.searchParams.get("status") || "").trim();
  const keyId = (url.searchParams.get("child_key_id") || url.searchParams.get("key_id") || "").trim();

  let sql = `SELECT id, parent_repo, child_key_id, child_repo, budget_usd, remaining_usd,
                    allow_to, task_prefix, max_per_spend, status, ttl_seconds, expires_at, label, created_at
             FROM delegations WHERE 1=1`;
  const binds = [];
  if (repo) {
    if (!parseRepo(repo)) return bad(request, "repo must be owner/repo");
    sql += ` AND parent_repo = ?`;
    binds.push(repo);
  }
  if (keyId) {
    sql += ` AND child_key_id = ?`;
    binds.push(keyId);
  }
  if (status && ["open", "depleted", "revoked", "expired"].includes(status)) {
    sql += ` AND status = ?`;
    binds.push(status);
  }
  sql += ` ORDER BY created_at DESC LIMIT ?`;
  binds.push(limit);

  try {
    const { results } = await env.DB.prepare(sql).bind(...binds).all();
    const rows = (results || []).map((r) => ({
      ...r,
      allow_to: delegateAllowToList(r.allow_to),
    }));
    return json(request, { ok: true, count: rows.length, delegations: rows });
  } catch (e) {
    return bad(
      request,
      "delegations table missing — run d1-delegate-migration.sql: " + (e.message || e),
      500
    );
  }
}

async function expireDelegations(env, ctx) {
  const t0 = Date.now();
  let expired = 0;
  let refundedTotal = 0;
  try {
    const q = await env.DB.prepare(
      `SELECT * FROM delegations
       WHERE status = 'open'
         AND expires_at IS NOT NULL
         AND expires_at < datetime('now')
       ORDER BY expires_at ASC LIMIT ?1`
    )
      .bind(EXPIRE_DELEGATE_BATCH)
      .all();
    for (const row of q.results || []) {
      try {
        const claim = await env.DB.prepare(
          `UPDATE delegations
           SET status = 'expired', closed_at = datetime('now'), updated_at = datetime('now')
           WHERE id = ?1 AND status = 'open' RETURNING *`
        )
          .bind(row.id)
          .first();
        if (!claim) continue;
        const refund = Number(claim.remaining_usd || 0);
        if (refund > 0) {
          await ensureAccount(env, row.parent_repo);
          await env.DB.batch([
            env.DB.prepare(
              `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
            ).bind(refund, row.parent_repo),
            env.DB.prepare(
              `UPDATE delegations SET remaining_usd = 0, updated_at = datetime('now') WHERE id = ?1`
            ).bind(row.id),
            env.DB.prepare(
              `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
               VALUES (?1, ?2, ?3, ?4, 'success', 0)`
            ).bind(SYSTEM_DELEGATE, row.parent_repo, refund, "delegate-expire-refund:" + row.id),
          ]);
          refundedTotal += refund;
        }
        await logDelegateEvent(env, row.id, "expired", {
          actor_repo: row.parent_repo,
          amount: refund,
          note: "ttl",
        });
        expired += 1;
        if (row.created_by) {
          scheduleWebhook(ctx, env, row.created_by, "delegate.expired", {
            id: row.id,
            parent_repo: row.parent_repo,
            refunded: refund,
            status: "expired",
          });
        }
      } catch (e) {
        console.log("delegate_expire", row.id, e && e.message);
      }
    }
  } catch (e) {
    return { expired: 0, error: e.message, latency_ms: Date.now() - t0 };
  }
  return { expired, refunded_total: refundedTotal, latency_ms: Date.now() - t0 };
}


export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: { ...securityHeaders(), ...corsHeaders(request) },
      });
    }

    // Early body-size gate (Content-Length) — bank-grade abuse resistance
    const oversized = rejectOversizedBody(request);
    if (oversized) return oversized;

    // Global per-IP POST budget (in addition to route-level RL)
    if (request.method === "POST") {
      try {
        const ip = clientIp(request);
        const ipRl = await checkRateLimit(
          env,
          "ip:post:" + ip,
          RL_IP_POST_MAX,
          RL_IP_POST_WINDOW_SEC
        );
        if (ipRl) {
          return bad(request, "Too many requests from this IP", 429, {
            code: "ip_rate_limited",
            retry_after_sec: ipRl.retry_after_sec,
          });
        }
      } catch (e) {
        console.log("ip_rl_error", e && e.message);
      }
    }

    try {
      if (request.method === "GET" && url.pathname === "/api/security/status") {
        return await handleSecurityStatus(request, env);
      }
      if (request.method === "POST" && url.pathname === "/api/admin/integrity") {
        return await handleAdminIntegrity(request, env);
      }

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
      if (request.method === "GET" && url.pathname === "/api/auth/gitlab") {
        return handleAuthGitlabStart(request, env, url);
      }
      if (request.method === "GET" && url.pathname === "/api/auth/gitlab/callback") {
        return await handleAuthGitlabCallback(request, env, url);
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
      if (request.method === "GET" && url.pathname === "/api/me/gitlab/repos") {
        return await handleMeGitlabRepos(request, env);
      }
      if (request.method === "GET" && url.pathname === "/api/me/repos") {
        return await handleMeReposUnified(request, env);
      }
      if (request.method === "GET" && url.pathname === "/api/agents") {
        return await handleAgentsList(request, url, env);
      }
      if (request.method === "GET" && url.pathname === "/api/agents/search") {
        return await handleAgentsSearch(request, url, env);
      }
      if (request.method === "GET" && url.pathname === "/api/agents/rank") {
        return await handleAgentsRank(request, url, env);
      }
      if (request.method === "POST" && url.pathname === "/api/agents/scan") {
        return await handleAgentsScan(request, env, ctx);
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
      if (request.method === "POST" && url.pathname === "/api/me/keys/bind") {
        return await handleMeKeysBind(request, env);
      }
      if (request.method === "POST" && url.pathname === "/api/me/keys/unbind") {
        return await handleMeKeysUnbind(request, env);
      }
      if (request.method === "GET" && url.pathname === "/api/me/key") {
        return await handleMeKeySelf(request, env);
      }
      if (request.method === "GET" && url.pathname === "/api/edge") {
        return await handleEdgeInfo(request, env);
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
        return await handleEscrowHold(request, env, ctx);
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
      
      if (request.method === "POST" && url.pathname === "/api/admin/sandbox-cleanup") {
        return await handleAdminSandboxCleanup(request, env);
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

      if (request.method === "GET" && url.pathname.startsWith("/api/trace/")) {
        const tid = url.pathname.slice("/api/trace/".length).replace(/\/$/, "");
        if (tid && tid !== "verify") return await handleTraceGet(request, env, tid);
      }

      if (request.method === "POST" && url.pathname === "/api/netting/run") {
        return await handleNettingRun(request, env);
      }
      if (request.method === "GET" && url.pathname === "/api/netting") {
        return await handleNettingList(request, url, env);
      }

      if (request.method === "POST" && url.pathname === "/api/clearing/run") {
        return await handleClearingRun(request, env, ctx);
      }
      if (request.method === "GET" && url.pathname === "/api/clearing") {
        return await handleClearingList(request, url, env);
      }
      if (request.method === "GET" && url.pathname.startsWith("/api/clearing/")) {
        const cid = url.pathname.slice("/api/clearing/".length).replace(/\/$/, "");
        if (cid && cid !== "run") {
          return await handleClearingGet(request, env, cid);
        }
      }


      if (request.method === "POST" && url.pathname === "/api/dispute/open") {
        return await handleDisputeOpen(request, env, ctx);
      }
      if (request.method === "POST" && url.pathname === "/api/dispute/accept") {
        return await handleDisputeAccept(request, env, ctx);
      }
      if (request.method === "POST" && url.pathname === "/api/dispute/vote") {
        return await handleDisputeVote(request, env, ctx);
      }
      if (request.method === "POST" && url.pathname === "/api/dispute/execute") {
        return await handleDisputeExecute(request, env, ctx);
      }
      if (request.method === "POST" && url.pathname === "/api/dispute/cancel") {
        return await handleDisputeCancel(request, env, ctx);
      }
      if (request.method === "GET" && url.pathname === "/api/dispute") {
        return await handleDisputeList(request, url, env);
      }
      if (request.method === "GET" && url.pathname.startsWith("/api/dispute/")) {
        const did = url.pathname.slice("/api/dispute/".length).replace(/\/$/, "");
        if (did && !did.includes("/")) return await handleDisputeGet(request, env, did);
      }

      if (request.method === "POST" && url.pathname === "/api/work/claim") {
        return await handleWorkClaim(request, env, ctx);
      }
      if (request.method === "POST" && url.pathname === "/api/work/lock") {
        return await handleWorkLock(request, env, ctx);
      }
      if (request.method === "POST" && url.pathname === "/api/work/attest") {
        return await handleWorkAttest(request, env, ctx);
      }
      if (request.method === "POST" && url.pathname === "/api/work/settle") {
        return await handleWorkSettle(request, env, ctx);
      }
      if (request.method === "POST" && url.pathname === "/api/work/refund") {
        return await handleWorkRefund(request, env, ctx);
      }
      if (request.method === "GET" && url.pathname === "/api/work") {
        return await handleWorkList(request, url, env);
      }
      if (request.method === "GET" && url.pathname.startsWith("/api/work/")) {
        const wid = url.pathname.slice("/api/work/".length).replace(/\/$/, "");
        if (wid && !["claim", "lock", "attest", "settle", "refund"].includes(wid)) {
          return await handleWorkGet(request, env, wid);
        }
      }

      /* Collaborative pools (swarm co-funding) */
      if (request.method === "POST" && url.pathname === "/api/pool/open") {
        return await handlePoolOpen(request, env, ctx);
      }
      if (request.method === "POST" && url.pathname === "/api/pool/contribute") {
        return await handlePoolContribute(request, env, ctx);
      }
      if (request.method === "POST" && url.pathname === "/api/pool/release") {
        return await handlePoolRelease(request, env, ctx);
      }
      if (request.method === "POST" && url.pathname === "/api/pool/refund") {
        return await handlePoolRefund(request, env, ctx);
      }
      if (request.method === "GET" && url.pathname === "/api/pool") {
        return await handlePoolList(request, url, env);
      }
      if (request.method === "GET" && url.pathname.startsWith("/api/pool/")) {
        const pid = url.pathname.slice("/api/pool/".length).replace(/\/$/, "");
        if (pid && !["open", "contribute", "release", "refund"].includes(pid)) {
          return await handlePoolGet(request, env, pid);
        }
      }

      if (request.method === "POST" && url.pathname === "/api/continuity/open") {
        return await handleContinuityOpen(request, env, ctx);
      }
      if (request.method === "POST" && url.pathname === "/api/continuity/beat") {
        return await handleContinuityBeat(request, env, ctx);
      }
      if (request.method === "POST" && url.pathname === "/api/continuity/close") {
        return await handleContinuityClose(request, env, ctx);
      }
      if (request.method === "POST" && url.pathname === "/api/continuity/recover") {
        return await handleContinuityRecover(request, env, ctx);
      }
      if (request.method === "GET" && url.pathname === "/api/continuity") {
        return await handleContinuityList(request, url, env);
      }
      if (request.method === "GET" && url.pathname.startsWith("/api/continuity/")) {
        const cid = url.pathname.slice("/api/continuity/".length).replace(/\/$/, "");
        if (cid && !["open", "beat", "close", "recover"].includes(cid)) {
          return await handleContinuityGet(request, env, cid);
        }
      }

      if (request.method === "POST" && url.pathname === "/api/ticket/mint") {
        return await handleTicketMint(request, env);
      }
      if (request.method === "POST" && url.pathname === "/api/ticket/transfer") {
        return await handleTicketTransfer(request, env);
      }
      if (request.method === "POST" && url.pathname === "/api/ticket/redeem") {
        return await handleTicketRedeem(request, env);
      }
      if (request.method === "GET" && url.pathname === "/api/ticket") {
        return await handleTicketList(request, url, env);
      }
      if (request.method === "GET" && url.pathname.startsWith("/api/ticket/")) {
        const tid = url.pathname.slice("/api/ticket/".length).replace(/\/$/, "");
        if (tid && !["mint", "transfer", "redeem"].includes(tid)) {
          return await handleTicketGet(request, env, tid);
        }
      }

      if (request.method === "POST" && url.pathname === "/api/bond/post") {
        return await handleBondPost(request, env, ctx);
      }
      if (request.method === "POST" && url.pathname === "/api/bond/match") {
        return await handleBondMatch(request, env, ctx);
      }
      if (request.method === "POST" && url.pathname === "/api/bond/fulfill") {
        return await handleBondFulfill(request, env, ctx);
      }
      if (request.method === "POST" && url.pathname === "/api/bond/slash") {
        return await handleBondSlash(request, env, ctx);
      }
      if (request.method === "POST" && url.pathname === "/api/bond/cancel") {
        return await handleBondCancel(request, env, ctx);
      }
      if (request.method === "GET" && url.pathname === "/api/bond") {
        return await handleBondList(request, url, env);
      }
      if (request.method === "GET" && url.pathname.startsWith("/api/bond/")) {
        const bid = url.pathname.slice("/api/bond/".length).replace(/\/$/, "");
        if (bid && !["post", "match", "fulfill", "slash", "cancel"].includes(bid)) {
          return await handleBondGet(request, env, bid);
        }
      }

      if (request.method === "POST" && url.pathname === "/api/saga/start") {
        return await handleSagaStart(request, env, ctx);
      }
      if (request.method === "POST" && url.pathname === "/api/saga/advance") {
        return await handleSagaAdvance(request, env, ctx);
      }
      if (request.method === "POST" && url.pathname === "/api/saga/compensate") {
        return await handleSagaCompensate(request, env, ctx);
      }
      if (request.method === "POST" && url.pathname === "/api/saga/cancel") {
        return await handleSagaCancel(request, env, ctx);
      }
      if (request.method === "GET" && url.pathname === "/api/saga") {
        return await handleSagaList(request, url, env);
      }
      if (request.method === "GET" && url.pathname.startsWith("/api/saga/")) {
        const sid = url.pathname.slice("/api/saga/".length).replace(/\/$/, "");
        if (sid && !["start", "advance", "compensate", "cancel"].includes(sid)) {
          return await handleSagaGet(request, env, sid);
        }
      }

      
      if (request.method === "GET" && url.pathname === "/api/shield") {
        return await handleShieldPublic(request, env);
      }
      if (request.method === "GET" && url.pathname === "/api/me/shield") {
        return await handleMeShieldGet(request, env);
      }
      if (request.method === "POST" && url.pathname === "/api/me/shield/release") {
        return await handleMeShieldRelease(request, env);
      }
      if (request.method === "POST" && url.pathname === "/api/admin/shield") {
        return await handleAdminShield(request, env);
      }

      if (request.method === "POST" && url.pathname === "/api/intent/create") {
        return await handleIntentCreate(request, env, ctx);
      }
      if (request.method === "POST" && url.pathname === "/api/intent/spend") {
        return await handleIntentSpend(request, env, ctx);
      }
      if (request.method === "POST" && url.pathname === "/api/intent/cancel") {
        return await handleIntentCancel(request, env, ctx);
      }
      if (request.method === "GET" && url.pathname === "/api/intent") {
        return await handleIntentList(request, url, env);
      }
      if (request.method === "GET" && url.pathname.startsWith("/api/intent/")) {
        const iid = url.pathname.slice("/api/intent/".length).replace(/\/$/, "");
        if (iid && !["create", "spend", "cancel"].includes(iid)) {
          return await handleIntentGet(request, env, iid);
        }
      }

      if (request.method === "POST" && url.pathname === "/api/hire/rfq") {
        return await handleHireRfq(request, env, ctx);
      }
      if (request.method === "POST" && url.pathname === "/api/hire/quote") {
        return await handleHireQuote(request, env, ctx);
      }
      if (request.method === "POST" && url.pathname === "/api/hire/accept") {
        return await handleHireAccept(request, env, ctx);
      }
      if (request.method === "POST" && url.pathname === "/api/hire/complete") {
        return await handleHireComplete(request, env, ctx);
      }
      if (request.method === "POST" && url.pathname === "/api/hire/cancel") {
        return await handleHireCancel(request, env, ctx);
      }
      if (request.method === "GET" && url.pathname === "/api/hire") {
        return await handleHireList(request, url, env);
      }
      if (request.method === "GET" && url.pathname.startsWith("/api/hire/")) {
        const hid = url.pathname.slice("/api/hire/".length).replace(/\/$/, "");
        if (hid && !["rfq", "quote", "accept", "complete", "cancel"].includes(hid)) {
          return await handleHireGet(request, env, hid);
        }
      }

      if (request.method === "POST" && url.pathname === "/api/standing/open") {
        return await handleStandingOpen(request, env, ctx);
      }
      if (request.method === "POST" && url.pathname === "/api/standing/cancel") {
        return await handleStandingCancel(request, env, ctx);
      }
      if (request.method === "POST" && url.pathname === "/api/standing/pause") {
        return await handleStandingPause(request, env, ctx);
      }
      if (request.method === "POST" && url.pathname === "/api/standing/resume") {
        return await handleStandingResume(request, env, ctx);
      }
      if (request.method === "GET" && url.pathname === "/api/standing") {
        return await handleStandingList(request, url, env);
      }
      if (request.method === "GET" && url.pathname.startsWith("/api/standing/")) {
        const sid = url.pathname.slice("/api/standing/".length).replace(/\/$/, "");
        if (sid && !["open", "cancel", "pause", "resume"].includes(sid)) {
          return await handleStandingGet(request, env, sid);
        }
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

      if (request.method === "GET" && url.pathname === "/api/me/credit") {
        return await handleMeCreditGet(request, env);
      }
      if (request.method === "POST" && url.pathname === "/api/me/credit") {
        return await handleMeCreditSet(request, env);
      }
      if (request.method === "POST" && url.pathname === "/api/me/credit/repay") {
        return await handleMeCreditRepay(request, env);
      }

      if (request.method === "POST" && url.pathname === "/api/commit") {
        return await handleCommitCreate(request, env, ctx);
      }
      if (request.method === "POST" && url.pathname === "/api/commit/reveal") {
        return await handleCommitReveal(request, env, ctx);
      }
      if (request.method === "POST" && url.pathname === "/api/commit/cancel") {
        return await handleCommitCancel(request, env, ctx);
      }
      if (request.method === "GET" && url.pathname === "/api/commit") {
        return await handleCommitList(request, url, env);
      }
      if (request.method === "GET" && url.pathname.startsWith("/api/commit/")) {
        const cid = url.pathname.slice("/api/commit/".length).replace(/\/$/, "");
        if (cid && !["reveal", "cancel"].includes(cid)) {
          return await handleCommitGet(request, env, cid);
        }
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
            me_gitlab_repos: "GET /api/me/gitlab/repos",
            me_repos: "GET /api/me/repos",
            agents: "GET /api/agents",
            agents_search: "GET /api/agents/search",
            agents_rank: "GET /api/agents/rank",
            agents_scan: "POST /api/agents/scan",
            me_keys: "GET|POST /api/me/keys",
            me_keys_bind: "POST /api/me/keys/bind",
            me_keys_unbind: "POST /api/me/keys/unbind",
            me_key: "GET /api/me/key",
            edge: "GET /api/edge",
            me_webhook: "GET|POST /api/me/webhook",
            me_webhook_clear: "POST /api/me/webhook/clear",
            me_webhook_deliveries: "GET /api/me/webhook/deliveries",
            escrow_hold: "POST /api/escrow/hold",
            escrow_release: "POST /api/escrow/release",
            escrow_refund: "POST /api/escrow/refund",
            escrow_list: "GET /api/escrow",
            escrow_expire_now: "POST /api/escrow/expire-now",
            standing_open: "POST /api/standing/open",
            standing_cancel: "POST /api/standing/cancel",
            standing_list: "GET /api/standing",
            stream_start: "POST /api/stream/start",
            stream_meter: "POST /api/stream/meter",
            stream_stop: "POST /api/stream/stop",
            stream_list: "GET /api/stream",
            me_safety: "GET|POST /api/me/safety",
            me_safety_unlock: "POST /api/me/safety/unlock",
            shield: "GET /api/shield",
            me_shield: "GET /api/me/shield",
            me_shield_release: "POST /api/me/shield/release",
            admin_shield: "POST /api/admin/shield",
            me_keys_unsuspend: "POST /api/me/keys/unsuspend",
            subwallet_open: "POST /api/subwallet/open",
            subwallet_spend: "POST /api/subwallet/spend",
            subwallet_close: "POST /api/subwallet/close",
            subwallet_list: "GET /api/subwallet",
            intent_create: "POST /api/intent/create",
            intent_spend: "POST /api/intent/spend",
            intent_cancel: "POST /api/intent/cancel",
            intent_list: "GET /api/intent",
            receipt_get: "GET /api/receipt/:id",
            receipt_verify: "POST /api/receipt/verify",
            me_policy: "GET|POST /api/me/policy",
            netting_run: "POST /api/netting/run",
            netting_list: "GET /api/netting",
            trace_get: "GET /api/trace/:id",
            ticket_mint: "POST /api/ticket/mint",
            ticket_transfer: "POST /api/ticket/transfer",
            ticket_redeem: "POST /api/ticket/redeem",
            ticket_list: "GET /api/ticket",
            ticket_get: "GET /api/ticket/:id",
            bond_post: "POST /api/bond/post",
            bond_match: "POST /api/bond/match",
            bond_fulfill: "POST /api/bond/fulfill",
            bond_slash: "POST /api/bond/slash",
            bond_cancel: "POST /api/bond/cancel",
            bond_list: "GET /api/bond",
            bond_get: "GET /api/bond/:id",
            saga_start: "POST /api/saga/start",
            saga_advance: "POST /api/saga/advance",
            saga_compensate: "POST /api/saga/compensate",
            saga_cancel: "POST /api/saga/cancel",
            saga_list: "GET /api/saga",
            saga_get: "GET /api/saga/:id",
            me_credit: "GET|POST /api/me/credit",
            me_credit_repay: "POST /api/me/credit/repay",
            commit: "POST /api/commit",
            commit_reveal: "POST /api/commit/reveal",
            commit_cancel: "POST /api/commit/cancel",
            commit_list: "GET /api/commit",
            commit_get: "GET /api/commit/:id",
            clearing_run: "POST /api/clearing/run",
            clearing_list: "GET /api/clearing",
            clearing_get: "GET /api/clearing/:id",
            work_claim: "POST /api/work/claim",
            work_lock: "POST /api/work/lock",
            work_attest: "POST /api/work/attest",
            work_settle: "POST /api/work/settle",
            work_refund: "POST /api/work/refund",
            work_list: "GET /api/work",
            work_get: "GET /api/work/:id",
            pool_open: "POST /api/pool/open",
            pool_contribute: "POST /api/pool/contribute",
            pool_release: "POST /api/pool/release",
            pool_refund: "POST /api/pool/refund",
            pool_list: "GET /api/pool",
            pool_get: "GET /api/pool/:id",
            continuity_open: "POST /api/continuity/open",
            continuity_beat: "POST /api/continuity/beat",
            continuity_close: "POST /api/continuity/close",
            continuity_recover: "POST /api/continuity/recover",
            continuity_list: "GET /api/continuity",
            continuity_get: "GET /api/continuity/:id",
          },
        });
      }
      if (request.method === "GET" && url.pathname === "/health") {
        const edge = getRequestEdge(request);
        return json(request, {
          ok: true,
          service: "a2a-ledger",
          ts: Date.now(),
          colo: edge.colo,
          country: edge.country,
        });
      }

      if (request.method === "POST" && url.pathname === "/api/delegate/open") {
        return await handleDelegateOpen(request, env, ctx);
      }
      if (request.method === "POST" && url.pathname === "/api/delegate/revoke") {
        return await handleDelegateRevoke(request, env, ctx);
      }
      if (request.method === "GET" && url.pathname === "/api/delegate") {
        return await handleDelegateList(request, url, env);
      }
      if (request.method === "GET" && url.pathname.startsWith("/api/delegate/")) {
        const id = url.pathname.slice("/api/delegate/".length);
        if (id && !id.includes("/")) return await handleDelegateGet(request, env, id);
      }

      if (request.method === "POST" && url.pathname === "/api/pay") {
        return await handlePay(request, env, ctx);
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
          const st = await processStandingOrders(env, ctx);
          console.log(
            JSON.stringify({
              cron: "standing-run",
              scheduledTime: event.scheduledTime,
              ...st,
            })
          );
        } catch (err) {
          console.error("standing-run failed:", err && err.message ? err.message : err);
        }

        try {
          const dg = await expireDelegations(env, ctx);
          console.log(
            JSON.stringify({
              cron: "delegate-expire",
              scheduledTime: event.scheduledTime,
              ...dg,
            })
          );
        } catch (err) {
          console.error("delegate-expire failed:", err && err.message ? err.message : err);
        }

        try {
          const dsp = await expireDisputes(env, ctx);
          console.log(
            JSON.stringify({
              cron: "dispute-expire",
              scheduledTime: event.scheduledTime,
              ...dsp,
            })
          );
        } catch (err) {
          console.error("dispute-expire failed:", err && err.message ? err.message : err);
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
        try {
          const tk = await expireTickets(env);
          console.log(
            JSON.stringify({
              cron: "ticket-expire",
              scheduledTime: event.scheduledTime,
              ...tk,
            })
          );
        } catch (err) {
          console.error("ticket-expire failed:", err && err.message ? err.message : err);
        }
        try {
          const bd = await expireBonds(env, ctx);
          console.log(
            JSON.stringify({
              cron: "bond-expire",
              scheduledTime: event.scheduledTime,
              ...bd,
            })
          );
        } catch (err) {
          console.error("bond-expire failed:", err && err.message ? err.message : err);
        }
        try {
          const sg = await expireSagas(env, ctx);
          console.log(
            JSON.stringify({
              cron: "saga-expire",
              scheduledTime: event.scheduledTime,
              ...sg,
            })
          );
        } catch (err) {
          console.error("saga-expire failed:", err && err.message ? err.message : err);
        }
        try {
          const cm = await expireCommits(env, ctx);
          console.log(
            JSON.stringify({
              cron: "commit-expire",
              scheduledTime: event.scheduledTime,
              ...(cm || {}),
            })
          );
        } catch (err) {
          console.error("commit-expire failed:", err && err.message ? err.message : err);
        }
        try {
          const wk = await expireWorkClaims(env, ctx);
          console.log(
            JSON.stringify({
              cron: "work-expire",
              scheduledTime: event.scheduledTime,
              ...(wk || {}),
            })
          );
        } catch (err) {
          console.error("work-expire failed:", err && err.message ? err.message : err);
        }
        try {
          const ct = await expireContinuitySessions(env, ctx);
          console.log(
            JSON.stringify({
              cron: "continuity-expire",
              scheduledTime: event.scheduledTime,
              ...(ct || {}),
            })
          );
        } catch (err) {
          console.error("continuity-expire failed:", err && err.message ? err.message : err);
        }
        try {
          const pl = await expireCollaborativePools(env, ctx);
          console.log(
            JSON.stringify({
              cron: "pool-expire",
              scheduledTime: event.scheduledTime,
              ...(pl || {}),
            })
          );
        } catch (err) {
          console.error("pool-expire failed:", err && err.message ? err.message : err);
        }
        try {
          const ic = await expireIntentCapsules(env, ctx);
          console.log(
            JSON.stringify({
              cron: "intent-expire",
              scheduledTime: event.scheduledTime,
              ...(ic || {}),
            })
          );
        } catch (err) {
          console.error("intent-expire failed:", err && err.message ? err.message : err);
        }
        try {
          const hr = await expireHireRfqs(env, ctx);
          console.log(
            JSON.stringify({
              cron: "hire-expire",
              scheduledTime: event.scheduledTime,
              ...(hr || {}),
            })
          );
        } catch (err) {
          console.error("hire-expire failed:", err && err.message ? err.message : err);
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


/* ─── GitLab OAuth ─── */

function handleAuthGitlabStart(request, env, url) {
  const clientId = env.GITLAB_CLIENT_ID;
  if (!clientId) return bad(request, "GITLAB_CLIENT_ID not configured on Worker", 500);

  const redirectUri = `${url.origin}/api/auth/gitlab/callback`;
  const state = randomId(16);
  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: "code",
    scope: "read_user read_api",
    state,
  });
  const headers = new Headers({
    Location: `https://gitlab.com/oauth/authorize?${params}`,
    "Set-Cookie": `a2a_oauth_state=${state}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600`,
  });
  return new Response(null, { status: 302, headers });
}

async function handleAuthGitlabCallback(request, env, url) {
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

  const blocked = await rejectIfAlreadySignedIn(request, env);
  if (blocked) return blocked;

  const cookies = parseCookies(request.headers.get("Cookie"));
  if (!cookies.a2a_oauth_state || cookies.a2a_oauth_state !== state) {
    return Response.redirect(`${DASHBOARD_URL}?auth_error=bad_state`, 302);
  }

  const clientId = env.GITLAB_CLIENT_ID;
  const clientSecret = env.GITLAB_CLIENT_SECRET;
  if (!clientId || !clientSecret) {
    return Response.redirect(`${DASHBOARD_URL}?auth_error=server_config`, 302);
  }

  const redirectUri = `${url.origin}/api/auth/gitlab/callback`;
  const tokenRes = await fetch("https://gitlab.com/oauth/token", {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      client_id: clientId,
      client_secret: clientSecret,
      code,
      grant_type: "authorization_code",
      redirect_uri: redirectUri,
    }),
  });
  const tokenData = await tokenRes.json();
  if (!tokenRes.ok || !tokenData.access_token) {
    return Response.redirect(`${DASHBOARD_URL}?auth_error=token_exchange`, 302);
  }

  const accessToken = tokenData.access_token;
  const userRes = await fetch("https://gitlab.com/api/v4/user", {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: "application/json",
      "User-Agent": "AgentPay-Worker",
    },
  });
  const profile = await userRes.json();
  if (!userRes.ok || !profile.id) {
    return Response.redirect(`${DASHBOARD_URL}?auth_error=userinfo`, 302);
  }

  let email = profile.email ? String(profile.email) : null;
  if (!email && profile.public_email) email = String(profile.public_email);
  if (!email) {
    // Fallback: GitLab may hide email — use noreply style
    email = `${profile.username || profile.id}@users.noreply.gitlab.com`;
  }

  const gitlabUserId = "gitlab:" + profile.id;
  const name = String(profile.name || profile.username || email.split("@")[0]);
  const picture = profile.avatar_url ? String(profile.avatar_url) : null;
  const glUsername = profile.username ? String(profile.username) : null;

  let sessionUserId = gitlabUserId;
  const byGitlab = await env.DB.prepare(`SELECT id FROM users WHERE id = ?1`)
    .bind(gitlabUserId)
    .first();

  if (byGitlab) {
    try {
      await env.DB.prepare(
        `UPDATE users
         SET email = ?1, name = ?2, picture = ?3, provider = 'gitlab',
             gitlab_access_token = ?4, gitlab_username = ?5, updated_at = datetime('now')
         WHERE id = ?6`
      )
        .bind(email, name, picture, accessToken, glUsername, gitlabUserId)
        .run();
    } catch (_) {
      // columns optional until ALTER
      await env.DB.prepare(
        `UPDATE users
         SET email = ?1, name = ?2, picture = ?3, provider = 'gitlab', updated_at = datetime('now')
         WHERE id = ?4`
      )
        .bind(email, name, picture, gitlabUserId)
        .run();
    }
    sessionUserId = gitlabUserId;
  } else {
    const byEmail = await env.DB.prepare(`SELECT id FROM users WHERE email = ?1`)
      .bind(email)
      .first();
    if (byEmail) {
      try {
        await env.DB.prepare(
          `UPDATE users
           SET name = COALESCE(NULLIF(?1, ''), name),
               picture = COALESCE(?2, picture),
               gitlab_access_token = ?3,
               gitlab_username = ?4,
               updated_at = datetime('now')
           WHERE id = ?5`
        )
          .bind(name, picture, accessToken, glUsername, byEmail.id)
          .run();
      } catch (_) {
        await env.DB.prepare(
          `UPDATE users
           SET name = COALESCE(NULLIF(?1, ''), name),
               picture = COALESCE(?2, picture),
               updated_at = datetime('now')
           WHERE id = ?3`
        )
          .bind(name, picture, byEmail.id)
          .run();
      }
      sessionUserId = byEmail.id;
    } else {
      try {
        await env.DB.prepare(
          `INSERT INTO users (id, email, name, picture, provider, gitlab_access_token, gitlab_username, updated_at)
           VALUES (?1, ?2, ?3, ?4, 'gitlab', ?5, ?6, datetime('now'))`
        )
          .bind(gitlabUserId, email, name, picture, accessToken, glUsername)
          .run();
      } catch (_) {
        await env.DB.prepare(
          `INSERT INTO users (id, email, name, picture, provider, updated_at)
           VALUES (?1, ?2, ?3, ?4, 'gitlab', datetime('now'))`
        )
          .bind(gitlabUserId, email, name, picture)
          .run();
      }
      sessionUserId = gitlabUserId;
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

  for (const r of all) {
    r.provider = "github";
  }
  const withCaps = await attachCachedCapabilities(env, all);
  return json(request, {
    ok: true,
    provider: "github",
    github_login: row.github_login || null,
    count: withCaps.length,
    repos: withCaps,
  });
}


/* ─── GitLab project list (parity with GitHub repo picker) ─── */

const RL_GITLAB_REPOS_MAX = 12;
const RL_GITLAB_REPOS_WINDOW_SEC = 3600;
const RL_AGENTS_SCAN_MAX = 30;
const RL_AGENTS_SCAN_WINDOW_SEC = 3600;

async function handleMeGitlabRepos(request, env) {
  const user = await getSessionUser(request, env);
  if (!user) return bad(request, "Sign in required", 401);

  const limited = await checkRateLimit(
    env,
    "gitlabrepos:" + user.id,
    RL_GITLAB_REPOS_MAX,
    RL_GITLAB_REPOS_WINDOW_SEC
  );
  if (limited) {
    return bad(
      request,
      "Rate limit: max " + RL_GITLAB_REPOS_MAX + " GitLab project fetches per hour",
      429,
      { code: "rate_limited", retry_after_sec: limited.retry_after_sec }
    );
  }

  let row;
  try {
    row = await env.DB.prepare(
      `SELECT gitlab_access_token, gitlab_username FROM users WHERE id = ?1`
    )
      .bind(user.id)
      .first();
  } catch (e) {
    return bad(
      request,
      "D1 missing gitlab_access_token / gitlab_username — run ALTER TABLE",
      500
    );
  }

  const token = row?.gitlab_access_token;
  if (!token) {
    return bad(
      request,
      "GitLab not linked. Log out, then Sign in with GitLab once to enable project picker.",
      400,
      { code: "gitlab_not_linked" }
    );
  }

  const all = [];
  let page = 1;
  const maxPages = 3;
  while (page <= maxPages) {
    const res = await fetch(
      `https://gitlab.com/api/v4/projects?membership=true&simple=true&order_by=last_activity_at&per_page=100&page=${page}`,
      {
        headers: {
          Authorization: `Bearer ${token}`,
          Accept: "application/json",
          "User-Agent": "AgentPay-Worker",
        },
      }
    );
    if (res.status === 401 || res.status === 403) {
      return bad(
        request,
        "GitLab token expired or revoked. Log out and Sign in with GitLab again (needs read_api).",
        401,
        { code: "gitlab_token_invalid" }
      );
    }
    if (!res.ok) {
      return bad(request, "GitLab API error HTTP " + res.status, 502);
    }
    const batch = await res.json();
    if (!Array.isArray(batch) || batch.length === 0) break;
    for (const r of batch) {
      if (r && r.path_with_namespace) {
        all.push({
          full_name: String(r.path_with_namespace),
          private: r.visibility === "private" || r.visibility === "internal",
          description: r.description ? String(r.description).slice(0, 120) : null,
          updated_at: r.last_activity_at || null,
          provider: "gitlab",
          web_url: r.web_url || null,
        });
      }
    }
    if (batch.length < 100) break;
    page += 1;
  }

  // Attach cached capabilities from agent_index
  const withCaps = await attachCachedCapabilities(env, all);

  return json(request, {
    ok: true,
    provider: "gitlab",
    gitlab_username: row.gitlab_username || null,
    count: withCaps.length,
    repos: withCaps,
  });
}

/** Unified: GitHub + GitLab repos the user can bind as agents */
async function handleMeReposUnified(request, env) {
  const user = await getSessionUser(request, env);
  if (!user) return bad(request, "Sign in required", 401);

  const out = { ok: true, repos: [], sources: {} };

  // GitHub
  try {
    const row = await env.DB.prepare(
      `SELECT github_access_token, github_login FROM users WHERE id = ?1`
    )
      .bind(user.id)
      .first();
    if (row?.github_access_token) {
      const res = await fetch(
        "https://api.github.com/user/repos?per_page=100&page=1&sort=updated&affiliation=owner,collaborator,organization_member",
        {
          headers: {
            Authorization: `Bearer ${row.github_access_token}`,
            Accept: "application/vnd.github+json",
            "User-Agent": "AgentPay-Worker",
          },
        }
      );
      if (res.ok) {
        const batch = await res.json();
        for (const r of batch || []) {
          if (r?.full_name) {
            out.repos.push({
              full_name: String(r.full_name),
              private: !!r.private,
              description: r.description ? String(r.description).slice(0, 120) : null,
              updated_at: r.updated_at || null,
              provider: "github",
            });
          }
        }
        out.sources.github = { ok: true, login: row.github_login, count: (batch || []).length };
      } else {
        out.sources.github = { ok: false, status: res.status };
      }
    } else {
      out.sources.github = { ok: false, code: "github_not_linked" };
    }
  } catch (e) {
    out.sources.github = { ok: false, error: (e && e.message) || "error" };
  }

  // GitLab
  try {
    const row = await env.DB.prepare(
      `SELECT gitlab_access_token, gitlab_username FROM users WHERE id = ?1`
    )
      .bind(user.id)
      .first();
    if (row?.gitlab_access_token) {
      const res = await fetch(
        "https://gitlab.com/api/v4/projects?membership=true&simple=true&order_by=last_activity_at&per_page=100&page=1",
        {
          headers: {
            Authorization: `Bearer ${row.gitlab_access_token}`,
            Accept: "application/json",
            "User-Agent": "AgentPay-Worker",
          },
        }
      );
      if (res.ok) {
        const batch = await res.json();
        for (const r of batch || []) {
          if (r?.path_with_namespace) {
            out.repos.push({
              full_name: String(r.path_with_namespace),
              private: r.visibility === "private" || r.visibility === "internal",
              description: r.description ? String(r.description).slice(0, 120) : null,
              updated_at: r.last_activity_at || null,
              provider: "gitlab",
              web_url: r.web_url || null,
            });
          }
        }
        out.sources.gitlab = {
          ok: true,
          username: row.gitlab_username,
          count: (batch || []).length,
        };
      } else {
        out.sources.gitlab = { ok: false, status: res.status };
      }
    } else {
      out.sources.gitlab = { ok: false, code: "gitlab_not_linked" };
    }
  } catch (e) {
    out.sources.gitlab = { ok: false, error: (e && e.message) || "error" };
  }

  out.repos = await attachCachedCapabilities(env, out.repos);
  out.count = out.repos.length;
  return json(request, out);
}

async function attachCachedCapabilities(env, repos) {
  if (!repos || !repos.length) return repos || [];
  try {
    const names = repos.map((r) => r.full_name).filter(Boolean).slice(0, 120);
    if (!names.length) return repos;
    // batch lookup
    const placeholders = names.map((_, i) => "?" + (i + 1)).join(",");
    const { results } = await env.DB.prepare(
      `SELECT repo_id, capabilities_json, capabilities_text, source, hireable
       FROM agent_index WHERE repo_id IN (${placeholders})`
    )
      .bind(...names)
      .all();
    const map = {};
    for (const row of results || []) {
      map[row.repo_id] = row;
    }
    return repos.map((r) => {
      const c = map[r.full_name];
      if (!c) return r;
      let caps = [];
      try {
        caps = JSON.parse(c.capabilities_json || "[]");
      } catch (_) {}
      return {
        ...r,
        capabilities: caps,
        capabilities_text: c.capabilities_text || "",
        cap_source: c.source || null,
        hireable: Number(c.hireable) === 1,
      };
    });
  } catch (_) {
    return repos;
  }
}

/* ─── Capabilities-Aware Agent Index ───
 * Parse AP-Capabilities / .agentpay/capabilities.json / wrangler.toml
 * so agents can hire by capability in O(1) without scanning 500 repos.
 */

async function ensureAgentIndexTable(env) {
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS agent_index (
       repo_id TEXT PRIMARY KEY,
       provider TEXT,
       owner_user_id TEXT,
       display_name TEXT,
       description TEXT,
       capabilities_json TEXT,
       capabilities_text TEXT,
       source TEXT,
       hireable INTEGER DEFAULT 1,
       meta_json TEXT,
       updated_at TEXT,
       indexed_at TEXT
     )`
  ).run();
  try {
    await env.DB.prepare(
      `CREATE INDEX IF NOT EXISTS idx_agent_index_caps ON agent_index(capabilities_text)`
    ).run();
  } catch (_) {}
  try {
    await env.DB.prepare(
      `CREATE INDEX IF NOT EXISTS idx_agent_index_provider ON agent_index(provider)`
    ).run();
  } catch (_) {}
}

function normalizeCapabilities(list) {
  const out = [];
  const seen = new Set();
  for (const raw of list || []) {
    let s = String(raw || "")
      .trim()
      .toLowerCase()
      .replace(/\s+/g, "");
    if (!s) continue;
    // allow model/vision, api:tool, skill.foo
    s = s.replace(/[^a-z0-9_.:/-]/g, "");
    if (!s || s.length > 64) continue;
    if (seen.has(s)) continue;
    seen.add(s);
    out.push(s);
  }
  return out.slice(0, 40);
}

function parseCapabilitiesJson(text) {
  try {
    const j = JSON.parse(text);
    if (Array.isArray(j)) return normalizeCapabilities(j);
    if (j && Array.isArray(j.capabilities)) return normalizeCapabilities(j.capabilities);
    if (j && typeof j === "object") {
      const keys = Object.keys(j).filter((k) => j[k]);
      return normalizeCapabilities(keys);
    }
  } catch (_) {}
  return [];
}

function parseApCapabilitiesFile(text) {
  // one capability per line or comma-separated; ignore comments
  const caps = [];
  for (const line of String(text || "").split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith("//")) continue;
    for (const part of trimmed.split(/[,;]/)) {
      if (part.trim()) caps.push(part.trim());
    }
  }
  return normalizeCapabilities(caps);
}

function parseWranglerTomlCapabilities(text) {
  const caps = [];
  const t = String(text || "");
  // name = "foo"
  const nameM = t.match(/^\s*name\s*=\s*["']([^"']+)["']/m);
  if (nameM) caps.push("worker:" + nameM[1].toLowerCase().replace(/\s+/g, "-"));
  // compatibility_date implies cloudflare-worker
  if (/compatibility_date\s*=/.test(t)) caps.push("runtime:cloudflare-worker");
  if (/\[\[d1_databases\]\]/.test(t) || /d1_databases/.test(t)) caps.push("storage:d1");
  if (/\[\[kv_namespaces\]\]/.test(t) || /kv_namespaces/.test(t)) caps.push("storage:kv");
  if (/\[\[r2_buckets\]\]/.test(t) || /r2_buckets/.test(t)) caps.push("storage:r2");
  if (/ai\s*=/.test(t) || /\[ai\]/.test(t)) caps.push("model:workers-ai");
  // custom [agentpay.capabilities] style: capabilities = ["a","b"]
  const block = t.match(/\[agentpay(?:\.capabilities)?\][\s\S]*?(?=\n\[|$)/i);
  if (block) {
    const arr = block[0].match(/capabilities\s*=\s*\[([^\]]*)\]/i);
    if (arr) {
      const parts = arr[1].match(/["']([^"']+)["']/g) || [];
      for (const p of parts) caps.push(p.replace(/["']/g, ""));
    }
  }
  return normalizeCapabilities(caps);
}

async function fetchGithubRaw(token, fullName, path) {
  const url = `https://api.github.com/repos/${fullName}/contents/${path}`;
  const res = await fetch(url, {
    headers: {
      Authorization: token ? `Bearer ${token}` : undefined,
      Accept: "application/vnd.github.raw",
      "User-Agent": "AgentPay-Worker",
    },
  });
  if (!res.ok) return null;
  return await res.text();
}

async function fetchGitlabRaw(token, pathWithNamespace, path, ref = "HEAD") {
  // GET /projects/:id/repository/files/:file_path/raw
  const project = encodeURIComponent(pathWithNamespace);
  const filePath = encodeURIComponent(path);
  const url = `https://gitlab.com/api/v4/projects/${project}/repository/files/${filePath}/raw?ref=${encodeURIComponent(ref)}`;
  const res = await fetch(url, {
    headers: {
      Authorization: token ? `Bearer ${token}` : undefined,
      Accept: "application/json",
      "User-Agent": "AgentPay-Worker",
    },
  });
  if (!res.ok) return null;
  return await res.text();
}

async function scanRepoCapabilities(env, { full_name, provider, token }) {
  const pathsJson = [
    ".agentpay/capabilities.json",
    "agentpay.capabilities.json",
    "AP-Capabilities.json",
  ];
  const pathsText = ["AP-Capabilities", ".agentpay/capabilities", "CAPABILITIES"];
  const pathsToml = ["wrangler.toml"];

  let source = null;
  let caps = [];
  let meta = {};

  const fetchRaw = async (path) => {
    if (provider === "gitlab") return fetchGitlabRaw(token, full_name, path);
    return fetchGithubRaw(token, full_name, path);
  };

  for (const p of pathsJson) {
    const text = await fetchRaw(p);
    if (text) {
      caps = parseCapabilitiesJson(text);
      if (caps.length) {
        source = p;
        break;
      }
    }
  }
  if (!caps.length) {
    for (const p of pathsText) {
      const text = await fetchRaw(p);
      if (text) {
        caps = parseApCapabilitiesFile(text);
        if (caps.length) {
          source = p;
          break;
        }
      }
    }
  }
  if (!caps.length) {
    for (const p of pathsToml) {
      const text = await fetchRaw(p);
      if (text) {
        caps = parseWranglerTomlCapabilities(text);
        if (caps.length) {
          source = "wrangler.toml";
          meta.wrangler_hint = true;
          break;
        }
      }
    }
  }

  // Always tag provider
  if (provider === "gitlab" && !caps.includes("vcs:gitlab")) caps.push("vcs:gitlab");
  if (provider === "github" && !caps.includes("vcs:github")) caps.push("vcs:github");
  caps = normalizeCapabilities(caps);

  return { capabilities: caps, source: source || (caps.length ? "inferred" : "none"), meta };
}

async function upsertAgentIndex(env, row) {
  await ensureAgentIndexTable(env);
  const capsJson = JSON.stringify(row.capabilities || []);
  const capsText = (row.capabilities || []).join(" ");
  await env.DB.prepare(
    `INSERT INTO agent_index (
       repo_id, provider, owner_user_id, display_name, description,
       capabilities_json, capabilities_text, source, hireable, meta_json,
       updated_at, indexed_at
     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, datetime('now'), datetime('now'))
     ON CONFLICT(repo_id) DO UPDATE SET
       provider = excluded.provider,
       owner_user_id = COALESCE(excluded.owner_user_id, agent_index.owner_user_id),
       display_name = COALESCE(excluded.display_name, agent_index.display_name),
       description = COALESCE(excluded.description, agent_index.description),
       capabilities_json = excluded.capabilities_json,
       capabilities_text = excluded.capabilities_text,
       source = excluded.source,
       hireable = excluded.hireable,
       meta_json = excluded.meta_json,
       updated_at = datetime('now'),
       indexed_at = datetime('now')`
  )
    .bind(
      row.repo_id,
      row.provider || null,
      row.owner_user_id || null,
      row.display_name || null,
      row.description || null,
      capsJson,
      capsText,
      row.source || null,
      row.hireable != null ? (row.hireable ? 1 : 0) : 1,
      row.meta ? JSON.stringify(row.meta) : null
    )
    .run();
}

async function handleAgentsScan(request, env, ctx) {
  const authUser = await getAuthUser(request, env);
  if (!authUser) return bad(request, "Sign in or API key required", 401);

  const limited = await checkRateLimit(
    env,
    "agentscan:" + (authUser.key_id || authUser.id),
    RL_AGENTS_SCAN_MAX,
    RL_AGENTS_SCAN_WINDOW_SEC
  );
  if (limited) {
    return bad(request, "Rate limit: agent scan", 429, {
      retry_after_sec: limited.retry_after_sec,
    });
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return bad(request, "Invalid JSON body");
  }

  const full_name = parseRepo(body.repo || body.full_name || body.repo_id);
  if (!full_name) return bad(request, "repo must be owner/repo");
  let provider = String(body.provider || "").toLowerCase();
  if (!["github", "gitlab"].includes(provider)) {
    // infer from tokens
    provider = "github";
  }

  // Resolve token from session user row
  let token = null;
  const uid = authUser.id;
  try {
    if (provider === "gitlab") {
      const row = await env.DB.prepare(
        `SELECT gitlab_access_token FROM users WHERE id = ?1`
      )
        .bind(uid)
        .first();
      token = row?.gitlab_access_token || null;
      if (!token) {
        // try github fallback only if provider forced wrong
        return bad(request, "GitLab token missing — sign in with GitLab", 400, {
          code: "gitlab_not_linked",
        });
      }
    } else {
      const row = await env.DB.prepare(
        `SELECT github_access_token FROM users WHERE id = ?1`
      )
        .bind(uid)
        .first();
      token = row?.github_access_token || null;
      if (!token) {
        return bad(request, "GitHub token missing — sign in with GitHub", 400, {
          code: "github_not_linked",
        });
      }
    }
  } catch (e) {
    return bad(request, "Token lookup failed: " + (e.message || e), 500);
  }

  const scanned = await scanRepoCapabilities(env, {
    full_name,
    provider,
    token,
  });

  await upsertAgentIndex(env, {
    repo_id: full_name,
    provider,
    owner_user_id: uid,
    display_name: body.display_name || full_name,
    description: body.description || null,
    capabilities: scanned.capabilities,
    source: scanned.source,
    hireable: body.hireable !== false,
    meta: scanned.meta,
  });

  // Optional: ensure account exists so agent is hireable on ledger
  await ensureAccount(env, full_name).catch(() => {});

  return json(request, {
    ok: true,
    repo_id: full_name,
    provider,
    capabilities: scanned.capabilities,
    source: scanned.source,
    hireable: true,
    hint: "Other agents can GET /api/agents/search?capability=model/vision",
  });
}

async function handleAgentsList(request, url, env) {
  await ensureAgentIndexTable(env).catch(() => {});
  const limit = Math.min(Math.max(Number(url.searchParams.get("limit") || 50), 1), 200);
  const provider = (url.searchParams.get("provider") || "").trim().toLowerCase();
  const hireable = url.searchParams.get("hireable");
  const capability = (url.searchParams.get("capability") || url.searchParams.get("q") || "")
    .trim()
    .toLowerCase();
  const sort = (url.searchParams.get("sort") || "rank").toLowerCase();

  let sql = `SELECT a.repo_id, a.provider, a.display_name, a.description,
                    a.capabilities_json, a.capabilities_text, a.source, a.hireable, a.indexed_at,
                    COALESCE(l.rep_score, 0) AS rep_score,
                    COALESCE(l.locked, 0) AS locked,
                    COALESCE(acc.balance, 0) AS balance
             FROM agent_index a
             LEFT JOIN agent_limits l ON l.repo_id = a.repo_id
             LEFT JOIN accounts acc ON acc.repo_id = a.repo_id
             WHERE 1=1`;
  const binds = [];
  if (provider === "github" || provider === "gitlab") {
    sql += ` AND a.provider = ?`;
    binds.push(provider);
  }
  if (hireable === "1" || hireable === "true") {
    sql += ` AND a.hireable = 1`;
  }
  if (capability) {
    sql += ` AND (a.capabilities_text LIKE ? OR a.capabilities_json LIKE ? OR a.repo_id LIKE ?)`;
    const like = "%" + capability + "%";
    binds.push(like, like, like);
  }
  sql += ` ORDER BY a.indexed_at DESC LIMIT ?`;
  binds.push(Math.min(limit * 3, 300));

  try {
    const { results } = await env.DB.prepare(sql).bind(...binds).all();
    let agents = (results || []).map((r) => scoreAgentRow(r, capability));
    agents = sortAgents(agents, sort).slice(0, limit);
    return json(request, {
      ok: true,
      count: agents.length,
      sort,
      query: capability || null,
      agents,
    });
  } catch (e) {
    return bad(
      request,
      "agent_index missing — first scan creates it: " + (e.message || e),
      500
    );
  }
}

async function handleAgentsSearch(request, url, env) {
  await ensureAgentIndexTable(env).catch(() => {});
  const capability = (url.searchParams.get("capability") || url.searchParams.get("q") || "")
    .trim()
    .toLowerCase();
  const limit = Math.min(Math.max(Number(url.searchParams.get("limit") || 20), 1), 100);
  const sort = (url.searchParams.get("sort") || "rank").toLowerCase();

  if (!capability) {
    return bad(request, "capability or q required (e.g. model/vision)");
  }

  try {
    const { results } = await env.DB.prepare(
      `SELECT a.repo_id, a.provider, a.display_name, a.description,
              a.capabilities_json, a.capabilities_text, a.source, a.hireable, a.indexed_at,
              COALESCE(l.rep_score, 0) AS rep_score,
              COALESCE(l.locked, 0) AS locked,
              COALESCE(acc.balance, 0) AS balance
       FROM agent_index a
       LEFT JOIN agent_limits l ON l.repo_id = a.repo_id
       LEFT JOIN accounts acc ON acc.repo_id = a.repo_id
       WHERE a.hireable = 1
         AND (
           a.capabilities_text LIKE ?1
           OR a.capabilities_json LIKE ?2
           OR a.repo_id LIKE ?3
         )
       ORDER BY a.indexed_at DESC
       LIMIT ?4`
    )
      .bind("%" + capability + "%", "%" + capability + "%", "%" + capability + "%", Math.min(limit * 3, 200))
      .all();

    let agents = (results || []).map((r) => scoreAgentRow(r, capability));
    agents = sortAgents(agents, sort).slice(0, limit);

    return json(request, {
      ok: true,
      query: capability,
      count: agents.length,
      sort,
      agents,
      latency_hint_ms: "ranked index lookup — no repo tree scan",
    });
  } catch (e) {
    return bad(request, "Search failed: " + (e.message || e), 500);
  }
}

/** Public ranked discovery for humans + agents (Find Agents page). */
async function handleAgentsRank(request, url, env) {
  await ensureAgentIndexTable(env).catch(() => {});
  const capability = (url.searchParams.get("capability") || url.searchParams.get("q") || "")
    .trim()
    .toLowerCase();
  const provider = (url.searchParams.get("provider") || "").trim().toLowerCase();
  const limit = Math.min(Math.max(Number(url.searchParams.get("limit") || 24), 1), 100);
  const hireableOnly = url.searchParams.get("hireable") !== "0";

  let sql = `SELECT a.repo_id, a.provider, a.display_name, a.description,
                    a.capabilities_json, a.capabilities_text, a.source, a.hireable, a.indexed_at,
                    COALESCE(l.rep_score, 0) AS rep_score,
                    COALESCE(l.locked, 0) AS locked,
                    COALESCE(l.credit_limit, 0) AS credit_limit,
                    COALESCE(acc.balance, 0) AS balance
             FROM agent_index a
             LEFT JOIN agent_limits l ON l.repo_id = a.repo_id
             LEFT JOIN accounts acc ON acc.repo_id = a.repo_id
             WHERE 1=1`;
  const binds = [];
  if (hireableOnly) {
    sql += ` AND a.hireable = 1`;
  }
  if (provider === "github" || provider === "gitlab") {
    sql += ` AND a.provider = ?`;
    binds.push(provider);
  }
  if (capability) {
    sql += ` AND (a.capabilities_text LIKE ? OR a.capabilities_json LIKE ? OR a.repo_id LIKE ? OR a.description LIKE ?)`;
    const like = "%" + capability + "%";
    binds.push(like, like, like, like);
  }
  sql += ` ORDER BY a.indexed_at DESC LIMIT ?`;
  binds.push(Math.min(limit * 4, 400));

  try {
    const t0 = Date.now();
    const { results } = await env.DB.prepare(sql).bind(...binds).all();
    let agents = (results || []).map((r) => scoreAgentRow(r, capability));
    agents = sortAgents(agents, "rank").slice(0, limit);
    return json(request, {
      ok: true,
      query: capability || null,
      provider: provider || null,
      count: agents.length,
      agents,
      algorithm: {
        factors: [
          "capability_match (exact > prefix > substring)",
          "rep_score from agent_limits",
          "hireable flag",
          "not locked",
          "indexed recency",
          "soft balance signal",
        ],
        note: "Rank is advisory for discovery; always verify work/attestations before large pays.",
      },
      latency_ms: Date.now() - t0,
    });
  } catch (e) {
    return bad(request, "Rank failed: " + (e.message || e), 500);
  }
}

function scoreAgentRow(r, capability) {
  let capabilities = [];
  try {
    capabilities = JSON.parse(r.capabilities_json || "[]");
  } catch (_) {}
  const caps = capabilities.map((c) => String(c).toLowerCase());
  const q = (capability || "").toLowerCase();
  let matchScore = 0;
  if (q) {
    if (caps.some((c) => c === q)) matchScore = 100;
    else if (caps.some((c) => c.startsWith(q) || q.startsWith(c))) matchScore = 70;
    else if (caps.some((c) => c.includes(q))) matchScore = 45;
    else if (String(r.repo_id || "").toLowerCase().includes(q)) matchScore = 25;
    else if (String(r.description || "").toLowerCase().includes(q)) matchScore = 15;
    else matchScore = 5;
  } else {
    matchScore = 20 + Math.min(30, caps.length * 3);
  }
  const rep = Number(r.rep_score || 0);
  const locked = Number(r.locked) === 1;
  const hireable = Number(r.hireable) === 1;
  const balance = Number(r.balance || 0);
  // Weighted rank 0–100 scale (approx)
  let rank =
    matchScore * 0.45 +
    Math.min(40, rep * 0.04) +
    (hireable ? 12 : 0) +
    (locked ? -25 : 8) +
    Math.min(8, Math.log10(balance + 1) * 3);
  rank = Math.round(Math.max(0, Math.min(100, rank)) * 10) / 10;
  return {
    repo_id: r.repo_id,
    provider: r.provider,
    display_name: r.display_name,
    description: r.description,
    capabilities,
    source: r.source,
    hireable,
    locked,
    rep_score: rep,
    balance,
    match_score: matchScore,
    rank_score: rank,
    indexed_at: r.indexed_at,
    match: q || undefined,
  };
}

function sortAgents(agents, sort) {
  const s = (sort || "rank").toLowerCase();
  const copy = agents.slice();
  if (s === "rep") {
    copy.sort((a, b) => (b.rep_score || 0) - (a.rep_score || 0) || (b.rank_score || 0) - (a.rank_score || 0));
  } else if (s === "recent") {
    copy.sort((a, b) => String(b.indexed_at || "").localeCompare(String(a.indexed_at || "")));
  } else if (s === "name") {
    copy.sort((a, b) => String(a.repo_id).localeCompare(String(b.repo_id)));
  } else {
    copy.sort(
      (a, b) =>
        (b.rank_score || 0) - (a.rank_score || 0) ||
        (b.match_score || 0) - (a.match_score || 0) ||
        (b.rep_score || 0) - (a.rep_score || 0)
    );
  }
  return copy;
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

  let bindMode = body.bind_mode != null ? String(body.bind_mode).toLowerCase().trim() : "";
  if (!["", "none", "learn", "colo", "ip", "both", "either"].includes(bindMode)) {
    return bad(request, "bind_mode must be none|learn|colo|ip|both|either");
  }
  if (bindMode === "none") bindMode = "";

  const edge = getRequestEdge(request);
  let boundColo = null;
  let boundIp = null;
  if (bindMode && bindMode !== "learn") {
    boundColo = edge.colo || (body.colo ? String(body.colo).toUpperCase().slice(0, 8) : null);
    boundIp = await hashIp(edge.ip);
  }

  const pinNow = !!(bindMode && bindMode !== "learn");
  try {
    await env.DB.prepare(
      `INSERT INTO api_keys (id, user_id, key_hash, key_prefix, label, bind_mode, bound_colo, bound_ip_hash, bound_at)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)`
    )
      .bind(
        id,
        user.id,
        keyHash,
        keyPrefix,
        label,
        bindMode || null,
        pinNow ? boundColo : null,
        pinNow ? boundIp : null,
        pinNow ? new Date().toISOString().replace("T", " ").slice(0, 19) : null
      )
      .run();
  } catch (_) {
    await env.DB.prepare(
      `INSERT INTO api_keys (id, user_id, key_hash, key_prefix, label)
       VALUES (?1, ?2, ?3, ?4, ?5)`
    )
      .bind(id, user.id, keyHash, keyPrefix, label)
      .run();
    bindMode = "";
  }

  return json(request, {
    ok: true,
    id,
    label,
    key_prefix: keyPrefix,
    key: secret,
    bind_mode: bindMode || null,
    bound_colo: bindMode && bindMode !== "learn" ? boundColo : null,
    edge: { colo: edge.colo, country: edge.country },
    hint: "Copy now. The full key is never shown again." +
      (bindMode ? " Edge binding: " + bindMode + "." : ""),
  });
}

async function handleMeKeysList(request, env) {
  const user = await getSessionUser(request, env);
  if (!user) return bad(request, "Sign in required", 401);

  let results;
  try {
    const q = await env.DB.prepare(
      `SELECT id, key_prefix, label, created_at, revoked_at, last_used_at,
              suspended_at, suspend_reason,
              bound_colo, bind_mode, last_colo, bind_violations, bound_at
       FROM api_keys WHERE user_id = ?1 ORDER BY created_at DESC LIMIT 50`
    )
      .bind(user.id)
      .all();
    results = q.results || [];
  } catch (_) {
    try {
      const q = await env.DB.prepare(
        `SELECT id, key_prefix, label, created_at, revoked_at, last_used_at, suspended_at, suspend_reason
         FROM api_keys WHERE user_id = ?1 ORDER BY created_at DESC LIMIT 50`
      )
        .bind(user.id)
        .all();
      results = q.results || [];
    } catch (__) {
      const q = await env.DB.prepare(
        `SELECT id, key_prefix, label, created_at, revoked_at, last_used_at
         FROM api_keys WHERE user_id = ?1 ORDER BY created_at DESC LIMIT 50`
      )
        .bind(user.id)
        .all();
      results = q.results || [];
    }
  }

  const edge = getRequestEdge(request);
  return json(request, {
    ok: true,
    count: results.length,
    current_edge: { colo: edge.colo, country: edge.country },
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
      bind_mode: k.bind_mode || null,
      bound_colo: k.bound_colo || null,
      last_colo: k.last_colo || null,
      bound_at: k.bound_at || null,
      bind_violations: Number(k.bind_violations || 0),
    })),
  });
}


async function handleMeKeysBind(request, env) {
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

  let mode = body.mode != null ? String(body.mode).toLowerCase().trim() : "either";
  if (!["learn", "colo", "ip", "both", "either"].includes(mode)) {
    return bad(request, "mode must be learn|colo|ip|both|either");
  }

  const row = await env.DB.prepare(
    `SELECT id, user_id, revoked_at FROM api_keys WHERE id = ?1`
  )
    .bind(id)
    .first();
  if (!row || row.user_id !== user.id) return bad(request, "Key not found", 404);
  if (row.revoked_at) return bad(request, "Key revoked", 400);

  const edge = getRequestEdge(request);
  const colo =
    (body.colo && String(body.colo).toUpperCase().slice(0, 8)) || edge.colo || null;
  const ipHash = await hashIp(edge.ip);

  if (mode !== "learn" && mode !== "ip" && !colo) {
    return bad(request, "No colo on this request and none provided — cannot bind", 400, {
      code: "no_colo",
    });
  }

  try {
    if (mode === "learn") {
      await env.DB.prepare(
        `UPDATE api_keys
         SET bind_mode = 'learn', bound_colo = NULL, bound_ip_hash = NULL,
             bound_at = NULL
         WHERE id = ?1`
      )
        .bind(id)
        .run();
    } else {
      await env.DB.prepare(
        `UPDATE api_keys
         SET bind_mode = ?2,
             bound_colo = ?3,
             bound_ip_hash = ?4,
             bound_at = datetime('now'),
             last_colo = COALESCE(?3, last_colo),
             last_ip_hash = COALESCE(?4, last_ip_hash)
         WHERE id = ?1`
      )
        .bind(
          id,
          mode,
          mode === "ip" ? null : colo,
          mode === "colo" ? null : ipHash
        )
        .run();
    }
  } catch (e) {
    return bad(
      request,
      "Colo columns missing — run d1-colo-migration.sql: " + (e.message || e),
      500
    );
  }

  await logSafetyEvent(env, "key.edge_bound", {
    api_key_id: id,
    user_id: user.id,
    reason: mode,
    meta: { colo, mode },
  });

  return json(request, {
    ok: true,
    id,
    bind_mode: mode,
    bound_colo: mode === "ip" || mode === "learn" ? null : colo,
    bound_ip: mode === "colo" || mode === "learn" ? false : !!ipHash,
    current_edge: { colo: edge.colo, country: edge.country },
    hint:
      mode === "learn"
        ? "First API use will pin colo + IP, then enforce either."
        : "Key locked to this edge. Off-edge requests return 403 key_edge_mismatch.",
  });
}

async function handleMeKeysUnbind(request, env) {
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
    `SELECT id, user_id FROM api_keys WHERE id = ?1`
  )
    .bind(id)
    .first();
  if (!row || row.user_id !== user.id) return bad(request, "Key not found", 404);

  try {
    await env.DB.prepare(
      `UPDATE api_keys
       SET bind_mode = NULL, bound_colo = NULL, bound_ip_hash = NULL,
           bound_at = NULL, bind_violations = 0
       WHERE id = ?1`
    )
      .bind(id)
      .run();
  } catch (e) {
    return bad(
      request,
      "Colo columns missing — run d1-colo-migration.sql: " + (e.message || e),
      500
    );
  }

  await logSafetyEvent(env, "key.edge_unbound", {
    api_key_id: id,
    user_id: user.id,
    reason: "owner_unbind",
  });

  return json(request, { ok: true, id, bind_mode: null, unbound: true });
}

/** Current API key metadata + binding (API key auth). */
async function handleMeKeySelf(request, env) {
  const authUser = await getAuthUser(request, env);
  if (!authUser) return bad(request, "Sign in or API key required", 401);
  const sus = rejectIfSuspendedKey(request, authUser);
  if (sus) return sus;

  if (authUser.auth_via !== "api_key") {
    return bad(request, "Use an API key Bearer token for this endpoint", 400, {
      code: "api_key_required",
    });
  }

  const edge = getRequestEdge(request);
  let row = null;
  try {
    row = await env.DB.prepare(
      `SELECT id, key_prefix, label, bind_mode, bound_colo, last_colo,
              bind_violations, bound_at, last_used_at, created_at
       FROM api_keys WHERE id = ?1`
    )
      .bind(authUser.key_id)
      .first();
  } catch (_) {
    row = await env.DB.prepare(
      `SELECT id, key_prefix, label, last_used_at, created_at
       FROM api_keys WHERE id = ?1`
    )
      .bind(authUser.key_id)
      .first();
  }

  return json(request, {
    ok: true,
    key: row
      ? {
          id: row.id,
          key_prefix: (row.key_prefix || "") + "…",
          label: row.label,
          bind_mode: row.bind_mode || null,
          bound_colo: row.bound_colo || null,
          last_colo: row.last_colo || null,
          bind_violations: Number(row.bind_violations || 0),
          bound_at: row.bound_at || null,
          last_used_at: row.last_used_at || null,
        }
      : null,
    current_edge: { colo: edge.colo, country: edge.country, ray: edge.ray },
    bound_ok: !(authUser.edge_blocked || authUser._edge_blocked),
  });
}

async function handleEdgeInfo(request, env) {
  const edge = getRequestEdge(request);
  return json(request, {
    ok: true,
    colo: edge.colo,
    country: edge.country,
    ray: edge.ray,
    has_ip: !!edge.ip,
    hint: "Bind API keys with POST /api/me/keys/bind { id, mode: 'colo'|'either'|'both'|'learn' }",
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
    events: ["escrow.released", "escrow.refunded", "escrow.expired", "wallet.locked", "agent.runaway_loop", "shield.quarantine", "shield.trip"],
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
    events: ["escrow.released", "escrow.refunded", "escrow.expired", "wallet.locked", "agent.runaway_loop", "shield.quarantine", "shield.trip"],
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

async function handlePay(request, env, ctx) {
  const t0 = Date.now();
  const waitUntil = (p) => {
    try {
      if (ctx && typeof ctx.waitUntil === "function") {
        ctx.waitUntil(Promise.resolve(p).catch((e) => console.log("pay_bg", e && e.message)));
        return;
      }
    } catch (_) {}
    // no ctx: still fire-and-forget without blocking too long
    Promise.resolve(p).catch(() => {});
  };

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
  const traceId = parseTraceId(
    body.trace_id || body.traceId || request.headers.get("X-Trace-Id")
  );


  // Delegation chain: child key + X-Delegate-Id spends parent-locked budget
  const delegateIdHdr =
    String(request.headers.get("X-Delegate-Id") || body.delegate_id || body.delegation_id || "")
      .trim();
  let activeDelegation = null;
  if (delegateIdHdr) {
    if (!authUser || authUser.auth_via !== "api_key" || !authUser.key_id) {
      return bad(request, "X-Delegate-Id requires Authorization: Bearer <child_api_key>", 401, {
        code: "delegate_auth",
      });
    }
    const sus = rejectIfSuspendedKey(request, authUser);
    if (sus) return sus;

    const toRepoEarly = parseRepo(body.to_repo || body.toRepo);
    const amountEarly = parseAmount(body.amount);
    const taskEarly = String(body.task || "").slice(0, 500);
    if (!toRepoEarly) return bad(request, "to_repo must be owner/repo");
    if (amountEarly == null) return bad(request, "amount must be between 0.000001 and 1000000");

    const claim = await claimDelegationSpend(env, {
      id: delegateIdHdr,
      childKeyId: authUser.key_id,
      toRepo: toRepoEarly,
      amount: amountEarly,
      task: taskEarly,
    });
    if (!claim.ok) {
      const st =
        claim.code === "not_found" ? 404 :
        claim.code === "table_missing" ? 500 :
        claim.code === "delegate_key_mismatch" || claim.code === "delegate_allow_to" || claim.code === "delegate_task_prefix"
          ? 403
          : claim.code === "delegate_insufficient"
            ? 402
            : 400;
      return bad(request, claim.error, st, {
        code: claim.code,
        remaining_usd: claim.remaining_usd,
        allow_to: claim.allow_to,
      });
    }
    activeDelegation = claim.delegation;
    // Force from_repo to parent — child spends parent's pocket money
    fromRepo = parseRepo(activeDelegation.parent_repo);
    // Skip parent wallet debit later — funds already in system/delegate
  }


  if (!fromRepo) {
    return bad(
      request,
      "from_repo must be owner/repo (or authenticate and set default agent)"
    );
  }
  if (!toRepo) return bad(request, "to_repo must be owner/repo");
  if (fromRepo === toRepo) return bad(request, "from_repo and to_repo must differ");
  if (amount == null) return bad(request, "amount must be between 0.000001 and 1000000");

  if (authUser) {
    authUser._policyCtx = { to_repo: toRepo, task };
    const blocked = await safetyGate(request, env, authUser, fromRepo, amount);
    if (blocked) return blocked;
  } else {
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

    const settleFrom = activeDelegation ? SYSTEM_DELEGATE : fromRepo;
  const payTaskLabel = activeDelegation ? ("delegate-spend:" + activeDelegation.id + ":" + task.slice(0, 40)) : task;

  await env.DB.batch([
    env.DB.prepare(
      `INSERT INTO accounts (repo_id, balance) VALUES (?, 0) ON CONFLICT(repo_id) DO NOTHING`
    ).bind(fromRepo),
    env.DB.prepare(
      `INSERT INTO accounts (repo_id, balance) VALUES (?, 0) ON CONFLICT(repo_id) DO NOTHING`
    ).bind(toRepo),
  ]);

  let fromBalance = null;
  let creditDrawn = 0;
  let usedCredit = false;

  // Delegation path: funds already locked in system/delegate — claim reduced remaining
  if (activeDelegation) {
    fromBalance = null; // parent cash untouched
    creditDrawn = 0;
    usedCredit = false;
    // Mark as settled from system/delegate below (skip parent debit)
  } else {
  // Fast cash path
  const cashDebit = await env.DB.prepare(
    `UPDATE accounts
     SET balance = balance - ?1, updated_at = datetime('now')
     WHERE repo_id = ?2 AND balance >= ?1
     RETURNING balance`
  )
    .bind(amount, fromRepo)
    .first();

  if (cashDebit) {
    fromBalance = Number(cashDebit.balance);
  } else {
    const debitRes = await debitWithCredit(env, fromRepo, amount);
    if (!debitRes.ok) {
      if (idem && wonLock) {
        await env.DB.prepare(
          `DELETE FROM idempotency WHERE key = ? AND status = 'pending'`
        )
          .bind(idem)
          .run()
          .catch(() => {});
      }
      waitUntil(
        env.DB.prepare(
          `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
           VALUES (?1, ?2, ?3, ?4, 'failed', ?5)`
        )
          .bind(settleFrom, toRepo, amount, payTaskLabel, Date.now() - t0)
          .run()
      );
      return bad(
        request,
        debitRes.error || "Insufficient funds",
        debitRes.code === "wallet_locked" ? 403 : 402,
        {
          code: debitRes.code || "insufficient",
          available_credit: debitRes.available_credit,
        }
      );
    }
    fromBalance = Number(debitRes.balance);
    creditDrawn = debitRes.credit_drawn || 0;
    usedCredit = creditDrawn > 0;
  }
  } // end non-delegation debit

  if (traceId) {
    try {
      await ensureTrace(env, traceId, {
        label: task || "pay",
        created_by: authUser && authUser.id,
      });
    } catch (_) {}
  }

  const latency = Date.now() - t0;
  let toBalance = null;
  let txId = null;

  async function compensateDebit() {
    try {
      await env.DB.prepare(
        `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
      )
        .bind(amount, fromRepo)
        .run();
      if (usedCredit && creditDrawn > 0) {
        await env.DB.prepare(
          `UPDATE agent_limits
           SET outstanding_credit = MAX(0, COALESCE(outstanding_credit, 0) - ?2),
               updated_at = datetime('now')
           WHERE repo_id = ?1`
        )
          .bind(fromRepo, creditDrawn)
          .run();
      }
    } catch (e) {
      console.log("pay_compensate_err", e && e.message);
    }
  }

  try {
    const batchRes = await env.DB.batch([
      env.DB.prepare(
        `UPDATE accounts
         SET balance = balance + ?1, updated_at = datetime('now')
         WHERE repo_id = ?2
         RETURNING balance`
      ).bind(amount, toRepo),
      env.DB.prepare(
        `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms, idempotency_key, trace_id)
         VALUES (?1, ?2, ?3, ?4, 'success', ?5, ?6, ?7)
         RETURNING id`
      ).bind(fromRepo, toRepo, amount, task, latency, idem, traceId),
    ]);
    // D1 batch: array of { results: [...] }
    const r0 = batchRes && batchRes[0];
    const r1 = batchRes && batchRes[1];
    const creditRow =
      (r0 && r0.results && r0.results[0]) ||
      (r0 && r0.result && r0.result[0]) ||
      null;
    const txRow =
      (r1 && r1.results && r1.results[0]) ||
      (r1 && r1.result && r1.result[0]) ||
      null;
    if (creditRow && creditRow.balance != null) toBalance = Number(creditRow.balance);
    if (txRow && txRow.id != null) txId = txRow.id;
  } catch (e) {
    // Fallback without RETURNING / without trace_id column
    try {
      await env.DB.batch([
        env.DB.prepare(
          `UPDATE accounts
           SET balance = balance + ?1, updated_at = datetime('now')
           WHERE repo_id = ?2`
        ).bind(amount, toRepo),
        env.DB.prepare(
          `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms, idempotency_key)
           VALUES (?1, ?2, ?3, ?4, 'success', ?5, ?6)`
        ).bind(settleFrom, toRepo, amount, payTaskLabel, latency, idem),
      ]);
    } catch (e2) {
      console.log("pay_settle_error", e2 && e2.message);
      await compensateDebit();
      if (idem && wonLock) {
        await env.DB.prepare(
          `DELETE FROM idempotency WHERE key = ? AND status = 'pending'`
        )
          .bind(idem)
          .run()
          .catch(() => {});
      }
      return bad(request, "Settlement failed — debit rolled back", 500);
    }
  }

  if (toBalance == null) {
    const row = await env.DB.prepare(
      `SELECT balance FROM accounts WHERE repo_id = ?1`
    )
      .bind(toRepo)
      .first()
      .catch(() => null);
    if (row) toBalance = Number(row.balance);
  }

  // Receipt before response so clients always get receipt_id when possible
  let receiptId = null;
  let receiptSig = null;
  try {
    const rcpt = await issuePayReceipt(env, {
      from_repo: fromRepo,
      to_repo: toRepo,
      amount,
      task,
      status: "success",
      tx_id: txId,
    });
    if (rcpt) {
      receiptId = rcpt.id;
      receiptSig = rcpt.signature;
    }
  } catch (e) {
    console.log("pay_receipt_err", e && e.message);
  }

  
  if (activeDelegation) {
    try {
      await logDelegateEvent(env, activeDelegation.id, "spent", {
        actor_repo: activeDelegation.parent_repo,
        amount,
        to_repo: toRepo,
        note: task,
      });
      await adjustRep(env, activeDelegation.parent_repo, CREDIT_REP_SUCCESS_BONUS, "delegate_spend", activeDelegation.id);
      if (activeDelegation.created_by) {
        scheduleWebhook(ctx, env, activeDelegation.created_by, "delegate.spent", {
          id: activeDelegation.id,
          parent_repo: activeDelegation.parent_repo,
          to_repo: toRepo,
          amount,
          remaining_usd: Number(activeDelegation.remaining_usd),
          status: activeDelegation.status,
          task,
        });
      }
    } catch (e) {
      console.log("delegate_post_spend", e && e.message);
    }
  } else if (authUser) {
    try {
      await safetyRecordSpend(env, authUser, fromRepo, amount);
    } catch (_) {}
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
    credit_drawn: creditDrawn || undefined,
    latency_ms: Date.now() - t0,
    balances: {
      [fromRepo]: fromBalance,
      [toRepo]: toBalance,
    },
  };
  if (receiptId) {
    payload.receipt_id = receiptId;
    payload.receipt_signature = receiptSig;
  }

  // Post-commit telemetry + idempotency (non-blocking)
  const keyId =
    authUser && authUser.auth_via === "api_key" ? authUser.key_id : null;
  const today = new Date().toISOString().slice(0, 10);
  const payloadJson = JSON.stringify(payload);

  waitUntil(
    (async () => {
      try {
        await env.DB.batch([
          env.DB.prepare(
            `INSERT INTO velocity_events (id, repo_id, api_key_id, amount, created_at)
             VALUES (?1, ?2, ?3, ?4, datetime('now'))`
          ).bind(randomId(12), fromRepo, keyId || null, Number(amount) || 0),
          env.DB.prepare(
            `UPDATE agent_limits
             SET daily_spent = CASE
                   WHEN substr(COALESCE(daily_window_start, ''), 1, 10) = ?3
                   THEN COALESCE(daily_spent, 0) + ?2
                   ELSE ?2
                 END,
                 daily_window_start = ?3,
                 updated_at = datetime('now')
             WHERE repo_id = ?1`
          ).bind(fromRepo, Number(amount) || 0, today),
        ]);
      } catch (_) {
        // ensure row then retry daily bump
        try {
          await ensureAgentLimits(env, fromRepo);
          await addDailySpent(env, fromRepo, amount);
          await recordVelocityEvent(env, fromRepo, amount, keyId);
        } catch (e2) {
          console.log("pay_telemetry", e2 && e2.message);
        }
      }
      try {
        await adjustRep(
          env,
          fromRepo,
          CREDIT_REP_SUCCESS_BONUS + Math.min(50, amount * CREDIT_REP_PER_USD),
          "pay_success"
        );
      } catch (_) {}
      if (idem && wonLock) {
        try {
          await env.DB.prepare(
            `UPDATE idempotency
             SET status = 'success', result_json = ?1, updated_at = datetime('now')
             WHERE key = ?2`
          )
            .bind(payloadJson, idem)
            .run();
        } catch (_) {}
      }
    })()
  );

  return json(request, payload);
}


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

async function handleEscrowHold(request, env, ctx) {
  const t0 = Date.now();
  const waitUntil = (p) => {
    try {
      if (ctx && typeof ctx.waitUntil === "function") {
        ctx.waitUntil(Promise.resolve(p).catch((e) => console.log("escrow_hold_bg", e && e.message)));
        return;
      }
    } catch (_) {}
    Promise.resolve(p).catch(() => {});
  };

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

  const debitRes = await debitWithCredit(env, fromRepo, amount);
  if (!debitRes.ok) {
    return bad(request, debitRes.error || "Insufficient funds", debitRes.code === "wallet_locked" ? 403 : 402, {
      code: debitRes.code || "insufficient",
      available_credit: debitRes.available_credit,
    });
  }
  const debit = { balance: debitRes.balance };
  const creditDrawn = debitRes.credit_drawn || 0;

  const id = "esc_" + randomId(12);
  const modifier = "+" + ttlSec + " seconds";

  let storedExpires = null;
  try {
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
    storedExpires = stored?.expires_at || null;
  } catch (e) {
    // best-effort compensate debit if insert failed
    try {
      await env.DB.prepare(
        `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
      )
        .bind(amount, fromRepo)
        .run();
    } catch (_) {}
    return bad(request, "Escrow hold failed: " + (e.message || e), 500);
  }

  // Post-commit: velocity + daily spend (non-blocking) — same pattern as pay
  waitUntil(safetyRecordSpend(env, authUser, fromRepo, amount));

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
      expires_at: storedExpires,
      ttl_seconds: ttlSec,
    },
    balance_from: debit.balance,
    credit_drawn: creditDrawn || undefined,
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


function parseTraceId(v) {
  const s = String(v || "").trim().slice(0, 128);
  if (!s) return null;
  if (!/^[A-Za-z0-9_.:\-]+$/.test(s)) return null;
  return s;
}

async function ensureTrace(env, traceId, { label, created_by } = {}) {
  if (!traceId) return;
  try {
    await env.DB.prepare(
      `INSERT INTO payment_traces (id, label, created_by, created_at)
       VALUES (?1, ?2, ?3, datetime('now'))
       ON CONFLICT(id) DO NOTHING`
    )
      .bind(traceId, label || null, created_by || null)
      .run();
  } catch (e) {
    console.log("ensure_trace", e && e.message);
  }
}

async function handleTraceGet(request, env, id) {
  id = parseTraceId(id);
  if (!id) return bad(request, "invalid trace id", 400);
  let txs = [];
  try {
    const { results } = await env.DB.prepare(
      `SELECT id, from_repo, to_repo, amount, task, status, latency_ms, created_at, trace_id
       FROM transactions WHERE trace_id = ?1 ORDER BY id ASC LIMIT 200`
    )
      .bind(id)
      .all();
    txs = results || [];
  } catch (e) {
    return bad(
      request,
      "trace column/table missing — run d1-trace-migration.sql: " + (e.message || e),
      500
    );
  }
  let meta = null;
  try {
    meta = await env.DB.prepare(`SELECT * FROM payment_traces WHERE id = ?1`).bind(id).first();
  } catch (_) {}
  const vol = txs
    .filter((t) => t.status === "success")
    .reduce((s, t) => s + Number(t.amount || 0), 0);
  return json(request, {
    ok: true,
    trace_id: id,
    meta: meta || null,
    count: txs.length,
    volume: Math.round(vol * 1e6) / 1e6,
    transactions: txs,
  });
}


/* ─── Obligation netting (bilateral batch settlement) ───
 * Soft net by default (report + ledger annotation). Pass apply_balances:true to move funds.
 */

/* ─── Cross-deployment clearing netting ───
 * Multilateral net positions over bilateral micro-pays in a time window.
 * Produces HMAC-SHA256 settlement manifest (RECEIPT_SECRET) for external rails.
 * Optional apply_balances: move net amounts via system/clearing.
 *
 * POST /api/clearing/run { window_hours?, apply_balances?, deployment_id? }
 * GET  /api/clearing?limit=
 * GET  /api/clearing/:id  → batch + positions + settlement + hmac
 */

function clearingSecret(env) {
  return env.RECEIPT_SECRET || env.SESSION_SECRET || env.GOOGLE_CLIENT_SECRET || "a2a-dev-receipt-secret";
}

async function hmacSettlement(env, canonicalJson) {
  return hmacSha256Hex(clearingSecret(env), canonicalJson);
}


/* ─── Verifiable Work Settlement (VWS) ───
 * 1) Provider POST /api/work/claim  { task, amount, expected_hash?, output_hash?, min_attestations? }
 * 2) Buyer     POST /api/work/lock   { id }  — locks amount from buyer → system/work
 * 3) Anyone    POST /api/work/attest { id, output_hash, note? }
 * 4) Settle    POST /api/work/settle { id }  — when attestations >= min and hash matches → pay provider
 * 5) Refund    POST /api/work/refund { id }  — buyer or timeout path
 * Receipt includes work proof + payment (HMAC).
 */

function parseWorkTtl(body) {
  const sec = Number(body.ttl_seconds ?? body.ttl);
  if (Number.isFinite(sec)) {
    if (sec < WORK_MIN_TTL_SEC || sec > WORK_MAX_TTL_SEC) return null;
    return Math.floor(sec);
  }
  return WORK_DEFAULT_TTL_SEC;
}

function isHexHash(s) {
  return typeof s === "string" && /^[a-fA-F0-9]{16,128}$/.test(s.trim());
}

async function logWorkEvent(env, claimId, event, { actor_repo, note } = {}) {
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

async function loadWorkClaim(env, id) {
  try {
    return await env.DB.prepare(`SELECT * FROM work_claims WHERE id = ?1`).bind(id).first();
  } catch {
    return null;
  }
}

async function handleWorkClaim(request, env, ctx) {
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

async function handleWorkLock(request, env, ctx) {
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

async function handleWorkAttest(request, env, ctx) {
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

async function handleWorkSettle(request, env, ctx) {
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

async function handleWorkRefund(request, env, ctx) {
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

async function handleWorkGet(request, env, id) {
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

async function handleWorkList(request, url, env) {
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

async function expireWorkClaims(env, ctx) {
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


async function handleClearingRun(request, env, ctx) {
  const t0 = Date.now();
  const authUser = await getAuthUser(request, env);
  if (!authUser) return bad(request, "Sign in or API key required", 401);

  const rlId =
    authUser.auth_via === "api_key"
      ? "cl:key:" + (authUser.key_id || authUser.id)
      : "cl:user:" + authUser.id;
  const limited = await checkRateLimit(env, rlId, RL_CLEARING_MAX, RL_CLEARING_WINDOW_SEC);
  if (limited) {
    return bad(request, "Rate limit: clearing", 429, { retry_after_sec: limited.retry_after_sec });
  }

  let body = {};
  try {
    body = await request.json();
  } catch {
    body = {};
  }

  let windowHours = Number(body.window_hours);
  if (!Number.isFinite(windowHours) || windowHours <= 0) windowHours = CLEARING_DEFAULT_WINDOW_HOURS;
  if (windowHours < CLEARING_MIN_WINDOW_HOURS || windowHours > CLEARING_MAX_WINDOW_HOURS) {
    return bad(request, "window_hours out of range");
  }
  const applyBalances = !!body.apply_balances;
  const deploymentId = String(body.deployment_id || body.deployment || "default").slice(0, 120);

  // Aggregate bilateral pays in window (exclude system/* counterparties)
  let txs = [];
  try {
    const q = await env.DB.prepare(
      `SELECT from_repo, to_repo, amount FROM transactions
       WHERE status = 'success'
         AND created_at >= datetime('now', ?1)
         AND from_repo NOT LIKE 'system/%'
         AND to_repo NOT LIKE 'system/%'
       LIMIT 20000`
    )
      .bind("-" + windowHours + " hours")
      .all();
    txs = q.results || [];
  } catch (e) {
    return bad(request, "transactions query failed: " + (e.message || e), 500);
  }

  // Net position per repo: +in -out
  const pos = new Map(); // repo -> { out, in }
  let gross = 0;
  for (const t of txs) {
    const a = Number(t.amount) || 0;
    if (!(a > 0)) continue;
    gross += a;
    const fr = t.from_repo;
    const tr = t.to_repo;
    if (!pos.has(fr)) pos.set(fr, { out: 0, in: 0 });
    if (!pos.has(tr)) pos.set(tr, { out: 0, in: 0 });
    pos.get(fr).out += a;
    pos.get(tr).in += a;
  }
  gross = Math.round(gross * 1e6) / 1e6;

  const positions = [];
  let volumeNet = 0;
  for (const [repo, v] of pos.entries()) {
    const net = Math.round((v.in - v.out) * 1e6) / 1e6;
    if (Math.abs(net) < MIN_AMOUNT) continue;
    positions.push({
      repo_id: repo,
      gross_out: Math.round(v.out * 1e6) / 1e6,
      gross_in: Math.round(v.in * 1e6) / 1e6,
      net_amount: net,
    });
    volumeNet += Math.abs(net);
  }
  volumeNet = Math.round((volumeNet / 2) * 1e6) / 1e6; // each $ counted twice in abs sum
  const volumeSaved = Math.max(0, Math.round((gross - volumeNet) * 1e6) / 1e6);

  if (positions.length > CLEARING_MAX_REPOS) {
    return bad(request, "too many positions — narrow window_hours");
  }

  const batchId = "clr_" + randomId(12);
  const settlement = {
    type: "agentpay.clearing.settlement",
    version: 1,
    batch_id: batchId,
    deployment_id: deploymentId,
    window_hours: windowHours,
    created_at: new Date().toISOString(),
    volume_gross: gross,
    volume_net: volumeNet,
    volume_saved: volumeSaved,
    positions: positions
      .slice()
      .sort((a, b) => a.repo_id.localeCompare(b.repo_id))
      .map((p) => ({
        repo_id: p.repo_id,
        net_amount: p.net_amount,
        gross_in: p.gross_in,
        gross_out: p.gross_out,
      })),
  };
  const settlementJson = JSON.stringify(settlement);
  const settlementHmac = await hmacSettlement(env, settlementJson);

  // Optional hard settle: payers (net < 0) → system/clearing → receivers (net > 0)
  let applied = 0;
  if (applyBalances && positions.length) {
    await ensureAccount(env, SYSTEM_CLEARING);
    for (const p of positions) {
      if (p.net_amount >= 0) continue;
      const need = Math.abs(p.net_amount);
      await ensureAccount(env, p.repo_id);
      const deb = await env.DB.prepare(
        `UPDATE accounts SET balance = balance - ?1, updated_at = datetime('now')
         WHERE repo_id = ?2 AND balance >= ?1 RETURNING balance`
      )
        .bind(need, p.repo_id)
        .first();
      if (!deb) {
        // skip underfunded; leave net unsettled for this repo
        continue;
      }
      await env.DB.prepare(
        `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
      )
        .bind(need, SYSTEM_CLEARING)
        .run();
      await env.DB.prepare(
        `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
         VALUES (?1, ?2, ?3, ?4, 'success', 0)`
      )
        .bind(p.repo_id, SYSTEM_CLEARING, need, "clearing-collect:" + batchId)
        .run();
      applied += 1;
    }
    for (const p of positions) {
      if (p.net_amount <= 0) continue;
      const pay = p.net_amount;
      await ensureAccount(env, p.repo_id);
      const pool = await env.DB.prepare(
        `UPDATE accounts SET balance = balance - ?1, updated_at = datetime('now')
         WHERE repo_id = ?2 AND balance >= ?1 RETURNING balance`
      )
        .bind(pay, SYSTEM_CLEARING)
        .first();
      if (!pool) continue;
      await env.DB.prepare(
        `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
      )
        .bind(pay, p.repo_id)
        .run();
      await env.DB.prepare(
        `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
         VALUES (?1, ?2, ?3, ?4, 'success', 0)`
      )
        .bind(SYSTEM_CLEARING, p.repo_id, pay, "clearing-pay:" + batchId)
        .run();
      applied += 1;
    }
  }

  try {
    const stmts = [
      env.DB.prepare(
        `INSERT INTO clearing_batches (
           id, window_hours, deployment_id, status, pairs_scanned, positions_count,
           volume_gross, volume_net, volume_saved, apply_balances,
           settlement_json, settlement_hmac, created_by, created_at
         ) VALUES (
           ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, datetime('now')
         )`
      ).bind(
        batchId,
        windowHours,
        deploymentId,
        applyBalances ? "applied" : "computed",
        txs.length,
        positions.length,
        gross,
        volumeNet,
        volumeSaved,
        applyBalances ? 1 : 0,
        settlementJson,
        settlementHmac,
        authUser.id || null
      ),
    ];
    for (const p of positions) {
      stmts.push(
        env.DB.prepare(
          `INSERT INTO clearing_positions (
             id, batch_id, repo_id, gross_out, gross_in, net_amount, created_at
           ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, datetime('now'))`
        ).bind(
          "cp_" + randomId(8),
          batchId,
          p.repo_id,
          p.gross_out,
          p.gross_in,
          p.net_amount
        )
      );
    }
    await env.DB.batch(stmts);
  } catch (e) {
    return bad(
      request,
      "clearing_batches table missing — run d1-clearing-migration.sql: " + (e.message || e),
      500
    );
  }

  // Also mint an HMAC receipt record for the settlement (cross-deployment verify)
  try {
    const rid = "rcpt_clr_" + randomId(10);
    const rPayload = {
      id: rid,
      type: "clearing_settlement",
      batch_id: batchId,
      deployment_id: deploymentId,
      volume_net: volumeNet,
      volume_saved: volumeSaved,
      hmac: settlementHmac,
      created_at: settlement.created_at,
    };
    const rJson = JSON.stringify(rPayload);
    const rSig = await hmacSha256Hex(clearingSecret(env), rJson);
    await env.DB.prepare(
      `INSERT INTO payment_receipts (id, payload_json, signature, from_repo, to_repo, amount, created_at)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, datetime('now'))`
    )
      .bind(rid, rJson, rSig, SYSTEM_CLEARING, deploymentId, volumeNet)
      .run();
  } catch (e) {
    console.log("clearing_receipt_skip", e && e.message);
  }

  if (authUser.id) {
    scheduleWebhook(ctx, env, authUser.id, "clearing.computed", {
      id: batchId,
      deployment_id: deploymentId,
      positions: positions.length,
      volume_saved: volumeSaved,
      apply_balances: applyBalances,
    });
  }

  return json(request, {
    ok: true,
    batch: {
      id: batchId,
      deployment_id: deploymentId,
      window_hours: windowHours,
      status: applyBalances ? "applied" : "computed",
      pairs_scanned: txs.length,
      positions_count: positions.length,
      volume_gross: gross,
      volume_net: volumeNet,
      volume_saved: volumeSaved,
      apply_balances: applyBalances,
      applied_legs: applied,
    },
    positions,
    settlement,
    settlement_hmac: settlementHmac,
    verify_hint:
      "HMAC-SHA256(RECEIPT_SECRET, settlement_json) === settlement_hmac. GET /api/clearing/" +
      batchId,
    latency_ms: Date.now() - t0,
  });
}

async function handleClearingGet(request, env, id) {
  id = String(id || "").trim();
  if (!id) return bad(request, "id required");
  let batch;
  try {
    batch = await env.DB.prepare(`SELECT * FROM clearing_batches WHERE id = ?1`).bind(id).first();
  } catch {
    return bad(request, "clearing_batches table missing — run d1-clearing-migration.sql", 500);
  }
  if (!batch) return bad(request, "Clearing batch not found", 404);

  let positions = [];
  try {
    const q = await env.DB.prepare(
      `SELECT repo_id, gross_out, gross_in, net_amount FROM clearing_positions
       WHERE batch_id = ?1 ORDER BY repo_id ASC`
    )
      .bind(id)
      .all();
    positions = q.results || [];
  } catch (_) {}

  let settlement = null;
  try {
    settlement = batch.settlement_json ? JSON.parse(batch.settlement_json) : null;
  } catch {
    settlement = batch.settlement_json;
  }

  // Recompute HMAC for verification convenience
  let hmac_ok = null;
  if (batch.settlement_json && batch.settlement_hmac) {
    const expect = await hmacSettlement(env, batch.settlement_json);
    hmac_ok = expect === batch.settlement_hmac;
  }

  return json(request, {
    ok: true,
    batch: {
      id: batch.id,
      deployment_id: batch.deployment_id,
      window_hours: batch.window_hours,
      status: batch.status,
      pairs_scanned: batch.pairs_scanned,
      positions_count: batch.positions_count,
      volume_gross: batch.volume_gross,
      volume_net: batch.volume_net,
      volume_saved: batch.volume_saved,
      apply_balances: !!batch.apply_balances,
      created_at: batch.created_at,
    },
    positions,
    settlement,
    settlement_hmac: batch.settlement_hmac,
    hmac_ok,
  });
}

async function handleClearingList(request, url, env) {
  const limit = Math.min(Math.max(Number(url.searchParams.get("limit") || 12), 1), 50);
  try {
    const { results } = await env.DB.prepare(
      `SELECT id, window_hours, deployment_id, status, pairs_scanned, positions_count,
              volume_gross, volume_net, volume_saved, apply_balances, created_at
       FROM clearing_batches ORDER BY created_at DESC LIMIT ?1`
    )
      .bind(limit)
      .all();
    return json(request, { ok: true, count: (results || []).length, batches: results || [] });
  } catch (e) {
    return bad(
      request,
      "clearing_batches table missing — run d1-clearing-migration.sql: " + (e.message || e),
      500
    );
  }
}


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
  windowHours = Math.max(
    NETTING_MIN_WINDOW_HOURS,
    Math.min(NETTING_MAX_WINDOW_HOURS, Math.floor(windowHours))
  );
  const applyBalances = !!body.apply_balances;
  const repoFilter = body.repo
    ? parseRepo(body.repo)
    : authUser.default_repo
      ? parseRepo(authUser.default_repo)
      : null;

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
          sid, runId, p.party_a, p.party_b, gab, gba, netAmt,
          netFrom, netTo, p.tx_count_a_to_b, p.tx_count_b_to_a
        )
        .run();
    } catch (e) {
      return bad(
        request,
        "netting tables missing — run d1-netting-migration.sql: " + (e.message || e),
        500
      );
    }

    await env.DB.prepare(
      `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
       VALUES (?1, ?2, ?3, ?4, 'success', ?5)`
    )
      .bind(SYSTEM_NETTING, netTo, netAmt, "net:" + sid + ":" + netFrom + "→" + netTo, Date.now() - t0)
      .run()
      .catch(() => {});

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
        runId, windowHours, pairs.length, pairsNetted,
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
    return json(request, { ok: true, runs: runs || [], settlements });
  } catch (e) {
    return bad(
      request,
      "netting tables missing — run d1-netting-migration.sql: " + (e.message || e),
      500
    );
  }
}


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

function parseDisputeTtl(body) {
  const sec = Number(body.ttl_seconds ?? body.ttl);
  if (Number.isFinite(sec)) {
    if (sec < DISPUTE_MIN_TTL_SEC || sec > DISPUTE_MAX_TTL_SEC) return null;
    return Math.floor(sec);
  }
  return DISPUTE_DEFAULT_TTL_SEC;
}

async function logDisputeEvent(env, disputeId, event, { actor_repo, amount, note, meta } = {}) {
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

async function loadDispute(env, id) {
  try {
    return await env.DB.prepare(`SELECT * FROM work_disputes WHERE id = ?1`).bind(id).first();
  } catch {
    return null;
  }
}

async function countOpenDisputeForClaim(env, claimId) {
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
async function executeDisputeRuling(env, dispute, t0, ctx) {
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

async function tryQuorumAndExecute(env, disputeId, ctx) {
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

async function handleDisputeOpen(request, env, ctx) {
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

  // Only buyer (complainant) may open
  const isBuyer =
    (authUser.default_repo && authUser.default_repo === buyerRepo) ||
    authUser.id === claim.created_by;
  // Allow if session user and default matches buyer
  const allowed =
    (authUser.default_repo && authUser.default_repo === buyerRepo) ||
    (authUser.auth_via === "session" && authUser.default_repo === buyerRepo);
  if (!allowed && !(authUser.default_repo === buyerRepo)) {
    // soft: allow if default_repo is buyer
    if (authUser.default_repo !== buyerRepo) {
      return bad(request, "Only the buyer may open a dispute on this claim", 403, { code: "not_buyer" });
    }
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

async function handleDisputeAccept(request, env, ctx) {
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

async function handleDisputeVote(request, env, ctx) {
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

async function handleDisputeExecute(request, env, ctx) {
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

async function handleDisputeCancel(request, env, ctx) {
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

async function handleDisputeGet(request, env, id) {
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

async function handleDisputeList(request, url, env) {
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

async function expireDisputes(env, ctx) {
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


/* ─── Capability tickets (spendable rights) ───
 * Mint: issuer debits optional USD bond + grants units of a capability string.
 * Transfer: holder → new holder (no unit change).
 * Redeem: burn units (and optional USD to service repo).
 * Capability is free-form: "model/gpt-tool", "api:vision", "can_call:foo".
 */
function parseTicketTtl(body) {
  const sec = Number(body.ttl_seconds ?? body.ttl);
  if (Number.isFinite(sec)) {
    if (sec < TICKET_MIN_TTL_SEC || sec > TICKET_MAX_TTL_SEC) return null;
    return Math.floor(sec);
  }
  return TICKET_DEFAULT_TTL_SEC;
}

function parseUnits(v) {
  const n = Number(v);
  if (!Number.isFinite(n) || n < TICKET_MIN_UNITS || n > TICKET_MAX_UNITS) return null;
  return Math.round(n * 1e6) / 1e6;
}

function parseCapability(v) {
  const s = String(v || "").trim().slice(0, 128);
  if (!s || !/^[A-Za-z0-9_.:\-\/]+$/.test(s)) return null;
  return s;
}

async function loadTicket(env, id) {
  try {
    return await env.DB.prepare(`SELECT * FROM capability_tickets WHERE id = ?1`).bind(id).first();
  } catch {
    return null;
  }
}

async function logTicketEvent(env, ticketId, event, { from_repo, to_repo, units, amount_usd, task } = {}) {
  try {
    await env.DB.prepare(
      `INSERT INTO ticket_events (id, ticket_id, event, from_repo, to_repo, units, amount_usd, task, created_at)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, datetime('now'))`
    )
      .bind(
        randomId(10),
        ticketId,
        event,
        from_repo || null,
        to_repo || null,
        units != null ? Number(units) : null,
        amount_usd != null ? Number(amount_usd) : null,
        task || null
      )
      .run();
  } catch (e) {
    console.log("ticket_event_err", e && e.message);
  }
}

async function handleTicketMint(request, env) {
  const t0 = Date.now();
  const authUser = await getAuthUser(request, env);
  if (!authUser) return bad(request, "Sign in or API key required", 401);

  const rlId =
    authUser.auth_via === "api_key"
      ? "tk:key:" + (authUser.key_id || authUser.id)
      : "tk:user:" + authUser.id;
  const limited = await checkRateLimit(env, rlId, RL_TICKET_MAX, RL_TICKET_WINDOW_SEC);
  if (limited) {
    return bad(request, "Rate limit: ticket ops", 429, { retry_after_sec: limited.retry_after_sec });
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return bad(request, "Invalid JSON body");
  }

  let issuer = parseRepo(body.issuer_repo || body.from_repo || body.fromRepo);
  if (!issuer && authUser.default_repo) issuer = parseRepo(authUser.default_repo);
  const holder = parseRepo(body.holder_repo || body.to_repo || body.toRepo) || issuer;
  const capability = parseCapability(body.capability || body.cap);
  const units = parseUnits(body.units ?? body.budget);
  const ttlSec = parseTicketTtl(body);
  const bond = body.bond_usd != null || body.amount != null ? parseAmount(body.bond_usd ?? body.amount) : null;
  const maxAmt =
    body.max_amount_usd != null && body.max_amount_usd !== ""
      ? parseAmount(body.max_amount_usd)
      : null;
  const task = String(body.task || "ticket-mint").slice(0, 500);

  if (!issuer) return bad(request, "issuer_repo required (or set default agent)");
  if (!holder) return bad(request, "holder_repo invalid");
  if (!capability) return bad(request, "capability required (e.g. model/vision or api:tool)");
  if (units == null) return bad(request, "units must be between " + TICKET_MIN_UNITS + " and " + TICKET_MAX_UNITS);
  if (ttlSec == null) {
    return bad(
      request,
      "ttl_seconds out of range (min " + TICKET_MIN_TTL_SEC + "s, max " + TICKET_MAX_TTL_SEC + "s)"
    );
  }

  // Optional USD bond locked from issuer (skin in the game)
  if (bond != null && bond > 0) {
    authUser._policyCtx = { to_repo: SYSTEM_TICKET, task };
    const blocked = await safetyGate(request, env, authUser, issuer, bond);
    if (blocked) return blocked;
  }

  if (bond != null && bond > 0) {
    await ensureAccount(env, issuer);
    const debit = await env.DB.prepare(
      `UPDATE accounts SET balance = balance - ?1, updated_at = datetime('now')
       WHERE repo_id = ?2 AND balance >= ?1 RETURNING balance`
    )
      .bind(bond, issuer)
      .first();
    if (!debit) return bad(request, "Insufficient funds for ticket bond", 402);
  }

  const id = "tk_" + randomId(12);
  const modifier = "+" + ttlSec + " seconds";
  const meta = body.meta && typeof body.meta === "object" ? JSON.stringify(body.meta).slice(0, 2000) : null;

  try {
    await env.DB.prepare(
      `INSERT INTO capability_tickets (
         id, issuer_repo, holder_repo, capability, units_total, units_remaining,
         max_amount_usd, status, created_by, expires_at, meta_json, created_at, updated_at
       ) VALUES (
         ?1, ?2, ?3, ?4, ?5, ?5, ?6, 'open', ?7,
         datetime('now', ?8), ?9, datetime('now'), datetime('now')
       )`
    )
      .bind(id, issuer, holder, capability, units, maxAmt, authUser.id, modifier, meta)
      .run();
  } catch (e) {
    if (bond != null && bond > 0) {
      await env.DB.prepare(
        `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
      )
        .bind(bond, issuer)
        .run();
    }
    return bad(
      request,
      "capability_tickets table missing — run d1-tickets-migration.sql: " + (e.message || e),
      500
    );
  }

  if (bond != null && bond > 0) {
    await env.DB.prepare(
      `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
       VALUES (?1, ?2, ?3, ?4, 'success', ?5)`
    )
      .bind(issuer, SYSTEM_TICKET, bond, "ticket-bond:" + id, Date.now() - t0)
      .run();
    await safetyRecordSpend(env, authUser, issuer, bond);
  }

  await logTicketEvent(env, id, "minted", {
    from_repo: issuer,
    to_repo: holder,
    units,
    amount_usd: bond || 0,
    task,
  });

  const row = await loadTicket(env, id);
  return json(request, {
    ok: true,
    ticket: {
      id,
      issuer_repo: issuer,
      holder_repo: holder,
      capability,
      units_total: units,
      units_remaining: units,
      max_amount_usd: maxAmt,
      bond_usd: bond || 0,
      status: "open",
      expires_at: row?.expires_at || null,
      ttl_seconds: ttlSec,
    },
    latency_ms: Date.now() - t0,
    hint: "Holder redeems via POST /api/ticket/redeem { id, units }. Transfer with POST /api/ticket/transfer.",
  });
}

async function handleTicketTransfer(request, env) {
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
  const toRepo = parseRepo(body.to_repo || body.toRepo || body.holder_repo);
  if (!id) return bad(request, "id required");
  if (!toRepo) return bad(request, "to_repo required");

  let row;
  try {
    row = await env.DB.prepare(`SELECT * FROM capability_tickets WHERE id = ?1`).bind(id).first();
  } catch {
    return bad(request, "capability_tickets table missing — run d1-tickets-migration.sql", 500);
  }
  if (!row) return bad(request, "Ticket not found", 404);
  if (row.status !== "open") {
    return bad(request, "Ticket not open (status=" + row.status + ")", 400, { code: "ticket_closed" });
  }
  if (row.expires_at) {
    const expMs = Date.parse(String(row.expires_at).replace(" ", "T") + "Z");
    if (Number.isFinite(expMs) && expMs < Date.now()) {
      return bad(request, "Ticket expired", 400, { code: "ticket_expired" });
    }
  }

  const allowed =
    authUser.id === row.created_by ||
    (authUser.default_repo &&
      (authUser.default_repo === row.holder_repo || authUser.default_repo === row.issuer_repo));
  if (!allowed) return bad(request, "Not authorized to transfer this ticket", 403);

  const fromHolder = row.holder_repo;
  await env.DB.prepare(
    `UPDATE capability_tickets
     SET holder_repo = ?2, updated_at = datetime('now')
     WHERE id = ?1 AND status = 'open'`
  )
    .bind(id, toRepo)
    .run();

  await logTicketEvent(env, id, "transferred", {
    from_repo: fromHolder,
    to_repo: toRepo,
    units: row.units_remaining,
  });

  return json(request, {
    ok: true,
    id,
    holder_repo: toRepo,
    from_holder: fromHolder,
    capability: row.capability,
    units_remaining: row.units_remaining,
    latency_ms: Date.now() - t0,
  });
}

async function handleTicketRedeem(request, env) {
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
  const units = parseUnits(body.units);
  const task = String(body.task || "ticket-redeem").slice(0, 500);
  const payTo = body.to_repo || body.toRepo ? parseRepo(body.to_repo || body.toRepo) : null;
  const amountUsd = body.amount != null ? parseAmount(body.amount) : null;

  if (!id) return bad(request, "id required");
  if (units == null) return bad(request, "units required");

  let row;
  try {
    row = await env.DB.prepare(`SELECT * FROM capability_tickets WHERE id = ?1`).bind(id).first();
  } catch {
    return bad(request, "capability_tickets table missing — run d1-tickets-migration.sql", 500);
  }
  if (!row) return bad(request, "Ticket not found", 404);
  if (row.status !== "open") {
    return bad(request, "Ticket not open (status=" + row.status + ")", 400, { code: "ticket_closed" });
  }
  if (row.expires_at) {
    const expMs = Date.parse(String(row.expires_at).replace(" ", "T") + "Z");
    if (Number.isFinite(expMs) && expMs < Date.now()) {
      return bad(request, "Ticket expired", 400, { code: "ticket_expired" });
    }
  }

  const allowed =
    authUser.id === row.created_by ||
    (authUser.default_repo && authUser.default_repo === row.holder_repo);
  if (!allowed) return bad(request, "Not authorized to redeem this ticket", 403);

  const remaining = Number(row.units_remaining);
  if (units > remaining) {
    return bad(request, "Insufficient ticket units (remaining " + remaining + ")", 402, {
      code: "ticket_insufficient",
      remaining,
    });
  }

  if (amountUsd != null && amountUsd > 0) {
    if (row.max_amount_usd != null && amountUsd > Number(row.max_amount_usd)) {
      return bad(request, "amount exceeds ticket max_amount_usd", 403, { code: "ticket_max_amount" });
    }
  }

  const claim = await env.DB.prepare(
    `UPDATE capability_tickets
     SET units_remaining = units_remaining - ?1,
         status = CASE WHEN units_remaining - ?1 <= 0.0000005 THEN 'exhausted' ELSE 'open' END,
         updated_at = datetime('now'),
         closed_at = CASE WHEN units_remaining - ?1 <= 0.0000005 THEN datetime('now') ELSE closed_at END,
         close_reason = CASE WHEN units_remaining - ?1 <= 0.0000005 THEN 'exhausted' ELSE close_reason END
     WHERE id = ?2 AND status = 'open' AND units_remaining >= ?1
     RETURNING id, units_remaining, status, capability, holder_repo, issuer_repo`
  )
    .bind(units, id)
    .first();

  if (!claim) return bad(request, "Redeem failed (race or insufficient)", 409);

  // Optional USD settlement to service provider
  if (amountUsd != null && amountUsd > 0 && payTo) {
    await ensureAccount(env, SYSTEM_TICKET);
    await ensureAccount(env, payTo);
    // Pay from system/ticket bond pool if funded; else from holder (soft fail)
    const fromBond = await env.DB.prepare(
      `UPDATE accounts SET balance = balance - ?1, updated_at = datetime('now')
       WHERE repo_id = ?2 AND balance >= ?1 RETURNING balance`
    )
      .bind(amountUsd, SYSTEM_TICKET)
      .first();
    if (fromBond) {
      await env.DB.prepare(
        `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
      )
        .bind(amountUsd, payTo)
        .run();
      await env.DB.prepare(
        `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
         VALUES (?1, ?2, ?3, ?4, 'success', ?5)`
      )
        .bind(SYSTEM_TICKET, payTo, amountUsd, "ticket-redeem:" + id + ":" + task.slice(0, 40), Date.now() - t0)
        .run();
    }
  }

  await logTicketEvent(env, id, "redeemed", {
    from_repo: claim.holder_repo,
    to_repo: payTo,
    units,
    amount_usd: amountUsd || 0,
    task,
  });

  await env.DB.prepare(
    `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
     VALUES (?1, ?2, ?3, ?4, 'success', ?5)`
  )
    .bind(
      claim.holder_repo,
      SYSTEM_TICKET,
      0,
      "ticket-units:" + id + ":" + units + ":" + claim.capability,
      Date.now() - t0
    )
    .run()
    .catch(() => {});

  return json(request, {
    ok: true,
    id,
    capability: claim.capability,
    units_burned: units,
    units_remaining: Math.max(0, Number(claim.units_remaining)),
    status: claim.status,
    amount_usd: amountUsd || 0,
    to_repo: payTo,
    latency_ms: Date.now() - t0,
  });
}

async function handleTicketGet(request, env, id) {
  id = String(id || "").trim();
  if (!id) return bad(request, "id required");
  const row = await loadTicket(env, id);
  if (!row) {
    // distinguish missing table
    try {
      await env.DB.prepare(`SELECT 1 FROM capability_tickets LIMIT 1`).first();
    } catch (e) {
      return bad(request, "capability_tickets table missing — run d1-tickets-migration.sql", 500);
    }
    return bad(request, "Ticket not found", 404);
  }
  let events = [];
  try {
    const q = await env.DB.prepare(
      `SELECT event, from_repo, to_repo, units, amount_usd, task, created_at
       FROM ticket_events WHERE ticket_id = ?1 ORDER BY created_at DESC LIMIT 30`
    )
      .bind(id)
      .all();
    events = q.results || [];
  } catch (_) {}
  return json(request, { ok: true, ticket: row, events });
}

async function handleTicketList(request, url, env) {
  const limit = Math.min(Math.max(Number(url.searchParams.get("limit") || 25), 1), 100);
  const repo = (url.searchParams.get("repo") || "").trim();
  const status = (url.searchParams.get("status") || "").trim();
  const capability = (url.searchParams.get("capability") || "").trim();

  let sql = `SELECT id, issuer_repo, holder_repo, capability, units_total, units_remaining,
                    max_amount_usd, status, expires_at, created_at
             FROM capability_tickets WHERE 1=1`;
  const binds = [];
  if (repo) {
    if (!parseRepo(repo)) return bad(request, "repo must be owner/repo");
    sql += ` AND (issuer_repo = ? OR holder_repo = ?)`;
    binds.push(repo, repo);
  }
  if (status && ["open", "exhausted", "expired", "closed"].includes(status)) {
    sql += ` AND status = ?`;
    binds.push(status);
  }
  if (capability) {
    sql += ` AND capability = ?`;
    binds.push(capability.slice(0, 128));
  }
  sql += ` ORDER BY created_at DESC LIMIT ?`;
  binds.push(limit);

  try {
    const { results } = await env.DB.prepare(sql).bind(...binds).all();
    return json(request, { ok: true, count: results.length, tickets: results });
  } catch (e) {
    return bad(
      request,
      "capability_tickets table missing — run d1-tickets-migration.sql: " + (e.message || e),
      500
    );
  }
}

async function expireTickets(env) {
  const t0 = Date.now();
  let results;
  try {
    const q = await env.DB.prepare(
      `SELECT id FROM capability_tickets
       WHERE status = 'open'
         AND expires_at IS NOT NULL
         AND expires_at < datetime('now')
       ORDER BY expires_at ASC
       LIMIT ?1`
    )
      .bind(EXPIRE_TICKET_BATCH)
      .all();
    results = q.results || [];
  } catch (e) {
    return { expired: 0, scanned: 0, error: e.message, latency_ms: Date.now() - t0 };
  }
  let expired = 0;
  for (const r of results) {
    try {
      const claim = await env.DB.prepare(
        `UPDATE capability_tickets
         SET status = 'expired', closed_at = datetime('now'), close_reason = 'expired',
             updated_at = datetime('now')
         WHERE id = ?1 AND status = 'open'
         RETURNING id`
      )
        .bind(r.id)
        .first();
      if (claim) {
        expired += 1;
        await logTicketEvent(env, r.id, "expired", {});
      }
    } catch (e) {
      console.log("ticket_expire_err", r.id, e && e.message);
    }
  }
  return { expired, scanned: results.length, latency_ms: Date.now() - t0 };
}


/* ─── Intent bonds (graded commitment) ───
 * Lifecycle: open → matched → fulfilled | slashed | expired | cancelled
 * Poster locks bond_amount into system/bond.
 * Match: counterparty attests intent is accepted.
 * Fulfill: full refund of bond to poster.
 * Slash: fraction (slash_bps or body.slash_bps) → system/slash-pool; rest → poster.
 * Expire open: full refund. Expire matched past match_expires: auto-slash default bps.
 */
function parseBondTtl(body, field, def) {
  const sec = Number(body[field] ?? body.ttl);
  if (Number.isFinite(sec)) {
    if (sec < BOND_MIN_TTL_SEC || sec > BOND_MAX_TTL_SEC) return null;
    return Math.floor(sec);
  }
  return def;
}

async function logBondEvent(env, bondId, event, { actor_repo, amount, note } = {}) {
  try {
    await env.DB.prepare(
      `INSERT INTO bond_events (id, bond_id, event, actor_repo, amount, note, created_at)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, datetime('now'))`
    )
      .bind(
        randomId(10),
        bondId,
        event,
        actor_repo || null,
        amount != null ? Number(amount) : null,
        note ? String(note).slice(0, 500) : null
      )
      .run();
  } catch (e) {
    console.log("bond_event_err", e && e.message);
  }
}

async function loadBond(env, id) {
  try {
    return await env.DB.prepare(`SELECT * FROM intent_bonds WHERE id = ?1`).bind(id).first();
  } catch {
    return null;
  }
}

async function handleBondPost(request, env, ctx) {
  const t0 = Date.now();
  const authUser = await getAuthUser(request, env);
  if (!authUser) return bad(request, "Sign in or API key required", 401);

  const rlId =
    authUser.auth_via === "api_key"
      ? "bd:key:" + (authUser.key_id || authUser.id)
      : "bd:user:" + authUser.id;
  const limited = await checkRateLimit(env, rlId, RL_BOND_MAX, RL_BOND_WINDOW_SEC);
  if (limited) {
    return bad(request, "Rate limit: bond ops", 429, { retry_after_sec: limited.retry_after_sec });
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return bad(request, "Invalid JSON body");
  }

  let poster = parseRepo(body.poster_repo || body.from_repo || body.fromRepo);
  if (!poster && authUser.default_repo) poster = parseRepo(authUser.default_repo);
  const counterparty = body.counterparty_repo || body.to_repo
    ? parseRepo(body.counterparty_repo || body.to_repo)
    : null;
  const intent = String(body.intent || body.statement || "").trim().slice(0, 1000);
  const task = String(body.task || "intent-bond").slice(0, 500);
  const amount = parseAmount(body.bond_amount ?? body.amount);
  const ttlSec = parseBondTtl(body, "ttl_seconds", BOND_DEFAULT_TTL_SEC);
  const matchTtlSec = parseBondTtl(body, "match_ttl_seconds", BOND_DEFAULT_MATCH_TTL_SEC);
  let slashBps = Number(body.slash_bps);
  if (!Number.isFinite(slashBps)) slashBps = BOND_DEFAULT_SLASH_BPS;
  slashBps = Math.max(0, Math.min(10000, Math.floor(slashBps)));

  if (!poster) return bad(request, "poster_repo required (or set default agent)");
  if (!intent) return bad(request, "intent required (what you commit to do)");
  if (amount == null || amount < BOND_MIN || amount > BOND_MAX) {
    return bad(request, "bond_amount must be between " + BOND_MIN + " and " + BOND_MAX);
  }
  if (ttlSec == null) {
    return bad(request, "ttl_seconds out of range");
  }

  authUser._policyCtx = { to_repo: SYSTEM_BOND, task };
  const blocked = await safetyGate(request, env, authUser, poster, amount);
  if (blocked) return blocked;

  await ensureAccount(env, poster);
  const debit = await env.DB.prepare(
    `UPDATE accounts SET balance = balance - ?1, updated_at = datetime('now')
     WHERE repo_id = ?2 AND balance >= ?1 RETURNING balance`
  )
    .bind(amount, poster)
    .first();
  if (!debit) return bad(request, "Insufficient funds for bond", 402);

  const id = "bd_" + randomId(12);
  const modifier = "+" + ttlSec + " seconds";
  const meta = body.meta && typeof body.meta === "object" ? JSON.stringify(body.meta).slice(0, 2000) : null;

  try {
    await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO intent_bonds (
           id, poster_repo, counterparty_repo, intent, task, bond_amount, slash_bps,
           status, created_by, expires_at, meta_json, created_at, updated_at
         ) VALUES (
           ?1, ?2, ?3, ?4, ?5, ?6, ?7, 'open', ?8,
           datetime('now', ?9), ?10, datetime('now'), datetime('now')
         )`
      ).bind(
        id, poster, counterparty, intent, task, amount, slashBps,
        authUser.id, modifier, meta
      ),
      env.DB.prepare(
        `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
         VALUES (?1, ?2, ?3, ?4, 'success', ?5)`
      ).bind(poster, SYSTEM_BOND, amount, "bond-lock:" + id, Date.now() - t0),
    ]);
  } catch (e) {
    await env.DB.prepare(
      `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
    )
      .bind(amount, poster)
      .run();
    return bad(
      request,
      "intent_bonds table missing — run d1-bonds-migration.sql: " + (e.message || e),
      500
    );
  }

  await safetyRecordSpend(env, authUser, poster, amount);
  await logBondEvent(env, id, "posted", { actor_repo: poster, amount, note: intent.slice(0, 200) });

  if (authUser.id) {
    scheduleWebhook(ctx, env, authUser.id, "bond.posted", {
      id,
      poster_repo: poster,
      counterparty_repo: counterparty,
      bond_amount: amount,
      intent: intent.slice(0, 200),
      status: "open",
    });
  }

  const row = await loadBond(env, id);
  return json(request, {
    ok: true,
    bond: {
      id,
      poster_repo: poster,
      counterparty_repo: counterparty,
      intent,
      task,
      bond_amount: amount,
      slash_bps: slashBps,
      status: "open",
      expires_at: row?.expires_at || null,
      ttl_seconds: ttlSec,
      match_ttl_seconds: matchTtlSec,
    },
    balance_poster: debit.balance,
    latency_ms: Date.now() - t0,
    hint: "Counterparty: POST /api/bond/match { id }. Then fulfill or slash.",
  });
}

async function handleBondMatch(request, env, ctx) {
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
  let cp = parseRepo(body.counterparty_repo || body.from_repo || body.matcher_repo);
  if (!cp && authUser.default_repo) cp = parseRepo(authUser.default_repo);
  const matchTtlSec = parseBondTtl(body, "match_ttl_seconds", BOND_DEFAULT_MATCH_TTL_SEC);

  if (!id) return bad(request, "id required");
  if (!cp) return bad(request, "counterparty_repo required (or default agent)");

  let row;
  try {
    row = await env.DB.prepare(`SELECT * FROM intent_bonds WHERE id = ?1`).bind(id).first();
  } catch {
    return bad(request, "intent_bonds table missing — run d1-bonds-migration.sql", 500);
  }
  if (!row) return bad(request, "Bond not found", 404);
  if (row.status !== "open") {
    return bad(request, "Bond not open (status=" + row.status + ")", 400, { code: "bond_not_open" });
  }
  if (row.expires_at) {
    const expMs = Date.parse(String(row.expires_at).replace(" ", "T") + "Z");
    if (Number.isFinite(expMs) && expMs < Date.now()) {
      return bad(request, "Bond expired", 400, { code: "bond_expired" });
    }
  }
  if (row.counterparty_repo && row.counterparty_repo !== cp) {
    return bad(request, "Bond reserved for " + row.counterparty_repo, 403);
  }
  if (cp === row.poster_repo) {
    return bad(request, "Poster cannot match own bond", 400);
  }

  const mod = "+" + (matchTtlSec || BOND_DEFAULT_MATCH_TTL_SEC) + " seconds";
  const claim = await env.DB.prepare(
    `UPDATE intent_bonds
     SET status = 'matched',
         counterparty_repo = ?2,
         matched_by = ?3,
         matched_at = datetime('now'),
         match_expires_at = datetime('now', ?4),
         updated_at = datetime('now')
     WHERE id = ?1 AND status = 'open'
     RETURNING *`
  )
    .bind(id, cp, authUser.id, mod)
    .first();
  if (!claim) return bad(request, "Match race failed", 409);

  await logBondEvent(env, id, "matched", { actor_repo: cp, note: "matched" });

  if (row.created_by) {
    scheduleWebhook(ctx, env, row.created_by, "bond.matched", {
      id,
      poster_repo: row.poster_repo,
      counterparty_repo: cp,
      bond_amount: row.bond_amount,
      status: "matched",
    });
  }

  return json(request, {
    ok: true,
    id,
    status: "matched",
    counterparty_repo: cp,
    match_expires_at: claim.match_expires_at,
    latency_ms: Date.now() - t0,
  });
}

async function handleBondFulfill(request, env, ctx) {
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
    row = await env.DB.prepare(`SELECT * FROM intent_bonds WHERE id = ?1`).bind(id).first();
  } catch {
    return bad(request, "intent_bonds table missing — run d1-bonds-migration.sql", 500);
  }
  if (!row) return bad(request, "Bond not found", 404);
  if (row.status !== "matched" && row.status !== "open") {
    return bad(request, "Bond not fulfillable (status=" + row.status + ")");
  }

  const allowed =
    authUser.id === row.created_by ||
    authUser.id === row.matched_by ||
    (authUser.default_repo &&
      (authUser.default_repo === row.poster_repo ||
        authUser.default_repo === row.counterparty_repo));
  if (!allowed) return bad(request, "Not authorized to fulfill", 403);

  const claim = await env.DB.prepare(
    `UPDATE intent_bonds
     SET status = 'fulfilled',
         fulfilled_at = datetime('now'),
         closed_at = datetime('now'),
         close_reason = 'fulfilled',
         updated_at = datetime('now')
     WHERE id = ?1 AND status IN ('open', 'matched')
     RETURNING *`
  )
    .bind(id)
    .first();
  if (!claim) return bad(request, "Fulfill race", 409);

  const refund = Number(row.bond_amount);
  await ensureAccount(env, row.poster_repo);
  await env.DB.batch([
    env.DB.prepare(
      `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
    ).bind(refund, row.poster_repo),
    env.DB.prepare(
      `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
       VALUES (?1, ?2, ?3, ?4, 'success', ?5)`
    ).bind(SYSTEM_BOND, row.poster_repo, refund, "bond-fulfill-refund:" + id, Date.now() - t0),
  ]);

  await logBondEvent(env, id, "fulfilled", { actor_repo: authUser.default_repo, amount: refund });

  if (row.created_by) {
    scheduleWebhook(ctx, env, row.created_by, "bond.fulfilled", {
      id,
      poster_repo: row.poster_repo,
      bond_amount: refund,
      status: "fulfilled",
    });
  }

  return json(request, {
    ok: true,
    id,
    status: "fulfilled",
    refunded: refund,
    latency_ms: Date.now() - t0,
  });
}

async function handleBondSlash(request, env, ctx) {
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
  const reason = String(body.reason || "slash").slice(0, 500);
  if (!id) return bad(request, "id required");

  let row;
  try {
    row = await env.DB.prepare(`SELECT * FROM intent_bonds WHERE id = ?1`).bind(id).first();
  } catch {
    return bad(request, "intent_bonds table missing — run d1-bonds-migration.sql", 500);
  }
  if (!row) return bad(request, "Bond not found", 404);
  if (row.status !== "matched" && row.status !== "open") {
    return bad(request, "Bond not slashable (status=" + row.status + ")");
  }

  // Matcher or poster (or reserved counterparty) may slash
  const allowed =
    authUser.id === row.matched_by ||
    authUser.id === row.created_by ||
    (authUser.default_repo &&
      (authUser.default_repo === row.counterparty_repo ||
        authUser.default_repo === row.poster_repo));
  if (!allowed) return bad(request, "Not authorized to slash", 403);

  let bps = Number(body.slash_bps);
  if (!Number.isFinite(bps)) bps = Number(row.slash_bps) || BOND_DEFAULT_SLASH_BPS;
  bps = Math.max(0, Math.min(10000, Math.floor(bps)));

  const bondAmt = Number(row.bond_amount);
  const slashAmt = Math.round(((bondAmt * bps) / 10000) * 1e6) / 1e6;
  const refund = Math.round((bondAmt - slashAmt) * 1e6) / 1e6;

  const claim = await env.DB.prepare(
    `UPDATE intent_bonds
     SET status = 'slashed',
         slashed_at = datetime('now'),
         slash_amount = ?2,
         closed_at = datetime('now'),
         close_reason = ?3,
         updated_at = datetime('now')
     WHERE id = ?1 AND status IN ('open', 'matched')
     RETURNING *`
  )
    .bind(id, slashAmt, reason)
    .first();
  if (!claim) return bad(request, "Slash race", 409);

  await ensureAccount(env, row.poster_repo);
  await ensureAccount(env, SYSTEM_SLASH_POOL);

  const stmts = [];
  if (slashAmt > 0) {
    stmts.push(
      env.DB.prepare(
        `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
      ).bind(slashAmt, SYSTEM_SLASH_POOL)
    );
    stmts.push(
      env.DB.prepare(
        `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
         VALUES (?1, ?2, ?3, ?4, 'success', ?5)`
      ).bind(SYSTEM_BOND, SYSTEM_SLASH_POOL, slashAmt, "bond-slash:" + id, Date.now() - t0)
    );
  }
  if (refund > 0) {
    stmts.push(
      env.DB.prepare(
        `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
      ).bind(refund, row.poster_repo)
    );
    stmts.push(
      env.DB.prepare(
        `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
         VALUES (?1, ?2, ?3, ?4, 'success', ?5)`
      ).bind(SYSTEM_BOND, row.poster_repo, refund, "bond-slash-refund:" + id, Date.now() - t0)
    );
  }
  if (stmts.length) await env.DB.batch(stmts);

  await adjustRep(env, row.poster_repo, -CREDIT_REP_FAIL_PENALTY, "bond_slashed", id);
  await logBondEvent(env, id, "slashed", {
    actor_repo: authUser.default_repo,
    amount: slashAmt,
    note: reason,
  });

  if (row.created_by) {
    scheduleWebhook(ctx, env, row.created_by, "bond.slashed", {
      id,
      poster_repo: row.poster_repo,
      slash_amount: slashAmt,
      refunded: refund,
      reason,
      status: "slashed",
    });
  }

  return json(request, {
    ok: true,
    id,
    status: "slashed",
    slash_bps: bps,
    slash_amount: slashAmt,
    refunded: refund,
    latency_ms: Date.now() - t0,
  });
}

async function handleBondCancel(request, env, ctx) {
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
    row = await env.DB.prepare(`SELECT * FROM intent_bonds WHERE id = ?1`).bind(id).first();
  } catch {
    return bad(request, "intent_bonds table missing — run d1-bonds-migration.sql", 500);
  }
  if (!row) return bad(request, "Bond not found", 404);
  if (row.status !== "open") {
    return bad(request, "Only open (unmatched) bonds can be cancelled", 400);
  }

  const allowed =
    authUser.id === row.created_by ||
    (authUser.default_repo && authUser.default_repo === row.poster_repo);
  if (!allowed) return bad(request, "Not authorized to cancel", 403);

  const claim = await env.DB.prepare(
    `UPDATE intent_bonds
     SET status = 'cancelled',
         closed_at = datetime('now'),
         close_reason = 'cancelled',
         updated_at = datetime('now')
     WHERE id = ?1 AND status = 'open'
     RETURNING *`
  )
    .bind(id)
    .first();
  if (!claim) return bad(request, "Cancel race", 409);

  const refund = Number(row.bond_amount);
  await ensureAccount(env, row.poster_repo);
  await env.DB.batch([
    env.DB.prepare(
      `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
    ).bind(refund, row.poster_repo),
    env.DB.prepare(
      `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
       VALUES (?1, ?2, ?3, ?4, 'success', ?5)`
    ).bind(SYSTEM_BOND, row.poster_repo, refund, "bond-cancel-refund:" + id, Date.now() - t0),
  ]);

  await logBondEvent(env, id, "cancelled", { actor_repo: row.poster_repo, amount: refund });

  return json(request, {
    ok: true,
    id,
    status: "cancelled",
    refunded: refund,
    latency_ms: Date.now() - t0,
  });
}

async function handleBondGet(request, env, id) {
  id = String(id || "").trim();
  if (!id) return bad(request, "id required");
  const row = await loadBond(env, id);
  if (!row) {
    try {
      await env.DB.prepare(`SELECT 1 FROM intent_bonds LIMIT 1`).first();
    } catch {
      return bad(request, "intent_bonds table missing — run d1-bonds-migration.sql", 500);
    }
    return bad(request, "Bond not found", 404);
  }
  let events = [];
  try {
    const q = await env.DB.prepare(
      `SELECT event, actor_repo, amount, note, created_at
       FROM bond_events WHERE bond_id = ?1 ORDER BY created_at DESC LIMIT 40`
    )
      .bind(id)
      .all();
    events = q.results || [];
  } catch (_) {}
  return json(request, { ok: true, bond: row, events });
}

async function handleBondList(request, url, env) {
  const limit = Math.min(Math.max(Number(url.searchParams.get("limit") || 25), 1), 100);
  const repo = (url.searchParams.get("repo") || "").trim();
  const status = (url.searchParams.get("status") || "").trim();

  let sql = `SELECT id, poster_repo, counterparty_repo, intent, task, bond_amount, slash_bps,
                    status, expires_at, match_expires_at, slash_amount, created_at
             FROM intent_bonds WHERE 1=1`;
  const binds = [];
  if (repo) {
    if (!parseRepo(repo)) return bad(request, "repo must be owner/repo");
    sql += ` AND (poster_repo = ? OR counterparty_repo = ?)`;
    binds.push(repo, repo);
  }
  if (status && ["open", "matched", "fulfilled", "slashed", "expired", "cancelled"].includes(status)) {
    sql += ` AND status = ?`;
    binds.push(status);
  }
  sql += ` ORDER BY created_at DESC LIMIT ?`;
  binds.push(limit);

  try {
    const { results } = await env.DB.prepare(sql).bind(...binds).all();
    return json(request, { ok: true, count: results.length, bonds: results });
  } catch (e) {
    return bad(
      request,
      "intent_bonds table missing — run d1-bonds-migration.sql: " + (e.message || e),
      500
    );
  }
}

async function expireBonds(env, ctx) {
  const t0 = Date.now();
  let expiredOpen = 0;
  let expiredMatch = 0;
  let refundedTotal = 0;
  let slashedTotal = 0;

  // 1) Open past expires_at → full refund + expired
  try {
    const q = await env.DB.prepare(
      `SELECT * FROM intent_bonds
       WHERE status = 'open'
         AND expires_at IS NOT NULL
         AND expires_at < datetime('now')
       ORDER BY expires_at ASC LIMIT ?1`
    )
      .bind(EXPIRE_BOND_BATCH)
      .all();
    for (const row of q.results || []) {
      try {
        const claim = await env.DB.prepare(
          `UPDATE intent_bonds
           SET status = 'expired', closed_at = datetime('now'), close_reason = 'expired',
               updated_at = datetime('now')
           WHERE id = ?1 AND status = 'open' RETURNING id`
        )
          .bind(row.id)
          .first();
        if (!claim) continue;
        const refund = Number(row.bond_amount);
        await ensureAccount(env, row.poster_repo);
        await env.DB.batch([
          env.DB.prepare(
            `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
          ).bind(refund, row.poster_repo),
          env.DB.prepare(
            `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
             VALUES (?1, ?2, ?3, ?4, 'success', 0)`
          ).bind(SYSTEM_BOND, row.poster_repo, refund, "bond-expire-refund:" + row.id),
        ]);
        await logBondEvent(env, row.id, "expired", { actor_repo: null, amount: refund });
        expiredOpen += 1;
        refundedTotal += refund;
        if (row.created_by) {
          scheduleWebhook(ctx, env, row.created_by, "bond.expired", {
            id: row.id,
            poster_repo: row.poster_repo,
            bond_amount: refund,
            status: "expired",
          });
        }
      } catch (e) {
        console.log("bond_expire_open", row.id, e && e.message);
      }
    }
  } catch (e) {
    return { expired_open: 0, expired_match: 0, error: e.message, latency_ms: Date.now() - t0 };
  }

  // 2) Matched past match_expires_at → default slash
  try {
    const q = await env.DB.prepare(
      `SELECT * FROM intent_bonds
       WHERE status = 'matched'
         AND match_expires_at IS NOT NULL
         AND match_expires_at < datetime('now')
       ORDER BY match_expires_at ASC LIMIT ?1`
    )
      .bind(EXPIRE_BOND_BATCH)
      .all();
    for (const row of q.results || []) {
      try {
        const bps = Number(row.slash_bps) || BOND_DEFAULT_SLASH_BPS;
        const bondAmt = Number(row.bond_amount);
        const slashAmt = Math.round(((bondAmt * bps) / 10000) * 1e6) / 1e6;
        const refund = Math.round((bondAmt - slashAmt) * 1e6) / 1e6;
        const claim = await env.DB.prepare(
          `UPDATE intent_bonds
           SET status = 'slashed', slashed_at = datetime('now'), slash_amount = ?2,
               closed_at = datetime('now'), close_reason = 'match_timeout',
               updated_at = datetime('now')
           WHERE id = ?1 AND status = 'matched' RETURNING id`
        )
          .bind(row.id, slashAmt)
          .first();
        if (!claim) continue;
        await ensureAccount(env, row.poster_repo);
        await ensureAccount(env, SYSTEM_SLASH_POOL);
        const stmts = [];
        if (slashAmt > 0) {
          stmts.push(
            env.DB.prepare(
              `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
            ).bind(slashAmt, SYSTEM_SLASH_POOL)
          );
          stmts.push(
            env.DB.prepare(
              `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
               VALUES (?1, ?2, ?3, ?4, 'success', 0)`
            ).bind(SYSTEM_BOND, SYSTEM_SLASH_POOL, slashAmt, "bond-match-timeout-slash:" + row.id)
          );
        }
        if (refund > 0) {
          stmts.push(
            env.DB.prepare(
              `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
            ).bind(refund, row.poster_repo)
          );
          stmts.push(
            env.DB.prepare(
              `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
               VALUES (?1, ?2, ?3, ?4, 'success', 0)`
            ).bind(SYSTEM_BOND, row.poster_repo, refund, "bond-match-timeout-refund:" + row.id)
          );
        }
        if (stmts.length) await env.DB.batch(stmts);
        await logBondEvent(env, row.id, "slashed", {
          amount: slashAmt,
          note: "match_timeout",
        });
        expiredMatch += 1;
        slashedTotal += slashAmt;
        refundedTotal += refund;
        if (row.created_by) {
          scheduleWebhook(ctx, env, row.created_by, "bond.slashed", {
            id: row.id,
            slash_amount: slashAmt,
            refunded: refund,
            reason: "match_timeout",
            status: "slashed",
          });
        }
      } catch (e) {
        console.log("bond_expire_match", row.id, e && e.message);
      }
    }
  } catch (e) {
    console.log("bond_expire_match_q", e && e.message);
  }

  return {
    expired_open: expiredOpen,
    expired_match: expiredMatch,
    refunded_total: refundedTotal,
    slashed_total: slashedTotal,
    latency_ms: Date.now() - t0,
  };
}


/* ─── Multi-agent atomic graphs (saga with money) ───
 * Owner locks total_budget into system/saga.
 * Steps run in order via advance: debit reserved → credit step.to_repo.
 * On failure: compensate walks completed steps reverse and refunds to owner.
 * Cancel (open, no spent): full refund of reserved.
 * Expire open/running past TTL: auto-compensate.
 */
function parseSagaTtl(body) {
  const sec = Number(body.ttl_seconds ?? body.ttl);
  if (Number.isFinite(sec)) {
    if (sec < SAGA_MIN_TTL_SEC || sec > SAGA_MAX_TTL_SEC) return null;
    return Math.floor(sec);
  }
  return SAGA_DEFAULT_TTL_SEC;
}

async function logSagaEvent(env, sagaId, event, { step_index, amount, note } = {}) {
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

async function loadSaga(env, id) {
  try {
    return await env.DB.prepare(`SELECT * FROM payment_sagas WHERE id = ?1`).bind(id).first();
  } catch {
    return null;
  }
}

async function loadSagaSteps(env, sagaId) {
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

async function handleSagaStart(request, env, ctx) {
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

async function handleSagaAdvance(request, env, ctx) {
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

async function compensateSagaInternal(env, row, reason, t0, ctx) {
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

async function handleSagaCompensate(request, env, ctx) {
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

async function handleSagaCancel(request, env, ctx) {
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

async function handleSagaGet(request, env, id) {
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

async function handleSagaList(request, url, env) {
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

async function expireSagas(env, ctx) {
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
 * Glob: * matches any segment remainder (owner/* or star/name or *).
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


/* ─── Commit–reveal counterfactual pay ───
 * 1) POST /api/commit  { to_repo, amount, task?, commit_hash, ttl_seconds? }
 *    Locks amount from from_repo → system/commit. commit_hash = sha256(preimage).
 * 2) POST /api/commit/reveal { id, preimage }
 *    If sha256(preimage) === commit_hash → pay system/commit → to_repo.
 * 3) POST /api/commit/cancel { id }  (before reveal) → full refund to from_repo.
 * 4) Cron / expire → refund (counterfactual: never paid).
 *
 * Preimage is opaque UTF-8 string (or hex). Client should use high entropy.
 */

function parseCommitTtl(body) {
  const sec = Number(body.ttl_seconds ?? body.ttl);
  if (Number.isFinite(sec)) {
    if (sec < COMMIT_MIN_TTL_SEC || sec > COMMIT_MAX_TTL_SEC) return null;
    return Math.floor(sec);
  }
  return COMMIT_DEFAULT_TTL_SEC;
}

function isHex64(s) {
  return typeof s === "string" && /^[a-fA-F0-9]{64}$/.test(s.trim());
}

async function logCommitEvent(env, commitId, event, { actor_repo, note } = {}) {
  try {
    await env.DB.prepare(
      `INSERT INTO commit_events (id, commit_id, event, actor_repo, note, created_at)
       VALUES (?1, ?2, ?3, ?4, ?5, datetime('now'))`
    )
      .bind(
        randomId(10),
        commitId,
        event,
        actor_repo || null,
        note ? String(note).slice(0, 500) : null
      )
      .run();
  } catch (e) {
    console.log("commit_event_err", e && e.message);
  }
}

async function loadCommit(env, id) {
  try {
    return await env.DB.prepare(`SELECT * FROM payment_commits WHERE id = ?1`).bind(id).first();
  } catch {
    return null;
  }
}

async function handleCommitCreate(request, env, ctx) {
  const t0 = Date.now();
  const authUser = await getAuthUser(request, env);
  if (!authUser) return bad(request, "Sign in or API key required", 401);

  const rlId =
    authUser.auth_via === "api_key"
      ? "cm:key:" + (authUser.key_id || authUser.id)
      : "cm:user:" + authUser.id;
  const limited = await checkRateLimit(env, rlId, RL_COMMIT_MAX, RL_COMMIT_WINDOW_SEC);
  if (limited) {
    return bad(request, "Rate limit: commit ops", 429, { retry_after_sec: limited.retry_after_sec });
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return bad(request, "Invalid JSON body");
  }

  let fromRepo = parseRepo(body.from_repo || body.fromRepo);
  if (!fromRepo && authUser.default_repo) fromRepo = parseRepo(authUser.default_repo);
  const toRepo = parseRepo(body.to_repo || body.toRepo);
  const amount = parseAmount(body.amount);
  const task = String(body.task || "commit").slice(0, 500);
  const ttlSec = parseCommitTtl(body);
  let commitHash = String(body.commit_hash || body.hash || "").trim().toLowerCase();

  // Optional: server hashes preimage if client sends preimage at commit (less private)
  if (!isHex64(commitHash) && body.preimage != null) {
    commitHash = await sha256Hex(String(body.preimage));
  }
  if (!fromRepo) return bad(request, "from_repo required (or set default agent)");
  if (!toRepo) return bad(request, "to_repo required");
  if (amount == null || amount < COMMIT_MIN || amount > COMMIT_MAX) {
    return bad(request, "amount invalid");
  }
  if (ttlSec == null) return bad(request, "ttl_seconds out of range");
  if (!isHex64(commitHash)) {
    return bad(request, "commit_hash must be sha256 hex (64 chars), or pass preimage to hash server-side");
  }

  authUser._policyCtx = { to_repo: toRepo, task: "commit:" + task };
  const blocked = await safetyGate(request, env, authUser, fromRepo, amount);
  if (blocked) return blocked;

  const debitRes = await debitWithCredit(env, fromRepo, amount);
  if (!debitRes.ok) {
    return bad(request, debitRes.error || "Insufficient funds", debitRes.code === "wallet_locked" ? 403 : 402, {
      code: debitRes.code || "insufficient",
      available_credit: debitRes.available_credit,
    });
  }

  const id = "cm_" + randomId(12);
  const modifier = "+" + ttlSec + " seconds";

  try {
    await ensureAccount(env, SYSTEM_COMMIT);
    await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO payment_commits (
           id, from_repo, to_repo, amount, task, commit_hash, status,
           created_by, expires_at, created_at, updated_at
         ) VALUES (
           ?1, ?2, ?3, ?4, ?5, ?6, 'committed', ?7,
           datetime('now', ?8), datetime('now'), datetime('now')
         )`
      ).bind(id, fromRepo, toRepo, amount, task, commitHash, authUser.id, modifier),
      env.DB.prepare(
        `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
         VALUES (?1, ?2, ?3, ?4, 'success', ?5)`
      ).bind(fromRepo, SYSTEM_COMMIT, amount, "commit-lock:" + id, Date.now() - t0),
    ]);
  } catch (e) {
    // refund cash/credit best-effort
    await env.DB.prepare(
      `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
    )
      .bind(amount, fromRepo)
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
      "payment_commits table missing — run d1-commit-migration.sql: " + (e.message || e),
      500
    );
  }

  await safetyRecordSpend(env, authUser, fromRepo, amount);
  await logCommitEvent(env, id, "committed", { actor_repo: fromRepo, note: task });

  if (authUser.id) {
    scheduleWebhook(ctx, env, authUser.id, "commit.created", {
      id,
      from_repo: fromRepo,
      to_repo: toRepo,
      amount,
      task,
      status: "committed",
      expires_in_sec: ttlSec,
    });
  }

  return json(request, {
    ok: true,
    commit: {
      id,
      from_repo: fromRepo,
      to_repo: toRepo,
      amount,
      task,
      commit_hash: commitHash,
      status: "committed",
      ttl_seconds: ttlSec,
      credit_drawn: debitRes.credit_drawn || 0,
    },
    balance_from: debitRes.balance,
    latency_ms: Date.now() - t0,
    hint: "Reveal with POST /api/commit/reveal { id, preimage }. Cancel for counterfactual refund.",
  });
}

async function handleCommitReveal(request, env, ctx) {
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
  const preimage = body.preimage != null ? String(body.preimage) : "";
  if (!id) return bad(request, "id required");
  if (!preimage) return bad(request, "preimage required");

  let row;
  try {
    row = await env.DB.prepare(`SELECT * FROM payment_commits WHERE id = ?1`).bind(id).first();
  } catch {
    return bad(request, "payment_commits table missing — run d1-commit-migration.sql", 500);
  }
  if (!row) return bad(request, "Commit not found", 404);
  if (row.status !== "committed") {
    return bad(request, "Commit not revealable (status=" + row.status + ")", 400, {
      code: "commit_closed",
    });
  }
  if (row.expires_at) {
    const expMs = Date.parse(String(row.expires_at).replace(" ", "T") + "Z");
    if (Number.isFinite(expMs) && expMs < Date.now()) {
      return bad(request, "Commit expired — wait for refund cron or cancel", 400, {
        code: "commit_expired",
      });
    }
  }

  const hash = await sha256Hex(preimage);
  if (hash.toLowerCase() !== String(row.commit_hash).toLowerCase()) {
    await logCommitEvent(env, id, "reveal_failed", {
      actor_repo: authUser.default_repo || null,
      note: "hash_mismatch",
    });
    return bad(request, "Preimage does not match commit_hash", 403, { code: "bad_preimage" });
  }

  // Anyone with preimage can reveal (classic HTLC). Optional: restrict to to_repo / creator.
  const claim = await env.DB.prepare(
    `UPDATE payment_commits
     SET status = 'revealed',
         revealed_at = datetime('now'),
         closed_at = datetime('now'),
         close_reason = 'revealed',
         reveal_note = ?2,
         updated_at = datetime('now')
     WHERE id = ?1 AND status = 'committed'
     RETURNING *`
  )
    .bind(id, String(body.note || "").slice(0, 200) || null)
    .first();
  if (!claim) return bad(request, "Reveal race", 409);

  const amount = Number(row.amount);
  await ensureAccount(env, row.to_repo);
  await ensureAccount(env, SYSTEM_COMMIT);
  await env.DB.batch([
    env.DB.prepare(
      `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
    ).bind(amount, row.to_repo),
    env.DB.prepare(
      `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
       VALUES (?1, ?2, ?3, ?4, 'success', ?5)`
    ).bind(
      SYSTEM_COMMIT,
      row.to_repo,
      amount,
      "commit-reveal:" + id + ":" + (row.task || "").slice(0, 40),
      Date.now() - t0
    ),
  ]);

  await logCommitEvent(env, id, "revealed", {
    actor_repo: authUser.default_repo || row.to_repo,
    note: "paid",
  });
  await adjustRep(env, row.from_repo, CREDIT_REP_SUCCESS_BONUS, "commit_reveal", id);

  if (row.created_by) {
    scheduleWebhook(ctx, env, row.created_by, "commit.revealed", {
      id,
      from_repo: row.from_repo,
      to_repo: row.to_repo,
      amount,
      status: "revealed",
    });
  }

  return json(request, {
    ok: true,
    id,
    status: "revealed",
    paid_to: row.to_repo,
    amount,
    latency_ms: Date.now() - t0,
  });
}

async function handleCommitCancel(request, env, ctx) {
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
    row = await env.DB.prepare(`SELECT * FROM payment_commits WHERE id = ?1`).bind(id).first();
  } catch {
    return bad(request, "payment_commits table missing — run d1-commit-migration.sql", 500);
  }
  if (!row) return bad(request, "Commit not found", 404);
  if (row.status !== "committed") {
    return bad(request, "Only committed (unrevealed) commits can be cancelled", 400);
  }

  const allowed =
    authUser.id === row.created_by ||
    (authUser.default_repo && authUser.default_repo === row.from_repo);
  if (!allowed) return bad(request, "Not authorized to cancel", 403);

  const claim = await env.DB.prepare(
    `UPDATE payment_commits
     SET status = 'cancelled',
         cancelled_at = datetime('now'),
         closed_at = datetime('now'),
         close_reason = 'cancelled',
         updated_at = datetime('now')
     WHERE id = ?1 AND status = 'committed'
     RETURNING *`
  )
    .bind(id)
    .first();
  if (!claim) return bad(request, "Cancel race", 409);

  const refund = Number(row.amount);
  await ensureAccount(env, row.from_repo);
  await env.DB.batch([
    env.DB.prepare(
      `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
    ).bind(refund, row.from_repo),
    env.DB.prepare(
      `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
       VALUES (?1, ?2, ?3, ?4, 'success', ?5)`
    ).bind(SYSTEM_COMMIT, row.from_repo, refund, "commit-cancel-refund:" + id, Date.now() - t0),
  ]);

  await logCommitEvent(env, id, "cancelled", { actor_repo: row.from_repo, note: "counterfactual" });

  if (row.created_by) {
    scheduleWebhook(ctx, env, row.created_by, "commit.cancelled", {
      id,
      from_repo: row.from_repo,
      amount: refund,
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

async function handleCommitGet(request, env, id) {
  id = String(id || "").trim();
  if (!id) return bad(request, "id required");
  const row = await loadCommit(env, id);
  if (!row) {
    try {
      await env.DB.prepare(`SELECT 1 FROM payment_commits LIMIT 1`).first();
    } catch {
      return bad(request, "payment_commits table missing — run d1-commit-migration.sql", 500);
    }
    return bad(request, "Commit not found", 404);
  }
  let events = [];
  try {
    const q = await env.DB.prepare(
      `SELECT event, actor_repo, note, created_at
       FROM commit_events WHERE commit_id = ?1 ORDER BY created_at DESC LIMIT 40`
    )
      .bind(id)
      .all();
    events = q.results || [];
  } catch (_) {}
  // Never return preimage; hash is public
  return json(request, { ok: true, commit: row, events });
}

async function handleCommitList(request, url, env) {
  const limit = Math.min(Math.max(Number(url.searchParams.get("limit") || 20), 1), 100);
  const repo = (url.searchParams.get("repo") || "").trim();
  const status = (url.searchParams.get("status") || "").trim();

  let sql = `SELECT id, from_repo, to_repo, amount, task, commit_hash, status,
                    expires_at, revealed_at, created_at
             FROM payment_commits WHERE 1=1`;
  const binds = [];
  if (repo) {
    if (!parseRepo(repo)) return bad(request, "repo must be owner/repo");
    sql += ` AND (from_repo = ? OR to_repo = ?)`;
    binds.push(repo, repo);
  }
  if (status && ["committed", "revealed", "cancelled", "expired"].includes(status)) {
    sql += ` AND status = ?`;
    binds.push(status);
  }
  sql += ` ORDER BY created_at DESC LIMIT ?`;
  binds.push(limit);

  try {
    const { results } = await env.DB.prepare(sql).bind(...binds).all();
    return json(request, { ok: true, count: results.length, commits: results });
  } catch (e) {
    return bad(
      request,
      "payment_commits table missing — run d1-commit-migration.sql: " + (e.message || e),
      500
    );
  }
}

async function expireCommits(env, ctx) {
  const t0 = Date.now();
  let expired = 0;
  let refundedTotal = 0;
  try {
    const q = await env.DB.prepare(
      `SELECT * FROM payment_commits
       WHERE status = 'committed'
         AND expires_at IS NOT NULL
         AND expires_at < datetime('now')
       ORDER BY expires_at ASC LIMIT ?1`
    )
      .bind(EXPIRE_COMMIT_BATCH)
      .all();
    for (const row of q.results || []) {
      try {
        const claim = await env.DB.prepare(
          `UPDATE payment_commits
           SET status = 'expired', closed_at = datetime('now'), close_reason = 'expired',
               updated_at = datetime('now')
           WHERE id = ?1 AND status = 'committed' RETURNING id`
        )
          .bind(row.id)
          .first();
        if (!claim) continue;
        const refund = Number(row.amount);
        await ensureAccount(env, row.from_repo);
        await env.DB.batch([
          env.DB.prepare(
            `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
          ).bind(refund, row.from_repo),
          env.DB.prepare(
            `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
             VALUES (?1, ?2, ?3, ?4, 'success', 0)`
          ).bind(SYSTEM_COMMIT, row.from_repo, refund, "commit-expire-refund:" + row.id),
        ]);
        await logCommitEvent(env, row.id, "expired", { amount: refund });
        expired += 1;
        refundedTotal += refund;
        if (row.created_by) {
          scheduleWebhook(ctx, env, row.created_by, "commit.expired", {
            id: row.id,
            from_repo: row.from_repo,
            amount: refund,
            status: "expired",
          });
        }
      } catch (e) {
        console.log("commit_expire", row.id, e && e.message);
      }
    }
  } catch (e) {
    return { expired: 0, error: e.message, latency_ms: Date.now() - t0 };
  }
  return { expired, refunded_total: refundedTotal, latency_ms: Date.now() - t0 };
}


async function handleMeCreditGet(request, env) {
  const user = await getSessionUser(request, env);
  if (!user) return bad(request, "Sign in required", 401);
  const repo = user.default_repo ? parseRepo(user.default_repo) : null;
  if (!repo) {
    return json(request, {
      ok: true,
      default_repo: null,
      credit: null,
      hint: "Bind a default agent first",
    });
  }
  const state = await getCreditState(env, repo);
  let recent = [];
  try {
    const q = await env.DB.prepare(
      `SELECT delta, score_after, reason, ref_id, created_at
       FROM rep_events WHERE repo_id = ?1 ORDER BY created_at DESC LIMIT 12`
    )
      .bind(repo)
      .all();
    recent = q.results || [];
  } catch (_) {}
  return json(request, {
    ok: true,
    default_repo: repo,
    credit: state,
    recent_rep: recent,
    schema: {
      credit_limit: "Max outstanding borrow (USD)",
      outstanding_credit: "Current drawn credit",
      available_credit: "credit_limit - outstanding",
      rep_score: "Reputation points (earned on successful activity)",
      suggested_limit: "rep_score * " + CREDIT_REP_TO_LIMIT_RATIO,
    },
  });
}

async function handleMeCreditSet(request, env) {
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
  const sets = [];
  const binds = [];
  if ("credit_limit" in body) {
    let lim = body.credit_limit;
    if (lim === null || lim === "") lim = 0;
    lim = Number(lim);
    if (!Number.isFinite(lim) || lim < 0 || lim > CREDIT_MAX_LIMIT) {
      return bad(request, "credit_limit must be 0.." + CREDIT_MAX_LIMIT);
    }
    // Cannot set below outstanding
    const st = await getCreditState(env, repo);
    if (lim < st.outstanding_credit) {
      return bad(
        request,
        "credit_limit cannot be below outstanding_credit ($" + st.outstanding_credit.toFixed(6) + ")"
      );
    }
    sets.push("credit_limit = ?" + (binds.length + 1));
    binds.push(lim);
  }
  if (!sets.length) return bad(request, "Provide credit_limit");
  sets.push("updated_at = datetime('now')");
  binds.push(repo);
  await env.DB.prepare(
    `UPDATE agent_limits SET ${sets.join(", ")} WHERE repo_id = ?${binds.length}`
  )
    .bind(...binds)
    .run();

  await logSafetyEvent(env, "credit.updated", {
    repo_id: repo,
    user_id: user.id,
    reason: "dashboard",
    meta: body,
  });
  const state = await getCreditState(env, repo);
  return json(request, { ok: true, default_repo: repo, credit: state });
}

async function handleMeCreditRepay(request, env) {
  const user = await getSessionUser(request, env);
  if (!user) return bad(request, "Sign in required", 401);
  const repo = user.default_repo ? parseRepo(user.default_repo) : null;
  if (!repo) return bad(request, "Bind a default agent first");

  let body;
  try {
    body = await request.json();
  } catch {
    body = {};
  }
  let amount = body.amount != null ? parseAmount(body.amount) : null;
  if (amount == null) {
    // repay all possible from balance
    const acc = await env.DB.prepare(`SELECT balance FROM accounts WHERE repo_id = ?1`)
      .bind(repo)
      .first();
    const st = await getCreditState(env, repo);
    amount = Math.min(Number(acc?.balance || 0), st.outstanding_credit);
    amount = Math.round(amount * 1e6) / 1e6;
  }
  if (!(amount > 0)) return bad(request, "Nothing to repay or amount invalid");

  const result = await repayCredit(env, repo, amount);
  if (!result.ok) return bad(request, result.error, result.code === "insufficient" ? 402 : 400);
  await env.DB.prepare(
    `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
     VALUES (?1, ?2, ?3, ?4, 'success', 0)`
  )
    .bind(repo, "system/credit", result.repaid, "credit-repay")
    .run()
    .catch(() => {});
  return json(request, { ok: true, default_repo: repo, ...result });
}


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

/* ─── Heartbeat Continuity (dead-agent recovery) ─── */

function parseContInterval(body) {
  const sec = Number(body.interval_sec ?? body.interval);
  if (Number.isFinite(sec)) {
    if (sec < CONT_MIN_INTERVAL_SEC || sec > CONT_MAX_INTERVAL_SEC) return null;
    return Math.floor(sec);
  }
  return CONT_DEFAULT_INTERVAL_SEC;
}

function parseContGrace(body) {
  const sec = Number(body.grace_sec ?? body.grace);
  if (Number.isFinite(sec)) {
    if (sec < CONT_MIN_GRACE_SEC || sec > CONT_MAX_GRACE_SEC) return null;
    return Math.floor(sec);
  }
  return CONT_DEFAULT_GRACE_SEC;
}

async function logContEvent(env, sessionId, event, { actor_repo, note } = {}) {
  try {
    await env.DB.prepare(
      `INSERT INTO continuity_events (id, session_id, event, actor_repo, note, created_at)
       VALUES (?1, ?2, ?3, ?4, ?5, datetime('now'))`
    )
      .bind(
        randomId(10),
        sessionId,
        event,
        actor_repo || null,
        note ? String(note).slice(0, 500) : null
      )
      .run();
  } catch (e) {
    console.log("cont_event_err", e && e.message);
  }
}

async function loadContSession(env, id) {
  try {
    return await env.DB.prepare(`SELECT * FROM continuity_sessions WHERE id = ?1`).bind(id).first();
  } catch {
    return null;
  }
}

/** Recover one session (bond movement + status). Caller must have claimed status. */
async function recoverContinuitySession(env, row, reason, t0, ctx) {
  const bond = Number(row.bond_usd || 0);
  const action = String(row.recovery_action || "refund");
  let paidTo = row.owner_repo;
  let slashed = 0;
  let refunded = bond;

  if (bond > 0) {
    await ensureAccount(env, SYSTEM_CONTINUITY);

    if (action === "successor" && row.successor_repo) {
      paidTo = row.successor_repo;
      await ensureAccount(env, paidTo);
      await env.DB.batch([
        env.DB.prepare(
          `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
        ).bind(bond, paidTo),
        env.DB.prepare(
          `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
           VALUES (?1, ?2, ?3, ?4, 'success', ?5)`
        ).bind(
          SYSTEM_CONTINUITY,
          paidTo,
          bond,
          "continuity-successor:" + row.id,
          typeof t0 === "number" ? Date.now() - t0 : 0
        ),
      ]);
      refunded = bond;
      slashed = 0;
    } else if (action === "slash_refund") {
      const bps = Math.min(10000, Math.max(0, Number(row.slash_bps || 0)));
      slashed = Math.round(((bond * bps) / 10000) * 1e6) / 1e6;
      refunded = Math.round((bond - slashed) * 1e6) / 1e6;
      await ensureAccount(env, row.owner_repo);
      const stmts = [];
      if (slashed > 0) {
        await ensureAccount(env, SYSTEM_SLASH_POOL);
        stmts.push(
          env.DB.prepare(
            `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
          ).bind(slashed, SYSTEM_SLASH_POOL),
          env.DB.prepare(
            `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
             VALUES (?1, ?2, ?3, ?4, 'success', 0)`
          ).bind(SYSTEM_CONTINUITY, SYSTEM_SLASH_POOL, slashed, "continuity-slash:" + row.id)
        );
      }
      if (refunded > 0) {
        stmts.push(
          env.DB.prepare(
            `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
          ).bind(refunded, row.owner_repo),
          env.DB.prepare(
            `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
             VALUES (?1, ?2, ?3, ?4, 'success', 0)`
          ).bind(SYSTEM_CONTINUITY, row.owner_repo, refunded, "continuity-refund:" + row.id)
        );
      }
      if (stmts.length) await env.DB.batch(stmts);
      paidTo = row.owner_repo;
    } else {
      // refund
      paidTo = row.owner_repo;
      await ensureAccount(env, paidTo);
      await env.DB.batch([
        env.DB.prepare(
          `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
        ).bind(bond, paidTo),
        env.DB.prepare(
          `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
           VALUES (?1, ?2, ?3, ?4, 'success', 0)`
        ).bind(SYSTEM_CONTINUITY, paidTo, bond, "continuity-refund:" + row.id),
      ]);
    }
  }

  await env.DB.prepare(
    `UPDATE continuity_sessions
     SET status = 'recovered',
         recovered_to = ?2,
         recovered_at = datetime('now'),
         closed_at = datetime('now'),
         close_reason = ?3,
         updated_at = datetime('now')
     WHERE id = ?1`
  )
    .bind(row.id, paidTo, String(reason || "recovered").slice(0, 200))
    .run();

  await logContEvent(env, row.id, "recovered", {
    actor_repo: null,
    note: reason + " → " + paidTo + (slashed ? " slash=" + slashed : ""),
  });

  await adjustRep(env, row.owner_repo, -CREDIT_REP_FAIL_PENALTY, "continuity_missed", row.id);

  if (row.created_by) {
    scheduleWebhook(ctx, env, row.created_by, "continuity.recovered", {
      id: row.id,
      owner_repo: row.owner_repo,
      successor_repo: row.successor_repo,
      recovered_to: paidTo,
      bond_usd: bond,
      refunded,
      slashed,
      reason: reason || "recovered",
      status: "recovered",
    });
  }

  return { recovered_to: paidTo, refunded, slashed, bond };
}

async function handleContinuityOpen(request, env, ctx) {
  const t0 = Date.now();
  const authUser = await getAuthUser(request, env);
  if (!authUser) return bad(request, "Sign in or API key required", 401);

  const rlId =
    authUser.auth_via === "api_key"
      ? "ct:key:" + (authUser.key_id || authUser.id)
      : "ct:user:" + authUser.id;
  const limited = await checkRateLimit(env, rlId, RL_CONT_MAX, RL_CONT_WINDOW_SEC);
  if (limited) {
    return bad(request, "Rate limit: continuity ops", 429, { retry_after_sec: limited.retry_after_sec });
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return bad(request, "Invalid JSON body");
  }

  let ownerRepo = parseRepo(body.owner_repo || body.from_repo);
  if (!ownerRepo && authUser.default_repo) ownerRepo = parseRepo(authUser.default_repo);
  const successorRepo = body.successor_repo ? parseRepo(body.successor_repo) : null;
  const intervalSec = parseContInterval(body);
  const graceSec = parseContGrace(body);
  const missLimit = Math.min(
    CONT_MAX_MISS_LIMIT,
    Math.max(1, Math.floor(Number(body.miss_limit) || CONT_DEFAULT_MISS_LIMIT))
  );
  let bond = body.bond_usd != null ? parseAmount(body.bond_usd) : 0;
  if (bond == null) bond = 0;
  if (bond < CONT_MIN_BOND || bond > CONT_MAX_BOND) return bad(request, "bond_usd invalid");

  let recoveryAction = String(body.recovery_action || "refund").toLowerCase();
  if (!["refund", "successor", "slash_refund"].includes(recoveryAction)) {
    return bad(request, "recovery_action must be refund | successor | slash_refund");
  }
  if (recoveryAction === "successor" && !successorRepo) {
    return bad(request, "successor_repo required when recovery_action=successor");
  }
  const slashBps = Math.min(10000, Math.max(0, Math.floor(Number(body.slash_bps) || 0)));

  const refType = String(body.ref_type || "standalone").slice(0, 40);
  const refId = body.ref_id ? String(body.ref_id).slice(0, 80) : null;
  const label = body.label ? String(body.label).slice(0, 200) : null;

  if (!ownerRepo) return bad(request, "owner_repo required (or set default agent)");
  if (intervalSec == null) return bad(request, "interval_sec out of range");
  if (graceSec == null) return bad(request, "grace_sec out of range");

  if (bond > 0) {
    authUser._policyCtx = { to_repo: SYSTEM_CONTINUITY, task: "continuity:open" };
    const blocked = await safetyGate(request, env, authUser, ownerRepo, bond);
    if (blocked) return blocked;

    const debitRes = await debitWithCredit(env, ownerRepo, bond);
    if (!debitRes.ok) {
      return bad(request, debitRes.error || "Insufficient funds", debitRes.code === "wallet_locked" ? 403 : 402, {
        code: debitRes.code || "insufficient",
      });
    }
  }

  const id = "ct_" + randomId(12);
  const totalWindow = intervalSec + graceSec;
  const modifier = "+" + totalWindow + " seconds";

  try {
    if (bond > 0) await ensureAccount(env, SYSTEM_CONTINUITY);
    const stmts = [
      env.DB.prepare(
        `INSERT INTO continuity_sessions (
           id, owner_repo, successor_repo, ref_type, ref_id, bond_usd, status,
           interval_sec, grace_sec, miss_limit, miss_count,
           last_heartbeat_at, next_deadline_at, recovery_action, slash_bps,
           created_by, label, created_at, updated_at
         ) VALUES (
           ?1, ?2, ?3, ?4, ?5, ?6, 'active',
           ?7, ?8, ?9, 0,
           datetime('now'), datetime('now', ?10), ?11, ?12,
           ?13, ?14, datetime('now'), datetime('now')
         )`
      ).bind(
        id,
        ownerRepo,
        successorRepo,
        refType,
        refId,
        bond,
        intervalSec,
        graceSec,
        missLimit,
        modifier,
        recoveryAction,
        slashBps,
        authUser.id,
        label
      ),
    ];
    if (bond > 0) {
      stmts.push(
        env.DB.prepare(
          `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
           VALUES (?1, ?2, ?3, ?4, 'success', ?5)`
        ).bind(ownerRepo, SYSTEM_CONTINUITY, bond, "continuity-bond:" + id, Date.now() - t0)
      );
    }
    await env.DB.batch(stmts);
  } catch (e) {
    if (bond > 0) {
      await env.DB.prepare(
        `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
      )
        .bind(bond, ownerRepo)
        .run()
        .catch(() => {});
    }
    return bad(
      request,
      "continuity_sessions table missing — run d1-continuity-migration.sql: " + (e.message || e),
      500
    );
  }

  if (bond > 0) await safetyRecordSpend(env, authUser, ownerRepo, bond);
  await logContEvent(env, id, "opened", { actor_repo: ownerRepo, note: label || refType });

  if (authUser.id) {
    scheduleWebhook(ctx, env, authUser.id, "continuity.opened", {
      id,
      owner_repo: ownerRepo,
      successor_repo: successorRepo,
      bond_usd: bond,
      interval_sec: intervalSec,
      grace_sec: graceSec,
      recovery_action: recoveryAction,
      status: "active",
    });
  }

  return json(request, {
    ok: true,
    session: {
      id,
      owner_repo: ownerRepo,
      successor_repo: successorRepo,
      bond_usd: bond,
      status: "active",
      interval_sec: intervalSec,
      grace_sec: graceSec,
      miss_limit: missLimit,
      recovery_action: recoveryAction,
      slash_bps: slashBps,
      ref_type: refType,
      ref_id: refId,
      label,
    },
    latency_ms: Date.now() - t0,
    hint: "POST /api/continuity/beat { id } before next_deadline_at or recovery fires.",
  });
}

async function handleContinuityBeat(request, env, ctx) {
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
    row = await env.DB.prepare(`SELECT * FROM continuity_sessions WHERE id = ?1`).bind(id).first();
  } catch {
    return bad(request, "continuity_sessions table missing — run d1-continuity-migration.sql", 500);
  }
  if (!row) return bad(request, "Session not found", 404);
  if (row.status !== "active") {
    return bad(request, "Session not active (status=" + row.status + ")", 400, { code: "cont_closed" });
  }

  const allowed =
    authUser.id === row.created_by ||
    (authUser.default_repo && authUser.default_repo === row.owner_repo) ||
    (authUser.auth_via === "api_key" && authUser.default_repo === row.owner_repo);
  if (!allowed) return bad(request, "Not authorized to heartbeat this session", 403);

  // If already past deadline, do not accept beat — force recovery path
  if (row.next_deadline_at) {
    const expMs = Date.parse(String(row.next_deadline_at).replace(" ", "T") + "Z");
    if (Number.isFinite(expMs) && expMs < Date.now()) {
      return bad(request, "Deadline passed — session will recover on cron or POST /api/continuity/recover", 400, {
        code: "cont_deadline_passed",
      });
    }
  }

  const intervalSec = Number(row.interval_sec);
  const graceSec = Number(row.grace_sec || 0);
  const modifier = "+" + (intervalSec + graceSec) + " seconds";

  const upd = await env.DB.prepare(
    `UPDATE continuity_sessions
     SET last_heartbeat_at = datetime('now'),
         next_deadline_at = datetime('now', ?2),
         miss_count = 0,
         updated_at = datetime('now')
     WHERE id = ?1 AND status = 'active'
     RETURNING *`
  )
    .bind(id, modifier)
    .first();
  if (!upd) return bad(request, "Beat race", 409);

  await logContEvent(env, id, "beat", {
    actor_repo: authUser.default_repo || row.owner_repo,
    note: body.note ? String(body.note).slice(0, 200) : null,
  });

  if (row.created_by) {
    scheduleWebhook(ctx, env, row.created_by, "continuity.beat", {
      id,
      owner_repo: row.owner_repo,
      next_deadline_at: upd.next_deadline_at,
      status: "active",
    });
  }

  return json(request, {
    ok: true,
    id,
    status: "active",
    last_heartbeat_at: upd.last_heartbeat_at,
    next_deadline_at: upd.next_deadline_at,
    latency_ms: Date.now() - t0,
  });
}

async function handleContinuityClose(request, env, ctx) {
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
    row = await env.DB.prepare(`SELECT * FROM continuity_sessions WHERE id = ?1`).bind(id).first();
  } catch {
    return bad(request, "continuity_sessions table missing — run d1-continuity-migration.sql", 500);
  }
  if (!row) return bad(request, "Session not found", 404);
  if (row.status !== "active") return bad(request, "Session not active", 400);

  const allowed =
    authUser.id === row.created_by ||
    (authUser.default_repo && authUser.default_repo === row.owner_repo);
  if (!allowed) return bad(request, "Not authorized to close", 403);

  const claim = await env.DB.prepare(
    `UPDATE continuity_sessions
     SET status = 'closed', closed_at = datetime('now'), close_reason = 'closed',
         updated_at = datetime('now')
     WHERE id = ?1 AND status = 'active'
     RETURNING *`
  )
    .bind(id)
    .first();
  if (!claim) return bad(request, "Close race", 409);

  const bond = Number(row.bond_usd || 0);
  if (bond > 0) {
    await ensureAccount(env, row.owner_repo);
    await env.DB.batch([
      env.DB.prepare(
        `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
      ).bind(bond, row.owner_repo),
      env.DB.prepare(
        `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
         VALUES (?1, ?2, ?3, ?4, 'success', ?5)`
      ).bind(SYSTEM_CONTINUITY, row.owner_repo, bond, "continuity-close-refund:" + id, Date.now() - t0),
    ]);
  }

  await logContEvent(env, id, "closed", { actor_repo: row.owner_repo, note: "owner_close" });

  if (row.created_by) {
    scheduleWebhook(ctx, env, row.created_by, "continuity.closed", {
      id,
      owner_repo: row.owner_repo,
      refunded: bond,
      status: "closed",
    });
  }

  return json(request, {
    ok: true,
    id,
    status: "closed",
    refunded: bond,
    latency_ms: Date.now() - t0,
  });
}

async function handleContinuityRecover(request, env, ctx) {
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
    row = await env.DB.prepare(`SELECT * FROM continuity_sessions WHERE id = ?1`).bind(id).first();
  } catch {
    return bad(request, "continuity_sessions table missing — run d1-continuity-migration.sql", 500);
  }
  if (!row) return bad(request, "Session not found", 404);
  if (row.status !== "active") return bad(request, "Session not active", 400);

  // Manual recover: creator, owner, or successor may trigger if deadline passed
  const pastDeadline =
    row.next_deadline_at &&
    Date.parse(String(row.next_deadline_at).replace(" ", "T") + "Z") < Date.now();
  if (!pastDeadline) {
    return bad(request, "Deadline not yet passed — keep beating or wait", 400, {
      code: "cont_not_due",
      next_deadline_at: row.next_deadline_at,
    });
  }

  const claim = await env.DB.prepare(
    `UPDATE continuity_sessions SET status = 'recovering', updated_at = datetime('now')
     WHERE id = ?1 AND status = 'active' RETURNING *`
  )
    .bind(id)
    .first();
  if (!claim) return bad(request, "Recover race", 409);

  const result = await recoverContinuitySession(env, claim, body.reason || "manual_recover", t0, ctx);
  return json(request, {
    ok: true,
    id,
    status: "recovered",
    ...result,
    latency_ms: Date.now() - t0,
  });
}

async function handleContinuityGet(request, env, id) {
  id = String(id || "").trim();
  if (!id) return bad(request, "id required");
  const row = await loadContSession(env, id);
  if (!row) {
    try {
      await env.DB.prepare(`SELECT 1 FROM continuity_sessions LIMIT 1`).first();
    } catch {
      return bad(request, "continuity_sessions table missing — run d1-continuity-migration.sql", 500);
    }
    return bad(request, "Session not found", 404);
  }
  let events = [];
  try {
    const q = await env.DB.prepare(
      `SELECT event, actor_repo, note, created_at
       FROM continuity_events WHERE session_id = ?1 ORDER BY created_at DESC LIMIT 40`
    )
      .bind(id)
      .all();
    events = q.results || [];
  } catch (_) {}
  return json(request, { ok: true, session: row, events });
}

async function handleContinuityList(request, url, env) {
  const limit = Math.min(Math.max(Number(url.searchParams.get("limit") || 20), 1), 100);
  const repo = (url.searchParams.get("repo") || "").trim();
  const status = (url.searchParams.get("status") || "").trim();

  let sql = `SELECT id, owner_repo, successor_repo, ref_type, ref_id, bond_usd, status,
                    interval_sec, grace_sec, miss_limit, miss_count,
                    last_heartbeat_at, next_deadline_at, recovery_action,
                    recovered_to, label, created_at
             FROM continuity_sessions WHERE 1=1`;
  const binds = [];
  if (repo) {
    if (!parseRepo(repo)) return bad(request, "repo must be owner/repo");
    sql += ` AND (owner_repo = ? OR successor_repo = ?)`;
    binds.push(repo, repo);
  }
  if (status && ["active", "recovered", "closed", "expired"].includes(status)) {
    sql += ` AND status = ?`;
    binds.push(status);
  }
  sql += ` ORDER BY created_at DESC LIMIT ?`;
  binds.push(limit);

  try {
    const { results } = await env.DB.prepare(sql).bind(...binds).all();
    return json(request, { ok: true, count: results.length, sessions: results });
  } catch (e) {
    return bad(
      request,
      "continuity_sessions table missing — run d1-continuity-migration.sql: " + (e.message || e),
      500
    );
  }
}

async function expireContinuitySessions(env, ctx) {
  const t0 = Date.now();
  let recovered = 0;
  let bondTotal = 0;
  try {
    const q = await env.DB.prepare(
      `SELECT * FROM continuity_sessions
       WHERE status = 'active'
         AND next_deadline_at IS NOT NULL
         AND next_deadline_at < datetime('now')
       ORDER BY next_deadline_at ASC LIMIT ?1`
    )
      .bind(EXPIRE_CONT_BATCH)
      .all();
    for (const row of q.results || []) {
      try {
        const missLimit = Number(row.miss_limit || 1);
        const nextMiss = Number(row.miss_count || 0) + 1;

        if (nextMiss < missLimit) {
          // Soft miss: extend once more by interval only, increment miss_count
          const intervalSec = Number(row.interval_sec);
          const modifier = "+" + intervalSec + " seconds";
          await env.DB.prepare(
            `UPDATE continuity_sessions
             SET miss_count = ?2,
                 next_deadline_at = datetime('now', ?3),
                 updated_at = datetime('now')
             WHERE id = ?1 AND status = 'active'`
          )
            .bind(row.id, nextMiss, modifier)
            .run();
          await logContEvent(env, row.id, "missed", {
            note: "miss " + nextMiss + "/" + missLimit,
          });
          if (row.created_by) {
            scheduleWebhook(ctx, env, row.created_by, "continuity.missed", {
              id: row.id,
              owner_repo: row.owner_repo,
              miss_count: nextMiss,
              miss_limit: missLimit,
              status: "active",
            });
          }
          continue;
        }

        const claim = await env.DB.prepare(
          `UPDATE continuity_sessions SET status = 'recovering', updated_at = datetime('now')
           WHERE id = ?1 AND status = 'active' RETURNING *`
        )
          .bind(row.id)
          .first();
        if (!claim) continue;
        const r = await recoverContinuitySession(env, claim, "heartbeat_timeout", t0, ctx);
        recovered += 1;
        bondTotal += Number(r.bond || 0);
      } catch (e) {
        console.log("cont_expire", row.id, e && e.message);
      }
    }
  } catch (e) {
    return { recovered: 0, error: e.message, latency_ms: Date.now() - t0 };
  }
  return { recovered, bond_total: bondTotal, latency_ms: Date.now() - t0 };
}


/* ─── Collaborative Pools (swarm co-funding) ───
 * Agents contribute cash into a shared pool toward target_amount.
 * When funded (or early release by creator), funds go to beneficiary_repo.
 * Expire/cancel refunds all held contributions.
 *
 * POST /api/pool/open       { beneficiary_repo, target_amount, task?, title?, ttl_seconds? }
 * POST /api/pool/contribute { id, amount, from_repo? }
 * POST /api/pool/release    { id }  — creator/beneficiary; requires funded or force
 * POST /api/pool/refund     { id }  — cancel open pool → refund contributors
 * GET  /api/pool            ?repo=&status=
 * GET  /api/pool/:id
 */

function parsePoolTtl(body) {
  const sec = Number(body.ttl_seconds ?? body.ttl);
  if (Number.isFinite(sec)) {
    if (sec < POOL_MIN_TTL_SEC || sec > POOL_MAX_TTL_SEC) return null;
    return Math.floor(sec);
  }
  return POOL_DEFAULT_TTL_SEC;
}

async function logPoolEvent(env, poolId, event, { actor_repo, note } = {}) {
  try {
    await env.DB.prepare(
      `INSERT INTO pool_events (id, pool_id, event, actor_repo, note, created_at)
       VALUES (?1, ?2, ?3, ?4, ?5, datetime('now'))`
    )
      .bind(
        randomId(10),
        poolId,
        event,
        actor_repo || null,
        note ? String(note).slice(0, 500) : null
      )
      .run();
  } catch (e) {
    console.log("pool_event_err", e && e.message);
  }
}

async function loadPool(env, id) {
  try {
    return await env.DB.prepare(`SELECT * FROM collaborative_pools WHERE id = ?1`).bind(id).first();
  } catch {
    return null;
  }
}

async function handlePoolOpen(request, env, ctx) {
  const t0 = Date.now();
  const authUser = await getAuthUser(request, env);
  if (!authUser) return bad(request, "Sign in or API key required", 401);

  const rlId =
    authUser.auth_via === "api_key"
      ? "pool:key:" + (authUser.key_id || authUser.id)
      : "pool:user:" + authUser.id;
  const limited = await checkRateLimit(env, rlId, RL_POOL_MAX, RL_POOL_WINDOW_SEC);
  if (limited) {
    return bad(request, "Rate limit: pool ops", 429, { retry_after_sec: limited.retry_after_sec });
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return bad(request, "Invalid JSON body");
  }

  let creatorRepo = parseRepo(body.creator_repo || body.from_repo);
  if (!creatorRepo && authUser.default_repo) creatorRepo = parseRepo(authUser.default_repo);
  const beneficiary = parseRepo(body.beneficiary_repo || body.to_repo || body.beneficiary);
  const target = parseAmount(body.target_amount ?? body.amount);
  const task = String(body.task || "swarm-pool").slice(0, 500);
  const title = body.title ? String(body.title).slice(0, 200) : null;
  const ttlSec = parsePoolTtl(body);
  const minContrib = body.min_contribution != null ? parseAmount(body.min_contribution) : POOL_MIN;

  if (!creatorRepo) return bad(request, "creator_repo required (or set default agent)");
  if (!beneficiary) return bad(request, "beneficiary_repo required");
  if (target == null || target < POOL_MIN || target > POOL_MAX) return bad(request, "target_amount invalid");
  if (ttlSec == null) return bad(request, "ttl_seconds out of range");
  if (minContrib == null || minContrib < POOL_MIN) return bad(request, "min_contribution invalid");

  const id = "pl_" + randomId(12);
  const modifier = "+" + ttlSec + " seconds";

  try {
    await env.DB.prepare(
      `INSERT INTO collaborative_pools (
         id, title, creator_repo, beneficiary_repo, task,
         target_amount, funded_amount, min_contribution, status,
         ttl_seconds, expires_at, created_by, created_at, updated_at
       ) VALUES (
         ?1, ?2, ?3, ?4, ?5,
         ?6, 0, ?7, 'open',
         ?8, datetime('now', ?9), ?10, datetime('now'), datetime('now')
       )`
    )
      .bind(
        id,
        title,
        creatorRepo,
        beneficiary,
        task,
        target,
        minContrib,
        ttlSec,
        modifier,
        authUser.id
      )
      .run();
  } catch (e) {
    return bad(
      request,
      "collaborative_pools table missing — run d1-pool-migration.sql: " + (e.message || e),
      500
    );
  }

  await logPoolEvent(env, id, "opened", { actor_repo: creatorRepo, note: title || task });

  if (authUser.id) {
    scheduleWebhook(ctx, env, authUser.id, "pool.opened", {
      id,
      creator_repo: creatorRepo,
      beneficiary_repo: beneficiary,
      target_amount: target,
      task,
      status: "open",
    });
  }

  return json(request, {
    ok: true,
    pool: {
      id,
      title,
      creator_repo: creatorRepo,
      beneficiary_repo: beneficiary,
      task,
      target_amount: target,
      funded_amount: 0,
      min_contribution: minContrib,
      status: "open",
      ttl_seconds: ttlSec,
    },
    latency_ms: Date.now() - t0,
    hint: "Others POST /api/pool/contribute { id, amount }. Release when funded.",
  });
}

async function handlePoolContribute(request, env, ctx) {
  const t0 = Date.now();
  const authUser = await getAuthUser(request, env);
  if (!authUser) return bad(request, "Sign in or API key required", 401);

  const rlId =
    authUser.auth_via === "api_key"
      ? "pool:key:" + (authUser.key_id || authUser.id)
      : "pool:user:" + authUser.id;
  const limited = await checkRateLimit(env, rlId, RL_POOL_MAX, RL_POOL_WINDOW_SEC);
  if (limited) {
    return bad(request, "Rate limit: pool ops", 429, { retry_after_sec: limited.retry_after_sec });
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return bad(request, "Invalid JSON body");
  }

  const id = String(body.id || "").trim();
  const amount = parseAmount(body.amount);
  let fromRepo = parseRepo(body.from_repo || body.fromRepo);
  if (!fromRepo && authUser.default_repo) fromRepo = parseRepo(authUser.default_repo);

  if (!id) return bad(request, "id required");
  if (!fromRepo) return bad(request, "from_repo required (or set default agent)");
  if (amount == null) return bad(request, "amount invalid");

  const pool = await loadPool(env, id);
  if (!pool) {
    try {
      await env.DB.prepare(`SELECT 1 FROM collaborative_pools LIMIT 1`).first();
    } catch {
      return bad(request, "collaborative_pools table missing — run d1-pool-migration.sql", 500);
    }
    return bad(request, "Pool not found", 404);
  }
  if (pool.status !== "open") {
    return bad(request, "Pool not open (status=" + pool.status + ")", 400, { code: "pool_closed" });
  }
  if (pool.expires_at) {
    const expMs = Date.parse(String(pool.expires_at).replace(" ", "T") + "Z");
    if (Number.isFinite(expMs) && expMs < Date.now()) {
      return bad(request, "Pool expired — wait for refund cron or POST /api/pool/refund", 400, {
        code: "pool_expired",
      });
    }
  }

  const minC = Number(pool.min_contribution || POOL_MIN);
  if (amount < minC) {
    return bad(request, "Contribution below min_contribution ($" + minC + ")", 400);
  }

  const remaining = Math.round((Number(pool.target_amount) - Number(pool.funded_amount || 0)) * 1e6) / 1e6;
  if (remaining <= 0) {
    return bad(request, "Pool already at target", 400, { code: "pool_full" });
  }
  const applyAmt = Math.min(amount, remaining);

  authUser._policyCtx = { to_repo: SYSTEM_POOL, task: "pool:contribute:" + id };
  const blocked = await safetyGate(request, env, authUser, fromRepo, applyAmt);
  if (blocked) return blocked;

  const debitRes = await debitWithCredit(env, fromRepo, applyAmt);
  if (!debitRes.ok) {
    return bad(request, debitRes.error || "Insufficient funds", debitRes.code === "wallet_locked" ? 403 : 402, {
      code: debitRes.code || "insufficient",
      available_credit: debitRes.available_credit,
    });
  }

  const cid = "pc_" + randomId(10);
  try {
    await ensureAccount(env, SYSTEM_POOL);
    await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO pool_contributions (
           id, pool_id, from_repo, amount, status, created_by, created_at
         ) VALUES (?1, ?2, ?3, ?4, 'held', ?5, datetime('now'))`
      ).bind(cid, id, fromRepo, applyAmt, authUser.id),
      env.DB.prepare(
        `UPDATE collaborative_pools
         SET funded_amount = funded_amount + ?2,
             status = CASE
               WHEN funded_amount + ?2 >= target_amount THEN 'funded'
               ELSE status
             END,
             updated_at = datetime('now')
         WHERE id = ?1 AND status = 'open'`
      ).bind(id, applyAmt),
      env.DB.prepare(
        `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
         VALUES (?1, ?2, ?3, ?4, 'success', ?5)`
      ).bind(fromRepo, SYSTEM_POOL, applyAmt, "pool-contribute:" + id, Date.now() - t0),
    ]);
  } catch (e) {
    await env.DB.prepare(
      `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
    )
      .bind(applyAmt, fromRepo)
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
    return bad(request, "Contribute failed: " + (e.message || e), 500);
  }

  await safetyRecordSpend(env, authUser, fromRepo, applyAmt);
  await logPoolEvent(env, id, "contributed", {
    actor_repo: fromRepo,
    note: "$" + applyAmt,
  });

  const updated = await loadPool(env, id);
  const funded = Number(updated?.funded_amount || 0);
  const target = Number(pool.target_amount);
  const status = updated?.status || "open";

  if (pool.created_by) {
    scheduleWebhook(ctx, env, pool.created_by, "pool.contributed", {
      id,
      contribution_id: cid,
      from_repo: fromRepo,
      amount: applyAmt,
      funded_amount: funded,
      target_amount: target,
      status,
    });
  }
  if (status === "funded" && pool.created_by) {
    scheduleWebhook(ctx, env, pool.created_by, "pool.funded", {
      id,
      funded_amount: funded,
      target_amount: target,
      status: "funded",
    });
  }

  return json(request, {
    ok: true,
    contribution_id: cid,
    pool_id: id,
    from_repo: fromRepo,
    amount: applyAmt,
    funded_amount: funded,
    target_amount: target,
    status,
    ready_to_release: status === "funded",
    latency_ms: Date.now() - t0,
  });
}

async function handlePoolRelease(request, env, ctx) {
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

  const pool = await loadPool(env, id);
  if (!pool) return bad(request, "Pool not found", 404);
  if (!["open", "funded"].includes(pool.status)) {
    return bad(request, "Pool not releasable (status=" + pool.status + ")", 400);
  }

  const allowed =
    authUser.id === pool.created_by ||
    (authUser.default_repo &&
      (authUser.default_repo === pool.creator_repo ||
        authUser.default_repo === pool.beneficiary_repo));
  if (!allowed) return bad(request, "Not authorized to release this pool", 403);

  const funded = Number(pool.funded_amount || 0);
  if (funded <= 0) return bad(request, "Nothing funded to release", 400);

  // Default: require fully funded unless force=true (creator only)
  const force = body.force === true;
  if (pool.status !== "funded" && funded < Number(pool.target_amount)) {
    if (!force || authUser.id !== pool.created_by) {
      return bad(
        request,
        "Pool not fully funded ($" +
          funded +
          " / $" +
          pool.target_amount +
          "). Creator may pass force:true for early release.",
        400,
        { code: "underfunded", funded_amount: funded, target_amount: Number(pool.target_amount) }
      );
    }
  }

  const claim = await env.DB.prepare(
    `UPDATE collaborative_pools
     SET status = 'released', released_at = datetime('now'), updated_at = datetime('now')
     WHERE id = ?1 AND status IN ('open', 'funded')
     RETURNING *`
  )
    .bind(id)
    .first();
  if (!claim) return bad(request, "Release race", 409);

  await ensureAccount(env, pool.beneficiary_repo);
  await ensureAccount(env, SYSTEM_POOL);
  await env.DB.batch([
    env.DB.prepare(
      `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
    ).bind(funded, pool.beneficiary_repo),
    env.DB.prepare(
      `UPDATE pool_contributions SET status = 'released' WHERE pool_id = ?1 AND status = 'held'`
    ).bind(id),
    env.DB.prepare(
      `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
       VALUES (?1, ?2, ?3, ?4, 'success', ?5)`
    ).bind(
      SYSTEM_POOL,
      pool.beneficiary_repo,
      funded,
      "pool-release:" + id + ":" + (pool.task || "").slice(0, 40),
      Date.now() - t0
    ),
  ]);

  await logPoolEvent(env, id, "released", {
    actor_repo: authUser.default_repo || pool.creator_repo,
    note: "$" + funded + " → " + pool.beneficiary_repo,
  });
  await adjustRep(env, pool.beneficiary_repo, CREDIT_REP_SUCCESS_BONUS, "pool_release", id);

  if (pool.created_by) {
    scheduleWebhook(ctx, env, pool.created_by, "pool.released", {
      id,
      beneficiary_repo: pool.beneficiary_repo,
      amount: funded,
      status: "released",
    });
  }

  return json(request, {
    ok: true,
    id,
    status: "released",
    paid_to: pool.beneficiary_repo,
    amount: funded,
    latency_ms: Date.now() - t0,
  });
}

async function handlePoolRefund(request, env, ctx) {
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

  const pool = await loadPool(env, id);
  if (!pool) return bad(request, "Pool not found", 404);
  if (!["open", "funded"].includes(pool.status)) {
    return bad(request, "Pool not refundable (status=" + pool.status + ")", 400);
  }

  const allowed =
    authUser.id === pool.created_by ||
    (authUser.default_repo && authUser.default_repo === pool.creator_repo);
  if (!allowed) return bad(request, "Not authorized to refund this pool", 403);

  const claim = await env.DB.prepare(
    `UPDATE collaborative_pools
     SET status = 'cancelled', cancelled_at = datetime('now'), updated_at = datetime('now')
     WHERE id = ?1 AND status IN ('open', 'funded')
     RETURNING *`
  )
    .bind(id)
    .first();
  if (!claim) return bad(request, "Refund race", 409);

  let contribs = [];
  try {
    const q = await env.DB.prepare(
      `SELECT id, from_repo, amount FROM pool_contributions
       WHERE pool_id = ?1 AND status = 'held'`
    )
      .bind(id)
      .all();
    contribs = q.results || [];
  } catch (_) {}

  let refundedTotal = 0;
  for (const c of contribs) {
    try {
      await ensureAccount(env, c.from_repo);
      await env.DB.batch([
        env.DB.prepare(
          `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
        ).bind(c.amount, c.from_repo),
        env.DB.prepare(
          `UPDATE pool_contributions SET status = 'refunded' WHERE id = ?1`
        ).bind(c.id),
        env.DB.prepare(
          `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
           VALUES (?1, ?2, ?3, ?4, 'success', 0)`
        ).bind(SYSTEM_POOL, c.from_repo, c.amount, "pool-refund:" + id),
      ]);
      refundedTotal += Number(c.amount);
    } catch (e) {
      console.log("pool_refund_one", c.id, e && e.message);
    }
  }

  await env.DB.prepare(
    `UPDATE collaborative_pools SET funded_amount = 0, updated_at = datetime('now') WHERE id = ?1`
  )
    .bind(id)
    .run();

  await logPoolEvent(env, id, "cancelled", {
    actor_repo: authUser.default_repo || pool.creator_repo,
    note: "refunded $" + refundedTotal,
  });

  if (pool.created_by) {
    scheduleWebhook(ctx, env, pool.created_by, "pool.cancelled", {
      id,
      refunded: refundedTotal,
      status: "cancelled",
    });
  }

  return json(request, {
    ok: true,
    id,
    status: "cancelled",
    refunded: refundedTotal,
    contributors: contribs.length,
    latency_ms: Date.now() - t0,
  });
}

async function handlePoolGet(request, env, id) {
  id = String(id || "").trim();
  if (!id) return bad(request, "id required");
  const pool = await loadPool(env, id);
  if (!pool) {
    try {
      await env.DB.prepare(`SELECT 1 FROM collaborative_pools LIMIT 1`).first();
    } catch {
      return bad(request, "collaborative_pools table missing — run d1-pool-migration.sql", 500);
    }
    return bad(request, "Pool not found", 404);
  }
  let contributions = [];
  let events = [];
  try {
    const q = await env.DB.prepare(
      `SELECT id, from_repo, amount, status, created_at
       FROM pool_contributions WHERE pool_id = ?1 ORDER BY created_at ASC`
    )
      .bind(id)
      .all();
    contributions = q.results || [];
  } catch (_) {}
  try {
    const q = await env.DB.prepare(
      `SELECT event, actor_repo, note, created_at
       FROM pool_events WHERE pool_id = ?1 ORDER BY created_at DESC LIMIT 40`
    )
      .bind(id)
      .all();
    events = q.results || [];
  } catch (_) {}
  return json(request, { ok: true, pool, contributions, events });
}

async function handlePoolList(request, url, env) {
  const limit = Math.min(Math.max(Number(url.searchParams.get("limit") || 20), 1), 100);
  const repo = (url.searchParams.get("repo") || "").trim();
  const status = (url.searchParams.get("status") || "").trim();

  let sql = `SELECT id, title, creator_repo, beneficiary_repo, task,
                    target_amount, funded_amount, min_contribution, status,
                    expires_at, created_at
             FROM collaborative_pools WHERE 1=1`;
  const binds = [];
  if (repo) {
    if (!parseRepo(repo)) return bad(request, "repo must be owner/repo");
    sql += ` AND (creator_repo = ? OR beneficiary_repo = ?)`;
    binds.push(repo, repo);
  }
  if (status && ["open", "funded", "released", "cancelled", "expired"].includes(status)) {
    sql += ` AND status = ?`;
    binds.push(status);
  }
  sql += ` ORDER BY created_at DESC LIMIT ?`;
  binds.push(limit);

  try {
    const { results } = await env.DB.prepare(sql).bind(...binds).all();
    return json(request, { ok: true, count: results.length, pools: results });
  } catch (e) {
    return bad(
      request,
      "collaborative_pools table missing — run d1-pool-migration.sql: " + (e.message || e),
      500
    );
  }
}

async function expireCollaborativePools(env, ctx) {
  const t0 = Date.now();
  let expired = 0;
  let refundedTotal = 0;
  try {
    const q = await env.DB.prepare(
      `SELECT * FROM collaborative_pools
       WHERE status IN ('open', 'funded')
         AND expires_at IS NOT NULL
         AND expires_at < datetime('now')
       ORDER BY expires_at ASC LIMIT ?1`
    )
      .bind(EXPIRE_POOL_BATCH)
      .all();
    for (const pool of q.results || []) {
      try {
        const claim = await env.DB.prepare(
          `UPDATE collaborative_pools
           SET status = 'expired', cancelled_at = datetime('now'), updated_at = datetime('now')
           WHERE id = ?1 AND status IN ('open', 'funded') RETURNING id`
        )
          .bind(pool.id)
          .first();
        if (!claim) continue;

        const cq = await env.DB.prepare(
          `SELECT id, from_repo, amount FROM pool_contributions
           WHERE pool_id = ?1 AND status = 'held'`
        )
          .bind(pool.id)
          .all();
        for (const c of cq.results || []) {
          try {
            await ensureAccount(env, c.from_repo);
            await env.DB.batch([
              env.DB.prepare(
                `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
              ).bind(c.amount, c.from_repo),
              env.DB.prepare(
                `UPDATE pool_contributions SET status = 'refunded' WHERE id = ?1`
              ).bind(c.id),
              env.DB.prepare(
                `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
                 VALUES (?1, ?2, ?3, ?4, 'success', 0)`
              ).bind(SYSTEM_POOL, c.from_repo, c.amount, "pool-expire-refund:" + pool.id),
            ]);
            refundedTotal += Number(c.amount);
          } catch (e) {
            console.log("pool_expire_one", c.id, e && e.message);
          }
        }
        await env.DB.prepare(
          `UPDATE collaborative_pools SET funded_amount = 0, updated_at = datetime('now') WHERE id = ?1`
        )
          .bind(pool.id)
          .run();
        await logPoolEvent(env, pool.id, "expired", { note: "ttl" });
        expired += 1;
        if (pool.created_by) {
          scheduleWebhook(ctx, env, pool.created_by, "pool.expired", {
            id: pool.id,
            status: "expired",
          });
        }
      } catch (e) {
        console.log("pool_expire", pool.id, e && e.message);
      }
    }
  } catch (e) {
    return { expired: 0, error: e.message, latency_ms: Date.now() - t0 };
  }
  return { expired, refunded_total: refundedTotal, latency_ms: Date.now() - t0 };
}


/* ─── Edge Shield API ─── */

async function handleShieldPublic(request, env) {
  const global = await getShield(env, "global");
  return json(request, {
    ok: true,
    global: {
      level: Number(global.level || 0),
      reason: global.reason || null,
      cools_at: global.cools_at || null,
      last_trip_at: global.last_trip_at || null,
    },
    levels: {
      0: "normal",
      1: "watch",
      2: "throttle",
      3: "freeze / quarantine",
      4: "emergency",
    },
    hint: "Level ≥3 blocks new spends. Auto-trips on runaway loops and mass wallet locks.",
  });
}

async function handleMeShieldGet(request, env) {
  const authUser = await getAuthUser(request, env);
  if (!authUser) return bad(request, "Sign in or API key required", 401);

  const global = await getShield(env, "global");
  let repo = authUser.default_repo ? parseRepo(authUser.default_repo) : null;
  let local = null;
  if (repo) local = await getShield(env, repo);

  let events = [];
  try {
    const q = await env.DB.prepare(
      `SELECT event, scope, scope_id, level, reason, created_at
       FROM shield_events
       WHERE scope_id = 'global' OR scope_id = ?1
       ORDER BY created_at DESC LIMIT 20`
    )
      .bind(repo || "")
      .all();
    events = q.results || [];
  } catch (_) {}

  return json(request, {
    ok: true,
    global: {
      level: Number(global.level || 0),
      reason: global.reason || null,
      cools_at: global.cools_at || null,
    },
    agent: local
      ? {
          repo_id: repo,
          level: Number(local.level || 0),
          reason: local.reason || null,
          cools_at: local.cools_at || null,
          trip_count: Number(local.trip_count || 0),
        }
      : null,
    events,
  });
}

async function handleMeShieldRelease(request, env) {
  const authUser = await getAuthUser(request, env);
  if (!authUser) return bad(request, "Sign in or API key required", 401);

  let body = {};
  try {
    body = await request.json();
  } catch (_) {}

  let repo = parseRepo(body.repo_id || body.repo) || parseRepo(authUser.default_repo);
  if (!repo) return bad(request, "repo_id required (or set default agent)");

  // Only owner session (not pure API key of different agent) — session or matching default_repo
  if (authUser.auth_via === "api_key" && authUser.default_repo !== repo) {
    return bad(request, "API key not bound to this agent", 403);
  }

  const before = await getShield(env, repo);
  if (Number(before.level || 0) === 0) {
    return json(request, { ok: true, already: true, agent: { repo_id: repo, level: 0 } });
  }

  const after = await setShieldLevel(env, repo, 0, "owner_release");
  // Also unlock wallet if locked
  try {
    await unlockWallet(env, repo, { user_id: authUser.id });
  } catch (_) {}

  if (authUser.id) {
    scheduleWebhook(null, env, authUser.id, "shield.released", {
      repo_id: repo,
      previous_level: Number(before.level || 0),
    });
  }

  return json(request, {
    ok: true,
    released: true,
    agent: {
      repo_id: repo,
      level: Number(after.level || 0),
      reason: after.reason || null,
    },
  });
}

async function handleAdminShield(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return bad(request, "Invalid JSON body");
  }
  const admin = await assertAdminSecret(request, env, body);
  if (!admin.ok) return admin.response;

  const scope = String(body.scope || "global").toLowerCase();
  const id = scope === "global" ? "global" : parseRepo(body.repo_id || body.repo);
  if (scope !== "global" && !id) return bad(request, "repo_id required for repo scope");

  const level = Math.max(0, Math.min(SHIELD_MAX_LEVEL, Math.floor(Number(body.level) || 0)));
  const reason = body.reason ? String(body.reason).slice(0, 500) : "admin";
  const cooldownSec = body.cooldown_sec != null ? Number(body.cooldown_sec) : SHIELD_COOLDOWN_SEC;

  const row = await setShieldLevel(env, id, level, reason, { cooldownSec });
  return json(request, {
    ok: true,
    shield: {
      id,
      level: Number(row.level || 0),
      reason: row.reason || null,
      cools_at: row.cools_at || null,
    },
  });
}
