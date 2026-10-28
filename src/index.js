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

import { ensureAccount } from "./shared/accounts.js";

import {
  getCreditState,
  adjustRep,
  debitWithCredit,
  repayCredit,
} from "./shared/credit.js";

import { dispatchWebhook, scheduleWebhook } from "./shared/webhooks.js";

import {
  getSessionUser,
  rejectIfAlreadySignedIn,
  enforceKeyBinding,
  getApiKeyUser,
  getAuthUser,
  rejectIfSuspendedKey,
} from "./shared/auth.js";

import {
  matchRepoGlob,
  normalizePolicy,
  getAgentPolicy,
  checkSpendPolicy,
  handleMePolicyGet,
  handleMePolicySet,
} from "./shared/policy.js";

import {
  lockWallet,
  safetyGate,
  safetyRecordSpend,
} from "./shared/gate.js";

import {
  expireHeldEscrows,
  pruneTelemetry,
} from "./shared/expire.js";

import {
  handleSecurityStatus,
  handleAdminIntegrity,
  handleAdminSandboxCleanup,
} from "./shared/security.js";

import {
  handleIntentCreate,
  handleIntentSpend,
  handleIntentCancel,
  handleIntentGet,
  handleIntentList,
  expireIntentCapsules,
} from "./shared/intent.js";

import {
  handleHireRfq,
  handleHireQuote,
  handleHireAccept,
  handleHireComplete,
  handleHireCancel,
  handleHireGet,
  handleHireList,
  expireHireRfqs,
} from "./shared/hire.js";

import {
  handleStandingOpen,
  handleStandingCancel,
  handleStandingPause,
  handleStandingResume,
  handleStandingGet,
  handleStandingList,
  processStandingOrders,
} from "./shared/standing.js";

import {
  handleDelegateOpen,
  handleDelegateRevoke,
  handleDelegateGet,
  handleDelegateList,
  expireDelegations,
  claimDelegationSpend,
} from "./shared/delegate.js";

import {
  handleDisputeOpen,
  handleDisputeAccept,
  handleDisputeVote,
  handleDisputeExecute,
  handleDisputeCancel,
  handleDisputeGet,
  handleDisputeList,
  expireDisputes,
} from "./shared/dispute.js";

import {
  handleWorkClaim,
  handleWorkLock,
  handleWorkAttest,
  handleWorkSettle,
  handleWorkRefund,
  handleWorkGet,
  handleWorkList,
  expireWorkClaims,
} from "./shared/work.js";

import {
  handleSagaStart,
  handleSagaAdvance,
  handleSagaCompensate,
  handleSagaCancel,
  handleSagaGet,
  handleSagaList,
  expireSagas,
} from "./shared/saga.js";

import {
  handleCommitCreate,
  handleCommitReveal,
  handleCommitCancel,
  handleCommitGet,
  handleCommitList,
  expireCommits,
} from "./shared/commit.js";

import {
  handleContinuityOpen,
  handleContinuityBeat,
  handleContinuityClose,
  handleContinuityRecover,
  handleContinuityGet,
  handleContinuityList,
  expireContinuitySessions,
} from "./shared/continuity.js";

import {
  handlePoolOpen,
  handlePoolContribute,
  handlePoolRelease,
  handlePoolRefund,
  handlePoolGet,
  handlePoolList,
  expireCollaborativePools,
} from "./shared/pool.js";

import {
  handleBondPost,
  handleBondMatch,
  handleBondFulfill,
  handleBondSlash,
  handleBondCancel,
  handleBondGet,
  handleBondList,
  expireBonds,
} from "./shared/bond.js";

import {
  handleTicketMint,
  handleTicketTransfer,
  handleTicketRedeem,
  handleTicketGet,
  handleTicketList,
  expireTickets,
} from "./shared/ticket.js";

import {
  handleClearingRun,
  handleClearingGet,
  handleClearingList,
} from "./shared/clearing.js";

import {
  handleNettingRun,
  handleNettingList,
} from "./shared/netting.js";

import {
  handleShieldPublic,
  handleMeShieldGet,
  handleMeShieldRelease,
  handleAdminShield,
} from "./shared/shieldApi.js";

import {
  handleAuthGoogleStart,
  handleAuthGoogleCallback,
  handleAuthGithubStart,
  handleAuthGithubCallback,
  handleAuthGitlabStart,
  handleAuthGitlabCallback,
  handleAuthMe,
  handleAuthLogout,
} from "./shared/oauth.js";

import {
  handleMeAgent,
  handleMeGithubRepos,
  handleMeGitlabRepos,
  handleMeReposUnified,
  handleAgentsScan,
  handleAgentsList,
  handleAgentsSearch,
  handleAgentsRank,
  handleMeBalance,
} from "./shared/agents.js";

import {
  handleMeKeysCreate,
  handleMeKeysList,
  handleMeKeysRevoke,
  handleMeKeysBind,
  handleMeKeysUnbind,
  handleMeKeySelf,
  handleEdgeInfo,
  handleMeKeysUnsuspend,
} from "./shared/keys.js";

import {
  handleMeWebhookGet,
  handleMeWebhookSet,
  handleMeWebhookClear,
  handleMeWebhookDeliveries,
} from "./shared/webhookApi.js";

import {
  handlePay,
  handleFund,
  handleBalance,
  handleLedger,
  issuePayReceipt,
  parseTraceId,
  ensureTrace,
} from "./shared/ledger.js";

import {
  handleEscrowHold,
  handleEscrowRelease,
  handleEscrowRefund,
  handleEscrowList,
} from "./shared/escrow.js";

































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


/* receipts issue helpers moved to shared/ledger.js */

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


/* ─── Safety controls (dashboard / API) ─── */


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

