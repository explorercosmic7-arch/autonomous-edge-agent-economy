import {
  securityHeaders,
  corsHeaders,
  json,
  bad,
  rejectOversizedBody,
  clientIp,
} from "./shared/http.js";

import { checkRateLimit } from "./shared/rateLimit.js";

import { getRequestEdge } from "./shared/edge.js";

import { getAuthUser } from "./shared/auth.js";

import {
  handleMePolicyGet,
  handleMePolicySet,
} from "./shared/policy.js";

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
} from "./shared/ledger.js";

import {
  handleEscrowHold,
  handleEscrowRelease,
  handleEscrowRefund,
  handleEscrowList,
} from "./shared/escrow.js";

import {
  handleStreamStart,
  handleStreamMeter,
  handleStreamStop,
  handleStreamList,
} from "./shared/stream.js";

import {
  handleSubWalletOpen,
  handleSubWalletSpend,
  handleSubWalletClose,
  handleSubWalletList,
  expireSubWallets,
} from "./shared/subwallet.js";

import {
  handleReceiptGet,
  handleReceiptVerify,
  handleTraceGet,
} from "./shared/receipts.js";

import {
  handleMeCreditGet,
  handleMeCreditSet,
  handleMeCreditRepay,
} from "./shared/meCredit.js";

import {
  handleMeSafetyGet,
  handleMeSafetySet,
  handleMeSafetyUnlock,
} from "./shared/meSafety.js";

import {
  RL_IP_POST_MAX,
  RL_IP_POST_WINDOW_SEC,
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
