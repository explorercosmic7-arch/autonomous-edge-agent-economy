/**
 * Shared safety gate — lockWallet, safetyGate, safetyRecordSpend.
 * Orchestrates auth / shield / policy / velocity / agent + fleet budget / approval checks.
 *
 * Order (important):
 *  shield → wallet lock → policy → daily → fleet → **approval** → velocity
 * Approval before velocity so a large intentional pay returns approval_required
 * instead of velocity_usd when both would apply.
 */
import {
  ensureAgentLimits,
  logSafetyEvent,
  checkWalletLocked,
  suspendApiKey,
  checkVelocity,
  checkDailyBudget,
  recordVelocityEvent,
  addDailySpent,
  checkFleetBudget,
  addFleetSpent,
} from "./safety.js";
import {
  checkShieldGate,
  setShieldLevel,
  maybeAutoTripGlobalShield,
} from "./shield.js";
import { checkSpendPolicy } from "./policy.js";
import { rejectIfSuspendedKey } from "./auth.js";
import { adjustRep } from "./credit.js";
import { scheduleWebhook } from "./webhooks.js";
import { bad } from "./http.js";
import {
  CREDIT_REP_FAIL_PENALTY,
  SHIELD_LEVEL_FREEZE,
  SHIELD_COOLDOWN_SEC,
} from "./constants.js";
import { checkApprovalGate } from "./approval.js";

/* ─── Safety: lockWallet ─── */
export async function lockWallet(
  env,
  repoId,
  reason,
  { api_key_id, user_id, ctx } = {}
) {
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

export async function safetyGate(request, env, authUser, fromRepo, amount) {
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

  // Policy-as-code (allow/deny, max_amount, task prefix)
  const pctx = (authUser && authUser._policyCtx) || {};
  const polHit = await checkSpendPolicy(
    env,
    fromRepo,
    amount,
    pctx.to_repo,
    pctx.task
  );
  if (polHit) {
    return bad(request, polHit.error, 403, {
      code: polHit.code || "policy_denied",
    });
  }

  // Per-agent daily budget
  const budgetHit = await checkDailyBudget(env, fromRepo, amount);
  if (budgetHit) {
    return bad(request, budgetHit.error, 429, { code: budgetHit.code });
  }

  // Fleet (account-wide) budget — only when we know the user
  const uid = authUser && authUser.id;
  if (uid) {
    const fleetHit = await checkFleetBudget(env, uid, amount);
    if (fleetHit && fleetHit.hard) {
      try {
        await logSafetyEvent(env, "fleet.budget_exceeded", {
          user_id: uid,
          repo_id: fromRepo,
          reason: fleetHit.error,
          meta: {
            code: fleetHit.code,
            daily_spent: fleetHit.daily_spent,
            monthly_spent: fleetHit.monthly_spent,
            amount,
          },
        });
        scheduleWebhook(null, env, uid, "fleet.budget_exceeded", {
          repo_id: fromRepo,
          reason: fleetHit.error,
          code: fleetHit.code,
          daily_spent: fleetHit.daily_spent,
          monthly_spent: fleetHit.monthly_spent,
          daily_budget: fleetHit.daily_budget,
          monthly_budget: fleetHit.monthly_budget,
          amount: Number(amount),
          remaining: fleetHit.remaining,
        });
      } catch (e) {
        console.log("fleet_hard_webhook", e && e.message);
      }
      return bad(request, fleetHit.error, 429, {
        code: fleetHit.code,
        daily_spent: fleetHit.daily_spent,
        monthly_spent: fleetHit.monthly_spent,
      });
    }
    // Soft warn: log + webhook, do not block
    if (fleetHit && fleetHit.warn) {
      await logSafetyEvent(env, "fleet.budget_warn", {
        user_id: uid,
        repo_id: fromRepo,
        reason: fleetHit.error,
        meta: {
          daily_spent: fleetHit.daily_spent,
          daily_budget: fleetHit.daily_budget,
        },
      });
      scheduleWebhook(null, env, uid, "fleet.budget_warn", {
        repo_id: fromRepo,
        reason: fleetHit.error,
        daily_spent: fleetHit.daily_spent,
        daily_budget: fleetHit.daily_budget,
      });
    }
  }

  // Approval gates BEFORE velocity — human hold is clearer than velocity for large intentional spends.
  // Skip if this pay already validated an approved X-Approval-Id.
  if (uid && !authUser._approvalConsumed) {
    try {
      const appr = await checkApprovalGate(env, authUser, fromRepo, amount, {
        toRepo: pctx.to_repo,
        task: pctx.task,
        idempotency_key: pctx.idempotency_key,
      });
      if (appr && appr.block) {
        return bad(request, appr.error, 403, {
          code: appr.code || "approval_required",
          approval_id: appr.approval_id,
          expires_at: appr.expires_at,
          rule_code: appr.rule_code,
          status: appr.status,
        });
      }
    } catch (e) {
      console.log("approval_gate", e && e.message);
    }
  }

  const keyId =
    authUser && authUser.auth_via === "api_key" ? authUser.key_id : null;
  const vel = await checkVelocity(env, fromRepo, amount, keyId);
  if (vel) {
    if (vel.spike && keyId) {
      const u = authUser && authUser.id;
      await suspendApiKey(env, keyId, vel.error, {
        repo_id: fromRepo,
        user_id: u,
      });
      await lockWallet(env, fromRepo, vel.error, {
        api_key_id: keyId,
        user_id: u,
      });
      await logSafetyEvent(env, "agent.runaway_loop", {
        repo_id: fromRepo,
        api_key_id: keyId,
        user_id: u,
        reason: vel.error,
      });
      try {
        await setShieldLevel(
          env,
          fromRepo,
          SHIELD_LEVEL_FREEZE,
          "runaway_loop: " + vel.error,
          { cooldownSec: SHIELD_COOLDOWN_SEC }
        );
        await maybeAutoTripGlobalShield(env);
      } catch (e) {
        console.log("shield_trip_on_spike", e && e.message);
      }
      if (u) {
        scheduleWebhook(null, env, u, "agent.runaway_loop", {
          repo_id: fromRepo,
          reason: vel.error,
          api_key_id: keyId,
        });
        scheduleWebhook(null, env, u, "shield.quarantine", {
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

/** Call after a successful debit to update velocity + agent daily + fleet spent. */
export async function safetyRecordSpend(env, authUser, fromRepo, amount) {
  if (!fromRepo || !amount) return;
  const keyId =
    authUser && authUser.auth_via === "api_key" ? authUser.key_id : null;
  await recordVelocityEvent(env, fromRepo, amount, keyId);
  await addDailySpent(env, fromRepo, amount);
  if (authUser && authUser.id) {
    await addFleetSpent(env, authUser.id, amount);
  }
}
