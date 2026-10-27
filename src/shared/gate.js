/**
 * Shared safety gate — lockWallet, safetyGate, safetyRecordSpend.
 * Orchestrates auth / shield / policy / velocity / daily budget checks.
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

/* ─── Safety: lockWallet (needs adjustRep + scheduleWebhook); rest in shared/safety.js ─── */

export async export function lockWallet(env, repoId, reason, { api_key_id, user_id, ctx } = {}) {
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


export async export function safetyGate(request, env, authUser, fromRepo, amount) {
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
export async export function safetyRecordSpend(env, authUser, fromRepo, amount) {
  if (!fromRepo || !amount) return;
  const keyId = authUser && authUser.auth_via === "api_key" ? authUser.key_id : null;
  await recordVelocityEvent(env, fromRepo, amount, keyId);
  await addDailySpent(env, fromRepo, amount);
}


