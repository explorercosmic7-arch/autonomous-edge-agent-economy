/**
 * Shared safety helpers — agent limits, velocity, daily budget, wallet checks.
 * lockWallet stays in index (needs adjustRep + scheduleWebhook).
 */

import { randomId } from "./utils.js";
import {
  SAFETY_DEFAULT_VELOCITY_MAX_TX,
  SAFETY_DEFAULT_VELOCITY_TX_WINDOW_SEC,
  SAFETY_DEFAULT_VELOCITY_MAX_USD,
  SAFETY_DEFAULT_VELOCITY_USD_WINDOW_SEC,
  SAFETY_SPIKE_TX_PER_SEC,
} from "./constants.js";

/* ─── Safety helpers (budget / velocity / lock / kill-switch) ─── */

export async function logSafetyEvent(env, event, { repo_id, api_key_id, user_id, reason, meta } = {}) {
  try {
    await env.DB.prepare(
      `INSERT INTO safety_events (id, event, repo_id, api_key_id, user_id, reason, meta_json, created_at)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, datetime('now'))`
    )
      .bind(
        randomId(12),
        event,
        repo_id || null,
        api_key_id || null,
        user_id || null,
        reason || null,
        meta ? JSON.stringify(meta) : null
      )
      .run();
  } catch (e) {
    console.log("safety_event_log_error", e && e.message);
  }
}

export async function ensureAgentLimits(env, repoId) {
  try {
    await env.DB.prepare(
      `INSERT INTO agent_limits (repo_id, updated_at) VALUES (?1, datetime('now'))
       ON CONFLICT(repo_id) DO NOTHING`
    )
      .bind(repoId)
      .run();
  } catch (e) {
    console.log("ensure_agent_limits", e && e.message);
  }
}

export async function getAgentLimits(env, repoId) {
  try {
    await ensureAgentLimits(env, repoId);
    return await env.DB.prepare(`SELECT * FROM agent_limits WHERE repo_id = ?1`)
      .bind(repoId)
      .first();
  } catch {
    return null;
  }
}

/** If wallet locked → { locked: true, reason }. Else null. */
export async function checkWalletLocked(env, repoId) {
  const lim = await getAgentLimits(env, repoId);
  if (lim && Number(lim.locked) === 1) {
    return { locked: true, reason: lim.lock_reason || "Wallet locked" };
  }
  return null;
}

export async function unlockWallet(env, repoId, { user_id } = {}) {
  await env.DB.prepare(
    `UPDATE agent_limits
     SET locked = 0,
         locked_at = NULL,
         lock_reason = NULL,
         updated_at = datetime('now')
     WHERE repo_id = ?1`
  )
    .bind(repoId)
    .run();
  await logSafetyEvent(env, "wallet.unlocked", { repo_id: repoId, user_id });
}

export async function suspendApiKey(env, keyId, reason, { repo_id, user_id } = {}) {
  if (!keyId) return;
  try {
    await env.DB.prepare(
      `UPDATE api_keys
       SET suspended_at = datetime('now'), suspend_reason = ?2
       WHERE id = ?1 AND suspended_at IS NULL`
    )
      .bind(keyId, String(reason || "suspended").slice(0, 500))
      .run();
  } catch (e) {
    console.log("suspend_key_error", e && e.message);
    return;
  }
  await logSafetyEvent(env, "key.suspended", {
    api_key_id: keyId,
    repo_id,
    user_id,
    reason,
  });
}

export async function recordVelocityEvent(env, repoId, amount, apiKeyId) {
  try {
    await env.DB.prepare(
      `INSERT INTO velocity_events (id, repo_id, api_key_id, amount, created_at)
       VALUES (?1, ?2, ?3, ?4, datetime('now'))`
    )
      .bind(randomId(12), repoId, apiKeyId || null, Number(amount) || 0)
      .run();
  } catch (e) {
    console.log("velocity_record_error", e && e.message);
  }
}

/**
 * Sliding-window velocity check.
 * Returns null if OK, or { code, error, retry_after_sec?, spike? }.
 */
export async function checkVelocity(env, repoId, amount, apiKeyId) {
  const lim = await getAgentLimits(env, repoId);
  const maxTx = (lim && lim.velocity_max_tx != null)
    ? Number(lim.velocity_max_tx)
    : SAFETY_DEFAULT_VELOCITY_MAX_TX;
  const txWindow = (lim && lim.velocity_tx_window_sec != null)
    ? Number(lim.velocity_tx_window_sec)
    : SAFETY_DEFAULT_VELOCITY_TX_WINDOW_SEC;
  const maxUsd = (lim && lim.velocity_max_usd != null)
    ? Number(lim.velocity_max_usd)
    : SAFETY_DEFAULT_VELOCITY_MAX_USD;
  const usdWindow = (lim && lim.velocity_window_sec != null)
    ? Number(lim.velocity_window_sec)
    : SAFETY_DEFAULT_VELOCITY_USD_WINDOW_SEC;

  try {
    // Spike: txs in last 1 second
    const spike = await env.DB.prepare(
      `SELECT COUNT(*) AS c FROM velocity_events
       WHERE repo_id = ?1 AND created_at >= datetime('now', '-1 seconds')`
    )
      .bind(repoId)
      .first();
    if (spike && Number(spike.c) >= SAFETY_SPIKE_TX_PER_SEC) {
      return {
        code: "velocity_spike",
        error:
          "Sudden spike detected (" +
          spike.c +
          " tx/sec). Edge interceptor engaged.",
        spike: true,
        retry_after_sec: 5,
      };
    }

    const txCount = await env.DB.prepare(
      `SELECT COUNT(*) AS c FROM velocity_events
       WHERE repo_id = ?1 AND created_at >= datetime('now', ?2)`
    )
      .bind(repoId, "-" + txWindow + " seconds")
      .first();
    if (txCount && Number(txCount.c) >= maxTx) {
      return {
        code: "velocity_tx",
        error:
          "Velocity limit: max " +
          maxTx +
          " transactions / " +
          txWindow +
          "s",
        retry_after_sec: txWindow,
      };
    }

    const usdSum = await env.DB.prepare(
      `SELECT COALESCE(SUM(amount), 0) AS s FROM velocity_events
       WHERE repo_id = ?1 AND created_at >= datetime('now', ?2)`
    )
      .bind(repoId, "-" + usdWindow + " seconds")
      .first();
    const spentWindow = Number(usdSum?.s || 0) + (Number(amount) || 0);
    if (spentWindow > maxUsd) {
      return {
        code: "velocity_usd",
        error:
          "Velocity limit: max $" +
          maxUsd +
          " / " +
          usdWindow +
          "s",
        retry_after_sec: usdWindow,
      };
    }
  } catch (e) {
    console.log("velocity_check_error", e && e.message);
  }
  return null;
}

/**
 * Daily budget cap. Resets when UTC day changes.
 * Returns null if OK, or { code, error }.
 */
export async function checkDailyBudget(env, repoId, amount) {
  const lim = await getAgentLimits(env, repoId);
  if (!lim || lim.daily_budget == null) return null;

  const today = new Date().toISOString().slice(0, 10); // YYYY-MM-DD UTC-ish
  let dailySpent = Number(lim.daily_spent || 0);
  const windowStart = lim.daily_window_start
    ? String(lim.daily_window_start).slice(0, 10)
    : null;

  if (windowStart !== today) {
    dailySpent = 0;
    try {
      await env.DB.prepare(
        `UPDATE agent_limits
         SET daily_spent = 0, daily_window_start = ?2, updated_at = datetime('now')
         WHERE repo_id = ?1`
      )
        .bind(repoId, today)
        .run();
    } catch (_) {}
  }

  if (dailySpent + Number(amount) > Number(lim.daily_budget)) {
    return {
      code: "daily_budget",
      error:
        "Daily budget cap reached ($" +
        lim.daily_budget +
        "). Spent today: $" +
        dailySpent.toFixed(6),
    };
  }
  return null;
}

export async function addDailySpent(env, repoId, amount) {
  const today = new Date().toISOString().slice(0, 10);
  try {
    await ensureAgentLimits(env, repoId);
    const lim = await env.DB.prepare(
      `SELECT daily_window_start FROM agent_limits WHERE repo_id = ?1`
    )
      .bind(repoId)
      .first();
    const windowStart = lim?.daily_window_start
      ? String(lim.daily_window_start).slice(0, 10)
      : null;
    if (windowStart !== today) {
      await env.DB.prepare(
        `UPDATE agent_limits
         SET daily_spent = ?2, daily_window_start = ?3, updated_at = datetime('now')
         WHERE repo_id = ?1`
      )
        .bind(repoId, Number(amount) || 0, today)
        .run();
    } else {
      await env.DB.prepare(
        `UPDATE agent_limits
         SET daily_spent = daily_spent + ?2, updated_at = datetime('now')
         WHERE repo_id = ?1`
      )
        .bind(repoId, Number(amount) || 0)
        .run();
    }
  } catch (e) {
    console.log("daily_spent_error", e && e.message);
  }
}

