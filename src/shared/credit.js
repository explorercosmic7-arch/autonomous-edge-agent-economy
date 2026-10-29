/**
 * Shared reputation-backed credit — limits, draw, repay, rep adjust.
 * Path on GitHub: src/shared/credit.js
 *
 * Depends on: safety.js (ensureAgentLimits, getAgentLimits), accounts.js (ensureAccount),
 *             constants.js (CREDIT_*), utils.js (randomId)
 *
 * MUST export debitWithCredit — used by ledger.js and escrow.js.
 */
import { randomId } from "./utils.js";
import { ensureAgentLimits, getAgentLimits } from "./safety.js";
import { ensureAccount } from "./accounts.js";
import {
  CREDIT_DEFAULT_LIMIT,
  CREDIT_MAX_LIMIT,
  CREDIT_REP_TO_LIMIT_RATIO,
  CREDIT_AUTO_LIMIT,
} from "./constants.js";

/* ─── Reputation-backed credit ───
 * agent_limits.credit_limit  — max outstanding draw (null/0 = cash only)
 * agent_limits.outstanding_credit — current borrowed
 * agent_limits.rep_score — reputation points
 * Spend path: if balance < amount, draw min(shortfall, available_credit).
 * Repay: POST /api/me/credit/repay reduces outstanding from free balance.
 * Auto-limit: suggested = min(CREDIT_MAX_LIMIT, rep_score * CREDIT_REP_TO_LIMIT_RATIO)
 */

export async function getCreditState(env, repoId) {
  const lim = await getAgentLimits(env, repoId);
  if (!lim) {
    return {
      credit_limit: CREDIT_DEFAULT_LIMIT,
      outstanding_credit: 0,
      available_credit: CREDIT_DEFAULT_LIMIT,
      rep_score: 0,
      rep_events: 0,
      suggested_limit: 0,
      locked: false,
    };
  }
  const limit =
    lim.credit_limit != null ? Number(lim.credit_limit) : CREDIT_DEFAULT_LIMIT;
  const outstanding = Number(lim.outstanding_credit || 0);
  const rep = Number(lim.rep_score || 0);
  const suggested = Math.min(
    CREDIT_MAX_LIMIT,
    Math.round(rep * CREDIT_REP_TO_LIMIT_RATIO * 1e6) / 1e6
  );
  const effectiveLimit = Math.max(limit, 0);
  const available = Math.max(
    0,
    Math.round((effectiveLimit - outstanding) * 1e6) / 1e6
  );
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

export async function adjustRep(env, repoId, delta, reason, refId) {
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
        .bind(
          randomId(10),
          repoId,
          Number(delta),
          score,
          String(reason || "").slice(0, 200),
          refId || null
        )
        .run();
    } catch (_) {
      /* rep_events table optional */
    }
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
 *
 * IMPORTANT: this name must stay `debitWithCredit` — ledger.js + escrow.js import it.
 */
export async function debitWithCredit(env, repoId, amount) {
  amount = Number(amount);
  if (!(amount > 0) || !Number.isFinite(amount)) {
    return { ok: false, error: "Invalid amount", code: "invalid_amount" };
  }
  await ensureAccount(env, repoId);
  const acc = await env.DB.prepare(
    `SELECT balance FROM accounts WHERE repo_id = ?1`
  )
    .bind(repoId)
    .first();
  const bal = Number(acc?.balance || 0);

  // Fast path: enough cash
  if (bal >= amount) {
    const row = await env.DB.prepare(
      `UPDATE accounts SET balance = balance - ?1, updated_at = datetime('now')
       WHERE repo_id = ?2 AND balance >= ?1 RETURNING balance`
    )
      .bind(amount, repoId)
      .first();
    if (!row) {
      return { ok: false, error: "Insufficient funds", code: "insufficient" };
    }
    return {
      ok: true,
      balance: Number(row.balance),
      credit_drawn: 0,
      outstanding: 0,
    };
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

  // Draw credit: use all cash, increase outstanding
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
    return {
      ok: false,
      error: "Credit draw race or limit exceeded",
      code: "credit_race",
    };
  }

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

export async function repayCredit(env, repoId, amount) {
  amount = Number(amount);
  if (!(amount > 0)) return { ok: false, error: "amount required" };
  const lim = await getAgentLimits(env, repoId);
  const outstanding = Number(lim?.outstanding_credit || 0);
  if (outstanding <= 0) {
    return { ok: true, repaid: 0, outstanding: 0, already_clear: true };
  }
  const pay = Math.min(amount, outstanding);
  await ensureAccount(env, repoId);
  const deb = await env.DB.prepare(
    `UPDATE accounts SET balance = balance - ?1, updated_at = datetime('now')
     WHERE repo_id = ?2 AND balance >= ?1 RETURNING balance`
  )
    .bind(pay, repoId)
    .first();
  if (!deb) {
    return {
      ok: false,
      error: "Insufficient balance to repay credit",
      code: "insufficient",
    };
  }
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
