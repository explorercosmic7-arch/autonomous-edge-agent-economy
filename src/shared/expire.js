/**
 * Shared expire / prune — escrow auto-expire + telemetry prune (cron helpers).
 */
import { ensureAccount } from "./accounts.js";
import { scheduleWebhook } from "./webhooks.js";
import { randomId } from "./utils.js";
import {
  EXPIRE_BATCH_LIMIT,
  SYSTEM_ESCROW,
} from "./constants.js";

/* ─── Auto-expire held escrows (cron) ─── */

export async function expireHeldEscrows(env, ctx) {
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
export const PRUNE_VELOCITY_HOURS = 24;
export const PRUNE_SAFETY_DAYS = 90;
export const PRUNE_WEBHOOK_DAYS = 30;
export const PRUNE_RATE_LIMIT_DAYS = 7;
export const PRUNE_IDEM_DAYS = 7;

export async function pruneTelemetry(env) {
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


