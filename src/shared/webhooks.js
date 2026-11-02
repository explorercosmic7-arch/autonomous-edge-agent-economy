/**
 * Shared webhooks — signed outbound events + waitUntil scheduling.
 * Failures never throw into the ledger path.
 *
 * Envelope v1:
 *   { v: 1, id, event, created_at, data }
 * Headers:
 *   X-AgentPay-Signature: sha256=<hmac-hex>
 *   X-AgentPay-Event: <event>
 *   X-AgentPay-Delivery-Id: <payload.id>
 *   X-AgentPay-Timestamp: <unix seconds>
 *
 * Retry: one extra attempt on timeout / network / 5xx (attempts column reflects total).
 */
import { randomId, hmacSha256Hex } from "./utils.js";
import { WEBHOOK_TIMEOUT_MS } from "./constants.js";

/** Canonical event names (advertised + emitted). Keep stable for receivers. */
export const WEBHOOK_EVENTS = [
  "webhook.ping",
  "approval.requested",
  "approval.approved",
  "approval.rejected",
  "approval.alert",
  "approval.expired",
  "approval.consumed",
  "wallet.locked",
  "wallet.unlocked",
  "agent.runaway_loop",
  "fleet.budget_warn",
  "fleet.budget_exceeded",
  "shield.quarantine",
  "shield.trip",
  "escrow.released",
  "escrow.refunded",
  "escrow.expired",
];

/**
 * POST signed event to user's webhook_url.
 * webhook_secret_hash stores the raw signing secret (whsec_…) for HMAC outbound.
 */
export async function dispatchWebhook(env, userId, event, data) {
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

  const deliveryId = "evt_" + randomId(12);
  const createdAt = new Date().toISOString();
  const tsSec = Math.floor(Date.now() / 1000);
  const payload = {
    v: 1,
    id: deliveryId,
    event,
    created_at: createdAt,
    data: data || {},
  };
  const body = JSON.stringify(payload);

  let statusCode = null;
  let ok = 0;
  let error = null;
  let attempts = 0;

  const maxAttempts = 2; // initial + one retry on soft failure
  for (let i = 0; i < maxAttempts; i++) {
    attempts = i + 1;
    statusCode = null;
    error = null;
    ok = 0;
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
            "X-AgentPay-Delivery-Id": deliveryId,
            "X-AgentPay-Timestamp": String(tsSec),
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

    // Success or hard 4xx (except 408/429) → stop
    if (ok) break;
    const soft =
      error === "timeout" ||
      !statusCode ||
      statusCode >= 500 ||
      statusCode === 408 ||
      statusCode === 429;
    if (!soft) break;
    if (i + 1 < maxAttempts) {
      // brief pause before retry
      await new Promise((r) => setTimeout(r, 250));
    }
  }

  try {
    await env.DB.prepare(
      `INSERT INTO webhook_deliveries (
         id, user_id, event, escrow_id, url, payload_json,
         status_code, ok, error, attempts, created_at
       ) VALUES (
         ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, datetime('now')
       )`
    )
      .bind(
        randomId(12),
        userId,
        event,
        (data && (data.escrow_id || data.approval_id || data.id)) || null,
        url,
        body,
        statusCode,
        ok,
        error,
        attempts
      )
      .run();
  } catch (e) {
    console.log("webhook_log_error", e && e.message);
  }

  return {
    ok: !!ok,
    status_code: statusCode,
    error,
    attempts,
    delivery_id: deliveryId,
  };
}

/** Fire webhook without blocking the HTTP response when ctx is available. */
export function scheduleWebhook(ctx, env, userId, event, data) {
  const p = dispatchWebhook(env, userId, event, data).catch((e) => {
    console.log("webhook_bg_error", e && e.message);
  });
  if (ctx && typeof ctx.waitUntil === "function") ctx.waitUntil(p);
  return p;
}
