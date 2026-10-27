/**
 * Shared webhooks — signed outbound events + waitUntil scheduling.
 * Failures never throw into the ledger path.
 */
import { randomId, hmacSha256Hex } from "./utils.js";
import { WEBHOOK_TIMEOUT_MS } from "./constants.js";

/* ─── Webhooks ─── */

/**
 * POST signed event to user's webhook_url.
 * webhook_secret_hash stores the raw signing secret (whsec_…) for HMAC outbound.
 * Failures are logged; never throw into ledger path.
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
export function scheduleWebhook(ctx, env, userId, event, data) {
  const p = dispatchWebhook(env, userId, event, data).catch((e) => {
    console.log("webhook_bg_error", e && e.message);
  });
  if (ctx && typeof ctx.waitUntil === "function") ctx.waitUntil(p);
  return p;
}

