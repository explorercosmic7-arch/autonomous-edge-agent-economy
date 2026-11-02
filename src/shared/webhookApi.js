/**
 * Me webhook config API — get/set/clear URL + secret, list deliveries, test ping.
 * (dispatch lives in shared/webhooks.js)
 */
import { json, bad } from "./http.js";
import { randomId, parseWebhookUrl } from "./utils.js";
import { checkRateLimit } from "./rateLimit.js";
import { getSessionUser } from "./auth.js";
import {
  RL_WEBHOOK_SET_MAX,
  RL_WEBHOOK_SET_WINDOW_SEC,
} from "./constants.js";
import { WEBHOOK_EVENTS, dispatchWebhook } from "./webhooks.js";

/* ─── Me / webhook ─── */

export async function handleMeWebhookGet(request, env) {
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
    secret_prefix: row?.webhook_secret_prefix
      ? row.webhook_secret_prefix + "…"
      : null,
    events: WEBHOOK_EVENTS,
    envelope: {
      v: 1,
      headers: [
        "X-AgentPay-Signature: sha256=<hmac-sha256(secret, rawBody)>",
        "X-AgentPay-Event",
        "X-AgentPay-Delivery-Id",
        "X-AgentPay-Timestamp",
      ],
    },
  });
}

export async function handleMeWebhookSet(request, env) {
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
    events: WEBHOOK_EVENTS,
    hint:
      "Copy secret now. Verify X-AgentPay-Signature: sha256=<hmac-sha256(secret, rawBody)>. " +
      "POST /api/me/webhook/test to send a signed webhook.ping.",
  });
}

export async function handleMeWebhookClear(request, env) {
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

export async function handleMeWebhookDeliveries(request, env, url) {
  const user = await getSessionUser(request, env);
  if (!user) return bad(request, "Sign in required", 401);
  const limit = Math.min(
    Math.max(Number(url.searchParams.get("limit") || 25), 1),
    100
  );
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

/**
 * One-click test: signed webhook.ping to the configured URL.
 * Rate-limited with the same bucket as set.
 */
export async function handleMeWebhookTest(request, env) {
  const user = await getSessionUser(request, env);
  if (!user) return bad(request, "Sign in required", 401);

  const limited = await checkRateLimit(
    env,
    "webhooktest:" + user.id,
    10,
    3600
  );
  if (limited) {
    return bad(request, "Rate limit: max 10 webhook tests per hour", 429, {
      retry_after_sec: limited.retry_after_sec,
      code: "webhook_test_rate_limited",
    });
  }

  const row = await env.DB.prepare(
    `SELECT webhook_url FROM users WHERE id = ?1`
  )
    .bind(user.id)
    .first();
  if (!row || !row.webhook_url) {
    return bad(
      request,
      "Configure a webhook URL first (POST /api/me/webhook)",
      400,
      { code: "webhook_not_configured" }
    );
  }

  const result = await dispatchWebhook(env, user.id, "webhook.ping", {
    message: "AgentPay webhook test",
    user_id: user.id,
    ts: new Date().toISOString(),
  });

  if (result.skipped) {
    return bad(
      request,
      "Webhook not configured or lookup failed",
      400,
      { code: result.reason || "skipped" }
    );
  }

  return json(request, {
    ok: !!result.ok,
    event: "webhook.ping",
    delivery_id: result.delivery_id || null,
    status_code: result.status_code,
    error: result.error || null,
    attempts: result.attempts || 1,
    url: row.webhook_url,
  });
}
