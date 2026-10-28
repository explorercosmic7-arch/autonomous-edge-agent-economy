/**
 * Me webhook config API — get/set/clear URL + secret, list deliveries
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
    secret_prefix: row?.webhook_secret_prefix ? row.webhook_secret_prefix + "…" : null,
    events: ["escrow.released", "escrow.refunded", "escrow.expired", "wallet.locked", "agent.runaway_loop", "shield.quarantine", "shield.trip"],
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
    events: ["escrow.released", "escrow.refunded", "escrow.expired", "wallet.locked", "agent.runaway_loop", "shield.quarantine", "shield.trip"],
    hint: "Copy secret now. Verify X-AgentPay-Signature: sha256=<hmac-sha256(secret, rawBody)>.",
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

  const limit = Math.min(Math.max(Number(url.searchParams.get("limit") || 25), 1), 100);
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
