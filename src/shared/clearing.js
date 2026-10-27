/**
 * Shared Clearing — multilateral clearing batches + HMAC settlement manifests.
 */
import { json, bad } from "./http.js";
import {
  parseRepo,
  randomId,
  hmacSha256Hex,
  MIN_AMOUNT,
} from "./utils.js";
import { checkRateLimit } from "./rateLimit.js";
import { getAuthUser } from "./auth.js";
import { ensureAccount } from "./accounts.js";
import { scheduleWebhook } from "./webhooks.js";
import {
  SYSTEM_CLEARING,
  CLEARING_DEFAULT_WINDOW_HOURS,
  CLEARING_MIN_WINDOW_HOURS,
  CLEARING_MAX_WINDOW_HOURS,
  CLEARING_MAX_REPOS,
  RL_CLEARING_MAX,
  RL_CLEARING_WINDOW_SEC,
} from "./constants.js";

/* ─── Cross-deployment clearing netting ───
 * Multilateral net positions over bilateral micro-pays in a time window.
 * Produces HMAC-SHA256 settlement manifest (RECEIPT_SECRET) for external rails.
 * Optional apply_balances: move net amounts via system/clearing.
 *
 * POST /api/clearing/run { window_hours?, apply_balances?, deployment_id? }
 * GET  /api/clearing?limit=
 * GET  /api/clearing/:id  → batch + positions + settlement + hmac
 */

export function clearingSecret(env) {
  return env.RECEIPT_SECRET || env.SESSION_SECRET || env.GOOGLE_CLIENT_SECRET || "a2a-dev-receipt-secret";
}

export async function hmacSettlement(env, canonicalJson) {
  return hmacSha256Hex(clearingSecret(env), canonicalJson);
}


export async function handleClearingRun(request, env, ctx) {
  const t0 = Date.now();
  const authUser = await getAuthUser(request, env);
  if (!authUser) return bad(request, "Sign in or API key required", 401);

  const rlId =
    authUser.auth_via === "api_key"
      ? "cl:key:" + (authUser.key_id || authUser.id)
      : "cl:user:" + authUser.id;
  const limited = await checkRateLimit(env, rlId, RL_CLEARING_MAX, RL_CLEARING_WINDOW_SEC);
  if (limited) {
    return bad(request, "Rate limit: clearing", 429, { retry_after_sec: limited.retry_after_sec });
  }

  let body = {};
  try {
    body = await request.json();
  } catch {
    body = {};
  }

  let windowHours = Number(body.window_hours);
  if (!Number.isFinite(windowHours) || windowHours <= 0) windowHours = CLEARING_DEFAULT_WINDOW_HOURS;
  if (windowHours < CLEARING_MIN_WINDOW_HOURS || windowHours > CLEARING_MAX_WINDOW_HOURS) {
    return bad(request, "window_hours out of range");
  }
  const applyBalances = !!body.apply_balances;
  const deploymentId = String(body.deployment_id || body.deployment || "default").slice(0, 120);

  // Aggregate bilateral pays in window (exclude system/* counterparties)
  let txs = [];
  try {
    const q = await env.DB.prepare(
      `SELECT from_repo, to_repo, amount FROM transactions
       WHERE status = 'success'
         AND created_at >= datetime('now', ?1)
         AND from_repo NOT LIKE 'system/%'
         AND to_repo NOT LIKE 'system/%'
       LIMIT 20000`
    )
      .bind("-" + windowHours + " hours")
      .all();
    txs = q.results || [];
  } catch (e) {
    return bad(request, "transactions query failed: " + (e.message || e), 500);
  }

  // Net position per repo: +in -out
  const pos = new Map(); // repo -> { out, in }
  let gross = 0;
  for (const t of txs) {
    const a = Number(t.amount) || 0;
    if (!(a > 0)) continue;
    gross += a;
    const fr = t.from_repo;
    const tr = t.to_repo;
    if (!pos.has(fr)) pos.set(fr, { out: 0, in: 0 });
    if (!pos.has(tr)) pos.set(tr, { out: 0, in: 0 });
    pos.get(fr).out += a;
    pos.get(tr).in += a;
  }
  gross = Math.round(gross * 1e6) / 1e6;

  const positions = [];
  let volumeNet = 0;
  for (const [repo, v] of pos.entries()) {
    const net = Math.round((v.in - v.out) * 1e6) / 1e6;
    if (Math.abs(net) < MIN_AMOUNT) continue;
    positions.push({
      repo_id: repo,
      gross_out: Math.round(v.out * 1e6) / 1e6,
      gross_in: Math.round(v.in * 1e6) / 1e6,
      net_amount: net,
    });
    volumeNet += Math.abs(net);
  }
  volumeNet = Math.round((volumeNet / 2) * 1e6) / 1e6; // each $ counted twice in abs sum
  const volumeSaved = Math.max(0, Math.round((gross - volumeNet) * 1e6) / 1e6);

  if (positions.length > CLEARING_MAX_REPOS) {
    return bad(request, "too many positions — narrow window_hours");
  }

  const batchId = "clr_" + randomId(12);
  const settlement = {
    type: "agentpay.clearing.settlement",
    version: 1,
    batch_id: batchId,
    deployment_id: deploymentId,
    window_hours: windowHours,
    created_at: new Date().toISOString(),
    volume_gross: gross,
    volume_net: volumeNet,
    volume_saved: volumeSaved,
    positions: positions
      .slice()
      .sort((a, b) => a.repo_id.localeCompare(b.repo_id))
      .map((p) => ({
        repo_id: p.repo_id,
        net_amount: p.net_amount,
        gross_in: p.gross_in,
        gross_out: p.gross_out,
      })),
  };
  const settlementJson = JSON.stringify(settlement);
  const settlementHmac = await hmacSettlement(env, settlementJson);

  // Optional hard settle: payers (net < 0) → system/clearing → receivers (net > 0)
  let applied = 0;
  if (applyBalances && positions.length) {
    await ensureAccount(env, SYSTEM_CLEARING);
    for (const p of positions) {
      if (p.net_amount >= 0) continue;
      const need = Math.abs(p.net_amount);
      await ensureAccount(env, p.repo_id);
      const deb = await env.DB.prepare(
        `UPDATE accounts SET balance = balance - ?1, updated_at = datetime('now')
         WHERE repo_id = ?2 AND balance >= ?1 RETURNING balance`
      )
        .bind(need, p.repo_id)
        .first();
      if (!deb) {
        // skip underfunded; leave net unsettled for this repo
        continue;
      }
      await env.DB.prepare(
        `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
      )
        .bind(need, SYSTEM_CLEARING)
        .run();
      await env.DB.prepare(
        `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
         VALUES (?1, ?2, ?3, ?4, 'success', 0)`
      )
        .bind(p.repo_id, SYSTEM_CLEARING, need, "clearing-collect:" + batchId)
        .run();
      applied += 1;
    }
    for (const p of positions) {
      if (p.net_amount <= 0) continue;
      const pay = p.net_amount;
      await ensureAccount(env, p.repo_id);
      const pool = await env.DB.prepare(
        `UPDATE accounts SET balance = balance - ?1, updated_at = datetime('now')
         WHERE repo_id = ?2 AND balance >= ?1 RETURNING balance`
      )
        .bind(pay, SYSTEM_CLEARING)
        .first();
      if (!pool) continue;
      await env.DB.prepare(
        `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
      )
        .bind(pay, p.repo_id)
        .run();
      await env.DB.prepare(
        `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
         VALUES (?1, ?2, ?3, ?4, 'success', 0)`
      )
        .bind(SYSTEM_CLEARING, p.repo_id, pay, "clearing-pay:" + batchId)
        .run();
      applied += 1;
    }
  }

  try {
    const stmts = [
      env.DB.prepare(
        `INSERT INTO clearing_batches (
           id, window_hours, deployment_id, status, pairs_scanned, positions_count,
           volume_gross, volume_net, volume_saved, apply_balances,
           settlement_json, settlement_hmac, created_by, created_at
         ) VALUES (
           ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, datetime('now')
         )`
      ).bind(
        batchId,
        windowHours,
        deploymentId,
        applyBalances ? "applied" : "computed",
        txs.length,
        positions.length,
        gross,
        volumeNet,
        volumeSaved,
        applyBalances ? 1 : 0,
        settlementJson,
        settlementHmac,
        authUser.id || null
      ),
    ];
    for (const p of positions) {
      stmts.push(
        env.DB.prepare(
          `INSERT INTO clearing_positions (
             id, batch_id, repo_id, gross_out, gross_in, net_amount, created_at
           ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, datetime('now'))`
        ).bind(
          "cp_" + randomId(8),
          batchId,
          p.repo_id,
          p.gross_out,
          p.gross_in,
          p.net_amount
        )
      );
    }
    await env.DB.batch(stmts);
  } catch (e) {
    return bad(
      request,
      "clearing_batches table missing — run d1-clearing-migration.sql: " + (e.message || e),
      500
    );
  }

  // Also mint an HMAC receipt record for the settlement (cross-deployment verify)
  try {
    const rid = "rcpt_clr_" + randomId(10);
    const rPayload = {
      id: rid,
      type: "clearing_settlement",
      batch_id: batchId,
      deployment_id: deploymentId,
      volume_net: volumeNet,
      volume_saved: volumeSaved,
      hmac: settlementHmac,
      created_at: settlement.created_at,
    };
    const rJson = JSON.stringify(rPayload);
    const rSig = await hmacSha256Hex(clearingSecret(env), rJson);
    await env.DB.prepare(
      `INSERT INTO payment_receipts (id, payload_json, signature, from_repo, to_repo, amount, created_at)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, datetime('now'))`
    )
      .bind(rid, rJson, rSig, SYSTEM_CLEARING, deploymentId, volumeNet)
      .run();
  } catch (e) {
    console.log("clearing_receipt_skip", e && e.message);
  }

  if (authUser.id) {
    scheduleWebhook(ctx, env, authUser.id, "clearing.computed", {
      id: batchId,
      deployment_id: deploymentId,
      positions: positions.length,
      volume_saved: volumeSaved,
      apply_balances: applyBalances,
    });
  }

  return json(request, {
    ok: true,
    batch: {
      id: batchId,
      deployment_id: deploymentId,
      window_hours: windowHours,
      status: applyBalances ? "applied" : "computed",
      pairs_scanned: txs.length,
      positions_count: positions.length,
      volume_gross: gross,
      volume_net: volumeNet,
      volume_saved: volumeSaved,
      apply_balances: applyBalances,
      applied_legs: applied,
    },
    positions,
    settlement,
    settlement_hmac: settlementHmac,
    verify_hint:
      "HMAC-SHA256(RECEIPT_SECRET, settlement_json) === settlement_hmac. GET /api/clearing/" +
      batchId,
    latency_ms: Date.now() - t0,
  });
}

export async function handleClearingGet(request, env, id) {
  id = String(id || "").trim();
  if (!id) return bad(request, "id required");
  let batch;
  try {
    batch = await env.DB.prepare(`SELECT * FROM clearing_batches WHERE id = ?1`).bind(id).first();
  } catch {
    return bad(request, "clearing_batches table missing — run d1-clearing-migration.sql", 500);
  }
  if (!batch) return bad(request, "Clearing batch not found", 404);

  let positions = [];
  try {
    const q = await env.DB.prepare(
      `SELECT repo_id, gross_out, gross_in, net_amount FROM clearing_positions
       WHERE batch_id = ?1 ORDER BY repo_id ASC`
    )
      .bind(id)
      .all();
    positions = q.results || [];
  } catch (_) {}

  let settlement = null;
  try {
    settlement = batch.settlement_json ? JSON.parse(batch.settlement_json) : null;
  } catch {
    settlement = batch.settlement_json;
  }

  // Recompute HMAC for verification convenience
  let hmac_ok = null;
  if (batch.settlement_json && batch.settlement_hmac) {
    const expect = await hmacSettlement(env, batch.settlement_json);
    hmac_ok = expect === batch.settlement_hmac;
  }

  return json(request, {
    ok: true,
    batch: {
      id: batch.id,
      deployment_id: batch.deployment_id,
      window_hours: batch.window_hours,
      status: batch.status,
      pairs_scanned: batch.pairs_scanned,
      positions_count: batch.positions_count,
      volume_gross: batch.volume_gross,
      volume_net: batch.volume_net,
      volume_saved: batch.volume_saved,
      apply_balances: !!batch.apply_balances,
      created_at: batch.created_at,
    },
    positions,
    settlement,
    settlement_hmac: batch.settlement_hmac,
    hmac_ok,
  });
}

export async function handleClearingList(request, url, env) {
  const limit = Math.min(Math.max(Number(url.searchParams.get("limit") || 12), 1), 50);
  try {
    const { results } = await env.DB.prepare(
      `SELECT id, window_hours, deployment_id, status, pairs_scanned, positions_count,
              volume_gross, volume_net, volume_saved, apply_balances, created_at
       FROM clearing_batches ORDER BY created_at DESC LIMIT ?1`
    )
      .bind(limit)
      .all();
    return json(request, { ok: true, count: (results || []).length, batches: results || [] });
  } catch (e) {
    return bad(
      request,
      "clearing_batches table missing — run d1-clearing-migration.sql: " + (e.message || e),
      500
    );
  }
}


