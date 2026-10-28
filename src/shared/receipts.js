/**
 * Payment receipts + payment traces (GET)
 * Issue helpers live in shared/ledger.js (issuePayReceipt, receiptSecret, parseTraceId)
 */
import { json, bad } from "./http.js";
import { hmacSha256Hex } from "./utils.js";
import {
  receiptSecret,
  parseTraceId,
} from "./ledger.js";

/* receipts issue helpers moved to shared/ledger.js */

export async function handleReceiptGet(request, env, id) {
  id = String(id || "").trim();
  if (!id || id.length > 64) return bad(request, "invalid receipt id", 400);
  let row;
  try {
    row = await env.DB.prepare(
      `SELECT id, tx_id, from_repo, to_repo, amount, task, status, payload_json, signature, created_at
       FROM payment_receipts WHERE id = ?1`
    )
      .bind(id)
      .first();
  } catch (e) {
    return bad(request, "payment_receipts table missing — run d1-receipts-migration.sql", 500);
  }
  if (!row) return bad(request, "Receipt not found", 404);
  return json(request, {
    ok: true,
    receipt: {
      id: row.id,
      tx_id: row.tx_id,
      from_repo: row.from_repo,
      to_repo: row.to_repo,
      amount: row.amount,
      task: row.task,
      status: row.status,
      created_at: row.created_at,
      signature: row.signature,
      payload: row.payload_json,
    },
    verify: "POST /api/receipt/verify with { id } or { payload, signature }",
  });
}

export async function handleReceiptVerify(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return bad(request, "Invalid JSON body");
  }

  let payloadStr = body.payload;
  let signature = body.signature;
  const id = body.id ? String(body.id).trim() : null;

  if (id && (!payloadStr || !signature)) {
    let row;
    try {
      row = await env.DB.prepare(
        `SELECT payload_json, signature FROM payment_receipts WHERE id = ?1`
      )
        .bind(id)
        .first();
    } catch {
      return bad(request, "payment_receipts table missing — run d1-receipts-migration.sql", 500);
    }
    if (!row) return bad(request, "Receipt not found", 404);
    payloadStr = row.payload_json;
    signature = row.signature;
  }

  if (!payloadStr || !signature) {
    return bad(request, "payload + signature required (or id)");
  }

  const expected = await hmacSha256Hex(receiptSecret(env), String(payloadStr));
  const ok = expected === String(signature).toLowerCase() || expected === String(signature);
  return json(request, {
    ok: true,
    valid: ok,
    id: id || null,
  });
}


export async function handleTraceGet(request, env, id) {
  id = parseTraceId(id);
  if (!id) return bad(request, "invalid trace id", 400);
  let txs = [];
  try {
    const { results } = await env.DB.prepare(
      `SELECT id, from_repo, to_repo, amount, task, status, latency_ms, created_at, trace_id
       FROM transactions WHERE trace_id = ?1 ORDER BY id ASC LIMIT 200`
    )
      .bind(id)
      .all();
    txs = results || [];
  } catch (e) {
    return bad(
      request,
      "trace column/table missing — run d1-trace-migration.sql: " + (e.message || e),
      500
    );
  }
  let meta = null;
  try {
    meta = await env.DB.prepare(`SELECT * FROM payment_traces WHERE id = ?1`).bind(id).first();
  } catch (_) {}
  const vol = txs
    .filter((t) => t.status === "success")
    .reduce((s, t) => s + Number(t.amount || 0), 0);
  return json(request, {
    ok: true,
    trace_id: id,
    meta: meta || null,
    count: txs.length,
    volume: Math.round(vol * 1e6) / 1e6,
    transactions: txs,
  });
}
