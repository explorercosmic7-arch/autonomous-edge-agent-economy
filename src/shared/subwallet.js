/**
 * Ephemeral sub-wallets (task wallets)
 * open / spend / close / list + expireSubWallets (cron)
 */
import { json, bad } from "./http.js";
import {
  parseRepo,
  parseAmount,
  randomId,
} from "./utils.js";
import { checkRateLimit } from "./rateLimit.js";
import {
  getAuthUser,
  rejectIfSuspendedKey,
} from "./auth.js";
import { ensureAccount } from "./accounts.js";
import { safetyGate, safetyRecordSpend } from "./gate.js";
import {
  SYSTEM_SUBWALLET,
  SUBWALLET_MIN_BUDGET,
  SUBWALLET_MAX_BUDGET,
  SUBWALLET_DEFAULT_TTL_SEC,
  SUBWALLET_MIN_TTL_SEC,
  SUBWALLET_MAX_TTL_SEC,
  RL_SUBWALLET_MAX,
  RL_SUBWALLET_WINDOW_SEC,
  EXPIRE_SUBWALLET_BATCH,
} from "./constants.js";

/* ─── Ephemeral sub-wallets (task wallets) ───
 * Parent debits budget → held in system/subwallet.
 * Child spends only via POST /api/subwallet/spend { id, to_repo, amount }.
 * Close / TTL expire → refund remaining to parent. Blast radius = budget only.
 */

export function parseSubWalletTtl(body) {
  const sec = Number(body.ttl_seconds ?? body.ttl);
  if (Number.isFinite(sec)) {
    if (sec < SUBWALLET_MIN_TTL_SEC || sec > SUBWALLET_MAX_TTL_SEC) return null;
    return Math.floor(sec);
  }
  return SUBWALLET_DEFAULT_TTL_SEC;
}

export async function loadSubWallet(env, id) {
  try {
    return await env.DB.prepare(`SELECT * FROM sub_wallets WHERE id = ?1`).bind(id).first();
  } catch (e) {
    return null;
  }
}

export async function handleSubWalletOpen(request, env) {
  const t0 = Date.now();
  const authUser = await getAuthUser(request, env);
  if (!authUser) return bad(request, "Sign in or API key required", 401);

  const rlId =
    authUser.auth_via === "api_key"
      ? "sw:key:" + (authUser.key_id || authUser.id)
      : "sw:user:" + authUser.id;
  const limited = await checkRateLimit(env, rlId, RL_SUBWALLET_MAX, RL_SUBWALLET_WINDOW_SEC);
  if (limited) {
    return bad(request, "Rate limit: too many sub-wallet ops", 429, {
      retry_after_sec: limited.retry_after_sec,
    });
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return bad(request, "Invalid JSON body");
  }

  let parentRepo = parseRepo(body.parent_repo || body.from_repo || body.fromRepo);
  if (!parentRepo && authUser.default_repo) {
    parentRepo = parseRepo(authUser.default_repo);
  }
  const budget = parseAmount(body.budget ?? body.amount);
  const label = String(body.label || body.name || "task").slice(0, 64);
  const task = String(body.task || "sub-task").slice(0, 500);
  const ttlSec = parseSubWalletTtl(body);
  const idem =
    String(request.headers.get("Idempotency-Key") || body.idempotency_key || "")
      .trim()
      .slice(0, 128) || null;

  if (!parentRepo) return bad(request, "parent_repo required (or set default agent)");
  if (budget == null || budget < SUBWALLET_MIN_BUDGET || budget > SUBWALLET_MAX_BUDGET) {
    return bad(
      request,
      "budget must be between " + SUBWALLET_MIN_BUDGET + " and " + SUBWALLET_MAX_BUDGET
    );
  }
  if (ttlSec == null) {
    return bad(
      request,
      "ttl_seconds out of range (min " +
        SUBWALLET_MIN_TTL_SEC +
        "s, max " +
        SUBWALLET_MAX_TTL_SEC +
        "s)"
    );
  }

  {
    authUser._policyCtx = { to_repo: null, task };
    const blocked = await safetyGate(request, env, authUser, parentRepo, budget);
    if (blocked) return blocked;
  }

  if (idem) {
    try {
      const existing = await env.DB.prepare(
        `SELECT * FROM sub_wallets WHERE idempotency_key = ?1`
      )
        .bind(idem)
        .first();
      if (existing) {
        return json(request, { ok: true, replayed: true, sub_wallet: existing });
      }
    } catch (e) {
      return bad(request, "sub_wallets table missing — run d1-subwallet-migration.sql", 500);
    }
  }

  await ensureAccount(env, parentRepo);

  const debit = await env.DB.prepare(
    `UPDATE accounts
     SET balance = balance - ?1, updated_at = datetime('now')
     WHERE repo_id = ?2 AND balance >= ?1
     RETURNING balance`
  )
    .bind(budget, parentRepo)
    .first();

  if (!debit) return bad(request, "Insufficient funds on parent", 402);

  const id = "sw_" + randomId(12);
  const modifier = "+" + ttlSec + " seconds";

  try {
    await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO sub_wallets (
           id, parent_repo, label, task, status, budget, spent, remaining,
           created_by, expires_at, idempotency_key, created_at, updated_at
         ) VALUES (
           ?1, ?2, ?3, ?4, 'open', ?5, 0, ?5, ?6,
           datetime('now', ?7), ?8, datetime('now'), datetime('now')
         )`
      ).bind(id, parentRepo, label, task, budget, authUser.id, modifier, idem),
      env.DB.prepare(
        `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms, idempotency_key)
         VALUES (?1, ?2, ?3, ?4, 'success', ?5, ?6)`
      ).bind(
        parentRepo,
        SYSTEM_SUBWALLET,
        budget,
        "subwallet-open:" + id,
        Date.now() - t0,
        idem
      ),
    ]);
  } catch (e) {
    await env.DB.prepare(
      `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
    )
      .bind(budget, parentRepo)
      .run();
    return bad(request, "Sub-wallet create failed: " + (e.message || e), 500);
  }

  await safetyRecordSpend(env, authUser, parentRepo, budget);

  const row = await loadSubWallet(env, id);
  return json(request, {
    ok: true,
    status: "open",
    sub_wallet: {
      id,
      parent_repo: parentRepo,
      label,
      task,
      budget,
      spent: 0,
      remaining: budget,
      status: "open",
      expires_at: row?.expires_at || null,
      ttl_seconds: ttlSec,
    },
    balance_parent: debit.balance,
    latency_ms: Date.now() - t0,
    hint: "Child spends only via POST /api/subwallet/spend { id, to_repo, amount }. Close or wait for TTL to refund remainder.",
  });
}

export async function handleSubWalletSpend(request, env) {
  const t0 = Date.now();
  const authUser = await getAuthUser(request, env);
  if (!authUser) return bad(request, "Sign in or API key required", 401);

  const sus = rejectIfSuspendedKey(request, authUser);
  if (sus) return sus;

  let body;
  try {
    body = await request.json();
  } catch {
    return bad(request, "Invalid JSON body");
  }

  const id = String(body.id || "").trim();
  const toRepo = parseRepo(body.to_repo || body.toRepo);
  const amount = parseAmount(body.amount);
  const task = String(body.task || "subwallet-spend").slice(0, 500);

  if (!id) return bad(request, "id required");
  if (!toRepo) return bad(request, "to_repo required");
  if (amount == null) return bad(request, "invalid amount");

  let row;
  try {
    row = await env.DB.prepare(`SELECT * FROM sub_wallets WHERE id = ?1`).bind(id).first();
  } catch {
    return bad(request, "sub_wallets table missing — run d1-subwallet-migration.sql", 500);
  }
  if (!row) return bad(request, "Sub-wallet not found", 404);
  if (row.status !== "open") {
    return bad(request, "Sub-wallet not open (status=" + row.status + ")", 400, {
      code: "subwallet_closed",
    });
  }

  // TTL check
  if (row.expires_at) {
    const expMs = Date.parse(String(row.expires_at).replace(" ", "T") + "Z");
    if (Number.isFinite(expMs) && expMs < Date.now()) {
      return bad(request, "Sub-wallet expired — close or wait for cron refund", 400, {
        code: "subwallet_expired",
      });
    }
  }

  // Authorization: creator or parent default agent
  const allowed =
    authUser.id === row.created_by ||
    (authUser.default_repo && authUser.default_repo === row.parent_repo);
  if (!allowed) return bad(request, "Not authorized to spend this sub-wallet", 403);

  const remaining = Number(row.remaining != null ? row.remaining : row.budget - row.spent);
  if (amount > remaining) {
    return bad(request, "Insufficient sub-wallet remaining ($" + remaining.toFixed(6) + ")", 402, {
      code: "subwallet_insufficient",
      remaining,
    });
  }

  await ensureAccount(env, toRepo);

  const claim = await env.DB.prepare(
    `UPDATE sub_wallets
     SET spent = spent + ?1,
         remaining = remaining - ?1,
         status = CASE WHEN remaining - ?1 <= 0.0000005 THEN 'exhausted' ELSE 'open' END,
         updated_at = datetime('now')
     WHERE id = ?2 AND status = 'open' AND remaining >= ?1
     RETURNING id, spent, remaining, status, parent_repo`
  )
    .bind(amount, id)
    .first();

  if (!claim) {
    return bad(request, "Spend failed (race or insufficient remaining)", 409);
  }

  await env.DB.batch([
    env.DB.prepare(
      `UPDATE accounts
       SET balance = balance + ?1, updated_at = datetime('now')
       WHERE repo_id = ?2`
    ).bind(amount, toRepo),
    env.DB.prepare(
      `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
       VALUES (?1, ?2, ?3, ?4, 'success', ?5)`
    ).bind(
      SYSTEM_SUBWALLET,
      toRepo,
      amount,
      "subwallet-spend:" + id + ":" + task.slice(0, 40),
      Date.now() - t0
    ),
  ]);

  return json(request, {
    ok: true,
    id,
    to_repo: toRepo,
    amount,
    spent: claim.spent,
    remaining: Math.max(0, Number(claim.remaining)),
    status: claim.status,
    parent_repo: claim.parent_repo,
    latency_ms: Date.now() - t0,
  });
}

export async function handleSubWalletClose(request, env) {
  const t0 = Date.now();
  const authUser = await getAuthUser(request, env);
  if (!authUser) return bad(request, "Sign in or API key required", 401);

  let body;
  try {
    body = await request.json();
  } catch {
    return bad(request, "Invalid JSON body");
  }

  const id = String(body.id || "").trim();
  if (!id) return bad(request, "id required");

  let row;
  try {
    row = await env.DB.prepare(`SELECT * FROM sub_wallets WHERE id = ?1`).bind(id).first();
  } catch {
    return bad(request, "sub_wallets table missing — run d1-subwallet-migration.sql", 500);
  }
  if (!row) return bad(request, "Sub-wallet not found", 404);
  if (row.status !== "open" && row.status !== "exhausted") {
    return bad(request, "Sub-wallet already closed (status=" + row.status + ")");
  }

  const allowed =
    authUser.id === row.created_by ||
    (authUser.default_repo && authUser.default_repo === row.parent_repo);
  if (!allowed) return bad(request, "Not authorized to close this sub-wallet", 403);

  const refund = await closeSubWalletInternal(env, row, "closed", t0);
  return json(request, {
    ok: true,
    status: "closed",
    id,
    spent: Number(row.spent),
    refunded: refund,
    parent_repo: row.parent_repo,
    latency_ms: Date.now() - t0,
  });
}

export async function closeSubWalletInternal(env, row, reason, t0) {
  const id = row.id;
  const claim = await env.DB.prepare(
    `UPDATE sub_wallets
     SET status = ?2,
         closed_at = datetime('now'),
         close_reason = ?3,
         remaining = 0,
         updated_at = datetime('now')
     WHERE id = ?1 AND status IN ('open', 'exhausted')
     RETURNING id, remaining, parent_repo, spent, budget`
  )
    .bind(id, reason === "expired" ? "expired" : "closed", reason || "closed")
    .first();

  if (!claim) return 0;

  // Use pre-update remaining from row (claim.remaining already 0)
  const refund = Math.max(
    0,
    Math.round(Number(row.remaining != null ? row.remaining : row.budget - row.spent) * 1e6) / 1e6
  );

  if (refund > 0) {
    await ensureAccount(env, row.parent_repo);
    await env.DB.batch([
      env.DB.prepare(
        `UPDATE accounts
         SET balance = balance + ?1, updated_at = datetime('now')
         WHERE repo_id = ?2`
      ).bind(refund, row.parent_repo),
      env.DB.prepare(
        `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
         VALUES (?1, ?2, ?3, ?4, 'success', ?5)`
      ).bind(
        SYSTEM_SUBWALLET,
        row.parent_repo,
        refund,
        "subwallet-" + (reason || "close") + "-refund:" + id,
        typeof t0 === "number" ? Date.now() - t0 : 0
      ),
    ]);
  }
  return refund;
}

export async function handleSubWalletList(request, url, env) {
  const limit = Math.min(Math.max(Number(url.searchParams.get("limit") || 25), 1), 100);
  const repo = (url.searchParams.get("repo") || "").trim();
  const status = (url.searchParams.get("status") || "").trim();

  let sql = `SELECT id, parent_repo, label, task, status, budget, spent, remaining,
                    created_by, expires_at, closed_at, close_reason, created_at
             FROM sub_wallets WHERE 1=1`;
  const binds = [];

  if (repo) {
    if (!parseRepo(repo)) return bad(request, "repo must be owner/repo");
    sql += ` AND parent_repo = ?`;
    binds.push(repo);
  }
  if (status && ["open", "closed", "expired", "exhausted"].includes(status)) {
    sql += ` AND status = ?`;
    binds.push(status);
  }
  sql += ` ORDER BY created_at DESC LIMIT ?`;
  binds.push(limit);

  try {
    const { results } = await env.DB.prepare(sql).bind(...binds).all();
    return json(request, { ok: true, count: results.length, sub_wallets: results });
  } catch (e) {
    return bad(request, "sub_wallets table missing — run d1-subwallet-migration.sql", 500);
  }
}

export async function expireSubWallets(env) {
  const t0 = Date.now();
  let results;
  try {
    const q = await env.DB.prepare(
      `SELECT * FROM sub_wallets
       WHERE status = 'open'
         AND expires_at IS NOT NULL
         AND expires_at < datetime('now')
       ORDER BY expires_at ASC
       LIMIT ?1`
    )
      .bind(EXPIRE_SUBWALLET_BATCH)
      .all();
    results = q.results || [];
  } catch (e) {
    return { expired: 0, scanned: 0, error: e.message, latency_ms: Date.now() - t0 };
  }

  let expired = 0;
  let refundedTotal = 0;
  for (const row of results) {
    try {
      const refund = await closeSubWalletInternal(env, row, "expired", t0);
      expired += 1;
      refundedTotal += refund;
    } catch (e) {
      console.log("subwallet_expire_error", row.id, e && e.message);
    }
  }
  return {
    expired,
    scanned: results.length,
    refunded_total: refundedTotal,
    latency_ms: Date.now() - t0,
  };
}
