/**
 * Core ledger — pay, fund, balance, ledger + helpers
 * Path on GitHub: src/shared/ledger.js
 *
 * (receipt issue + trace helpers included for pay path)
 *
 * REQUIRES: src/shared/credit.js exports debitWithCredit
 */
import { json, bad } from "./http.js";
import {
  parseRepo,
  parseAmount,
  sleep,
  randomId,
  hmacSha256Hex,
} from "./utils.js";
import { checkRateLimit } from "./rateLimit.js";
import {
  getAuthUser,
  rejectIfSuspendedKey,
} from "./auth.js";
import { ensureAccount } from "./accounts.js";
import {
  checkWalletLocked,
  ensureAgentLimits,
  recordVelocityEvent,
  addDailySpent,
  checkVelocity,
} from "./safety.js";
import {
  debitWithCredit,
  adjustRep,
} from "./credit.js";
import {
  safetyGate,
  safetyRecordSpend,
} from "./gate.js";
import { scheduleWebhook } from "./webhooks.js";
import {
  claimDelegationSpend,
  logDelegateEvent,
} from "./delegate.js";
import {
  RL_PAY_MAX,
  RL_PAY_WINDOW_SEC,
  FAUCET_MAX_PER_CALL,
  FAUCET_ACCOUNT_CAP,
  SYSTEM_FAUCET,
  SYSTEM_DELEGATE,
  CREDIT_REP_SUCCESS_BONUS,
  CREDIT_REP_PER_USD,
} from "./constants.js";

/* ─── Ledger helpers ─── */

export async function readBalances(env, fromRepo, toRepo) {
  const [fromAcc, toAcc] = await env.DB.batch([
    env.DB.prepare(`SELECT balance FROM accounts WHERE repo_id = ?`).bind(fromRepo),
    env.DB.prepare(`SELECT balance FROM accounts WHERE repo_id = ?`).bind(toRepo),
  ]);
  return {
    from: fromAcc.results?.[0]?.balance ?? 0,
    to: toAcc.results?.[0]?.balance ?? 0,
  };
}

export async function waitForIdem(env, key) {
  for (let i = 0; i < 12; i++) {
    const row = await env.DB.prepare(
      `SELECT status, result_json FROM idempotency WHERE key = ?`
    )
      .bind(key)
      .first();
    if (row?.status === "success" && row.result_json) {
      const data = JSON.parse(row.result_json);
      data.replayed = true;
      return data;
    }
    if (row?.status === "failed") {
      return { ok: false, error: row.result_json || "Insufficient funds", replayed: true };
    }
    if (!row) return null;
    await sleep(25);
  }
  return { ok: false, error: "Payment still in flight", pending: true };
}

/* ─── Pay ─── */

export async function handlePay(request, env, ctx) {
  const t0 = Date.now();
  const waitUntil = (p) => {
    try {
      if (ctx && typeof ctx.waitUntil === "function") {
        ctx.waitUntil(Promise.resolve(p).catch((e) => console.log("pay_bg", e && e.message)));
        return;
      }
    } catch (_) {}
    Promise.resolve(p).catch(() => {});
  };

  let body;
  try {
    body = await request.json();
  } catch {
    return bad(request, "Invalid JSON body");
  }

  const authUser = await getAuthUser(request, env);
  const rlId = authUser
    ? authUser.auth_via === "api_key"
      ? "pay:key:" + (authUser.key_id || authUser.id)
      : "pay:user:" + authUser.id
    : "pay:anon:" + (request.headers.get("CF-Connecting-IP") || "x").slice(0, 64);
  const limited = await checkRateLimit(env, rlId, RL_PAY_MAX, RL_PAY_WINDOW_SEC);
  if (limited) {
    return bad(request, "Rate limit: too many payments", 429, {
      retry_after_sec: limited.retry_after_sec,
    });
  }

  let fromRepo = parseRepo(body.from_repo || body.fromRepo);
  if (!fromRepo && authUser?.default_repo) {
    fromRepo = parseRepo(authUser.default_repo);
  }
  const toRepo = parseRepo(body.to_repo || body.toRepo);
  const amount = parseAmount(body.amount);
  const task = String(body.task || "").slice(0, 500);
  const idem =
    String(request.headers.get("Idempotency-Key") || body.idempotency_key || "")
      .trim()
      .slice(0, 128) || null;
  const traceId = parseTraceId(
    body.trace_id || body.traceId || request.headers.get("X-Trace-Id")
  );

  // Delegation chain: child key + X-Delegate-Id spends parent-locked budget
  const delegateIdHdr = String(
    request.headers.get("X-Delegate-Id") || body.delegate_id || body.delegation_id || ""
  ).trim();
  let activeDelegation = null;

  if (delegateIdHdr) {
    if (!authUser || authUser.auth_via !== "api_key" || !authUser.key_id) {
      return bad(request, "X-Delegate-Id requires Authorization: Bearer <child_api_key>", 401, {
        code: "delegate_auth",
      });
    }
    const sus = rejectIfSuspendedKey(request, authUser);
    if (sus) return sus;
    const toRepoEarly = parseRepo(body.to_repo || body.toRepo);
    const amountEarly = parseAmount(body.amount);
    const taskEarly = String(body.task || "").slice(0, 500);
    if (!toRepoEarly) return bad(request, "to_repo must be owner/repo");
    if (amountEarly == null) return bad(request, "amount must be between 0.000001 and 1000000");
    const claim = await claimDelegationSpend(env, {
      id: delegateIdHdr,
      childKeyId: authUser.key_id,
      toRepo: toRepoEarly,
      amount: amountEarly,
      task: taskEarly,
    });
    if (!claim.ok) {
      const st =
        claim.code === "not_found"
          ? 404
          : claim.code === "table_missing"
            ? 500
            : claim.code === "delegate_key_mismatch" ||
                claim.code === "delegate_allow_to" ||
                claim.code === "delegate_task_prefix"
              ? 403
              : claim.code === "delegate_insufficient"
                ? 402
                : 400;
      return bad(request, claim.error, st, {
        code: claim.code,
        remaining_usd: claim.remaining_usd,
        allow_to: claim.allow_to,
      });
    }
    activeDelegation = claim.delegation;
    fromRepo = parseRepo(activeDelegation.parent_repo);
  }

  if (!fromRepo) {
    return bad(
      request,
      "from_repo must be owner/repo (or authenticate and set default agent)"
    );
  }
  if (!toRepo) return bad(request, "to_repo must be owner/repo");
  if (fromRepo === toRepo) return bad(request, "from_repo and to_repo must differ");
  if (amount == null) return bad(request, "amount must be between 0.000001 and 1000000");

  if (authUser) {
    authUser._policyCtx = { to_repo: toRepo, task };
    const blocked = await safetyGate(request, env, authUser, fromRepo, amount);
    if (blocked) return blocked;
  } else {
    const locked = await checkWalletLocked(env, fromRepo);
    if (locked) return bad(request, locked.reason, 403, { code: "wallet_locked" });
    const vel = await checkVelocity(env, fromRepo, amount, null);
    if (vel) {
      return bad(request, vel.error, 429, {
        code: vel.code,
        retry_after_sec: vel.retry_after_sec,
      });
    }
  }

  let wonLock = false;
  if (idem) {
    const ins = await env.DB.prepare(
      `INSERT INTO idempotency (key, status) VALUES (?1, 'pending')
       ON CONFLICT(key) DO NOTHING`
    )
      .bind(idem)
      .run();
    wonLock = (ins.meta?.changes || 0) === 1;
    if (!wonLock) {
      const replay = await waitForIdem(env, idem);
      if (replay && replay.ok) return json(request, replay);
      if (replay && replay.pending) return json(request, replay, 202);
      if (replay && !replay.ok) return bad(request, replay.error, 402);
    }
  }

  const settleFrom = activeDelegation ? SYSTEM_DELEGATE : fromRepo;
  const payTaskLabel = activeDelegation
    ? "delegate-spend:" + activeDelegation.id + ":" + task.slice(0, 40)
    : task;

  await env.DB.batch([
    env.DB.prepare(
      `INSERT INTO accounts (repo_id, balance) VALUES (?, 0) ON CONFLICT(repo_id) DO NOTHING`
    ).bind(fromRepo),
    env.DB.prepare(
      `INSERT INTO accounts (repo_id, balance) VALUES (?, 0) ON CONFLICT(repo_id) DO NOTHING`
    ).bind(toRepo),
  ]);

  let fromBalance = null;
  let creditDrawn = 0;
  let usedCredit = false;

  if (activeDelegation) {
    // Funds already locked in system/delegate — claim reduced remaining
    fromBalance = null;
    creditDrawn = 0;
    usedCredit = false;
  } else {
    // Fast cash path
    const cashDebit = await env.DB.prepare(
      `UPDATE accounts
       SET balance = balance - ?1, updated_at = datetime('now')
       WHERE repo_id = ?2 AND balance >= ?1
       RETURNING balance`
    )
      .bind(amount, fromRepo)
      .first();

    if (cashDebit) {
      fromBalance = Number(cashDebit.balance);
    } else {
      // Cash short → debitWithCredit (cash + optional credit line)
      const debitRes = await debitWithCredit(env, fromRepo, amount);
      if (!debitRes.ok) {
        if (idem && wonLock) {
          await env.DB.prepare(
            `DELETE FROM idempotency WHERE key = ? AND status = 'pending'`
          )
            .bind(idem)
            .run()
            .catch(() => {});
        }
        waitUntil(
          env.DB.prepare(
            `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
             VALUES (?1, ?2, ?3, ?4, 'failed', ?5)`
          )
            .bind(settleFrom, toRepo, amount, payTaskLabel, Date.now() - t0)
            .run()
        );
        return bad(
          request,
          debitRes.error || "Insufficient funds",
          debitRes.code === "wallet_locked" ? 403 : 402,
          {
            code: debitRes.code || "insufficient",
            available_credit: debitRes.available_credit,
          }
        );
      }
      fromBalance = Number(debitRes.balance);
      creditDrawn = debitRes.credit_drawn || 0;
      usedCredit = creditDrawn > 0;
    }
  }

  if (traceId) {
    try {
      await ensureTrace(env, traceId, {
        label: task || "pay",
        created_by: authUser && authUser.id,
      });
    } catch (_) {}
  }

  const latency = Date.now() - t0;
  let toBalance = null;
  let txId = null;

  async function compensateDebit() {
    if (activeDelegation) return;
    try {
      await env.DB.prepare(
        `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
      )
        .bind(amount, fromRepo)
        .run();
      if (usedCredit && creditDrawn > 0) {
        await env.DB.prepare(
          `UPDATE agent_limits
           SET outstanding_credit = MAX(0, COALESCE(outstanding_credit, 0) - ?2),
               updated_at = datetime('now')
           WHERE repo_id = ?1`
        )
          .bind(fromRepo, creditDrawn)
          .run();
      }
    } catch (e) {
      console.log("pay_compensate_err", e && e.message);
    }
  }

  try {
    const batchRes = await env.DB.batch([
      env.DB.prepare(
        `UPDATE accounts
         SET balance = balance + ?1, updated_at = datetime('now')
         WHERE repo_id = ?2
         RETURNING balance`
      ).bind(amount, toRepo),
      env.DB.prepare(
        `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms, idempotency_key, trace_id)
         VALUES (?1, ?2, ?3, ?4, 'success', ?5, ?6, ?7)
         RETURNING id`
      ).bind(settleFrom, toRepo, amount, payTaskLabel, latency, idem, traceId),
    ]);
    const r0 = batchRes && batchRes[0];
    const r1 = batchRes && batchRes[1];
    const creditRow =
      (r0 && r0.results && r0.results[0]) ||
      (r0 && r0.result && r0.result[0]) ||
      null;
    const txRow =
      (r1 && r1.results && r1.results[0]) ||
      (r1 && r1.result && r1.result[0]) ||
      null;
    if (creditRow && creditRow.balance != null) toBalance = Number(creditRow.balance);
    if (txRow && txRow.id != null) txId = txRow.id;
  } catch (e) {
    try {
      await env.DB.batch([
        env.DB.prepare(
          `UPDATE accounts
           SET balance = balance + ?1, updated_at = datetime('now')
           WHERE repo_id = ?2`
        ).bind(amount, toRepo),
        env.DB.prepare(
          `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms, idempotency_key)
           VALUES (?1, ?2, ?3, ?4, 'success', ?5, ?6)`
        ).bind(settleFrom, toRepo, amount, payTaskLabel, latency, idem),
      ]);
    } catch (e2) {
      console.log("pay_settle_error", e2 && e2.message);
      await compensateDebit();
      if (idem && wonLock) {
        await env.DB.prepare(
          `DELETE FROM idempotency WHERE key = ? AND status = 'pending'`
        )
          .bind(idem)
          .run()
          .catch(() => {});
      }
      return bad(request, "Settlement failed — debit rolled back", 500);
    }
  }

  if (toBalance == null) {
    const row = await env.DB.prepare(
      `SELECT balance FROM accounts WHERE repo_id = ?1`
    )
      .bind(toRepo)
      .first()
      .catch(() => null);
    if (row) toBalance = Number(row.balance);
  }

  let receiptId = null;
  let receiptSig = null;
  try {
    const rcpt = await issuePayReceipt(env, {
      from_repo: fromRepo,
      to_repo: toRepo,
      amount,
      task: payTaskLabel,
      status: "success",
      tx_id: txId,
    });
    if (rcpt) {
      receiptId = rcpt.id;
      receiptSig = rcpt.signature;
    }
  } catch (e) {
    console.log("pay_receipt_err", e && e.message);
  }

  if (activeDelegation) {
    try {
      await logDelegateEvent(env, activeDelegation.id, "spent", {
        actor_repo: activeDelegation.parent_repo,
        amount,
        to_repo: toRepo,
        note: task,
      });
      await adjustRep(
        env,
        activeDelegation.parent_repo,
        CREDIT_REP_SUCCESS_BONUS,
        "delegate_spend",
        activeDelegation.id
      );
      if (activeDelegation.created_by) {
        scheduleWebhook(ctx, env, activeDelegation.created_by, "delegate.spent", {
          id: activeDelegation.id,
          parent_repo: activeDelegation.parent_repo,
          to_repo: toRepo,
          amount,
          remaining_usd: Number(activeDelegation.remaining_usd),
          status: activeDelegation.status,
          task,
        });
      }
    } catch (e) {
      console.log("delegate_post_spend", e && e.message);
    }
  } else if (authUser) {
    try {
      await safetyRecordSpend(env, authUser, fromRepo, amount);
    } catch (_) {}
  }

  const payload = {
    ok: true,
    status: "success",
    replayed: false,
    from_repo: fromRepo,
    to_repo: toRepo,
    amount,
    task: payTaskLabel,
    trace_id: traceId || undefined,
    credit_drawn: creditDrawn || undefined,
    latency_ms: Date.now() - t0,
    balances: {
      [fromRepo]: fromBalance,
      [toRepo]: toBalance,
    },
  };
  if (receiptId) {
    payload.receipt_id = receiptId;
    payload.receipt_signature = receiptSig;
  }

  const keyId =
    authUser && authUser.auth_via === "api_key" ? authUser.key_id : null;
  const today = new Date().toISOString().slice(0, 10);
  const payloadJson = JSON.stringify(payload);

  waitUntil(
    (async () => {
      try {
        await env.DB.batch([
          env.DB.prepare(
            `INSERT INTO velocity_events (id, repo_id, api_key_id, amount, created_at)
             VALUES (?1, ?2, ?3, ?4, datetime('now'))`
          ).bind(randomId(12), fromRepo, keyId || null, Number(amount) || 0),
          env.DB.prepare(
            `UPDATE agent_limits
             SET daily_spent = CASE
                   WHEN substr(COALESCE(daily_window_start, ''), 1, 10) = ?3
                   THEN COALESCE(daily_spent, 0) + ?2
                   ELSE ?2
                 END,
                 daily_window_start = ?3,
                 updated_at = datetime('now')
             WHERE repo_id = ?1`
          ).bind(fromRepo, Number(amount) || 0, today),
        ]);
      } catch (_) {
        try {
          await ensureAgentLimits(env, fromRepo);
          await addDailySpent(env, fromRepo, amount);
          await recordVelocityEvent(env, fromRepo, amount, keyId);
        } catch (e2) {
          console.log("pay_telemetry", e2 && e2.message);
        }
      }
      try {
        await adjustRep(
          env,
          fromRepo,
          CREDIT_REP_SUCCESS_BONUS + Math.min(50, amount * CREDIT_REP_PER_USD),
          "pay_success"
        );
      } catch (_) {}
      if (idem && wonLock) {
        try {
          await env.DB.prepare(
            `UPDATE idempotency
             SET status = 'success', result_json = ?1, updated_at = datetime('now')
             WHERE key = ?2`
          )
            .bind(payloadJson, idem)
            .run();
        } catch (_) {}
      }
    })()
  );

  return json(request, payload);
}

export async function handleFund(request, env) {
  const t0 = Date.now();
  let body;
  try {
    body = await request.json();
  } catch {
    return bad(request, "Invalid JSON body");
  }
  const repo = parseRepo(body.repo || body.to_repo || body.toRepo);
  const amount = parseAmount(body.amount);
  const task = String(body.task || "faucet").slice(0, 500);
  if (!repo) return bad(request, "repo must be owner/repo");
  if (amount == null) return bad(request, "amount must be a positive number");
  if (amount > FAUCET_MAX_PER_CALL) {
    return bad(request, "Faucet max is $" + FAUCET_MAX_PER_CALL + " per request");
  }
  await ensureAccount(env, repo);
  const row = await env.DB.prepare(
    `UPDATE accounts
     SET balance = balance + ?1, updated_at = datetime('now')
     WHERE repo_id = ?2 AND (balance + ?1) <= ?3
     RETURNING balance`
  )
    .bind(amount, repo, FAUCET_ACCOUNT_CAP)
    .first();
  if (!row) {
    return bad(request, "Faucet cap reached ($" + FAUCET_ACCOUNT_CAP + " per agent)", 429);
  }
  await env.DB.prepare(
    `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
     VALUES (?1, ?2, ?3, ?4, 'success', ?5)`
  )
    .bind(SYSTEM_FAUCET, repo, amount, task, Date.now() - t0)
    .run();
  return json(request, {
    ok: true,
    status: "funded",
    repo,
    amount,
    balance: row.balance,
    cap: FAUCET_ACCOUNT_CAP,
    latency_ms: Date.now() - t0,
  });
}

export async function handleBalance(request, url, env) {
  const repo = parseRepo(url.searchParams.get("repo"));
  if (!repo) return bad(request, "repo query must be owner/repo");
  const row = await env.DB.prepare(
    `SELECT repo_id, balance, created_at, updated_at FROM accounts WHERE repo_id = ?`
  )
    .bind(repo)
    .first();
  if (!row) return json(request, { ok: true, repo_id: repo, balance: 0, exists: false });
  return json(request, { ok: true, ...row, exists: true });
}

export async function handleLedger(request, url, env) {
  const limit = Math.min(Math.max(Number(url.searchParams.get("limit") || 25), 1), 100);
  const repo = (url.searchParams.get("repo") || "").trim();
  let stmt;
  if (repo) {
    if (!parseRepo(repo)) return bad(request, "repo query must be owner/repo");
    stmt = env.DB.prepare(
      `SELECT id, from_repo, to_repo, amount, task, status, latency_ms, created_at, trace_id
       FROM transactions
       WHERE from_repo = ?1 OR to_repo = ?1
       ORDER BY id DESC LIMIT ?2`
    ).bind(repo, limit);
  } else {
    stmt = env.DB.prepare(
      `SELECT id, from_repo, to_repo, amount, task, status, latency_ms, created_at, trace_id
       FROM transactions ORDER BY id DESC LIMIT ?1`
    ).bind(limit);
  }
  const { results } = await stmt.all();
  return json(request, { ok: true, count: results.length, transactions: results });
}

/* ─── Signed payment receipts ─── */

export function receiptSecret(env) {
  return (
    env.RECEIPT_SECRET ||
    env.SESSION_SECRET ||
    env.GOOGLE_CLIENT_SECRET ||
    "a2a-dev-receipt-secret"
  );
}

export function canonicalReceiptPayload(p) {
  return JSON.stringify({
    v: 1,
    id: p.id,
    from_repo: p.from_repo,
    to_repo: p.to_repo,
    amount: p.amount,
    task: p.task || "",
    status: p.status || "success",
    created_at: p.created_at,
  });
}

export async function issuePayReceipt(
  env,
  { from_repo, to_repo, amount, task, status, tx_id }
) {
  try {
    const id = "rcpt_" + randomId(12);
    const created_at = new Date().toISOString();
    const body = {
      id,
      from_repo,
      to_repo,
      amount: Number(amount),
      task: task || "",
      status: status || "success",
      created_at,
    };
    const canon = canonicalReceiptPayload(body);
    const signature = await hmacSha256Hex(receiptSecret(env), canon);
    await env.DB.prepare(
      `INSERT INTO payment_receipts (
         id, tx_id, from_repo, to_repo, amount, task, status, payload_json, signature, created_at
       ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, datetime('now'))`
    )
      .bind(
        id,
        tx_id || null,
        from_repo,
        to_repo,
        Number(amount),
        task || "",
        status || "success",
        canon,
        signature
      )
      .run();
    return { id, signature, created_at, v: 1 };
  } catch (e) {
    console.log("receipt_issue_error", e && e.message);
    return null;
  }
}

export function parseTraceId(v) {
  const s = String(v || "").trim().slice(0, 128);
  if (!s) return null;
  if (!/^[A-Za-z0-9_.:\-]+$/.test(s)) return null;
  return s;
}

export async function ensureTrace(env, traceId, { label, created_by } = {}) {
  if (!traceId) return;
  try {
    await env.DB.prepare(
      `INSERT INTO payment_traces (id, label, created_by, created_at)
       VALUES (?1, ?2, ?3, datetime('now'))
       ON CONFLICT(id) DO NOTHING`
    )
      .bind(traceId, label || null, created_by || null)
      .run();
  } catch (e) {
    console.log("ensure_trace", e && e.message);
  }
}
