
/**
 * Autonomous Edge-Agent Economy
 * Pure Cloudflare Worker + D1 atomic ledger
 * POST /api/pay  — AI-to-AI micro-transfer
 */

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Access-Control-Max-Age": "86400",
};

const REPO_RE = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", ...CORS },
  });
}

function bad(message, status = 400) {
  return json({ ok: false, error: message }, status);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: CORS });
    }

    try {
      if (request.method === "POST" && url.pathname === "/api/pay") {
        return await handlePay(request, env);
      }
      if (request.method === "GET" && url.pathname === "/api/balance") {
        return await handleBalance(url, env);
      }
      if (request.method === "GET" && url.pathname === "/api/ledger") {
        return await handleLedger(url, env);
      }
      if (request.method === "GET" && url.pathname === "/health") {
        return json({ ok: true, service: "a2a-ledger", ts: Date.now() });
      }
      return bad("Not found", 404);
    } catch (err) {
      return bad(err.message || "Internal error", 500);
    }
  },
};

async function handlePay(request, env) {
  const t0 = Date.now();
  let body;
  try {
    body = await request.json();
  } catch {
    return bad("Invalid JSON body");
  }

  const fromRepo = String(body.from_repo || body.fromRepo || "").trim();
  const toRepo = String(body.to_repo || body.toRepo || "").trim();
  const task = String(body.task || "").slice(0, 500);
  const amount = Number(body.amount);

  if (!REPO_RE.test(fromRepo)) return bad("from_repo must be owner/repo");
  if (!REPO_RE.test(toRepo)) return bad("to_repo must be owner/repo");
  if (fromRepo === toRepo) return bad("from_repo and to_repo must differ");
  if (!Number.isFinite(amount) || amount <= 0) return bad("amount must be a positive number");
  if (amount > 1_000_000) return bad("amount exceeds max");

  // Auto-create both ledgers (zero-friction onboarding). Sender still needs funds.
  await env.DB.batch([
    env.DB.prepare(
      `INSERT INTO accounts (repo_id, balance) VALUES (?, 0) ON CONFLICT(repo_id) DO NOTHING`
    ).bind(fromRepo),
    env.DB.prepare(
      `INSERT INTO accounts (repo_id, balance) VALUES (?, 0) ON CONFLICT(repo_id) DO NOTHING`
    ).bind(toRepo),
  ]);

  // Atomic debit: SQLite serializes writers. Second parallel $1 spend on a $1
  // balance matches 0 rows — no dirty read, no extra locks.
  const debit = await env.DB.prepare(
    `UPDATE accounts
     SET balance = balance - ?1, updated_at = datetime('now')
     WHERE repo_id = ?2 AND balance >= ?1
     RETURNING balance`
  )
    .bind(amount, fromRepo)
    .first();

  if (!debit) {
    const latency = Date.now() - t0;
    await env.DB.prepare(
      `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
       VALUES (?1, ?2, ?3, ?4, 'failed', ?5)`
    )
      .bind(fromRepo, toRepo, amount, task, latency)
      .run();
    return bad("Insufficient funds", 402);
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
    ).bind(fromRepo, toRepo, amount, task, Date.now() - t0),
  ]);

  const latency_ms = Date.now() - t0;

  const [fromAcc, toAcc] = await env.DB.batch([
    env.DB.prepare(`SELECT repo_id, balance FROM accounts WHERE repo_id = ?`).bind(fromRepo),
    env.DB.prepare(`SELECT repo_id, balance FROM accounts WHERE repo_id = ?`).bind(toRepo),
  ]);

  return json({
    ok: true,
    status: "success",
    from_repo: fromRepo,
    to_repo: toRepo,
    amount,
    task,
    latency_ms,
    balances: {
      from: fromAcc.results?.[0]?.balance ?? debit.balance,
      to: toAcc.results?.[0]?.balance ?? null,
    },
  });
}

async function handleBalance(url, env) {
  const repo = (url.searchParams.get("repo") || "").trim();
  if (!REPO_RE.test(repo)) return bad("repo query must be owner/repo");

  const row = await env.DB.prepare(
    `SELECT repo_id, balance, created_at, updated_at FROM accounts WHERE repo_id = ?`
  )
    .bind(repo)
    .first();

  if (!row) return json({ ok: true, repo_id: repo, balance: 0, exists: false });
  return json({ ok: true, ...row, exists: true });
}

async function handleLedger(url, env) {
  const limit = Math.min(Number(url.searchParams.get("limit") || 25), 100);
  const repo = (url.searchParams.get("repo") || "").trim();

  let stmt;
  if (repo) {
    if (!REPO_RE.test(repo)) return bad("repo query must be owner/repo");
    stmt = env.DB.prepare(
      `SELECT id, from_repo, to_repo, amount, task, status, latency_ms, created_at
       FROM transactions
       WHERE from_repo = ?1 OR to_repo = ?1
       ORDER BY id DESC LIMIT ?2`
    ).bind(repo, limit);
  } else {
    stmt = env.DB.prepare(
      `SELECT id, from_repo, to_repo, amount, task, status, latency_ms, created_at
       FROM transactions
       ORDER BY id DESC LIMIT ?1`
    ).bind(limit);
  }

  const { results } = await stmt.all();
  return json({ ok: true, count: results.length, transactions: results });
}
