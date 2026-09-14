/**
 * Autonomous Edge-Agent Economy — Cloudflare Worker + D1
 * GET  /              service index
 * GET  /health
 * GET  /api/balance?repo=owner/repo
 * GET  /api/ledger?repo=&limit=
 * POST /api/pay       atomic micro-transfer
 * POST /api/fund      demo faucet (capped)
 */

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, Idempotency-Key",
  "Access-Control-Max-Age": "86400",
};

const REPO_RE = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const FAUCET_MAX_PER_CALL = 10;
const FAUCET_ACCOUNT_CAP = 100;
const SYSTEM_FAUCET = "system/faucet";

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", ...CORS },
  });
}

function bad(message, status = 400) {
  return json({ ok: false, error: message }, status);
}

function parseRepo(v) {
  const s = String(v || "").trim();
  return REPO_RE.test(s) ? s : null;
}

function parseAmount(v) {
  const n = Number(v);
  if (!Number.isFinite(n) || n <= 0) return null;
  if (n > 1_000_000) return null;
  return n;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: CORS });
    }

    try {
      if (request.method === "GET" && url.pathname === "/") {
        return json({
          ok: true,
          service: "a2a-ledger",
          endpoints: {
            health: "GET /health",
            pay: "POST /api/pay",
            fund: "POST /api/fund",
            balance: "GET /api/balance?repo=owner/repo",
            ledger: "GET /api/ledger",
          },
        });
      }
      if (request.method === "GET" && url.pathname === "/health") {
        return json({ ok: true, service: "a2a-ledger", ts: Date.now() });
      }
      if (request.method === "POST" && url.pathname === "/api/pay") {
        return await handlePay(request, env);
      }
      if (request.method === "POST" && url.pathname === "/api/fund") {
        return await handleFund(request, env);
      }
      if (request.method === "GET" && url.pathname === "/api/balance") {
        return await handleBalance(url, env);
      }
      if (request.method === "GET" && url.pathname === "/api/ledger") {
        return await handleLedger(url, env);
      }
      return bad("Not found", 404);
    } catch (err) {
      return bad(err.message || "Internal error", 500);
    }
  },
};

async function ensureAccount(env, repo) {
  await env.DB.prepare(
    `INSERT INTO accounts (repo_id, balance) VALUES (?, 0) ON CONFLICT(repo_id) DO NOTHING`
  )
    .bind(repo)
    .run();
}

async function handlePay(request, env) {
  const t0 = Date.now();
  let body;
  try {
    body = await request.json();
  } catch {
    return bad("Invalid JSON body");
  }

  const fromRepo = parseRepo(body.from_repo || body.fromRepo);
  const toRepo = parseRepo(body.to_repo || body.toRepo);
  const amount = parseAmount(body.amount);
  const task = String(body.task || "").slice(0, 500);

  if (!fromRepo) return bad("from_repo must be owner/repo");
  if (!toRepo) return bad("to_repo must be owner/repo");
  if (fromRepo === toRepo) return bad("from_repo and to_repo must differ");
  if (amount == null) return bad("amount must be a positive number");

  await env.DB.batch([
    env.DB.prepare(
      `INSERT INTO accounts (repo_id, balance) VALUES (?, 0) ON CONFLICT(repo_id) DO NOTHING`
    ).bind(fromRepo),
    env.DB.prepare(
      `INSERT INTO accounts (repo_id, balance) VALUES (?, 0) ON CONFLICT(repo_id) DO NOTHING`
    ).bind(toRepo),
  ]);

  // Serialized by SQLite: parallel spends on the same row cannot both match.
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
    env.DB.prepare(`SELECT balance FROM accounts WHERE repo_id = ?`).bind(fromRepo),
    env.DB.prepare(`SELECT balance FROM accounts WHERE repo_id = ?`).bind(toRepo),
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
      from: fromAcc.results?.[0]?.balance,
      to: toAcc.results?.[0]?.balance,
    },
  });
}

async function handleFund(request, env) {
  const t0 = Date.now();
  let body;
  try {
    body = await request.json();
  } catch {
    return bad("Invalid JSON body");
  }

  const repo = parseRepo(body.repo || body.to_repo || body.toRepo);
  const amount = parseAmount(body.amount);
  const task = String(body.task || "faucet").slice(0, 500);

  if (!repo) return bad("repo must be owner/repo");
  if (amount == null) return bad("amount must be a positive number");
  if (amount > FAUCET_MAX_PER_CALL) {
    return bad("Faucet max is $" + FAUCET_MAX_PER_CALL + " per request");
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
    return bad("Faucet cap reached ($" + FAUCET_ACCOUNT_CAP + " per agent)", 429);
  }

  const latency_ms = Date.now() - t0;
  await env.DB.prepare(
    `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
     VALUES (?1, ?2, ?3, ?4, 'success', ?5)`
  )
    .bind(SYSTEM_FAUCET, repo, amount, task, latency_ms)
    .run();

  return json({
    ok: true,
    status: "funded",
    repo,
    amount,
    balance: row.balance,
    cap: FAUCET_ACCOUNT_CAP,
    latency_ms,
  });
}

async function handleBalance(url, env) {
  const repo = parseRepo(url.searchParams.get("repo"));
  if (!repo) return bad("repo query must be owner/repo");

  const row = await env.DB.prepare(
    `SELECT repo_id, balance, created_at, updated_at FROM accounts WHERE repo_id = ?`
  )
    .bind(repo)
    .first();

  if (!row) return json({ ok: true, repo_id: repo, balance: 0, exists: false });
  return json({ ok: true, ...row, exists: true });
}

async function handleLedger(url, env) {
  const limit = Math.min(Math.max(Number(url.searchParams.get("limit") || 25), 1), 100);
  const repo = (url.searchParams.get("repo") || "").trim();

  let stmt;
  if (repo) {
    if (!parseRepo(repo)) return bad("repo query must be owner/repo");
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
