/**
 * Shared Commit — commit–reveal counterfactual pay + expireCommits cron.
 */
import { json, bad } from "./http.js";
import {
  parseRepo,
  parseAmount,
  randomId,
  sha256Hex,
} from "./utils.js";
import { checkRateLimit } from "./rateLimit.js";
import { getAuthUser } from "./auth.js";
import { ensureAccount } from "./accounts.js";
import { adjustRep, debitWithCredit } from "./credit.js";
import { scheduleWebhook } from "./webhooks.js";
import { safetyGate, safetyRecordSpend } from "./gate.js";
import {
  SYSTEM_COMMIT,
  COMMIT_MIN,
  COMMIT_MAX,
  COMMIT_DEFAULT_TTL_SEC,
  COMMIT_MIN_TTL_SEC,
  COMMIT_MAX_TTL_SEC,
  RL_COMMIT_MAX,
  RL_COMMIT_WINDOW_SEC,
  EXPIRE_COMMIT_BATCH,
  CREDIT_REP_SUCCESS_BONUS,
} from "./constants.js";

/* ─── Commit–reveal counterfactual pay ───
 * 1) POST /api/commit  { to_repo, amount, task?, commit_hash, ttl_seconds? }
 *    Locks amount from from_repo → system/commit. commit_hash = sha256(preimage).
 * 2) POST /api/commit/reveal { id, preimage }
 *    If sha256(preimage) === commit_hash → pay system/commit → to_repo.
 * 3) POST /api/commit/cancel { id }  (before reveal) → full refund to from_repo.
 * 4) Cron / expire → refund (counterfactual: never paid).
 *
 * Preimage is opaque UTF-8 string (or hex). Client should use high entropy.
 */

export function parseCommitTtl(body) {
  const sec = Number(body.ttl_seconds ?? body.ttl);
  if (Number.isFinite(sec)) {
    if (sec < COMMIT_MIN_TTL_SEC || sec > COMMIT_MAX_TTL_SEC) return null;
    return Math.floor(sec);
  }
  return COMMIT_DEFAULT_TTL_SEC;
}

export function isHex64(s) {
  return typeof s === "string" && /^[a-fA-F0-9]{64}$/.test(s.trim());
}

export async function logCommitEvent(env, commitId, event, { actor_repo, note } = {}) {
  try {
    await env.DB.prepare(
      `INSERT INTO commit_events (id, commit_id, event, actor_repo, note, created_at)
       VALUES (?1, ?2, ?3, ?4, ?5, datetime('now'))`
    )
      .bind(
        randomId(10),
        commitId,
        event,
        actor_repo || null,
        note ? String(note).slice(0, 500) : null
      )
      .run();
  } catch (e) {
    console.log("commit_event_err", e && e.message);
  }
}

export async function loadCommit(env, id) {
  try {
    return await env.DB.prepare(`SELECT * FROM payment_commits WHERE id = ?1`).bind(id).first();
  } catch {
    return null;
  }
}

export async function handleCommitCreate(request, env, ctx) {
  const t0 = Date.now();
  const authUser = await getAuthUser(request, env);
  if (!authUser) return bad(request, "Sign in or API key required", 401);

  const rlId =
    authUser.auth_via === "api_key"
      ? "cm:key:" + (authUser.key_id || authUser.id)
      : "cm:user:" + authUser.id;
  const limited = await checkRateLimit(env, rlId, RL_COMMIT_MAX, RL_COMMIT_WINDOW_SEC);
  if (limited) {
    return bad(request, "Rate limit: commit ops", 429, { retry_after_sec: limited.retry_after_sec });
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return bad(request, "Invalid JSON body");
  }

  let fromRepo = parseRepo(body.from_repo || body.fromRepo);
  if (!fromRepo && authUser.default_repo) fromRepo = parseRepo(authUser.default_repo);
  const toRepo = parseRepo(body.to_repo || body.toRepo);
  const amount = parseAmount(body.amount);
  const task = String(body.task || "commit").slice(0, 500);
  const ttlSec = parseCommitTtl(body);
  let commitHash = String(body.commit_hash || body.hash || "").trim().toLowerCase();

  // Optional: server hashes preimage if client sends preimage at commit (less private)
  if (!isHex64(commitHash) && body.preimage != null) {
    commitHash = await sha256Hex(String(body.preimage));
  }
  if (!fromRepo) return bad(request, "from_repo required (or set default agent)");
  if (!toRepo) return bad(request, "to_repo required");
  if (amount == null || amount < COMMIT_MIN || amount > COMMIT_MAX) {
    return bad(request, "amount invalid");
  }
  if (ttlSec == null) return bad(request, "ttl_seconds out of range");
  if (!isHex64(commitHash)) {
    return bad(request, "commit_hash must be sha256 hex (64 chars), or pass preimage to hash server-side");
  }

  authUser._policyCtx = { to_repo: toRepo, task: "commit:" + task };
  const blocked = await safetyGate(request, env, authUser, fromRepo, amount);
  if (blocked) return blocked;

  const debitRes = await debitWithCredit(env, fromRepo, amount);
  if (!debitRes.ok) {
    return bad(request, debitRes.error || "Insufficient funds", debitRes.code === "wallet_locked" ? 403 : 402, {
      code: debitRes.code || "insufficient",
      available_credit: debitRes.available_credit,
    });
  }

  const id = "cm_" + randomId(12);
  const modifier = "+" + ttlSec + " seconds";

  try {
    await ensureAccount(env, SYSTEM_COMMIT);
    await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO payment_commits (
           id, from_repo, to_repo, amount, task, commit_hash, status,
           created_by, expires_at, created_at, updated_at
         ) VALUES (
           ?1, ?2, ?3, ?4, ?5, ?6, 'committed', ?7,
           datetime('now', ?8), datetime('now'), datetime('now')
         )`
      ).bind(id, fromRepo, toRepo, amount, task, commitHash, authUser.id, modifier),
      env.DB.prepare(
        `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
         VALUES (?1, ?2, ?3, ?4, 'success', ?5)`
      ).bind(fromRepo, SYSTEM_COMMIT, amount, "commit-lock:" + id, Date.now() - t0),
    ]);
  } catch (e) {
    // refund cash/credit best-effort
    await env.DB.prepare(
      `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
    )
      .bind(amount, fromRepo)
      .run()
      .catch(() => {});
    if (debitRes.credit_drawn > 0) {
      await env.DB.prepare(
        `UPDATE agent_limits
         SET outstanding_credit = MAX(0, COALESCE(outstanding_credit, 0) - ?2),
             updated_at = datetime('now')
         WHERE repo_id = ?1`
      )
        .bind(fromRepo, debitRes.credit_drawn)
        .run()
        .catch(() => {});
    }
    return bad(
      request,
      "payment_commits table missing — run d1-commit-migration.sql: " + (e.message || e),
      500
    );
  }

  await safetyRecordSpend(env, authUser, fromRepo, amount);
  await logCommitEvent(env, id, "committed", { actor_repo: fromRepo, note: task });

  if (authUser.id) {
    scheduleWebhook(ctx, env, authUser.id, "commit.created", {
      id,
      from_repo: fromRepo,
      to_repo: toRepo,
      amount,
      task,
      status: "committed",
      expires_in_sec: ttlSec,
    });
  }

  return json(request, {
    ok: true,
    commit: {
      id,
      from_repo: fromRepo,
      to_repo: toRepo,
      amount,
      task,
      commit_hash: commitHash,
      status: "committed",
      ttl_seconds: ttlSec,
      credit_drawn: debitRes.credit_drawn || 0,
    },
    balance_from: debitRes.balance,
    latency_ms: Date.now() - t0,
    hint: "Reveal with POST /api/commit/reveal { id, preimage }. Cancel for counterfactual refund.",
  });
}

export async function handleCommitReveal(request, env, ctx) {
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
  const preimage = body.preimage != null ? String(body.preimage) : "";
  if (!id) return bad(request, "id required");
  if (!preimage) return bad(request, "preimage required");

  let row;
  try {
    row = await env.DB.prepare(`SELECT * FROM payment_commits WHERE id = ?1`).bind(id).first();
  } catch {
    return bad(request, "payment_commits table missing — run d1-commit-migration.sql", 500);
  }
  if (!row) return bad(request, "Commit not found", 404);
  if (row.status !== "committed") {
    return bad(request, "Commit not revealable (status=" + row.status + ")", 400, {
      code: "commit_closed",
    });
  }
  if (row.expires_at) {
    const expMs = Date.parse(String(row.expires_at).replace(" ", "T") + "Z");
    if (Number.isFinite(expMs) && expMs < Date.now()) {
      return bad(request, "Commit expired — wait for refund cron or cancel", 400, {
        code: "commit_expired",
      });
    }
  }

  const hash = await sha256Hex(preimage);
  if (hash.toLowerCase() !== String(row.commit_hash).toLowerCase()) {
    await logCommitEvent(env, id, "reveal_failed", {
      actor_repo: authUser.default_repo || null,
      note: "hash_mismatch",
    });
    return bad(request, "Preimage does not match commit_hash", 403, { code: "bad_preimage" });
  }

  // Anyone with preimage can reveal (classic HTLC). Optional: restrict to to_repo / creator.
  const claim = await env.DB.prepare(
    `UPDATE payment_commits
     SET status = 'revealed',
         revealed_at = datetime('now'),
         closed_at = datetime('now'),
         close_reason = 'revealed',
         reveal_note = ?2,
         updated_at = datetime('now')
     WHERE id = ?1 AND status = 'committed'
     RETURNING *`
  )
    .bind(id, String(body.note || "").slice(0, 200) || null)
    .first();
  if (!claim) return bad(request, "Reveal race", 409);

  const amount = Number(row.amount);
  await ensureAccount(env, row.to_repo);
  await ensureAccount(env, SYSTEM_COMMIT);
  await env.DB.batch([
    env.DB.prepare(
      `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
    ).bind(amount, row.to_repo),
    env.DB.prepare(
      `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
       VALUES (?1, ?2, ?3, ?4, 'success', ?5)`
    ).bind(
      SYSTEM_COMMIT,
      row.to_repo,
      amount,
      "commit-reveal:" + id + ":" + (row.task || "").slice(0, 40),
      Date.now() - t0
    ),
  ]);

  await logCommitEvent(env, id, "revealed", {
    actor_repo: authUser.default_repo || row.to_repo,
    note: "paid",
  });
  await adjustRep(env, row.from_repo, CREDIT_REP_SUCCESS_BONUS, "commit_reveal", id);

  if (row.created_by) {
    scheduleWebhook(ctx, env, row.created_by, "commit.revealed", {
      id,
      from_repo: row.from_repo,
      to_repo: row.to_repo,
      amount,
      status: "revealed",
    });
  }

  return json(request, {
    ok: true,
    id,
    status: "revealed",
    paid_to: row.to_repo,
    amount,
    latency_ms: Date.now() - t0,
  });
}

export async function handleCommitCancel(request, env, ctx) {
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
    row = await env.DB.prepare(`SELECT * FROM payment_commits WHERE id = ?1`).bind(id).first();
  } catch {
    return bad(request, "payment_commits table missing — run d1-commit-migration.sql", 500);
  }
  if (!row) return bad(request, "Commit not found", 404);
  if (row.status !== "committed") {
    return bad(request, "Only committed (unrevealed) commits can be cancelled", 400);
  }

  const allowed =
    authUser.id === row.created_by ||
    (authUser.default_repo && authUser.default_repo === row.from_repo);
  if (!allowed) return bad(request, "Not authorized to cancel", 403);

  const claim = await env.DB.prepare(
    `UPDATE payment_commits
     SET status = 'cancelled',
         cancelled_at = datetime('now'),
         closed_at = datetime('now'),
         close_reason = 'cancelled',
         updated_at = datetime('now')
     WHERE id = ?1 AND status = 'committed'
     RETURNING *`
  )
    .bind(id)
    .first();
  if (!claim) return bad(request, "Cancel race", 409);

  const refund = Number(row.amount);
  await ensureAccount(env, row.from_repo);
  await env.DB.batch([
    env.DB.prepare(
      `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
    ).bind(refund, row.from_repo),
    env.DB.prepare(
      `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
       VALUES (?1, ?2, ?3, ?4, 'success', ?5)`
    ).bind(SYSTEM_COMMIT, row.from_repo, refund, "commit-cancel-refund:" + id, Date.now() - t0),
  ]);

  await logCommitEvent(env, id, "cancelled", { actor_repo: row.from_repo, note: "counterfactual" });

  if (row.created_by) {
    scheduleWebhook(ctx, env, row.created_by, "commit.cancelled", {
      id,
      from_repo: row.from_repo,
      amount: refund,
      status: "cancelled",
    });
  }

  return json(request, {
    ok: true,
    id,
    status: "cancelled",
    refunded: refund,
    latency_ms: Date.now() - t0,
  });
}

export async function handleCommitGet(request, env, id) {
  id = String(id || "").trim();
  if (!id) return bad(request, "id required");
  const row = await loadCommit(env, id);
  if (!row) {
    try {
      await env.DB.prepare(`SELECT 1 FROM payment_commits LIMIT 1`).first();
    } catch {
      return bad(request, "payment_commits table missing — run d1-commit-migration.sql", 500);
    }
    return bad(request, "Commit not found", 404);
  }
  let events = [];
  try {
    const q = await env.DB.prepare(
      `SELECT event, actor_repo, note, created_at
       FROM commit_events WHERE commit_id = ?1 ORDER BY created_at DESC LIMIT 40`
    )
      .bind(id)
      .all();
    events = q.results || [];
  } catch (_) {}
  // Never return preimage; hash is public
  return json(request, { ok: true, commit: row, events });
}

export async function handleCommitList(request, url, env) {
  const limit = Math.min(Math.max(Number(url.searchParams.get("limit") || 20), 1), 100);
  const repo = (url.searchParams.get("repo") || "").trim();
  const status = (url.searchParams.get("status") || "").trim();

  let sql = `SELECT id, from_repo, to_repo, amount, task, commit_hash, status,
                    expires_at, revealed_at, created_at
             FROM payment_commits WHERE 1=1`;
  const binds = [];
  if (repo) {
    if (!parseRepo(repo)) return bad(request, "repo must be owner/repo");
    sql += ` AND (from_repo = ? OR to_repo = ?)`;
    binds.push(repo, repo);
  }
  if (status && ["committed", "revealed", "cancelled", "expired"].includes(status)) {
    sql += ` AND status = ?`;
    binds.push(status);
  }
  sql += ` ORDER BY created_at DESC LIMIT ?`;
  binds.push(limit);

  try {
    const { results } = await env.DB.prepare(sql).bind(...binds).all();
    return json(request, { ok: true, count: results.length, commits: results });
  } catch (e) {
    return bad(
      request,
      "payment_commits table missing — run d1-commit-migration.sql: " + (e.message || e),
      500
    );
  }
}

export async function expireCommits(env, ctx) {
  const t0 = Date.now();
  let expired = 0;
  let refundedTotal = 0;
  try {
    const q = await env.DB.prepare(
      `SELECT * FROM payment_commits
       WHERE status = 'committed'
         AND expires_at IS NOT NULL
         AND expires_at < datetime('now')
       ORDER BY expires_at ASC LIMIT ?1`
    )
      .bind(EXPIRE_COMMIT_BATCH)
      .all();
    for (const row of q.results || []) {
      try {
        const claim = await env.DB.prepare(
          `UPDATE payment_commits
           SET status = 'expired', closed_at = datetime('now'), close_reason = 'expired',
               updated_at = datetime('now')
           WHERE id = ?1 AND status = 'committed' RETURNING id`
        )
          .bind(row.id)
          .first();
        if (!claim) continue;
        const refund = Number(row.amount);
        await ensureAccount(env, row.from_repo);
        await env.DB.batch([
          env.DB.prepare(
            `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
          ).bind(refund, row.from_repo),
          env.DB.prepare(
            `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
             VALUES (?1, ?2, ?3, ?4, 'success', 0)`
          ).bind(SYSTEM_COMMIT, row.from_repo, refund, "commit-expire-refund:" + row.id),
        ]);
        await logCommitEvent(env, row.id, "expired", { amount: refund });
        expired += 1;
        refundedTotal += refund;
        if (row.created_by) {
          scheduleWebhook(ctx, env, row.created_by, "commit.expired", {
            id: row.id,
            from_repo: row.from_repo,
            amount: refund,
            status: "expired",
          });
        }
      } catch (e) {
        console.log("commit_expire", row.id, e && e.message);
      }
    }
  } catch (e) {
    return { expired: 0, error: e.message, latency_ms: Date.now() - t0 };
  }
  return { expired, refunded_total: refundedTotal, latency_ms: Date.now() - t0 };
}


