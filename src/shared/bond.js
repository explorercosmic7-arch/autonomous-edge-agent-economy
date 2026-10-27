/**
 * Shared Bond — intent bonds (post/match/fulfill/slash/cancel) + expireBonds cron.
 */
import { json, bad } from "./http.js";
import {
  parseRepo,
  parseAmount,
  randomId,
} from "./utils.js";
import { checkRateLimit } from "./rateLimit.js";
import { getAuthUser } from "./auth.js";
import { ensureAccount } from "./accounts.js";
import { adjustRep } from "./credit.js";
import { scheduleWebhook } from "./webhooks.js";
import { safetyGate, safetyRecordSpend } from "./gate.js";
import {
  SYSTEM_BOND,
  SYSTEM_SLASH_POOL,
  BOND_MIN,
  BOND_MAX,
  BOND_DEFAULT_TTL_SEC,
  BOND_MIN_TTL_SEC,
  BOND_MAX_TTL_SEC,
  BOND_DEFAULT_MATCH_TTL_SEC,
  BOND_DEFAULT_SLASH_BPS,
  RL_BOND_MAX,
  RL_BOND_WINDOW_SEC,
  EXPIRE_BOND_BATCH,
  CREDIT_REP_FAIL_PENALTY,
} from "./constants.js";

/* ─── Intent bonds (graded commitment) ───
 * Lifecycle: open → matched → fulfilled | slashed | expired | cancelled
 * Poster locks bond_amount into system/bond.
 * Match: counterparty attests intent is accepted.
 * Fulfill: full refund of bond to poster.
 * Slash: fraction (slash_bps or body.slash_bps) → system/slash-pool; rest → poster.
 * Expire open: full refund. Expire matched past match_expires: auto-slash default bps.
 */
export function parseBondTtl(body, field, def) {
  const sec = Number(body[field] ?? body.ttl);
  if (Number.isFinite(sec)) {
    if (sec < BOND_MIN_TTL_SEC || sec > BOND_MAX_TTL_SEC) return null;
    return Math.floor(sec);
  }
  return def;
}

export async function logBondEvent(env, bondId, event, { actor_repo, amount, note } = {}) {
  try {
    await env.DB.prepare(
      `INSERT INTO bond_events (id, bond_id, event, actor_repo, amount, note, created_at)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, datetime('now'))`
    )
      .bind(
        randomId(10),
        bondId,
        event,
        actor_repo || null,
        amount != null ? Number(amount) : null,
        note ? String(note).slice(0, 500) : null
      )
      .run();
  } catch (e) {
    console.log("bond_event_err", e && e.message);
  }
}

export async function loadBond(env, id) {
  try {
    return await env.DB.prepare(`SELECT * FROM intent_bonds WHERE id = ?1`).bind(id).first();
  } catch {
    return null;
  }
}

export async function handleBondPost(request, env, ctx) {
  const t0 = Date.now();
  const authUser = await getAuthUser(request, env);
  if (!authUser) return bad(request, "Sign in or API key required", 401);

  const rlId =
    authUser.auth_via === "api_key"
      ? "bd:key:" + (authUser.key_id || authUser.id)
      : "bd:user:" + authUser.id;
  const limited = await checkRateLimit(env, rlId, RL_BOND_MAX, RL_BOND_WINDOW_SEC);
  if (limited) {
    return bad(request, "Rate limit: bond ops", 429, { retry_after_sec: limited.retry_after_sec });
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return bad(request, "Invalid JSON body");
  }

  let poster = parseRepo(body.poster_repo || body.from_repo || body.fromRepo);
  if (!poster && authUser.default_repo) poster = parseRepo(authUser.default_repo);
  const counterparty = body.counterparty_repo || body.to_repo
    ? parseRepo(body.counterparty_repo || body.to_repo)
    : null;
  const intent = String(body.intent || body.statement || "").trim().slice(0, 1000);
  const task = String(body.task || "intent-bond").slice(0, 500);
  const amount = parseAmount(body.bond_amount ?? body.amount);
  const ttlSec = parseBondTtl(body, "ttl_seconds", BOND_DEFAULT_TTL_SEC);
  const matchTtlSec = parseBondTtl(body, "match_ttl_seconds", BOND_DEFAULT_MATCH_TTL_SEC);
  let slashBps = Number(body.slash_bps);
  if (!Number.isFinite(slashBps)) slashBps = BOND_DEFAULT_SLASH_BPS;
  slashBps = Math.max(0, Math.min(10000, Math.floor(slashBps)));

  if (!poster) return bad(request, "poster_repo required (or set default agent)");
  if (!intent) return bad(request, "intent required (what you commit to do)");
  if (amount == null || amount < BOND_MIN || amount > BOND_MAX) {
    return bad(request, "bond_amount must be between " + BOND_MIN + " and " + BOND_MAX);
  }
  if (ttlSec == null) {
    return bad(request, "ttl_seconds out of range");
  }

  authUser._policyCtx = { to_repo: SYSTEM_BOND, task };
  const blocked = await safetyGate(request, env, authUser, poster, amount);
  if (blocked) return blocked;

  await ensureAccount(env, poster);
  const debit = await env.DB.prepare(
    `UPDATE accounts SET balance = balance - ?1, updated_at = datetime('now')
     WHERE repo_id = ?2 AND balance >= ?1 RETURNING balance`
  )
    .bind(amount, poster)
    .first();
  if (!debit) return bad(request, "Insufficient funds for bond", 402);

  const id = "bd_" + randomId(12);
  const modifier = "+" + ttlSec + " seconds";
  const meta = body.meta && typeof body.meta === "object" ? JSON.stringify(body.meta).slice(0, 2000) : null;

  try {
    await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO intent_bonds (
           id, poster_repo, counterparty_repo, intent, task, bond_amount, slash_bps,
           status, created_by, expires_at, meta_json, created_at, updated_at
         ) VALUES (
           ?1, ?2, ?3, ?4, ?5, ?6, ?7, 'open', ?8,
           datetime('now', ?9), ?10, datetime('now'), datetime('now')
         )`
      ).bind(
        id, poster, counterparty, intent, task, amount, slashBps,
        authUser.id, modifier, meta
      ),
      env.DB.prepare(
        `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
         VALUES (?1, ?2, ?3, ?4, 'success', ?5)`
      ).bind(poster, SYSTEM_BOND, amount, "bond-lock:" + id, Date.now() - t0),
    ]);
  } catch (e) {
    await env.DB.prepare(
      `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
    )
      .bind(amount, poster)
      .run();
    return bad(
      request,
      "intent_bonds table missing — run d1-bonds-migration.sql: " + (e.message || e),
      500
    );
  }

  await safetyRecordSpend(env, authUser, poster, amount);
  await logBondEvent(env, id, "posted", { actor_repo: poster, amount, note: intent.slice(0, 200) });

  if (authUser.id) {
    scheduleWebhook(ctx, env, authUser.id, "bond.posted", {
      id,
      poster_repo: poster,
      counterparty_repo: counterparty,
      bond_amount: amount,
      intent: intent.slice(0, 200),
      status: "open",
    });
  }

  const row = await loadBond(env, id);
  return json(request, {
    ok: true,
    bond: {
      id,
      poster_repo: poster,
      counterparty_repo: counterparty,
      intent,
      task,
      bond_amount: amount,
      slash_bps: slashBps,
      status: "open",
      expires_at: row?.expires_at || null,
      ttl_seconds: ttlSec,
      match_ttl_seconds: matchTtlSec,
    },
    balance_poster: debit.balance,
    latency_ms: Date.now() - t0,
    hint: "Counterparty: POST /api/bond/match { id }. Then fulfill or slash.",
  });
}

export async function handleBondMatch(request, env, ctx) {
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
  let cp = parseRepo(body.counterparty_repo || body.from_repo || body.matcher_repo);
  if (!cp && authUser.default_repo) cp = parseRepo(authUser.default_repo);
  const matchTtlSec = parseBondTtl(body, "match_ttl_seconds", BOND_DEFAULT_MATCH_TTL_SEC);

  if (!id) return bad(request, "id required");
  if (!cp) return bad(request, "counterparty_repo required (or default agent)");

  let row;
  try {
    row = await env.DB.prepare(`SELECT * FROM intent_bonds WHERE id = ?1`).bind(id).first();
  } catch {
    return bad(request, "intent_bonds table missing — run d1-bonds-migration.sql", 500);
  }
  if (!row) return bad(request, "Bond not found", 404);
  if (row.status !== "open") {
    return bad(request, "Bond not open (status=" + row.status + ")", 400, { code: "bond_not_open" });
  }
  if (row.expires_at) {
    const expMs = Date.parse(String(row.expires_at).replace(" ", "T") + "Z");
    if (Number.isFinite(expMs) && expMs < Date.now()) {
      return bad(request, "Bond expired", 400, { code: "bond_expired" });
    }
  }
  if (row.counterparty_repo && row.counterparty_repo !== cp) {
    return bad(request, "Bond reserved for " + row.counterparty_repo, 403);
  }
  if (cp === row.poster_repo) {
    return bad(request, "Poster cannot match own bond", 400);
  }

  const mod = "+" + (matchTtlSec || BOND_DEFAULT_MATCH_TTL_SEC) + " seconds";
  const claim = await env.DB.prepare(
    `UPDATE intent_bonds
     SET status = 'matched',
         counterparty_repo = ?2,
         matched_by = ?3,
         matched_at = datetime('now'),
         match_expires_at = datetime('now', ?4),
         updated_at = datetime('now')
     WHERE id = ?1 AND status = 'open'
     RETURNING *`
  )
    .bind(id, cp, authUser.id, mod)
    .first();
  if (!claim) return bad(request, "Match race failed", 409);

  await logBondEvent(env, id, "matched", { actor_repo: cp, note: "matched" });

  if (row.created_by) {
    scheduleWebhook(ctx, env, row.created_by, "bond.matched", {
      id,
      poster_repo: row.poster_repo,
      counterparty_repo: cp,
      bond_amount: row.bond_amount,
      status: "matched",
    });
  }

  return json(request, {
    ok: true,
    id,
    status: "matched",
    counterparty_repo: cp,
    match_expires_at: claim.match_expires_at,
    latency_ms: Date.now() - t0,
  });
}

export async function handleBondFulfill(request, env, ctx) {
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
    row = await env.DB.prepare(`SELECT * FROM intent_bonds WHERE id = ?1`).bind(id).first();
  } catch {
    return bad(request, "intent_bonds table missing — run d1-bonds-migration.sql", 500);
  }
  if (!row) return bad(request, "Bond not found", 404);
  if (row.status !== "matched" && row.status !== "open") {
    return bad(request, "Bond not fulfillable (status=" + row.status + ")");
  }

  const allowed =
    authUser.id === row.created_by ||
    authUser.id === row.matched_by ||
    (authUser.default_repo &&
      (authUser.default_repo === row.poster_repo ||
        authUser.default_repo === row.counterparty_repo));
  if (!allowed) return bad(request, "Not authorized to fulfill", 403);

  const claim = await env.DB.prepare(
    `UPDATE intent_bonds
     SET status = 'fulfilled',
         fulfilled_at = datetime('now'),
         closed_at = datetime('now'),
         close_reason = 'fulfilled',
         updated_at = datetime('now')
     WHERE id = ?1 AND status IN ('open', 'matched')
     RETURNING *`
  )
    .bind(id)
    .first();
  if (!claim) return bad(request, "Fulfill race", 409);

  const refund = Number(row.bond_amount);
  await ensureAccount(env, row.poster_repo);
  await env.DB.batch([
    env.DB.prepare(
      `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
    ).bind(refund, row.poster_repo),
    env.DB.prepare(
      `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
       VALUES (?1, ?2, ?3, ?4, 'success', ?5)`
    ).bind(SYSTEM_BOND, row.poster_repo, refund, "bond-fulfill-refund:" + id, Date.now() - t0),
  ]);

  await logBondEvent(env, id, "fulfilled", { actor_repo: authUser.default_repo, amount: refund });

  if (row.created_by) {
    scheduleWebhook(ctx, env, row.created_by, "bond.fulfilled", {
      id,
      poster_repo: row.poster_repo,
      bond_amount: refund,
      status: "fulfilled",
    });
  }

  return json(request, {
    ok: true,
    id,
    status: "fulfilled",
    refunded: refund,
    latency_ms: Date.now() - t0,
  });
}

export async function handleBondSlash(request, env, ctx) {
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
  const reason = String(body.reason || "slash").slice(0, 500);
  if (!id) return bad(request, "id required");

  let row;
  try {
    row = await env.DB.prepare(`SELECT * FROM intent_bonds WHERE id = ?1`).bind(id).first();
  } catch {
    return bad(request, "intent_bonds table missing — run d1-bonds-migration.sql", 500);
  }
  if (!row) return bad(request, "Bond not found", 404);
  if (row.status !== "matched" && row.status !== "open") {
    return bad(request, "Bond not slashable (status=" + row.status + ")");
  }

  // Matcher or poster (or reserved counterparty) may slash
  const allowed =
    authUser.id === row.matched_by ||
    authUser.id === row.created_by ||
    (authUser.default_repo &&
      (authUser.default_repo === row.counterparty_repo ||
        authUser.default_repo === row.poster_repo));
  if (!allowed) return bad(request, "Not authorized to slash", 403);

  let bps = Number(body.slash_bps);
  if (!Number.isFinite(bps)) bps = Number(row.slash_bps) || BOND_DEFAULT_SLASH_BPS;
  bps = Math.max(0, Math.min(10000, Math.floor(bps)));

  const bondAmt = Number(row.bond_amount);
  const slashAmt = Math.round(((bondAmt * bps) / 10000) * 1e6) / 1e6;
  const refund = Math.round((bondAmt - slashAmt) * 1e6) / 1e6;

  const claim = await env.DB.prepare(
    `UPDATE intent_bonds
     SET status = 'slashed',
         slashed_at = datetime('now'),
         slash_amount = ?2,
         closed_at = datetime('now'),
         close_reason = ?3,
         updated_at = datetime('now')
     WHERE id = ?1 AND status IN ('open', 'matched')
     RETURNING *`
  )
    .bind(id, slashAmt, reason)
    .first();
  if (!claim) return bad(request, "Slash race", 409);

  await ensureAccount(env, row.poster_repo);
  await ensureAccount(env, SYSTEM_SLASH_POOL);

  const stmts = [];
  if (slashAmt > 0) {
    stmts.push(
      env.DB.prepare(
        `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
      ).bind(slashAmt, SYSTEM_SLASH_POOL)
    );
    stmts.push(
      env.DB.prepare(
        `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
         VALUES (?1, ?2, ?3, ?4, 'success', ?5)`
      ).bind(SYSTEM_BOND, SYSTEM_SLASH_POOL, slashAmt, "bond-slash:" + id, Date.now() - t0)
    );
  }
  if (refund > 0) {
    stmts.push(
      env.DB.prepare(
        `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
      ).bind(refund, row.poster_repo)
    );
    stmts.push(
      env.DB.prepare(
        `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
         VALUES (?1, ?2, ?3, ?4, 'success', ?5)`
      ).bind(SYSTEM_BOND, row.poster_repo, refund, "bond-slash-refund:" + id, Date.now() - t0)
    );
  }
  if (stmts.length) await env.DB.batch(stmts);

  await adjustRep(env, row.poster_repo, -CREDIT_REP_FAIL_PENALTY, "bond_slashed", id);
  await logBondEvent(env, id, "slashed", {
    actor_repo: authUser.default_repo,
    amount: slashAmt,
    note: reason,
  });

  if (row.created_by) {
    scheduleWebhook(ctx, env, row.created_by, "bond.slashed", {
      id,
      poster_repo: row.poster_repo,
      slash_amount: slashAmt,
      refunded: refund,
      reason,
      status: "slashed",
    });
  }

  return json(request, {
    ok: true,
    id,
    status: "slashed",
    slash_bps: bps,
    slash_amount: slashAmt,
    refunded: refund,
    latency_ms: Date.now() - t0,
  });
}

export async function handleBondCancel(request, env, ctx) {
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
    row = await env.DB.prepare(`SELECT * FROM intent_bonds WHERE id = ?1`).bind(id).first();
  } catch {
    return bad(request, "intent_bonds table missing — run d1-bonds-migration.sql", 500);
  }
  if (!row) return bad(request, "Bond not found", 404);
  if (row.status !== "open") {
    return bad(request, "Only open (unmatched) bonds can be cancelled", 400);
  }

  const allowed =
    authUser.id === row.created_by ||
    (authUser.default_repo && authUser.default_repo === row.poster_repo);
  if (!allowed) return bad(request, "Not authorized to cancel", 403);

  const claim = await env.DB.prepare(
    `UPDATE intent_bonds
     SET status = 'cancelled',
         closed_at = datetime('now'),
         close_reason = 'cancelled',
         updated_at = datetime('now')
     WHERE id = ?1 AND status = 'open'
     RETURNING *`
  )
    .bind(id)
    .first();
  if (!claim) return bad(request, "Cancel race", 409);

  const refund = Number(row.bond_amount);
  await ensureAccount(env, row.poster_repo);
  await env.DB.batch([
    env.DB.prepare(
      `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
    ).bind(refund, row.poster_repo),
    env.DB.prepare(
      `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
       VALUES (?1, ?2, ?3, ?4, 'success', ?5)`
    ).bind(SYSTEM_BOND, row.poster_repo, refund, "bond-cancel-refund:" + id, Date.now() - t0),
  ]);

  await logBondEvent(env, id, "cancelled", { actor_repo: row.poster_repo, amount: refund });

  return json(request, {
    ok: true,
    id,
    status: "cancelled",
    refunded: refund,
    latency_ms: Date.now() - t0,
  });
}

export async function handleBondGet(request, env, id) {
  id = String(id || "").trim();
  if (!id) return bad(request, "id required");
  const row = await loadBond(env, id);
  if (!row) {
    try {
      await env.DB.prepare(`SELECT 1 FROM intent_bonds LIMIT 1`).first();
    } catch {
      return bad(request, "intent_bonds table missing — run d1-bonds-migration.sql", 500);
    }
    return bad(request, "Bond not found", 404);
  }
  let events = [];
  try {
    const q = await env.DB.prepare(
      `SELECT event, actor_repo, amount, note, created_at
       FROM bond_events WHERE bond_id = ?1 ORDER BY created_at DESC LIMIT 40`
    )
      .bind(id)
      .all();
    events = q.results || [];
  } catch (_) {}
  return json(request, { ok: true, bond: row, events });
}

export async function handleBondList(request, url, env) {
  const limit = Math.min(Math.max(Number(url.searchParams.get("limit") || 25), 1), 100);
  const repo = (url.searchParams.get("repo") || "").trim();
  const status = (url.searchParams.get("status") || "").trim();

  let sql = `SELECT id, poster_repo, counterparty_repo, intent, task, bond_amount, slash_bps,
                    status, expires_at, match_expires_at, slash_amount, created_at
             FROM intent_bonds WHERE 1=1`;
  const binds = [];
  if (repo) {
    if (!parseRepo(repo)) return bad(request, "repo must be owner/repo");
    sql += ` AND (poster_repo = ? OR counterparty_repo = ?)`;
    binds.push(repo, repo);
  }
  if (status && ["open", "matched", "fulfilled", "slashed", "expired", "cancelled"].includes(status)) {
    sql += ` AND status = ?`;
    binds.push(status);
  }
  sql += ` ORDER BY created_at DESC LIMIT ?`;
  binds.push(limit);

  try {
    const { results } = await env.DB.prepare(sql).bind(...binds).all();
    return json(request, { ok: true, count: results.length, bonds: results });
  } catch (e) {
    return bad(
      request,
      "intent_bonds table missing — run d1-bonds-migration.sql: " + (e.message || e),
      500
    );
  }
}

export async function expireBonds(env, ctx) {
  const t0 = Date.now();
  let expiredOpen = 0;
  let expiredMatch = 0;
  let refundedTotal = 0;
  let slashedTotal = 0;

  // 1) Open past expires_at → full refund + expired
  try {
    const q = await env.DB.prepare(
      `SELECT * FROM intent_bonds
       WHERE status = 'open'
         AND expires_at IS NOT NULL
         AND expires_at < datetime('now')
       ORDER BY expires_at ASC LIMIT ?1`
    )
      .bind(EXPIRE_BOND_BATCH)
      .all();
    for (const row of q.results || []) {
      try {
        const claim = await env.DB.prepare(
          `UPDATE intent_bonds
           SET status = 'expired', closed_at = datetime('now'), close_reason = 'expired',
               updated_at = datetime('now')
           WHERE id = ?1 AND status = 'open' RETURNING id`
        )
          .bind(row.id)
          .first();
        if (!claim) continue;
        const refund = Number(row.bond_amount);
        await ensureAccount(env, row.poster_repo);
        await env.DB.batch([
          env.DB.prepare(
            `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
          ).bind(refund, row.poster_repo),
          env.DB.prepare(
            `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
             VALUES (?1, ?2, ?3, ?4, 'success', 0)`
          ).bind(SYSTEM_BOND, row.poster_repo, refund, "bond-expire-refund:" + row.id),
        ]);
        await logBondEvent(env, row.id, "expired", { actor_repo: null, amount: refund });
        expiredOpen += 1;
        refundedTotal += refund;
        if (row.created_by) {
          scheduleWebhook(ctx, env, row.created_by, "bond.expired", {
            id: row.id,
            poster_repo: row.poster_repo,
            bond_amount: refund,
            status: "expired",
          });
        }
      } catch (e) {
        console.log("bond_expire_open", row.id, e && e.message);
      }
    }
  } catch (e) {
    return { expired_open: 0, expired_match: 0, error: e.message, latency_ms: Date.now() - t0 };
  }

  // 2) Matched past match_expires_at → default slash
  try {
    const q = await env.DB.prepare(
      `SELECT * FROM intent_bonds
       WHERE status = 'matched'
         AND match_expires_at IS NOT NULL
         AND match_expires_at < datetime('now')
       ORDER BY match_expires_at ASC LIMIT ?1`
    )
      .bind(EXPIRE_BOND_BATCH)
      .all();
    for (const row of q.results || []) {
      try {
        const bps = Number(row.slash_bps) || BOND_DEFAULT_SLASH_BPS;
        const bondAmt = Number(row.bond_amount);
        const slashAmt = Math.round(((bondAmt * bps) / 10000) * 1e6) / 1e6;
        const refund = Math.round((bondAmt - slashAmt) * 1e6) / 1e6;
        const claim = await env.DB.prepare(
          `UPDATE intent_bonds
           SET status = 'slashed', slashed_at = datetime('now'), slash_amount = ?2,
               closed_at = datetime('now'), close_reason = 'match_timeout',
               updated_at = datetime('now')
           WHERE id = ?1 AND status = 'matched' RETURNING id`
        )
          .bind(row.id, slashAmt)
          .first();
        if (!claim) continue;
        await ensureAccount(env, row.poster_repo);
        await ensureAccount(env, SYSTEM_SLASH_POOL);
        const stmts = [];
        if (slashAmt > 0) {
          stmts.push(
            env.DB.prepare(
              `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
            ).bind(slashAmt, SYSTEM_SLASH_POOL)
          );
          stmts.push(
            env.DB.prepare(
              `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
               VALUES (?1, ?2, ?3, ?4, 'success', 0)`
            ).bind(SYSTEM_BOND, SYSTEM_SLASH_POOL, slashAmt, "bond-match-timeout-slash:" + row.id)
          );
        }
        if (refund > 0) {
          stmts.push(
            env.DB.prepare(
              `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
            ).bind(refund, row.poster_repo)
          );
          stmts.push(
            env.DB.prepare(
              `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
               VALUES (?1, ?2, ?3, ?4, 'success', 0)`
            ).bind(SYSTEM_BOND, row.poster_repo, refund, "bond-match-timeout-refund:" + row.id)
          );
        }
        if (stmts.length) await env.DB.batch(stmts);
        await logBondEvent(env, row.id, "slashed", {
          amount: slashAmt,
          note: "match_timeout",
        });
        expiredMatch += 1;
        slashedTotal += slashAmt;
        refundedTotal += refund;
        if (row.created_by) {
          scheduleWebhook(ctx, env, row.created_by, "bond.slashed", {
            id: row.id,
            slash_amount: slashAmt,
            refunded: refund,
            reason: "match_timeout",
            status: "slashed",
          });
        }
      } catch (e) {
        console.log("bond_expire_match", row.id, e && e.message);
      }
    }
  } catch (e) {
    console.log("bond_expire_match_q", e && e.message);
  }

  return {
    expired_open: expiredOpen,
    expired_match: expiredMatch,
    refunded_total: refundedTotal,
    slashed_total: slashedTotal,
    latency_ms: Date.now() - t0,
  };
}


