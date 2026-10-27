/**
 * Shared Continuity — heartbeat sessions, recover, expireContinuitySessions cron.
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
import { adjustRep, debitWithCredit } from "./credit.js";
import { scheduleWebhook } from "./webhooks.js";
import { safetyGate, safetyRecordSpend } from "./gate.js";
import {
  SYSTEM_CONTINUITY,
  SYSTEM_SLASH_POOL,
  CONT_MIN_BOND,
  CONT_MAX_BOND,
  CONT_DEFAULT_INTERVAL_SEC,
  CONT_MIN_INTERVAL_SEC,
  CONT_MAX_INTERVAL_SEC,
  CONT_DEFAULT_GRACE_SEC,
  CONT_MIN_GRACE_SEC,
  CONT_MAX_GRACE_SEC,
  CONT_DEFAULT_MISS_LIMIT,
  CONT_MAX_MISS_LIMIT,
  RL_CONT_MAX,
  RL_CONT_WINDOW_SEC,
  EXPIRE_CONT_BATCH,
  CREDIT_REP_FAIL_PENALTY,
} from "./constants.js";

/* ─── Heartbeat Continuity (dead-agent recovery) ─── */

export function parseContInterval(body) {
  const sec = Number(body.interval_sec ?? body.interval);
  if (Number.isFinite(sec)) {
    if (sec < CONT_MIN_INTERVAL_SEC || sec > CONT_MAX_INTERVAL_SEC) return null;
    return Math.floor(sec);
  }
  return CONT_DEFAULT_INTERVAL_SEC;
}

export function parseContGrace(body) {
  const sec = Number(body.grace_sec ?? body.grace);
  if (Number.isFinite(sec)) {
    if (sec < CONT_MIN_GRACE_SEC || sec > CONT_MAX_GRACE_SEC) return null;
    return Math.floor(sec);
  }
  return CONT_DEFAULT_GRACE_SEC;
}

export async function logContEvent(env, sessionId, event, { actor_repo, note } = {}) {
  try {
    await env.DB.prepare(
      `INSERT INTO continuity_events (id, session_id, event, actor_repo, note, created_at)
       VALUES (?1, ?2, ?3, ?4, ?5, datetime('now'))`
    )
      .bind(
        randomId(10),
        sessionId,
        event,
        actor_repo || null,
        note ? String(note).slice(0, 500) : null
      )
      .run();
  } catch (e) {
    console.log("cont_event_err", e && e.message);
  }
}

export async function loadContSession(env, id) {
  try {
    return await env.DB.prepare(`SELECT * FROM continuity_sessions WHERE id = ?1`).bind(id).first();
  } catch {
    return null;
  }
}

/** Recover one session (bond movement + status). Caller must have claimed status. */
export async function recoverContinuitySession(env, row, reason, t0, ctx) {
  const bond = Number(row.bond_usd || 0);
  const action = String(row.recovery_action || "refund");
  let paidTo = row.owner_repo;
  let slashed = 0;
  let refunded = bond;

  if (bond > 0) {
    await ensureAccount(env, SYSTEM_CONTINUITY);

    if (action === "successor" && row.successor_repo) {
      paidTo = row.successor_repo;
      await ensureAccount(env, paidTo);
      await env.DB.batch([
        env.DB.prepare(
          `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
        ).bind(bond, paidTo),
        env.DB.prepare(
          `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
           VALUES (?1, ?2, ?3, ?4, 'success', ?5)`
        ).bind(
          SYSTEM_CONTINUITY,
          paidTo,
          bond,
          "continuity-successor:" + row.id,
          typeof t0 === "number" ? Date.now() - t0 : 0
        ),
      ]);
      refunded = bond;
      slashed = 0;
    } else if (action === "slash_refund") {
      const bps = Math.min(10000, Math.max(0, Number(row.slash_bps || 0)));
      slashed = Math.round(((bond * bps) / 10000) * 1e6) / 1e6;
      refunded = Math.round((bond - slashed) * 1e6) / 1e6;
      await ensureAccount(env, row.owner_repo);
      const stmts = [];
      if (slashed > 0) {
        await ensureAccount(env, SYSTEM_SLASH_POOL);
        stmts.push(
          env.DB.prepare(
            `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
          ).bind(slashed, SYSTEM_SLASH_POOL),
          env.DB.prepare(
            `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
             VALUES (?1, ?2, ?3, ?4, 'success', 0)`
          ).bind(SYSTEM_CONTINUITY, SYSTEM_SLASH_POOL, slashed, "continuity-slash:" + row.id)
        );
      }
      if (refunded > 0) {
        stmts.push(
          env.DB.prepare(
            `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
          ).bind(refunded, row.owner_repo),
          env.DB.prepare(
            `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
             VALUES (?1, ?2, ?3, ?4, 'success', 0)`
          ).bind(SYSTEM_CONTINUITY, row.owner_repo, refunded, "continuity-refund:" + row.id)
        );
      }
      if (stmts.length) await env.DB.batch(stmts);
      paidTo = row.owner_repo;
    } else {
      // refund
      paidTo = row.owner_repo;
      await ensureAccount(env, paidTo);
      await env.DB.batch([
        env.DB.prepare(
          `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
        ).bind(bond, paidTo),
        env.DB.prepare(
          `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
           VALUES (?1, ?2, ?3, ?4, 'success', 0)`
        ).bind(SYSTEM_CONTINUITY, paidTo, bond, "continuity-refund:" + row.id),
      ]);
    }
  }

  await env.DB.prepare(
    `UPDATE continuity_sessions
     SET status = 'recovered',
         recovered_to = ?2,
         recovered_at = datetime('now'),
         closed_at = datetime('now'),
         close_reason = ?3,
         updated_at = datetime('now')
     WHERE id = ?1`
  )
    .bind(row.id, paidTo, String(reason || "recovered").slice(0, 200))
    .run();

  await logContEvent(env, row.id, "recovered", {
    actor_repo: null,
    note: reason + " → " + paidTo + (slashed ? " slash=" + slashed : ""),
  });

  await adjustRep(env, row.owner_repo, -CREDIT_REP_FAIL_PENALTY, "continuity_missed", row.id);

  if (row.created_by) {
    scheduleWebhook(ctx, env, row.created_by, "continuity.recovered", {
      id: row.id,
      owner_repo: row.owner_repo,
      successor_repo: row.successor_repo,
      recovered_to: paidTo,
      bond_usd: bond,
      refunded,
      slashed,
      reason: reason || "recovered",
      status: "recovered",
    });
  }

  return { recovered_to: paidTo, refunded, slashed, bond };
}

export async function handleContinuityOpen(request, env, ctx) {
  const t0 = Date.now();
  const authUser = await getAuthUser(request, env);
  if (!authUser) return bad(request, "Sign in or API key required", 401);

  const rlId =
    authUser.auth_via === "api_key"
      ? "ct:key:" + (authUser.key_id || authUser.id)
      : "ct:user:" + authUser.id;
  const limited = await checkRateLimit(env, rlId, RL_CONT_MAX, RL_CONT_WINDOW_SEC);
  if (limited) {
    return bad(request, "Rate limit: continuity ops", 429, { retry_after_sec: limited.retry_after_sec });
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return bad(request, "Invalid JSON body");
  }

  let ownerRepo = parseRepo(body.owner_repo || body.from_repo);
  if (!ownerRepo && authUser.default_repo) ownerRepo = parseRepo(authUser.default_repo);
  const successorRepo = body.successor_repo ? parseRepo(body.successor_repo) : null;
  const intervalSec = parseContInterval(body);
  const graceSec = parseContGrace(body);
  const missLimit = Math.min(
    CONT_MAX_MISS_LIMIT,
    Math.max(1, Math.floor(Number(body.miss_limit) || CONT_DEFAULT_MISS_LIMIT))
  );
  let bond = body.bond_usd != null ? parseAmount(body.bond_usd) : 0;
  if (bond == null) bond = 0;
  if (bond < CONT_MIN_BOND || bond > CONT_MAX_BOND) return bad(request, "bond_usd invalid");

  let recoveryAction = String(body.recovery_action || "refund").toLowerCase();
  if (!["refund", "successor", "slash_refund"].includes(recoveryAction)) {
    return bad(request, "recovery_action must be refund | successor | slash_refund");
  }
  if (recoveryAction === "successor" && !successorRepo) {
    return bad(request, "successor_repo required when recovery_action=successor");
  }
  const slashBps = Math.min(10000, Math.max(0, Math.floor(Number(body.slash_bps) || 0)));

  const refType = String(body.ref_type || "standalone").slice(0, 40);
  const refId = body.ref_id ? String(body.ref_id).slice(0, 80) : null;
  const label = body.label ? String(body.label).slice(0, 200) : null;

  if (!ownerRepo) return bad(request, "owner_repo required (or set default agent)");
  if (intervalSec == null) return bad(request, "interval_sec out of range");
  if (graceSec == null) return bad(request, "grace_sec out of range");

  if (bond > 0) {
    authUser._policyCtx = { to_repo: SYSTEM_CONTINUITY, task: "continuity:open" };
    const blocked = await safetyGate(request, env, authUser, ownerRepo, bond);
    if (blocked) return blocked;

    const debitRes = await debitWithCredit(env, ownerRepo, bond);
    if (!debitRes.ok) {
      return bad(request, debitRes.error || "Insufficient funds", debitRes.code === "wallet_locked" ? 403 : 402, {
        code: debitRes.code || "insufficient",
      });
    }
  }

  const id = "ct_" + randomId(12);
  const totalWindow = intervalSec + graceSec;
  const modifier = "+" + totalWindow + " seconds";

  try {
    if (bond > 0) await ensureAccount(env, SYSTEM_CONTINUITY);
    const stmts = [
      env.DB.prepare(
        `INSERT INTO continuity_sessions (
           id, owner_repo, successor_repo, ref_type, ref_id, bond_usd, status,
           interval_sec, grace_sec, miss_limit, miss_count,
           last_heartbeat_at, next_deadline_at, recovery_action, slash_bps,
           created_by, label, created_at, updated_at
         ) VALUES (
           ?1, ?2, ?3, ?4, ?5, ?6, 'active',
           ?7, ?8, ?9, 0,
           datetime('now'), datetime('now', ?10), ?11, ?12,
           ?13, ?14, datetime('now'), datetime('now')
         )`
      ).bind(
        id,
        ownerRepo,
        successorRepo,
        refType,
        refId,
        bond,
        intervalSec,
        graceSec,
        missLimit,
        modifier,
        recoveryAction,
        slashBps,
        authUser.id,
        label
      ),
    ];
    if (bond > 0) {
      stmts.push(
        env.DB.prepare(
          `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
           VALUES (?1, ?2, ?3, ?4, 'success', ?5)`
        ).bind(ownerRepo, SYSTEM_CONTINUITY, bond, "continuity-bond:" + id, Date.now() - t0)
      );
    }
    await env.DB.batch(stmts);
  } catch (e) {
    if (bond > 0) {
      await env.DB.prepare(
        `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
      )
        .bind(bond, ownerRepo)
        .run()
        .catch(() => {});
    }
    return bad(
      request,
      "continuity_sessions table missing — run d1-continuity-migration.sql: " + (e.message || e),
      500
    );
  }

  if (bond > 0) await safetyRecordSpend(env, authUser, ownerRepo, bond);
  await logContEvent(env, id, "opened", { actor_repo: ownerRepo, note: label || refType });

  if (authUser.id) {
    scheduleWebhook(ctx, env, authUser.id, "continuity.opened", {
      id,
      owner_repo: ownerRepo,
      successor_repo: successorRepo,
      bond_usd: bond,
      interval_sec: intervalSec,
      grace_sec: graceSec,
      recovery_action: recoveryAction,
      status: "active",
    });
  }

  return json(request, {
    ok: true,
    session: {
      id,
      owner_repo: ownerRepo,
      successor_repo: successorRepo,
      bond_usd: bond,
      status: "active",
      interval_sec: intervalSec,
      grace_sec: graceSec,
      miss_limit: missLimit,
      recovery_action: recoveryAction,
      slash_bps: slashBps,
      ref_type: refType,
      ref_id: refId,
      label,
    },
    latency_ms: Date.now() - t0,
    hint: "POST /api/continuity/beat { id } before next_deadline_at or recovery fires.",
  });
}

export async function handleContinuityBeat(request, env, ctx) {
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
    row = await env.DB.prepare(`SELECT * FROM continuity_sessions WHERE id = ?1`).bind(id).first();
  } catch {
    return bad(request, "continuity_sessions table missing — run d1-continuity-migration.sql", 500);
  }
  if (!row) return bad(request, "Session not found", 404);
  if (row.status !== "active") {
    return bad(request, "Session not active (status=" + row.status + ")", 400, { code: "cont_closed" });
  }

  const allowed =
    authUser.id === row.created_by ||
    (authUser.default_repo && authUser.default_repo === row.owner_repo) ||
    (authUser.auth_via === "api_key" && authUser.default_repo === row.owner_repo);
  if (!allowed) return bad(request, "Not authorized to heartbeat this session", 403);

  // If already past deadline, do not accept beat — force recovery path
  if (row.next_deadline_at) {
    const expMs = Date.parse(String(row.next_deadline_at).replace(" ", "T") + "Z");
    if (Number.isFinite(expMs) && expMs < Date.now()) {
      return bad(request, "Deadline passed — session will recover on cron or POST /api/continuity/recover", 400, {
        code: "cont_deadline_passed",
      });
    }
  }

  const intervalSec = Number(row.interval_sec);
  const graceSec = Number(row.grace_sec || 0);
  const modifier = "+" + (intervalSec + graceSec) + " seconds";

  const upd = await env.DB.prepare(
    `UPDATE continuity_sessions
     SET last_heartbeat_at = datetime('now'),
         next_deadline_at = datetime('now', ?2),
         miss_count = 0,
         updated_at = datetime('now')
     WHERE id = ?1 AND status = 'active'
     RETURNING *`
  )
    .bind(id, modifier)
    .first();
  if (!upd) return bad(request, "Beat race", 409);

  await logContEvent(env, id, "beat", {
    actor_repo: authUser.default_repo || row.owner_repo,
    note: body.note ? String(body.note).slice(0, 200) : null,
  });

  if (row.created_by) {
    scheduleWebhook(ctx, env, row.created_by, "continuity.beat", {
      id,
      owner_repo: row.owner_repo,
      next_deadline_at: upd.next_deadline_at,
      status: "active",
    });
  }

  return json(request, {
    ok: true,
    id,
    status: "active",
    last_heartbeat_at: upd.last_heartbeat_at,
    next_deadline_at: upd.next_deadline_at,
    latency_ms: Date.now() - t0,
  });
}

export async function handleContinuityClose(request, env, ctx) {
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
    row = await env.DB.prepare(`SELECT * FROM continuity_sessions WHERE id = ?1`).bind(id).first();
  } catch {
    return bad(request, "continuity_sessions table missing — run d1-continuity-migration.sql", 500);
  }
  if (!row) return bad(request, "Session not found", 404);
  if (row.status !== "active") return bad(request, "Session not active", 400);

  const allowed =
    authUser.id === row.created_by ||
    (authUser.default_repo && authUser.default_repo === row.owner_repo);
  if (!allowed) return bad(request, "Not authorized to close", 403);

  const claim = await env.DB.prepare(
    `UPDATE continuity_sessions
     SET status = 'closed', closed_at = datetime('now'), close_reason = 'closed',
         updated_at = datetime('now')
     WHERE id = ?1 AND status = 'active'
     RETURNING *`
  )
    .bind(id)
    .first();
  if (!claim) return bad(request, "Close race", 409);

  const bond = Number(row.bond_usd || 0);
  if (bond > 0) {
    await ensureAccount(env, row.owner_repo);
    await env.DB.batch([
      env.DB.prepare(
        `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
      ).bind(bond, row.owner_repo),
      env.DB.prepare(
        `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
         VALUES (?1, ?2, ?3, ?4, 'success', ?5)`
      ).bind(SYSTEM_CONTINUITY, row.owner_repo, bond, "continuity-close-refund:" + id, Date.now() - t0),
    ]);
  }

  await logContEvent(env, id, "closed", { actor_repo: row.owner_repo, note: "owner_close" });

  if (row.created_by) {
    scheduleWebhook(ctx, env, row.created_by, "continuity.closed", {
      id,
      owner_repo: row.owner_repo,
      refunded: bond,
      status: "closed",
    });
  }

  return json(request, {
    ok: true,
    id,
    status: "closed",
    refunded: bond,
    latency_ms: Date.now() - t0,
  });
}

export async function handleContinuityRecover(request, env, ctx) {
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
    row = await env.DB.prepare(`SELECT * FROM continuity_sessions WHERE id = ?1`).bind(id).first();
  } catch {
    return bad(request, "continuity_sessions table missing — run d1-continuity-migration.sql", 500);
  }
  if (!row) return bad(request, "Session not found", 404);
  if (row.status !== "active") return bad(request, "Session not active", 400);

  // Manual recover: creator, owner, or successor may trigger if deadline passed
  const pastDeadline =
    row.next_deadline_at &&
    Date.parse(String(row.next_deadline_at).replace(" ", "T") + "Z") < Date.now();
  if (!pastDeadline) {
    return bad(request, "Deadline not yet passed — keep beating or wait", 400, {
      code: "cont_not_due",
      next_deadline_at: row.next_deadline_at,
    });
  }

  const claim = await env.DB.prepare(
    `UPDATE continuity_sessions SET status = 'recovering', updated_at = datetime('now')
     WHERE id = ?1 AND status = 'active' RETURNING *`
  )
    .bind(id)
    .first();
  if (!claim) return bad(request, "Recover race", 409);

  const result = await recoverContinuitySession(env, claim, body.reason || "manual_recover", t0, ctx);
  return json(request, {
    ok: true,
    id,
    status: "recovered",
    ...result,
    latency_ms: Date.now() - t0,
  });
}

export async function handleContinuityGet(request, env, id) {
  id = String(id || "").trim();
  if (!id) return bad(request, "id required");
  const row = await loadContSession(env, id);
  if (!row) {
    try {
      await env.DB.prepare(`SELECT 1 FROM continuity_sessions LIMIT 1`).first();
    } catch {
      return bad(request, "continuity_sessions table missing — run d1-continuity-migration.sql", 500);
    }
    return bad(request, "Session not found", 404);
  }
  let events = [];
  try {
    const q = await env.DB.prepare(
      `SELECT event, actor_repo, note, created_at
       FROM continuity_events WHERE session_id = ?1 ORDER BY created_at DESC LIMIT 40`
    )
      .bind(id)
      .all();
    events = q.results || [];
  } catch (_) {}
  return json(request, { ok: true, session: row, events });
}

export async function handleContinuityList(request, url, env) {
  const limit = Math.min(Math.max(Number(url.searchParams.get("limit") || 20), 1), 100);
  const repo = (url.searchParams.get("repo") || "").trim();
  const status = (url.searchParams.get("status") || "").trim();

  let sql = `SELECT id, owner_repo, successor_repo, ref_type, ref_id, bond_usd, status,
                    interval_sec, grace_sec, miss_limit, miss_count,
                    last_heartbeat_at, next_deadline_at, recovery_action,
                    recovered_to, label, created_at
             FROM continuity_sessions WHERE 1=1`;
  const binds = [];
  if (repo) {
    if (!parseRepo(repo)) return bad(request, "repo must be owner/repo");
    sql += ` AND (owner_repo = ? OR successor_repo = ?)`;
    binds.push(repo, repo);
  }
  if (status && ["active", "recovered", "closed", "expired"].includes(status)) {
    sql += ` AND status = ?`;
    binds.push(status);
  }
  sql += ` ORDER BY created_at DESC LIMIT ?`;
  binds.push(limit);

  try {
    const { results } = await env.DB.prepare(sql).bind(...binds).all();
    return json(request, { ok: true, count: results.length, sessions: results });
  } catch (e) {
    return bad(
      request,
      "continuity_sessions table missing — run d1-continuity-migration.sql: " + (e.message || e),
      500
    );
  }
}

export async function expireContinuitySessions(env, ctx) {
  const t0 = Date.now();
  let recovered = 0;
  let bondTotal = 0;
  try {
    const q = await env.DB.prepare(
      `SELECT * FROM continuity_sessions
       WHERE status = 'active'
         AND next_deadline_at IS NOT NULL
         AND next_deadline_at < datetime('now')
       ORDER BY next_deadline_at ASC LIMIT ?1`
    )
      .bind(EXPIRE_CONT_BATCH)
      .all();
    for (const row of q.results || []) {
      try {
        const missLimit = Number(row.miss_limit || 1);
        const nextMiss = Number(row.miss_count || 0) + 1;

        if (nextMiss < missLimit) {
          // Soft miss: extend once more by interval only, increment miss_count
          const intervalSec = Number(row.interval_sec);
          const modifier = "+" + intervalSec + " seconds";
          await env.DB.prepare(
            `UPDATE continuity_sessions
             SET miss_count = ?2,
                 next_deadline_at = datetime('now', ?3),
                 updated_at = datetime('now')
             WHERE id = ?1 AND status = 'active'`
          )
            .bind(row.id, nextMiss, modifier)
            .run();
          await logContEvent(env, row.id, "missed", {
            note: "miss " + nextMiss + "/" + missLimit,
          });
          if (row.created_by) {
            scheduleWebhook(ctx, env, row.created_by, "continuity.missed", {
              id: row.id,
              owner_repo: row.owner_repo,
              miss_count: nextMiss,
              miss_limit: missLimit,
              status: "active",
            });
          }
          continue;
        }

        const claim = await env.DB.prepare(
          `UPDATE continuity_sessions SET status = 'recovering', updated_at = datetime('now')
           WHERE id = ?1 AND status = 'active' RETURNING *`
        )
          .bind(row.id)
          .first();
        if (!claim) continue;
        const r = await recoverContinuitySession(env, claim, "heartbeat_timeout", t0, ctx);
        recovered += 1;
        bondTotal += Number(r.bond || 0);
      } catch (e) {
        console.log("cont_expire", row.id, e && e.message);
      }
    }
  } catch (e) {
    return { recovered: 0, error: e.message, latency_ms: Date.now() - t0 };
  }
  return { recovered, bond_total: bondTotal, latency_ms: Date.now() - t0 };
}


