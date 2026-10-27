/**
 * Shared Pool — collaborative / swarm co-funding + expireCollaborativePools cron.
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
  SYSTEM_POOL,
  POOL_MIN,
  POOL_MAX,
  POOL_DEFAULT_TTL_SEC,
  POOL_MIN_TTL_SEC,
  POOL_MAX_TTL_SEC,
  RL_POOL_MAX,
  RL_POOL_WINDOW_SEC,
  EXPIRE_POOL_BATCH,
  CREDIT_REP_SUCCESS_BONUS,
} from "./constants.js";

/* ─── Collaborative Pools (swarm co-funding) ───
 * Agents contribute cash into a shared pool toward target_amount.
 * When funded (or early release by creator), funds go to beneficiary_repo.
 * Expire/cancel refunds all held contributions.
 *
 * POST /api/pool/open       { beneficiary_repo, target_amount, task?, title?, ttl_seconds? }
 * POST /api/pool/contribute { id, amount, from_repo? }
 * POST /api/pool/release    { id }  — creator/beneficiary; requires funded or force
 * POST /api/pool/refund     { id }  — cancel open pool → refund contributors
 * GET  /api/pool            ?repo=&status=
 * GET  /api/pool/:id
 */

export function parsePoolTtl(body) {
  const sec = Number(body.ttl_seconds ?? body.ttl);
  if (Number.isFinite(sec)) {
    if (sec < POOL_MIN_TTL_SEC || sec > POOL_MAX_TTL_SEC) return null;
    return Math.floor(sec);
  }
  return POOL_DEFAULT_TTL_SEC;
}

export async function logPoolEvent(env, poolId, event, { actor_repo, note } = {}) {
  try {
    await env.DB.prepare(
      `INSERT INTO pool_events (id, pool_id, event, actor_repo, note, created_at)
       VALUES (?1, ?2, ?3, ?4, ?5, datetime('now'))`
    )
      .bind(
        randomId(10),
        poolId,
        event,
        actor_repo || null,
        note ? String(note).slice(0, 500) : null
      )
      .run();
  } catch (e) {
    console.log("pool_event_err", e && e.message);
  }
}

export async function loadPool(env, id) {
  try {
    return await env.DB.prepare(`SELECT * FROM collaborative_pools WHERE id = ?1`).bind(id).first();
  } catch {
    return null;
  }
}

export async function handlePoolOpen(request, env, ctx) {
  const t0 = Date.now();
  const authUser = await getAuthUser(request, env);
  if (!authUser) return bad(request, "Sign in or API key required", 401);

  const rlId =
    authUser.auth_via === "api_key"
      ? "pool:key:" + (authUser.key_id || authUser.id)
      : "pool:user:" + authUser.id;
  const limited = await checkRateLimit(env, rlId, RL_POOL_MAX, RL_POOL_WINDOW_SEC);
  if (limited) {
    return bad(request, "Rate limit: pool ops", 429, { retry_after_sec: limited.retry_after_sec });
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return bad(request, "Invalid JSON body");
  }

  let creatorRepo = parseRepo(body.creator_repo || body.from_repo);
  if (!creatorRepo && authUser.default_repo) creatorRepo = parseRepo(authUser.default_repo);
  const beneficiary = parseRepo(body.beneficiary_repo || body.to_repo || body.beneficiary);
  const target = parseAmount(body.target_amount ?? body.amount);
  const task = String(body.task || "swarm-pool").slice(0, 500);
  const title = body.title ? String(body.title).slice(0, 200) : null;
  const ttlSec = parsePoolTtl(body);
  const minContrib = body.min_contribution != null ? parseAmount(body.min_contribution) : POOL_MIN;

  if (!creatorRepo) return bad(request, "creator_repo required (or set default agent)");
  if (!beneficiary) return bad(request, "beneficiary_repo required");
  if (target == null || target < POOL_MIN || target > POOL_MAX) return bad(request, "target_amount invalid");
  if (ttlSec == null) return bad(request, "ttl_seconds out of range");
  if (minContrib == null || minContrib < POOL_MIN) return bad(request, "min_contribution invalid");

  const id = "pl_" + randomId(12);
  const modifier = "+" + ttlSec + " seconds";

  try {
    await env.DB.prepare(
      `INSERT INTO collaborative_pools (
         id, title, creator_repo, beneficiary_repo, task,
         target_amount, funded_amount, min_contribution, status,
         ttl_seconds, expires_at, created_by, created_at, updated_at
       ) VALUES (
         ?1, ?2, ?3, ?4, ?5,
         ?6, 0, ?7, 'open',
         ?8, datetime('now', ?9), ?10, datetime('now'), datetime('now')
       )`
    )
      .bind(
        id,
        title,
        creatorRepo,
        beneficiary,
        task,
        target,
        minContrib,
        ttlSec,
        modifier,
        authUser.id
      )
      .run();
  } catch (e) {
    return bad(
      request,
      "collaborative_pools table missing — run d1-pool-migration.sql: " + (e.message || e),
      500
    );
  }

  await logPoolEvent(env, id, "opened", { actor_repo: creatorRepo, note: title || task });

  if (authUser.id) {
    scheduleWebhook(ctx, env, authUser.id, "pool.opened", {
      id,
      creator_repo: creatorRepo,
      beneficiary_repo: beneficiary,
      target_amount: target,
      task,
      status: "open",
    });
  }

  return json(request, {
    ok: true,
    pool: {
      id,
      title,
      creator_repo: creatorRepo,
      beneficiary_repo: beneficiary,
      task,
      target_amount: target,
      funded_amount: 0,
      min_contribution: minContrib,
      status: "open",
      ttl_seconds: ttlSec,
    },
    latency_ms: Date.now() - t0,
    hint: "Others POST /api/pool/contribute { id, amount }. Release when funded.",
  });
}

export async function handlePoolContribute(request, env, ctx) {
  const t0 = Date.now();
  const authUser = await getAuthUser(request, env);
  if (!authUser) return bad(request, "Sign in or API key required", 401);

  const rlId =
    authUser.auth_via === "api_key"
      ? "pool:key:" + (authUser.key_id || authUser.id)
      : "pool:user:" + authUser.id;
  const limited = await checkRateLimit(env, rlId, RL_POOL_MAX, RL_POOL_WINDOW_SEC);
  if (limited) {
    return bad(request, "Rate limit: pool ops", 429, { retry_after_sec: limited.retry_after_sec });
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return bad(request, "Invalid JSON body");
  }

  const id = String(body.id || "").trim();
  const amount = parseAmount(body.amount);
  let fromRepo = parseRepo(body.from_repo || body.fromRepo);
  if (!fromRepo && authUser.default_repo) fromRepo = parseRepo(authUser.default_repo);

  if (!id) return bad(request, "id required");
  if (!fromRepo) return bad(request, "from_repo required (or set default agent)");
  if (amount == null) return bad(request, "amount invalid");

  const pool = await loadPool(env, id);
  if (!pool) {
    try {
      await env.DB.prepare(`SELECT 1 FROM collaborative_pools LIMIT 1`).first();
    } catch {
      return bad(request, "collaborative_pools table missing — run d1-pool-migration.sql", 500);
    }
    return bad(request, "Pool not found", 404);
  }
  if (pool.status !== "open") {
    return bad(request, "Pool not open (status=" + pool.status + ")", 400, { code: "pool_closed" });
  }
  if (pool.expires_at) {
    const expMs = Date.parse(String(pool.expires_at).replace(" ", "T") + "Z");
    if (Number.isFinite(expMs) && expMs < Date.now()) {
      return bad(request, "Pool expired — wait for refund cron or POST /api/pool/refund", 400, {
        code: "pool_expired",
      });
    }
  }

  const minC = Number(pool.min_contribution || POOL_MIN);
  if (amount < minC) {
    return bad(request, "Contribution below min_contribution ($" + minC + ")", 400);
  }

  const remaining = Math.round((Number(pool.target_amount) - Number(pool.funded_amount || 0)) * 1e6) / 1e6;
  if (remaining <= 0) {
    return bad(request, "Pool already at target", 400, { code: "pool_full" });
  }
  const applyAmt = Math.min(amount, remaining);

  authUser._policyCtx = { to_repo: SYSTEM_POOL, task: "pool:contribute:" + id };
  const blocked = await safetyGate(request, env, authUser, fromRepo, applyAmt);
  if (blocked) return blocked;

  const debitRes = await debitWithCredit(env, fromRepo, applyAmt);
  if (!debitRes.ok) {
    return bad(request, debitRes.error || "Insufficient funds", debitRes.code === "wallet_locked" ? 403 : 402, {
      code: debitRes.code || "insufficient",
      available_credit: debitRes.available_credit,
    });
  }

  const cid = "pc_" + randomId(10);
  try {
    await ensureAccount(env, SYSTEM_POOL);
    await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO pool_contributions (
           id, pool_id, from_repo, amount, status, created_by, created_at
         ) VALUES (?1, ?2, ?3, ?4, 'held', ?5, datetime('now'))`
      ).bind(cid, id, fromRepo, applyAmt, authUser.id),
      env.DB.prepare(
        `UPDATE collaborative_pools
         SET funded_amount = funded_amount + ?2,
             status = CASE
               WHEN funded_amount + ?2 >= target_amount THEN 'funded'
               ELSE status
             END,
             updated_at = datetime('now')
         WHERE id = ?1 AND status = 'open'`
      ).bind(id, applyAmt),
      env.DB.prepare(
        `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
         VALUES (?1, ?2, ?3, ?4, 'success', ?5)`
      ).bind(fromRepo, SYSTEM_POOL, applyAmt, "pool-contribute:" + id, Date.now() - t0),
    ]);
  } catch (e) {
    await env.DB.prepare(
      `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
    )
      .bind(applyAmt, fromRepo)
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
    return bad(request, "Contribute failed: " + (e.message || e), 500);
  }

  await safetyRecordSpend(env, authUser, fromRepo, applyAmt);
  await logPoolEvent(env, id, "contributed", {
    actor_repo: fromRepo,
    note: "$" + applyAmt,
  });

  const updated = await loadPool(env, id);
  const funded = Number(updated?.funded_amount || 0);
  const target = Number(pool.target_amount);
  const status = updated?.status || "open";

  if (pool.created_by) {
    scheduleWebhook(ctx, env, pool.created_by, "pool.contributed", {
      id,
      contribution_id: cid,
      from_repo: fromRepo,
      amount: applyAmt,
      funded_amount: funded,
      target_amount: target,
      status,
    });
  }
  if (status === "funded" && pool.created_by) {
    scheduleWebhook(ctx, env, pool.created_by, "pool.funded", {
      id,
      funded_amount: funded,
      target_amount: target,
      status: "funded",
    });
  }

  return json(request, {
    ok: true,
    contribution_id: cid,
    pool_id: id,
    from_repo: fromRepo,
    amount: applyAmt,
    funded_amount: funded,
    target_amount: target,
    status,
    ready_to_release: status === "funded",
    latency_ms: Date.now() - t0,
  });
}

export async function handlePoolRelease(request, env, ctx) {
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

  const pool = await loadPool(env, id);
  if (!pool) return bad(request, "Pool not found", 404);
  if (!["open", "funded"].includes(pool.status)) {
    return bad(request, "Pool not releasable (status=" + pool.status + ")", 400);
  }

  const allowed =
    authUser.id === pool.created_by ||
    (authUser.default_repo &&
      (authUser.default_repo === pool.creator_repo ||
        authUser.default_repo === pool.beneficiary_repo));
  if (!allowed) return bad(request, "Not authorized to release this pool", 403);

  const funded = Number(pool.funded_amount || 0);
  if (funded <= 0) return bad(request, "Nothing funded to release", 400);

  // Default: require fully funded unless force=true (creator only)
  const force = body.force === true;
  if (pool.status !== "funded" && funded < Number(pool.target_amount)) {
    if (!force || authUser.id !== pool.created_by) {
      return bad(
        request,
        "Pool not fully funded ($" +
          funded +
          " / $" +
          pool.target_amount +
          "). Creator may pass force:true for early release.",
        400,
        { code: "underfunded", funded_amount: funded, target_amount: Number(pool.target_amount) }
      );
    }
  }

  const claim = await env.DB.prepare(
    `UPDATE collaborative_pools
     SET status = 'released', released_at = datetime('now'), updated_at = datetime('now')
     WHERE id = ?1 AND status IN ('open', 'funded')
     RETURNING *`
  )
    .bind(id)
    .first();
  if (!claim) return bad(request, "Release race", 409);

  await ensureAccount(env, pool.beneficiary_repo);
  await ensureAccount(env, SYSTEM_POOL);
  await env.DB.batch([
    env.DB.prepare(
      `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
    ).bind(funded, pool.beneficiary_repo),
    env.DB.prepare(
      `UPDATE pool_contributions SET status = 'released' WHERE pool_id = ?1 AND status = 'held'`
    ).bind(id),
    env.DB.prepare(
      `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
       VALUES (?1, ?2, ?3, ?4, 'success', ?5)`
    ).bind(
      SYSTEM_POOL,
      pool.beneficiary_repo,
      funded,
      "pool-release:" + id + ":" + (pool.task || "").slice(0, 40),
      Date.now() - t0
    ),
  ]);

  await logPoolEvent(env, id, "released", {
    actor_repo: authUser.default_repo || pool.creator_repo,
    note: "$" + funded + " → " + pool.beneficiary_repo,
  });
  await adjustRep(env, pool.beneficiary_repo, CREDIT_REP_SUCCESS_BONUS, "pool_release", id);

  if (pool.created_by) {
    scheduleWebhook(ctx, env, pool.created_by, "pool.released", {
      id,
      beneficiary_repo: pool.beneficiary_repo,
      amount: funded,
      status: "released",
    });
  }

  return json(request, {
    ok: true,
    id,
    status: "released",
    paid_to: pool.beneficiary_repo,
    amount: funded,
    latency_ms: Date.now() - t0,
  });
}

export async function handlePoolRefund(request, env, ctx) {
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

  const pool = await loadPool(env, id);
  if (!pool) return bad(request, "Pool not found", 404);
  if (!["open", "funded"].includes(pool.status)) {
    return bad(request, "Pool not refundable (status=" + pool.status + ")", 400);
  }

  const allowed =
    authUser.id === pool.created_by ||
    (authUser.default_repo && authUser.default_repo === pool.creator_repo);
  if (!allowed) return bad(request, "Not authorized to refund this pool", 403);

  const claim = await env.DB.prepare(
    `UPDATE collaborative_pools
     SET status = 'cancelled', cancelled_at = datetime('now'), updated_at = datetime('now')
     WHERE id = ?1 AND status IN ('open', 'funded')
     RETURNING *`
  )
    .bind(id)
    .first();
  if (!claim) return bad(request, "Refund race", 409);

  let contribs = [];
  try {
    const q = await env.DB.prepare(
      `SELECT id, from_repo, amount FROM pool_contributions
       WHERE pool_id = ?1 AND status = 'held'`
    )
      .bind(id)
      .all();
    contribs = q.results || [];
  } catch (_) {}

  let refundedTotal = 0;
  for (const c of contribs) {
    try {
      await ensureAccount(env, c.from_repo);
      await env.DB.batch([
        env.DB.prepare(
          `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
        ).bind(c.amount, c.from_repo),
        env.DB.prepare(
          `UPDATE pool_contributions SET status = 'refunded' WHERE id = ?1`
        ).bind(c.id),
        env.DB.prepare(
          `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
           VALUES (?1, ?2, ?3, ?4, 'success', 0)`
        ).bind(SYSTEM_POOL, c.from_repo, c.amount, "pool-refund:" + id),
      ]);
      refundedTotal += Number(c.amount);
    } catch (e) {
      console.log("pool_refund_one", c.id, e && e.message);
    }
  }

  await env.DB.prepare(
    `UPDATE collaborative_pools SET funded_amount = 0, updated_at = datetime('now') WHERE id = ?1`
  )
    .bind(id)
    .run();

  await logPoolEvent(env, id, "cancelled", {
    actor_repo: authUser.default_repo || pool.creator_repo,
    note: "refunded $" + refundedTotal,
  });

  if (pool.created_by) {
    scheduleWebhook(ctx, env, pool.created_by, "pool.cancelled", {
      id,
      refunded: refundedTotal,
      status: "cancelled",
    });
  }

  return json(request, {
    ok: true,
    id,
    status: "cancelled",
    refunded: refundedTotal,
    contributors: contribs.length,
    latency_ms: Date.now() - t0,
  });
}

export async function handlePoolGet(request, env, id) {
  id = String(id || "").trim();
  if (!id) return bad(request, "id required");
  const pool = await loadPool(env, id);
  if (!pool) {
    try {
      await env.DB.prepare(`SELECT 1 FROM collaborative_pools LIMIT 1`).first();
    } catch {
      return bad(request, "collaborative_pools table missing — run d1-pool-migration.sql", 500);
    }
    return bad(request, "Pool not found", 404);
  }
  let contributions = [];
  let events = [];
  try {
    const q = await env.DB.prepare(
      `SELECT id, from_repo, amount, status, created_at
       FROM pool_contributions WHERE pool_id = ?1 ORDER BY created_at ASC`
    )
      .bind(id)
      .all();
    contributions = q.results || [];
  } catch (_) {}
  try {
    const q = await env.DB.prepare(
      `SELECT event, actor_repo, note, created_at
       FROM pool_events WHERE pool_id = ?1 ORDER BY created_at DESC LIMIT 40`
    )
      .bind(id)
      .all();
    events = q.results || [];
  } catch (_) {}
  return json(request, { ok: true, pool, contributions, events });
}

export async function handlePoolList(request, url, env) {
  const limit = Math.min(Math.max(Number(url.searchParams.get("limit") || 20), 1), 100);
  const repo = (url.searchParams.get("repo") || "").trim();
  const status = (url.searchParams.get("status") || "").trim();

  let sql = `SELECT id, title, creator_repo, beneficiary_repo, task,
                    target_amount, funded_amount, min_contribution, status,
                    expires_at, created_at
             FROM collaborative_pools WHERE 1=1`;
  const binds = [];
  if (repo) {
    if (!parseRepo(repo)) return bad(request, "repo must be owner/repo");
    sql += ` AND (creator_repo = ? OR beneficiary_repo = ?)`;
    binds.push(repo, repo);
  }
  if (status && ["open", "funded", "released", "cancelled", "expired"].includes(status)) {
    sql += ` AND status = ?`;
    binds.push(status);
  }
  sql += ` ORDER BY created_at DESC LIMIT ?`;
  binds.push(limit);

  try {
    const { results } = await env.DB.prepare(sql).bind(...binds).all();
    return json(request, { ok: true, count: results.length, pools: results });
  } catch (e) {
    return bad(
      request,
      "collaborative_pools table missing — run d1-pool-migration.sql: " + (e.message || e),
      500
    );
  }
}

export async function expireCollaborativePools(env, ctx) {
  const t0 = Date.now();
  let expired = 0;
  let refundedTotal = 0;
  try {
    const q = await env.DB.prepare(
      `SELECT * FROM collaborative_pools
       WHERE status IN ('open', 'funded')
         AND expires_at IS NOT NULL
         AND expires_at < datetime('now')
       ORDER BY expires_at ASC LIMIT ?1`
    )
      .bind(EXPIRE_POOL_BATCH)
      .all();
    for (const pool of q.results || []) {
      try {
        const claim = await env.DB.prepare(
          `UPDATE collaborative_pools
           SET status = 'expired', cancelled_at = datetime('now'), updated_at = datetime('now')
           WHERE id = ?1 AND status IN ('open', 'funded') RETURNING id`
        )
          .bind(pool.id)
          .first();
        if (!claim) continue;

        const cq = await env.DB.prepare(
          `SELECT id, from_repo, amount FROM pool_contributions
           WHERE pool_id = ?1 AND status = 'held'`
        )
          .bind(pool.id)
          .all();
        for (const c of cq.results || []) {
          try {
            await ensureAccount(env, c.from_repo);
            await env.DB.batch([
              env.DB.prepare(
                `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
              ).bind(c.amount, c.from_repo),
              env.DB.prepare(
                `UPDATE pool_contributions SET status = 'refunded' WHERE id = ?1`
              ).bind(c.id),
              env.DB.prepare(
                `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
                 VALUES (?1, ?2, ?3, ?4, 'success', 0)`
              ).bind(SYSTEM_POOL, c.from_repo, c.amount, "pool-expire-refund:" + pool.id),
            ]);
            refundedTotal += Number(c.amount);
          } catch (e) {
            console.log("pool_expire_one", c.id, e && e.message);
          }
        }
        await env.DB.prepare(
          `UPDATE collaborative_pools SET funded_amount = 0, updated_at = datetime('now') WHERE id = ?1`
        )
          .bind(pool.id)
          .run();
        await logPoolEvent(env, pool.id, "expired", { note: "ttl" });
        expired += 1;
        if (pool.created_by) {
          scheduleWebhook(ctx, env, pool.created_by, "pool.expired", {
            id: pool.id,
            status: "expired",
          });
        }
      } catch (e) {
        console.log("pool_expire", pool.id, e && e.message);
      }
    }
  } catch (e) {
    return { expired: 0, error: e.message, latency_ms: Date.now() - t0 };
  }
  return { expired, refunded_total: refundedTotal, latency_ms: Date.now() - t0 };
}


