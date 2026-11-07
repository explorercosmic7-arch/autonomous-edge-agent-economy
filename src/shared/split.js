/**
 * Revenue split — one debit from from_repo → N credits by bps (sum = 10000).
 *
 * POST /api/split          { from_repo?, amount, recipients:[{repo,bps}], task?, idempotency_key? }
 * GET  /api/split          ?repo=&limit=
 * GET  /api/split/:id
 *
 * Immediate execute (v1). Residual rounding → last leg.
 * Scope verb: pay. safetyGate on total amount; each to_repo checked against key allowlist.
 */
import { json, bad } from "./http.js";
import { parseRepo, parseAmount, randomId } from "./utils.js";
import { checkRateLimit } from "./rateLimit.js";
import { getAuthUser, rejectIfSuspendedKey } from "./auth.js";
import { ensureAccount } from "./accounts.js";
import { debitWithCredit } from "./credit.js";
import { safetyGate, safetyRecordSpend } from "./gate.js";
import { scheduleWebhook } from "./webhooks.js";
import { applyScopeVerb, checkKeyScope } from "./scopes.js";
import {
  RL_SPLIT_MAX,
  RL_SPLIT_WINDOW_SEC,
  SPLIT_MIN,
  SPLIT_MAX,
  SPLIT_MAX_LEGS,
  SPLIT_MIN_LEGS,
} from "./constants.js";

const BPS_TOTAL = 10000;

function parseRecipients(raw) {
  if (!Array.isArray(raw) || !raw.length) return { error: "recipients array required" };
  if (raw.length < SPLIT_MIN_LEGS) {
    return { error: "Need at least " + SPLIT_MIN_LEGS + " recipients" };
  }
  if (raw.length > SPLIT_MAX_LEGS) {
    return { error: "Max " + SPLIT_MAX_LEGS + " recipients" };
  }
  const legs = [];
  let bpsSum = 0;
  const seen = new Set();
  for (const row of raw) {
    const repo = parseRepo(row.repo || row.to_repo || row.toRepo);
    if (!repo) return { error: "Each recipient needs repo as owner/repo" };
    if (seen.has(repo)) return { error: "Duplicate recipient: " + repo };
    seen.add(repo);
    const bps = Math.floor(Number(row.bps));
    if (!Number.isFinite(bps) || bps < 1 || bps > BPS_TOTAL) {
      return { error: "Each bps must be integer 1.." + BPS_TOTAL };
    }
    bpsSum += bps;
    legs.push({ repo, bps });
  }
  if (bpsSum !== BPS_TOTAL) {
    return {
      error: "bps must sum to " + BPS_TOTAL + " (got " + bpsSum + ")",
      code: "bps_sum",
      bps_sum: bpsSum,
    };
  }
  return { legs };
}

function allocateAmounts(total, legs) {
  const out = [];
  let allocated = 0;
  for (let i = 0; i < legs.length; i++) {
    let amt;
    if (i === legs.length - 1) {
      amt = Math.round((total - allocated) * 1e6) / 1e6;
    } else {
      amt = Math.round(((total * legs[i].bps) / BPS_TOTAL) * 1e6) / 1e6;
      allocated = Math.round((allocated + amt) * 1e6) / 1e6;
    }
    if (amt < 0) amt = 0;
    out.push({ repo: legs[i].repo, bps: legs[i].bps, amount_usd: amt });
  }
  return out;
}

export async function loadSplit(env, id) {
  try {
    return await env.DB.prepare(`SELECT * FROM revenue_splits WHERE id = ?1`)
      .bind(id)
      .first();
  } catch {
    return null;
  }
}

export async function loadSplitLegs(env, splitId) {
  try {
    const { results } = await env.DB.prepare(
      `SELECT id, to_repo, bps, amount_usd, created_at
       FROM revenue_split_legs WHERE split_id = ?1 ORDER BY rowid ASC`
    )
      .bind(splitId)
      .all();
    return results || [];
  } catch {
    return [];
  }
}

export async function handleSplitCreate(request, env, ctx) {
  const t0 = Date.now();
  const authUser = await getAuthUser(request, env);
  if (!authUser) return bad(request, "Sign in or API key required", 401);
  const sus = rejectIfSuspendedKey(request, authUser);
  if (sus) return sus;

  applyScopeVerb(authUser, "pay");

  const rlId =
    authUser.auth_via === "api_key"
      ? "split:key:" + (authUser.key_id || authUser.id)
      : "split:user:" + authUser.id;
  const limited = await checkRateLimit(env, rlId, RL_SPLIT_MAX, RL_SPLIT_WINDOW_SEC);
  if (limited) {
    return bad(request, "Rate limit: split ops", 429, {
      retry_after_sec: limited.retry_after_sec,
    });
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return bad(request, "Invalid JSON body");
  }

  let fromRepo = parseRepo(body.from_repo || body.fromRepo);
  if (!fromRepo && authUser.default_repo) {
    fromRepo = parseRepo(authUser.default_repo);
  }
  const amount = parseAmount(body.amount ?? body.amount_usd);
  const task = body.task != null ? String(body.task).slice(0, 500) : null;
  const idem =
    String(request.headers.get("Idempotency-Key") || body.idempotency_key || "")
      .trim()
      .slice(0, 128) || null;

  if (!fromRepo) {
    return bad(request, "from_repo required (or set default agent)");
  }
  if (amount == null || amount < SPLIT_MIN || amount > SPLIT_MAX) {
    return bad(request, "amount invalid");
  }

  const parsed = parseRecipients(body.recipients || body.legs || body.to);
  if (parsed.error) {
    return bad(request, parsed.error, 400, {
      code: parsed.code || "invalid_recipients",
      bps_sum: parsed.bps_sum,
    });
  }
  const legsIn = parsed.legs;
  if (legsIn.some((l) => l.repo === fromRepo)) {
    return bad(request, "from_repo cannot be a recipient", 400, {
      code: "self_recipient",
    });
  }

  if (authUser.auth_via === "api_key") {
    const scopeHit = checkKeyScope(authUser, "pay", {
      amount,
      toRepo: legsIn[0].repo,
    });
    if (scopeHit) {
      return bad(request, scopeHit.error, scopeHit.status || 403, {
        code: scopeHit.code,
        required: scopeHit.required,
        max_amount_usd: scopeHit.max_amount_usd,
      });
    }
    for (const leg of legsIn) {
      const h = checkKeyScope(authUser, "pay", {
        amount: 0,
        toRepo: leg.repo,
      });
      if (h && h.code === "key_repo_denied") {
        return bad(request, h.error, h.status || 403, {
          code: h.code,
          to_repo: leg.repo,
        });
      }
    }
  }

  authUser._policyCtx = {
    to_repo: legsIn[0].repo,
    task: task || "revenue-split",
    idempotency_key: idem,
  };
  const blocked = await safetyGate(request, env, authUser, fromRepo, amount);
  if (blocked) return blocked;

  if (idem) {
    try {
      const existing = await env.DB.prepare(
        `SELECT id FROM revenue_splits WHERE idempotency_key = ?1`
      )
        .bind(idem)
        .first();
      if (existing) {
        const row = await loadSplit(env, existing.id);
        const legs = await loadSplitLegs(env, existing.id);
        return json(request, {
          ok: true,
          replayed: true,
          split: row,
          legs,
        });
      }
    } catch (e) {
      return bad(
        request,
        "revenue_splits table missing — run d1-split-migration.sql: " +
          (e.message || e),
        500
      );
    }
  }

  const allocated = allocateAmounts(amount, legsIn);
  const sumLegs = allocated.reduce((s, l) => s + l.amount_usd, 0);
  if (Math.abs(sumLegs - amount) > 0.000001) {
    return bad(request, "Internal allocation mismatch", 500);
  }

  await ensureAccount(env, fromRepo);
  for (const leg of allocated) {
    await ensureAccount(env, leg.repo);
  }

  const debitRes = await debitWithCredit(env, fromRepo, amount);
  if (!debitRes.ok) {
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

  const splitId = "spl_" + randomId(12);
  const keyId =
    authUser.auth_via === "api_key" ? authUser.key_id || null : null;
  const latency = Date.now() - t0;

  try {
    const stmts = [
      env.DB.prepare(
        `INSERT INTO revenue_splits (
           id, from_repo, amount_usd, task, status, legs_count,
           created_by, api_key_id, idempotency_key, created_at, updated_at
         ) VALUES (
           ?1, ?2, ?3, ?4, 'completed', ?5,
           ?6, ?7, ?8, datetime('now'), datetime('now')
         )`
      ).bind(
        splitId,
        fromRepo,
        amount,
        task,
        allocated.length,
        authUser.id || null,
        keyId,
        idem
      ),
    ];

    for (const leg of allocated) {
      const legId = "sl_" + randomId(10);
      stmts.push(
        env.DB.prepare(
          `INSERT INTO revenue_split_legs (
             id, split_id, to_repo, bps, amount_usd, created_at
           ) VALUES (?1, ?2, ?3, ?4, ?5, datetime('now'))`
        ).bind(legId, splitId, leg.repo, leg.bps, leg.amount_usd)
      );
      stmts.push(
        env.DB.prepare(
          `UPDATE accounts
           SET balance = balance + ?1, updated_at = datetime('now')
           WHERE repo_id = ?2`
        ).bind(leg.amount_usd, leg.repo)
      );
      // Per-leg unique idempotency (transactions.idempotency_key is UNIQUE globally)
      const legIdem =
        (idem ? idem + ":" : "split:") + splitId + ":" + leg.repo;
      stmts.push(
        env.DB.prepare(
          `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms, idempotency_key)
           VALUES (?1, ?2, ?3, ?4, 'success', ?5, ?6)`
        ).bind(
          fromRepo,
          leg.repo,
          leg.amount_usd,
          "split:" + splitId + ":" + (task || "").slice(0, 40),
          latency,
          legIdem
        )
      );
    }

    await env.DB.batch(stmts);
  } catch (e) {
    try {
      await env.DB.prepare(
        `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
      )
        .bind(amount, fromRepo)
        .run();
      if (debitRes.credit_drawn > 0) {
        await env.DB.prepare(
          `UPDATE agent_limits
           SET outstanding_credit = MAX(0, COALESCE(outstanding_credit, 0) - ?2),
               updated_at = datetime('now')
           WHERE repo_id = ?1`
        )
          .bind(fromRepo, debitRes.credit_drawn)
          .run();
      }
    } catch (_) {}
    return bad(
      request,
      "Split settle failed — run d1-split-migration.sql if tables missing: " +
        (e.message || e),
      500
    );
  }

  try {
    await safetyRecordSpend(env, authUser, fromRepo, amount);
  } catch (_) {}

  if (authUser.id) {
    scheduleWebhook(ctx, env, authUser.id, "split.completed", {
      id: splitId,
      from_repo: fromRepo,
      amount_usd: amount,
      legs: allocated,
      status: "completed",
      task,
    });
  }

  return json(request, {
    ok: true,
    status: "completed",
    split: {
      id: splitId,
      from_repo: fromRepo,
      amount_usd: amount,
      task,
      status: "completed",
      legs_count: allocated.length,
    },
    legs: allocated.map((l) => ({
      to_repo: l.repo,
      bps: l.bps,
      amount_usd: l.amount_usd,
    })),
    credit_drawn: debitRes.credit_drawn || undefined,
    latency_ms: Date.now() - t0,
  });
}

export async function handleSplitGet(request, env, id) {
  id = String(id || "").trim();
  if (!id) return bad(request, "id required");
  const row = await loadSplit(env, id);
  if (!row) {
    try {
      await env.DB.prepare(`SELECT 1 FROM revenue_splits LIMIT 1`).first();
    } catch {
      return bad(
        request,
        "revenue_splits table missing — run d1-split-migration.sql",
        500
      );
    }
    return bad(request, "Split not found", 404);
  }
  const legs = await loadSplitLegs(env, id);
  return json(request, { ok: true, split: row, legs });
}

export async function handleSplitList(request, url, env) {
  const limit = Math.min(Math.max(Number(url.searchParams.get("limit") || 20), 1), 100);
  const repo = (url.searchParams.get("repo") || "").trim();
  let sql = `SELECT id, from_repo, amount_usd, task, status, legs_count, created_at
             FROM revenue_splits WHERE 1=1`;
  const binds = [];
  if (repo) {
    if (!parseRepo(repo)) return bad(request, "repo must be owner/repo");
    sql += ` AND from_repo = ?`;
    binds.push(repo);
  }
  sql += ` ORDER BY created_at DESC LIMIT ?`;
  binds.push(limit);
  try {
    const { results } = await env.DB.prepare(sql).bind(...binds).all();
    return json(request, {
      ok: true,
      count: (results || []).length,
      splits: results || [],
    });
  } catch (e) {
    return bad(
      request,
      "revenue_splits missing — run d1-split-migration.sql: " + (e.message || e),
      500
    );
  }
}
