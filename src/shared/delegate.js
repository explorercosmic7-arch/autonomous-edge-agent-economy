/**
 * Shared Delegation — parent authority / child pocket money + expireDelegations cron.
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
import { debitWithCredit } from "./credit.js";
import { scheduleWebhook } from "./webhooks.js";
import { safetyGate, safetyRecordSpend } from "./gate.js";
import {
  SYSTEM_DELEGATE,
  DELEGATE_MIN,
  DELEGATE_MAX,
  DELEGATE_DEFAULT_TTL_SEC,
  DELEGATE_MIN_TTL_SEC,
  DELEGATE_MAX_TTL_SEC,
  RL_DELEGATE_MAX,
  RL_DELEGATE_WINDOW_SEC,
  EXPIRE_DELEGATE_BATCH,
} from "./constants.js";

/* ─── Delegation chains (parent authority / child pocket money) ───
 * Parent locks budget → system/delegate. Child API key spends with:
 *   Authorization: Bearer a2a_…child_key
 *   X-Delegate-Id: dg_…
 * Constraints: allow_to, task_prefix, max_per_spend, remaining, TTL.
 * Parent revokes instantly. Extends intent + policy + colo bind on the key.
 *
 * POST /api/delegate/open   { parent_repo?, child_key_id, budget, allow_to?, task_prefix?, max_per_spend?, ttl_seconds?, label?, child_repo? }
 * POST /api/delegate/revoke { id }
 * GET  /api/delegate        ?repo=&status=
 * GET  /api/delegate/:id
 * Cron: expireDelegations
 */

export function parseDelegateTtl(body) {
  const sec = Number(body.ttl_seconds ?? body.ttl);
  if (Number.isFinite(sec)) {
    if (sec < DELEGATE_MIN_TTL_SEC || sec > DELEGATE_MAX_TTL_SEC) return null;
    return Math.floor(sec);
  }
  return DELEGATE_DEFAULT_TTL_SEC;
}

export function parseDelegateAllowTo(v) {
  if (v == null || v === "") return null;
  if (Array.isArray(v)) {
    const list = v.map((x) => parseRepo(x)).filter(Boolean);
    return list.length ? JSON.stringify(list) : null;
  }
  const s = String(v).trim();
  if (!s) return null;
  if (s.startsWith("[")) {
    try {
      const arr = JSON.parse(s);
      if (Array.isArray(arr)) {
        const list = arr.map((x) => parseRepo(x)).filter(Boolean);
        return list.length ? JSON.stringify(list) : null;
      }
    } catch (_) {}
  }
  const list = s.split(",").map((x) => parseRepo(x.trim())).filter(Boolean);
  return list.length ? JSON.stringify(list) : null;
}

export function delegateAllowToList(raw) {
  if (!raw) return null;
  try {
    const arr = typeof raw === "string" ? JSON.parse(raw) : raw;
    return Array.isArray(arr) ? arr : null;
  } catch {
    return null;
  }
}

export async function logDelegateEvent(env, delegationId, event, { actor_repo, amount, to_repo, note } = {}) {
  try {
    await env.DB.prepare(
      `INSERT INTO delegation_events (id, delegation_id, event, actor_repo, amount, to_repo, note, created_at)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, datetime('now'))`
    )
      .bind(
        randomId(10),
        delegationId,
        event,
        actor_repo || null,
        amount != null ? Number(amount) : null,
        to_repo || null,
        note ? String(note).slice(0, 500) : null
      )
      .run();
  } catch (e) {
    console.log("delegate_event_err", e && e.message);
  }
}

export async function loadDelegation(env, id) {
  try {
    return await env.DB.prepare(`SELECT * FROM delegations WHERE id = ?1`).bind(id).first();
  } catch {
    return null;
  }
}

/**
 * Resolve and claim a spend against a delegation.
 * Returns { ok, delegation, remaining } or { ok:false, error, code, status? }.
 */
export async function claimDelegationSpend(env, { id, childKeyId, toRepo, amount, task }) {
  const row = await loadDelegation(env, id);
  if (!row) {
    try {
      await env.DB.prepare(`SELECT 1 FROM delegations LIMIT 1`).first();
    } catch {
      return { ok: false, error: "delegations table missing — run d1-delegate-migration.sql", code: "table_missing" };
    }
    return { ok: false, error: "Delegation not found", code: "not_found" };
  }
  if (row.status !== "open") {
    return { ok: false, error: "Delegation not open (status=" + row.status + ")", code: "delegate_closed", status: row.status };
  }
  if (String(row.child_key_id) !== String(childKeyId)) {
    return { ok: false, error: "API key is not the delegated child key", code: "delegate_key_mismatch" };
  }
  if (row.expires_at) {
    const expMs = Date.parse(String(row.expires_at).replace(" ", "T") + "Z");
    if (Number.isFinite(expMs) && expMs < Date.now()) {
      return { ok: false, error: "Delegation expired", code: "delegate_expired" };
    }
  }
  const allow = delegateAllowToList(row.allow_to);
  if (allow && allow.length && !allow.includes(toRepo)) {
    return { ok: false, error: "to_repo not in delegation allow_to", code: "delegate_allow_to", allow_to: allow };
  }
  if (row.task_prefix) {
    const pref = String(row.task_prefix);
    if (!String(task || "").startsWith(pref)) {
      return { ok: false, error: 'task must start with prefix "' + pref + '"', code: "delegate_task_prefix" };
    }
  }
  if (row.max_per_spend != null && amount > Number(row.max_per_spend)) {
    return {
      ok: false,
      error: "amount exceeds max_per_spend ($" + row.max_per_spend + ")",
      code: "delegate_max_per_spend",
    };
  }
  const remaining = Number(row.remaining_usd || 0);
  if (amount > remaining) {
    return {
      ok: false,
      error: "Insufficient delegation remaining ($" + remaining.toFixed(6) + ")",
      code: "delegate_insufficient",
      remaining_usd: remaining,
    };
  }

  const claim = await env.DB.prepare(
    `UPDATE delegations
     SET remaining_usd = remaining_usd - ?2,
         status = CASE WHEN remaining_usd - ?2 <= 0.0000005 THEN 'depleted' ELSE status END,
         updated_at = datetime('now'),
         closed_at = CASE WHEN remaining_usd - ?2 <= 0.0000005 THEN datetime('now') ELSE closed_at END
     WHERE id = ?1 AND status = 'open' AND remaining_usd >= ?2
     RETURNING *`
  )
    .bind(id, amount)
    .first();
  if (!claim) {
    return { ok: false, error: "Delegation spend race or insufficient remaining", code: "delegate_race" };
  }
  return { ok: true, delegation: claim, remaining: Number(claim.remaining_usd) };
}

export async function handleDelegateOpen(request, env, ctx) {
  const t0 = Date.now();
  const authUser = await getAuthUser(request, env);
  if (!authUser) return bad(request, "Sign in or API key required", 401);

  const rlId =
    authUser.auth_via === "api_key"
      ? "dg:key:" + (authUser.key_id || authUser.id)
      : "dg:user:" + authUser.id;
  const limited = await checkRateLimit(env, rlId, RL_DELEGATE_MAX, RL_DELEGATE_WINDOW_SEC);
  if (limited) {
    return bad(request, "Rate limit: delegate ops", 429, { retry_after_sec: limited.retry_after_sec });
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return bad(request, "Invalid JSON body");
  }

  let parentRepo = parseRepo(body.parent_repo || body.from_repo || body.parent);
  if (!parentRepo && authUser.default_repo) parentRepo = parseRepo(authUser.default_repo);
  const childKeyId = String(body.child_key_id || body.key_id || body.child_key || "").trim();
  const childRepo = body.child_repo ? parseRepo(body.child_repo) : null;
  const budget = parseAmount(body.budget ?? body.amount ?? body.budget_usd);
  const ttlSec = parseDelegateTtl(body);
  const allowTo = parseDelegateAllowTo(body.allow_to ?? body.allowTo ?? body.to_allow);
  const taskPrefix =
    body.task_prefix != null
      ? String(body.task_prefix).slice(0, 120)
      : body.taskPrefix != null
        ? String(body.taskPrefix).slice(0, 120)
        : null;
  let maxPer =
    body.max_per_spend != null
      ? parseAmount(body.max_per_spend)
      : body.maxPerSpend != null
        ? parseAmount(body.maxPerSpend)
        : null;
  if (body.max_per_spend === "" || body.max_per_spend === null) maxPer = null;
  const label = body.label ? String(body.label).slice(0, 200) : null;

  if (!parentRepo) return bad(request, "parent_repo required (or set default agent)");
  if (!childKeyId) return bad(request, "child_key_id required (API key id from /api/me/keys)");
  if (budget == null || budget < DELEGATE_MIN || budget > DELEGATE_MAX) {
    return bad(request, "budget invalid");
  }
  if (ttlSec == null) return bad(request, "ttl_seconds out of range");
  if (maxPer != null && (maxPer < DELEGATE_MIN || maxPer > budget)) {
    return bad(request, "max_per_spend must be between min amount and budget");
  }

  // Child key must exist, active, and belong to same user (family of keys)
  let keyRow;
  try {
    keyRow = await env.DB.prepare(
      `SELECT id, user_id, revoked_at, suspended_at, label, key_prefix
       FROM api_keys WHERE id = ?1`
    )
      .bind(childKeyId)
      .first();
  } catch {
    return bad(request, "api_keys lookup failed", 500);
  }
  if (!keyRow || keyRow.revoked_at) {
    return bad(request, "child_key_id not found or revoked", 404, { code: "child_key_missing" });
  }
  if (keyRow.suspended_at) {
    return bad(request, "child API key is suspended", 403, { code: "child_key_suspended" });
  }
  if (String(keyRow.user_id) !== String(authUser.id)) {
    return bad(request, "child_key_id must belong to your account (same family)", 403, {
      code: "child_key_not_yours",
    });
  }

  authUser._policyCtx = { to_repo: SYSTEM_DELEGATE, task: "delegate:open" };
  const blocked = await safetyGate(request, env, authUser, parentRepo, budget);
  if (blocked) return blocked;

  const debitRes = await debitWithCredit(env, parentRepo, budget);
  if (!debitRes.ok) {
    return bad(request, debitRes.error || "Insufficient funds", debitRes.code === "wallet_locked" ? 403 : 402, {
      code: debitRes.code || "insufficient",
      available_credit: debitRes.available_credit,
    });
  }

  const id = "dg_" + randomId(12);
  const modifier = "+" + ttlSec + " seconds";

  try {
    await ensureAccount(env, SYSTEM_DELEGATE);
    await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO delegations (
           id, parent_repo, child_key_id, child_repo, budget_usd, remaining_usd,
           allow_to, task_prefix, max_per_spend, status, ttl_seconds, expires_at,
           label, created_by, created_at, updated_at
         ) VALUES (
           ?1, ?2, ?3, ?4, ?5, ?5,
           ?6, ?7, ?8, 'open', ?9, datetime('now', ?10),
           ?11, ?12, datetime('now'), datetime('now')
         )`
      ).bind(
        id,
        parentRepo,
        childKeyId,
        childRepo,
        budget,
        allowTo,
        taskPrefix,
        maxPer,
        ttlSec,
        modifier,
        label,
        authUser.id
      ),
      env.DB.prepare(
        `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
         VALUES (?1, ?2, ?3, ?4, 'success', ?5)`
      ).bind(parentRepo, SYSTEM_DELEGATE, budget, "delegate-open:" + id, Date.now() - t0),
    ]);
  } catch (e) {
    await env.DB.prepare(
      `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
    )
      .bind(budget, parentRepo)
      .run()
      .catch(() => {});
    if (debitRes.credit_drawn > 0) {
      await env.DB.prepare(
        `UPDATE agent_limits
         SET outstanding_credit = MAX(0, COALESCE(outstanding_credit, 0) - ?2),
             updated_at = datetime('now')
         WHERE repo_id = ?1`
      )
        .bind(parentRepo, debitRes.credit_drawn)
        .run()
        .catch(() => {});
    }
    return bad(
      request,
      "delegations table missing — run d1-delegate-migration.sql: " + (e.message || e),
      500
    );
  }

  await safetyRecordSpend(env, authUser, parentRepo, budget);
  await logDelegateEvent(env, id, "opened", {
    actor_repo: parentRepo,
    amount: budget,
    note: label || ("key:" + (keyRow.key_prefix || childKeyId)),
  });

  if (authUser.id) {
    scheduleWebhook(ctx, env, authUser.id, "delegate.opened", {
      id,
      parent_repo: parentRepo,
      child_key_id: childKeyId,
      child_repo: childRepo,
      budget_usd: budget,
      remaining_usd: budget,
      allow_to: delegateAllowToList(allowTo),
      task_prefix: taskPrefix,
      max_per_spend: maxPer,
      ttl_seconds: ttlSec,
      status: "open",
    });
  }

  return json(request, {
    ok: true,
    delegation: {
      id,
      parent_repo: parentRepo,
      child_key_id: childKeyId,
      child_key_prefix: keyRow.key_prefix || null,
      child_repo: childRepo,
      budget_usd: budget,
      remaining_usd: budget,
      allow_to: delegateAllowToList(allowTo),
      task_prefix: taskPrefix,
      max_per_spend: maxPer,
      status: "open",
      ttl_seconds: ttlSec,
      label,
    },
    latency_ms: Date.now() - t0,
    hint:
      "Child pays with Authorization: Bearer <child_key> and header X-Delegate-Id: " +
      id +
      ". Revoke anytime via POST /api/delegate/revoke.",
  });
}

export async function handleDelegateRevoke(request, env, ctx) {
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

  const row = await loadDelegation(env, id);
  if (!row) return bad(request, "Delegation not found", 404);
  if (row.status !== "open") {
    return bad(request, "Delegation not open (status=" + row.status + ")", 400);
  }

  const allowed =
    authUser.id === row.created_by ||
    (authUser.default_repo && authUser.default_repo === row.parent_repo);
  if (!allowed) return bad(request, "Not authorized to revoke this delegation", 403);

  const claim = await env.DB.prepare(
    `UPDATE delegations
     SET status = 'revoked', revoked_at = datetime('now'), closed_at = datetime('now'), updated_at = datetime('now')
     WHERE id = ?1 AND status = 'open'
     RETURNING *`
  )
    .bind(id)
    .first();
  if (!claim) return bad(request, "Revoke race", 409);

  const refund = Number(claim.remaining_usd || 0);
  if (refund > 0) {
    await ensureAccount(env, row.parent_repo);
    await ensureAccount(env, SYSTEM_DELEGATE);
    await env.DB.batch([
      env.DB.prepare(
        `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
      ).bind(refund, row.parent_repo),
      env.DB.prepare(
        `UPDATE delegations SET remaining_usd = 0, updated_at = datetime('now') WHERE id = ?1`
      ).bind(id),
      env.DB.prepare(
        `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
         VALUES (?1, ?2, ?3, ?4, 'success', ?5)`
      ).bind(SYSTEM_DELEGATE, row.parent_repo, refund, "delegate-revoke-refund:" + id, Date.now() - t0),
    ]);
  }

  await logDelegateEvent(env, id, "revoked", {
    actor_repo: row.parent_repo,
    amount: refund,
    note: "parent_revoke",
  });

  if (row.created_by) {
    scheduleWebhook(ctx, env, row.created_by, "delegate.revoked", {
      id,
      parent_repo: row.parent_repo,
      child_key_id: row.child_key_id,
      refunded: refund,
      status: "revoked",
    });
  }

  return json(request, {
    ok: true,
    id,
    status: "revoked",
    refunded: refund,
    latency_ms: Date.now() - t0,
  });
}

export async function handleDelegateGet(request, env, id) {
  id = String(id || "").trim();
  if (!id) return bad(request, "id required");
  const row = await loadDelegation(env, id);
  if (!row) {
    try {
      await env.DB.prepare(`SELECT 1 FROM delegations LIMIT 1`).first();
    } catch {
      return bad(request, "delegations table missing — run d1-delegate-migration.sql", 500);
    }
    return bad(request, "Delegation not found", 404);
  }
  let events = [];
  try {
    const q = await env.DB.prepare(
      `SELECT event, actor_repo, amount, to_repo, note, created_at
       FROM delegation_events WHERE delegation_id = ?1 ORDER BY created_at DESC LIMIT 40`
    )
      .bind(id)
      .all();
    events = q.results || [];
  } catch (_) {}
  return json(request, {
    ok: true,
    delegation: {
      ...row,
      allow_to: delegateAllowToList(row.allow_to),
    },
    events,
  });
}

export async function handleDelegateList(request, url, env) {
  const limit = Math.min(Math.max(Number(url.searchParams.get("limit") || 20), 1), 100);
  const repo = (url.searchParams.get("repo") || "").trim();
  const status = (url.searchParams.get("status") || "").trim();
  const keyId = (url.searchParams.get("child_key_id") || url.searchParams.get("key_id") || "").trim();

  let sql = `SELECT id, parent_repo, child_key_id, child_repo, budget_usd, remaining_usd,
                    allow_to, task_prefix, max_per_spend, status, ttl_seconds, expires_at, label, created_at
             FROM delegations WHERE 1=1`;
  const binds = [];
  if (repo) {
    if (!parseRepo(repo)) return bad(request, "repo must be owner/repo");
    sql += ` AND parent_repo = ?`;
    binds.push(repo);
  }
  if (keyId) {
    sql += ` AND child_key_id = ?`;
    binds.push(keyId);
  }
  if (status && ["open", "depleted", "revoked", "expired"].includes(status)) {
    sql += ` AND status = ?`;
    binds.push(status);
  }
  sql += ` ORDER BY created_at DESC LIMIT ?`;
  binds.push(limit);

  try {
    const { results } = await env.DB.prepare(sql).bind(...binds).all();
    const rows = (results || []).map((r) => ({
      ...r,
      allow_to: delegateAllowToList(r.allow_to),
    }));
    return json(request, { ok: true, count: rows.length, delegations: rows });
  } catch (e) {
    return bad(
      request,
      "delegations table missing — run d1-delegate-migration.sql: " + (e.message || e),
      500
    );
  }
}

export async function expireDelegations(env, ctx) {
  const t0 = Date.now();
  let expired = 0;
  let refundedTotal = 0;
  try {
    const q = await env.DB.prepare(
      `SELECT * FROM delegations
       WHERE status = 'open'
         AND expires_at IS NOT NULL
         AND expires_at < datetime('now')
       ORDER BY expires_at ASC LIMIT ?1`
    )
      .bind(EXPIRE_DELEGATE_BATCH)
      .all();
    for (const row of q.results || []) {
      try {
        const claim = await env.DB.prepare(
          `UPDATE delegations
           SET status = 'expired', closed_at = datetime('now'), updated_at = datetime('now')
           WHERE id = ?1 AND status = 'open' RETURNING *`
        )
          .bind(row.id)
          .first();
        if (!claim) continue;
        const refund = Number(claim.remaining_usd || 0);
        if (refund > 0) {
          await ensureAccount(env, row.parent_repo);
          await env.DB.batch([
            env.DB.prepare(
              `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
            ).bind(refund, row.parent_repo),
            env.DB.prepare(
              `UPDATE delegations SET remaining_usd = 0, updated_at = datetime('now') WHERE id = ?1`
            ).bind(row.id),
            env.DB.prepare(
              `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
               VALUES (?1, ?2, ?3, ?4, 'success', 0)`
            ).bind(SYSTEM_DELEGATE, row.parent_repo, refund, "delegate-expire-refund:" + row.id),
          ]);
          refundedTotal += refund;
        }
        await logDelegateEvent(env, row.id, "expired", {
          actor_repo: row.parent_repo,
          amount: refund,
          note: "ttl",
        });
        expired += 1;
        if (row.created_by) {
          scheduleWebhook(ctx, env, row.created_by, "delegate.expired", {
            id: row.id,
            parent_repo: row.parent_repo,
            refunded: refund,
            status: "expired",
          });
        }
      } catch (e) {
        console.log("delegate_expire", row.id, e && e.message);
      }
    }
  } catch (e) {
    return { expired: 0, error: e.message, latency_ms: Date.now() - t0 };
  }
  return { expired, refunded_total: refundedTotal, latency_ms: Date.now() - t0 };
}


