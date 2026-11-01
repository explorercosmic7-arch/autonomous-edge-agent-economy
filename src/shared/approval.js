/**
 * Approval gates — intelligent rules + pending request lifecycle.
 *
 * Design (v1):
 *  - No debit until human approves (simple, safe).
 *  - Account-wide settings (user_id), same pattern as fleet_limits.
 *  - Rules OR'd: amount threshold, new counterparty, task prefix match.
 *  - Soft alerts (webhook only) separate from hard approval holds.
 *
 * Used by: safetyGate (check), meApproval routes (settings / list / decide).
 */
import { randomId, parseRepo } from "./utils.js";
import { logSafetyEvent } from "./safety.js";
import { scheduleWebhook } from "./webhooks.js";

const DEFAULT_TTL = 3600;
const MIN_TTL = 60;
const MAX_TTL = 7 * 24 * 3600;

/* ─── Settings ─── */

export async function ensureApprovalSettings(env, userId) {
  if (!userId) return;
  try {
    await env.DB.prepare(
      `INSERT OR IGNORE INTO user_approval_settings (user_id) VALUES (?1)`
    )
      .bind(userId)
      .run();
  } catch (e) {
    console.log("ensure_approval_settings", e && e.message);
  }
}

export async function getApprovalSettings(env, userId) {
  if (!userId) return null;
  try {
    await ensureApprovalSettings(env, userId);
    return await env.DB.prepare(
      `SELECT * FROM user_approval_settings WHERE user_id = ?1`
    )
      .bind(userId)
      .first();
  } catch (e) {
    console.log("get_approval_settings", e && e.message);
    return null;
  }
}

export function serializeApprovalSettings(row) {
  if (!row) {
    return {
      enabled: true,
      approve_over_usd: null,
      alert_over_usd: null,
      approve_new_counterparty: false,
      approve_task_prefixes: [],
      ttl_seconds: DEFAULT_TTL,
      warn_bps: 8000,
    };
  }
  const prefixes = String(row.approve_task_prefixes || "")
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
  return {
    enabled: Number(row.enabled) !== 0,
    approve_over_usd:
      row.approve_over_usd == null ? null : Number(row.approve_over_usd),
    alert_over_usd:
      row.alert_over_usd == null ? null : Number(row.alert_over_usd),
    approve_new_counterparty: Number(row.approve_new_counterparty) === 1,
    approve_task_prefixes: prefixes,
    ttl_seconds: Number(row.ttl_seconds) || DEFAULT_TTL,
    warn_bps: Number(row.warn_bps) || 8000,
    updated_at: row.updated_at || null,
  };
}

/* ─── Counterparty history (new peer detection) ─── */

async function hasPaidCounterpartyBefore(env, userId, toRepo) {
  if (!userId || !toRepo) return true; // fail open on missing data
  try {
    // Prefer transactions tied to user's agents via api_keys / from_repo ownership
    // Lightweight: any successful ledger row to this to_repo from same user keys
    const row = await env.DB.prepare(
      `SELECT 1 AS ok FROM transactions t
       WHERE t.to_repo = ?1
         AND t.status IN ('ok','settled','released','completed','paid')
         AND (
           t.user_id = ?2
           OR t.from_repo IN (
             SELECT default_repo FROM users WHERE id = ?2 AND default_repo IS NOT NULL
           )
           OR EXISTS (
             SELECT 1 FROM api_keys k
             WHERE k.user_id = ?2 AND k.id = t.api_key_id
           )
         )
       LIMIT 1`
    )
      .bind(toRepo, userId)
      .first();
    if (row) return true;
  } catch (_) {
    // Schema variants: try simpler query
    try {
      const row2 = await env.DB.prepare(
        `SELECT 1 AS ok FROM transactions
         WHERE to_repo = ?1 AND from_repo LIKE ?2
         LIMIT 1`
      )
        .bind(toRepo, "%")
        .first();
      // Fall through — without reliable history, treat as known to avoid noise
      if (row2) return true;
    } catch (__) {}
  }
  // Second path: prior *approved* approvals to same peer count as known
  try {
    const prior = await env.DB.prepare(
      `SELECT 1 AS ok FROM approval_requests
       WHERE user_id = ?1 AND to_repo = ?2
         AND status IN ('approved')
       LIMIT 1`
    )
      .bind(userId, toRepo)
      .first();
    if (prior) return true;
  } catch (_) {}
  return false;
}

/* ─── Intelligent rule evaluation ─── */

/**
 * Evaluate approval + alert rules for a proposed spend.
 * Returns { needApproval, softAlert, rule_code, reason, settings } or nulls.
 */
export async function evaluateApprovalRules(
  env,
  userId,
  { fromRepo, toRepo, amount, task } = {}
) {
  const settingsRow = await getApprovalSettings(env, userId);
  const settings = serializeApprovalSettings(settingsRow);

  if (!settings.enabled) {
    return { needApproval: false, softAlert: false, settings };
  }

  const amt = Number(amount) || 0;
  const taskStr = String(task || "").toLowerCase();
  let needApproval = false;
  let softAlert = false;
  let rule_code = null;
  let reason = null;

  // 1) Hard: amount threshold
  if (
    settings.approve_over_usd != null &&
    Number.isFinite(settings.approve_over_usd) &&
    amt + 1e-12 >= settings.approve_over_usd
  ) {
    needApproval = true;
    rule_code = "approve_over_usd";
    reason = `Amount $${amt.toFixed(6)} ≥ approval threshold $${Number(
      settings.approve_over_usd
    ).toFixed(6)}`;
  }

  // 2) Soft alert threshold (never blocks by itself)
  if (
    settings.alert_over_usd != null &&
    Number.isFinite(settings.alert_over_usd) &&
    amt + 1e-12 >= settings.alert_over_usd
  ) {
    softAlert = true;
  }

  // Soft warn band under approve_over (e.g. 80% of threshold)
  if (
    !needApproval &&
    settings.approve_over_usd != null &&
    settings.approve_over_usd > 0
  ) {
    const band =
      (settings.approve_over_usd * (settings.warn_bps || 8000)) / 10000;
    if (amt + 1e-12 >= band) {
      softAlert = true;
      if (!rule_code) {
        rule_code = "approve_warn_band";
        reason = `Amount approaching approval threshold ($${amt.toFixed(
          6
        )} ≥ $${band.toFixed(6)} warn band)`;
      }
    }
  }

  // 3) Task prefix list
  if (!needApproval && settings.approve_task_prefixes.length) {
    for (const p of settings.approve_task_prefixes) {
      if (p && taskStr.includes(p)) {
        needApproval = true;
        rule_code = "approve_task_prefix";
        reason = `Task matches approval prefix "${p}"`;
        break;
      }
    }
  }

  // 4) New counterparty
  if (!needApproval && settings.approve_new_counterparty && toRepo) {
    const known = await hasPaidCounterpartyBefore(env, userId, toRepo);
    if (!known) {
      needApproval = true;
      rule_code = "approve_new_counterparty";
      reason = `First spend to new counterparty ${toRepo}`;
    }
  }

  return {
    needApproval,
    softAlert,
    rule_code,
    reason,
    settings,
  };
}

/* ─── Requests ─── */

export async function createApprovalRequest(
  env,
  {
    userId,
    fromRepo,
    toRepo,
    amount,
    task,
    rule_code,
    reason,
    ttl_seconds,
    api_key_id,
    idempotency_key,
    pay_meta,
  }
) {
  const id = "apr_" + randomId(12);
  const ttl = Math.min(
    MAX_TTL,
    Math.max(MIN_TTL, Number(ttl_seconds) || DEFAULT_TTL)
  );
  const expiresAt = new Date(Date.now() + ttl * 1000)
    .toISOString()
    .replace("T", " ")
    .replace(/\.\d{3}Z$/, "");

  await env.DB.prepare(
    `INSERT INTO approval_requests (
       id, user_id, from_repo, to_repo, amount, task,
       rule_code, reason, status, idempotency_key, pay_meta, api_key_id, expires_at
     ) VALUES (
       ?1, ?2, ?3, ?4, ?5, ?6,
       ?7, ?8, 'pending', ?9, ?10, ?11, ?12
     )`
  )
    .bind(
      id,
      userId,
      fromRepo,
      toRepo,
      Number(amount),
      task ? String(task).slice(0, 200) : null,
      rule_code || "approval_required",
      reason ? String(reason).slice(0, 500) : null,
      idempotency_key || null,
      pay_meta ? JSON.stringify(pay_meta).slice(0, 4000) : null,
      api_key_id || null,
      expiresAt
    )
    .run();

  return {
    id,
    status: "pending",
    expires_at: expiresAt,
    rule_code,
    reason,
    amount: Number(amount),
    from_repo: fromRepo,
    to_repo: toRepo,
    task: task || null,
  };
}

/** Expire stale pending rows (best-effort). */
export async function expirePendingApprovals(env, userId = null) {
  try {
    if (userId) {
      await env.DB.prepare(
        `UPDATE approval_requests
         SET status = 'expired', resolved_at = datetime('now'), resolve_note = 'ttl'
         WHERE user_id = ?1 AND status = 'pending'
           AND expires_at < datetime('now')`
      )
        .bind(userId)
        .run();
    } else {
      await env.DB.prepare(
        `UPDATE approval_requests
         SET status = 'expired', resolved_at = datetime('now'), resolve_note = 'ttl'
         WHERE status = 'pending' AND expires_at < datetime('now')`
      ).run();
    }
  } catch (e) {
    console.log("expire_approvals", e && e.message);
  }
}

export async function getApprovalRequest(env, id) {
  if (!id) return null;
  try {
    return await env.DB.prepare(
      `SELECT * FROM approval_requests WHERE id = ?1`
    )
      .bind(id)
      .first();
  } catch (_) {
    return null;
  }
}

export async function listApprovalRequests(env, userId, { status, limit } = {}) {
  await expirePendingApprovals(env, userId);
  const lim = Math.min(50, Math.max(1, Number(limit) || 20));
  try {
    if (status) {
      const { results } = await env.DB.prepare(
        `SELECT * FROM approval_requests
         WHERE user_id = ?1 AND status = ?2
         ORDER BY created_at DESC LIMIT ?3`
      )
        .bind(userId, status, lim)
        .all();
      return results || [];
    }
    const { results } = await env.DB.prepare(
      `SELECT * FROM approval_requests
       WHERE user_id = ?1
       ORDER BY created_at DESC LIMIT ?2`
    )
      .bind(userId, lim)
      .all();
    return results || [];
  } catch (e) {
    console.log("list_approvals", e && e.message);
    return [];
  }
}

/**
 * Main gate helper for safetyGate.
 * If approval required: creates pending request, webhooks, returns block payload object
 * (caller turns into Response via bad()).
 * Soft alerts only fire webhook + log.
 *
 * @returns {null | { block: true, code, error, approval_id, expires_at, rule_code, status }}
 */
export async function checkApprovalGate(
  env,
  authUser,
  fromRepo,
  amount,
  { toRepo, task, idempotency_key, ctx } = {}
) {
  if (!authUser || !authUser.id || !fromRepo) return null;

  const userId = authUser.id;
  const to = parseRepo(toRepo) || String(toRepo || "").trim() || null;
  const evalResult = await evaluateApprovalRules(env, userId, {
    fromRepo,
    toRepo: to,
    amount,
    task,
  });

  if (!evalResult) return null;

  // Soft alert only
  if (evalResult.softAlert && !evalResult.needApproval) {
    try {
      await logSafetyEvent(env, "approval.alert", {
        user_id: userId,
        repo_id: fromRepo,
        reason: evalResult.reason || "soft alert",
        meta: { amount, to_repo: to, task },
      });
      scheduleWebhook(ctx || null, env, userId, "approval.alert", {
        repo_id: fromRepo,
        to_repo: to,
        amount: Number(amount),
        task: task || null,
        rule_code: evalResult.rule_code || "alert",
        reason: evalResult.reason,
      });
    } catch (e) {
      console.log("approval_soft_alert", e && e.message);
    }
  }

  if (!evalResult.needApproval) return null;

  // Dedup: reuse open pending for same from/to/amount/task within window
  try {
    const existing = await env.DB.prepare(
      `SELECT id, expires_at, rule_code, reason, status FROM approval_requests
       WHERE user_id = ?1 AND status = 'pending'
         AND from_repo = ?2 AND to_repo = ?3
         AND amount = ?4
         AND IFNULL(task,'') = IFNULL(?5,'')
         AND expires_at >= datetime('now')
       ORDER BY created_at DESC LIMIT 1`
    )
      .bind(
        userId,
        fromRepo,
        to || "",
        Number(amount),
        task ? String(task).slice(0, 200) : null
      )
      .first();
    if (existing) {
      return {
        block: true,
        code: "approval_required",
        error: existing.reason || "Human approval required before this spend",
        approval_id: existing.id,
        expires_at: existing.expires_at,
        rule_code: existing.rule_code,
        status: "pending",
      };
    }
  } catch (_) {}

  const keyId =
    authUser.auth_via === "api_key" ? authUser.key_id || null : null;
  const req = await createApprovalRequest(env, {
    userId,
    fromRepo,
    toRepo: to || "",
    amount,
    task,
    rule_code: evalResult.rule_code || "approval_required",
    reason: evalResult.reason || "Human approval required",
    ttl_seconds: evalResult.settings.ttl_seconds,
    api_key_id: keyId,
    idempotency_key: idempotency_key || null,
    pay_meta: { from_repo: fromRepo, to_repo: to, amount, task },
  });

  await logSafetyEvent(env, "approval.requested", {
    user_id: userId,
    repo_id: fromRepo,
    reason: req.reason,
    meta: {
      approval_id: req.id,
      rule_code: req.rule_code,
      amount,
      to_repo: to,
    },
  });

  scheduleWebhook(ctx || null, env, userId, "approval.requested", {
    approval_id: req.id,
    repo_id: fromRepo,
    to_repo: to,
    amount: Number(amount),
    task: task || null,
    rule_code: req.rule_code,
    reason: req.reason,
    expires_at: req.expires_at,
  });

  return {
    block: true,
    code: "approval_required",
    error: req.reason || "Human approval required before this spend",
    approval_id: req.id,
    expires_at: req.expires_at,
    rule_code: req.rule_code,
    status: "pending",
  };
}

/**
 * Decide approve | reject on a pending request.
 * Approve does NOT auto-pay — agent/client must retry /api/pay after approve
 * (simple, avoids double-spend races). We set a short allow-token window optional later.
 */
export async function decideApproval(
  env,
  { id, userId, decision, resolved_by, note }
) {
  await expirePendingApprovals(env, userId);
  const row = await getApprovalRequest(env, id);
  if (!row) return { ok: false, error: "Approval not found", code: "not_found" };
  if (row.user_id !== userId) {
    return { ok: false, error: "Forbidden", code: "forbidden" };
  }
  if (row.status !== "pending") {
    return {
      ok: false,
      error: "Approval is not pending (" + row.status + ")",
      code: "not_pending",
      status: row.status,
    };
  }

  // Expired check
  try {
    const still = await env.DB.prepare(
      `SELECT 1 AS ok FROM approval_requests
       WHERE id = ?1 AND status = 'pending' AND expires_at >= datetime('now')`
    )
      .bind(id)
      .first();
    if (!still) {
      await env.DB.prepare(
        `UPDATE approval_requests
         SET status = 'expired', resolved_at = datetime('now'), resolve_note = 'ttl'
         WHERE id = ?1`
      )
        .bind(id)
        .run();
      return { ok: false, error: "Approval expired", code: "expired" };
    }
  } catch (_) {}

  const dec = String(decision || "").toLowerCase();
  if (dec !== "approve" && dec !== "reject") {
    return { ok: false, error: "decision must be approve or reject" };
  }
  const status = dec === "approve" ? "approved" : "rejected";

  await env.DB.prepare(
    `UPDATE approval_requests
     SET status = ?2,
         resolved_at = datetime('now'),
         resolved_by = ?3,
         resolve_note = ?4
     WHERE id = ?1 AND status = 'pending'`
  )
    .bind(
      id,
      status,
      resolved_by || userId,
      note ? String(note).slice(0, 400) : null
    )
    .run();

  await logSafetyEvent(env, "approval." + status, {
    user_id: userId,
    repo_id: row.from_repo,
    reason: note || status,
    meta: { approval_id: id, to_repo: row.to_repo, amount: row.amount },
  });

  scheduleWebhook(null, env, userId, "approval." + status, {
    approval_id: id,
    repo_id: row.from_repo,
    to_repo: row.to_repo,
    amount: row.amount,
    status,
  });

  // Mark a short-lived allow on approved: store expires in pay_meta flag
  // Client should pass X-Approval-Id on the next pay within TTL remnant.
  return {
    ok: true,
    id,
    status,
    from_repo: row.from_repo,
    to_repo: row.to_repo,
    amount: row.amount,
    task: row.task,
    // Agent must retry pay with header X-Approval-Id: id after approve
    next: status === "approved"
      ? {
          action: "retry_pay",
          header: "X-Approval-Id",
          approval_id: id,
          body: {
            from_repo: row.from_repo,
            to_repo: row.to_repo,
            amount: row.amount,
            task: row.task,
          },
        }
      : null,
  };
}

/**
 * After approve, agent retries pay with X-Approval-Id.
 * Validate the approval covers this spend and is approved + fresh.
 */
export async function consumeApprovedAllowance(
  env,
  authUser,
  approvalId,
  { fromRepo, toRepo, amount, task } = {}
) {
  if (!approvalId || !authUser || !authUser.id) {
    return { ok: false, error: "approval id required", code: "approval_id" };
  }
  const row = await getApprovalRequest(env, approvalId);
  if (!row || row.user_id !== authUser.id) {
    return { ok: false, error: "Invalid approval", code: "approval_invalid" };
  }
  if (row.status === "pending") {
    return { ok: false, error: "Still pending approval", code: "approval_pending" };
  }
  if (row.status === "rejected" || row.status === "expired" || row.status === "cancelled") {
    return { ok: false, error: "Approval " + row.status, code: "approval_" + row.status };
  }
  if (row.status !== "approved") {
    return { ok: false, error: "Approval not approved", code: "approval_invalid" };
  }
  // Match economics (tolerance for float)
  if (String(row.from_repo) !== String(fromRepo)) {
    return { ok: false, error: "from_repo mismatch", code: "approval_mismatch" };
  }
  if (String(row.to_repo) !== String(toRepo || "")) {
    return { ok: false, error: "to_repo mismatch", code: "approval_mismatch" };
  }
  if (Math.abs(Number(row.amount) - Number(amount)) > 1e-9) {
    return { ok: false, error: "amount mismatch", code: "approval_mismatch" };
  }
  // One-shot: mark cancelled/consumed so it cannot be reused
  try {
    await env.DB.prepare(
      `UPDATE approval_requests
       SET status = 'cancelled', resolve_note = 'consumed', resolved_at = datetime('now')
       WHERE id = ?1 AND status = 'approved'`
    )
      .bind(approvalId)
      .run();
  } catch (_) {}
  return { ok: true, approval_id: approvalId };
}
