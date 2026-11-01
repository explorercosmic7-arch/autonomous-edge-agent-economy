/**
 * Me approval — dashboard + agent-facing approval APIs.
 *
 * GET|POST /api/me/approval-settings
 * GET      /api/me/approvals
 * POST     /api/me/approvals/decide   { id, decision: "approve"|"reject", note? }
 */
import { json, bad } from "./http.js";
import { getAuthUser, getSessionUser, rejectIfSuspendedKey } from "./auth.js";
import {
  ensureApprovalSettings,
  getApprovalSettings,
  serializeApprovalSettings,
  listApprovalRequests,
  decideApproval,
  expirePendingApprovals,
  countPendingApprovals,
} from "./approval.js";

async function requireUser(request, env, { sessionOnly = false } = {}) {
  const user = sessionOnly
    ? await getSessionUser(request, env)
    : await getAuthUser(request, env);
  if (!user || !user.id) return { error: bad(request, "Sign in required", 401) };
  if (!sessionOnly) {
    const sus = rejectIfSuspendedKey(request, user);
    if (sus) return { error: sus };
  }
  return { user };
}

export async function handleMeApprovalSettingsGet(request, env) {
  const auth = await requireUser(request, env);
  if (auth.error) return auth.error;
  const row = await getApprovalSettings(env, auth.user.id);
  return json(request, {
    ok: true,
    user_id: auth.user.id,
    settings: serializeApprovalSettings(row),
  });
}

export async function handleMeApprovalSettingsSet(request, env) {
  // Only signed-in dashboard session may change thresholds
  const auth = await requireUser(request, env, { sessionOnly: true });
  if (auth.error) return auth.error;

  let body;
  try {
    body = await request.json();
  } catch {
    return bad(request, "Invalid JSON body");
  }

  await ensureApprovalSettings(env, auth.user.id);

  const parseOptMoney = (v) => {
    if (v === null || v === "" || v === undefined) return null;
    const n = Number(v);
    if (!Number.isFinite(n) || n < 0) return undefined;
    return Math.round(n * 1e6) / 1e6;
  };

  const sets = [];
  const binds = [];
  const add = (col, val, present) => {
    if (!present) return;
    sets.push(col + " = ?" + (binds.length + 1));
    binds.push(val);
  };

  if ("approve_over_usd" in body) {
    const v = parseOptMoney(body.approve_over_usd);
    if (v === undefined) return bad(request, "approve_over_usd invalid");
    add("approve_over_usd", v, true);
  }
  if ("alert_over_usd" in body) {
    const v = parseOptMoney(body.alert_over_usd);
    if (v === undefined) return bad(request, "alert_over_usd invalid");
    add("alert_over_usd", v, true);
  }
  if ("approve_new_counterparty" in body) {
    add(
      "approve_new_counterparty",
      body.approve_new_counterparty ? 1 : 0,
      true
    );
  }
  if ("approve_task_prefixes" in body) {
    let prefixes = body.approve_task_prefixes;
    if (Array.isArray(prefixes)) {
      prefixes = prefixes.map((s) => String(s).trim().toLowerCase()).filter(Boolean);
    } else if (typeof prefixes === "string") {
      prefixes = prefixes
        .split(",")
        .map((s) => s.trim().toLowerCase())
        .filter(Boolean);
    } else if (prefixes == null || prefixes === "") {
      prefixes = [];
    } else {
      return bad(request, "approve_task_prefixes invalid");
    }
    add("approve_task_prefixes", prefixes.join(",") || null, true);
  }
  if ("ttl_seconds" in body) {
    const t = Number(body.ttl_seconds);
    if (!Number.isFinite(t) || t < 60 || t > 7 * 24 * 3600) {
      return bad(request, "ttl_seconds must be 60–604800");
    }
    add("ttl_seconds", Math.floor(t), true);
  }
  if ("warn_bps" in body) {
    const w = Number(body.warn_bps);
    if (!Number.isFinite(w) || w < 1000 || w > 9900) {
      return bad(request, "warn_bps must be 1000–9900");
    }
    add("warn_bps", Math.floor(w), true);
  }
  if ("enabled" in body) {
    add("enabled", body.enabled ? 1 : 0, true);
  }

  if (!sets.length) return bad(request, "No fields to update");

  sets.push("updated_at = datetime('now')");
  binds.push(auth.user.id);

  await env.DB.prepare(
    `UPDATE user_approval_settings SET ${sets.join(", ")} WHERE user_id = ?${binds.length}`
  )
    .bind(...binds)
    .run();

  const row = await getApprovalSettings(env, auth.user.id);
  return json(request, {
    ok: true,
    user_id: auth.user.id,
    settings: serializeApprovalSettings(row),
  });
}

export async function handleMeApprovalsList(request, env) {
  const auth = await requireUser(request, env);
  if (auth.error) return auth.error;

  const url = new URL(request.url);
  const status = url.searchParams.get("status") || null;
  const limit = url.searchParams.get("limit");

  await expirePendingApprovals(env, auth.user.id);
  const rows = await listApprovalRequests(env, auth.user.id, {
    status,
    limit,
  });

  const pending = await countPendingApprovals(env, auth.user.id);
  return json(request, {
    ok: true,
    user_id: auth.user.id,
    pending_count: pending,
    approvals: rows.map((r) => ({
      id: r.id,
      from_repo: r.from_repo,
      to_repo: r.to_repo,
      amount: r.amount,
      task: r.task,
      rule_code: r.rule_code,
      reason: r.reason,
      status: r.status,
      created_at: r.created_at,
      expires_at: r.expires_at,
      resolved_at: r.resolved_at,
      resolved_by: r.resolved_by,
    })),
  });
}

export async function handleMeApprovalsDecide(request, env) {
  // Session only — human owner decides
  const auth = await requireUser(request, env, { sessionOnly: true });
  if (auth.error) return auth.error;

  let body;
  try {
    body = await request.json();
  } catch {
    return bad(request, "Invalid JSON body");
  }

  const id = String(body.id || body.approval_id || "").trim();
  if (!id) return bad(request, "id required");

  const result = await decideApproval(env, {
    id,
    userId: auth.user.id,
    decision: body.decision,
    resolved_by: auth.user.id,
    note: body.note || body.reason || null,
  });

  if (!result.ok) {
    return bad(request, result.error || "Decide failed", 400, {
      code: result.code,
      status: result.status,
    });
  }

  return json(request, {
    ok: true,
    approval: result,
  });
}
