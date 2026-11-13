/**
 * Day 03/04 · Agent instances — lifecycle + hard spend gates.
 * Status: created → funded → active → paused → retired
 * Only "active" may spend (pay / hire accept / work lock).
 */
import { json, bad } from "./http.js";
import { parseRepo, parseAmount, randomId } from "./utils.js";
import { checkRateLimit } from "./rateLimit.js";
import { getSessionUser, getAuthUser } from "./auth.js";
import { ensureAccount } from "./accounts.js";
import { recordSecurityEvent } from "./securityLog.js";
import {
  AGENT_INSTANCE_STATUSES,
  AGENT_INSTANCE_OPERABLE,
  MAX_AGENT_INSTANCES_PER_USER,
  RL_INSTANCE_CREATE_MAX,
  RL_INSTANCE_CREATE_WINDOW_SEC,
  FAUCET_MAX_PER_CALL,
  FAUCET_ACCOUNT_CAP,
  SYSTEM_FAUCET,
} from "./constants.js";

const CREATE_TABLE = `
CREATE TABLE IF NOT EXISTS agent_instances (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  repo_id TEXT NOT NULL,
  label TEXT,
  status TEXT NOT NULL DEFAULT 'created',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  funded_at TEXT,
  activated_at TEXT,
  paused_at TEXT,
  retired_at TEXT,
  pause_reason TEXT,
  meta_json TEXT
)`;

let _tableReady = false;

export async function ensureAgentInstanceTable(env) {
  if (_tableReady) return true;
  if (!env || !env.DB) return false;
  try {
    await env.DB.prepare(CREATE_TABLE).run();
    try {
      await env.DB.prepare(
        `CREATE INDEX IF NOT EXISTS idx_ainst_user ON agent_instances(user_id, created_at)`
      ).run();
    } catch (_) {}
    try {
      await env.DB.prepare(
        `CREATE INDEX IF NOT EXISTS idx_ainst_repo ON agent_instances(repo_id)`
      ).run();
    } catch (_) {}
    _tableReady = true;
    return true;
  } catch (e) {
    console.log("agent_instance_ensure", e && e.message);
    return false;
  }
}

function operableStatuses() {
  return AGENT_INSTANCE_OPERABLE && AGENT_INSTANCE_OPERABLE.length
    ? AGENT_INSTANCE_OPERABLE
    : ["active"];
}

export function isInstanceOperable(status) {
  return operableStatuses().includes(String(status || "").toLowerCase());
}

export async function loadInstance(env, id) {
  if (!id) return null;
  await ensureAgentInstanceTable(env);
  try {
    return await env.DB.prepare(`SELECT * FROM agent_instances WHERE id = ?1`)
      .bind(id)
      .first();
  } catch {
    return null;
  }
}

/**
 * Hard gate: instance must exist and be active (or in OPERABLE list).
 * Returns { ok:true, instance } or { ok:false, error, code, status, instance? }
 */
export async function assertInstanceActive(env, instanceId, { requireId } = {}) {
  const id = String(instanceId || "").trim();
  if (!id) {
    if (requireId) {
      return {
        ok: false,
        error: "instance_id required",
        code: "instance_required",
        status: 400,
      };
    }
    return { ok: true, instance: null };
  }
  const row = await loadInstance(env, id);
  if (!row) {
    return {
      ok: false,
      error: "Agent instance not found",
      code: "instance_not_found",
      status: 404,
    };
  }
  const st = String(row.status || "").toLowerCase();
  if (!isInstanceOperable(st)) {
    const code =
      st === "paused"
        ? "instance_paused"
        : st === "retired"
          ? "instance_retired"
          : "instance_not_active";
    return {
      ok: false,
      error:
        st === "paused"
          ? "Agent instance is paused — resume before spending"
          : st === "retired"
            ? "Agent instance is retired — cannot spend"
            : "Agent instance is not active (status=" + st + ")",
      code,
      status: 403,
      instance: publicInstance(row),
    };
  }
  return { ok: true, instance: row };
}

/** Read instance_id from body or header X-Instance-Id */
export function readInstanceId(body, request) {
  const fromBody =
    body &&
    (body.instance_id || body.instanceId || body.agent_instance_id);
  if (fromBody) return String(fromBody).trim();
  if (request) {
    const h = request.headers.get("X-Instance-Id");
    if (h) return String(h).trim();
  }
  return "";
}

export async function maybeAssertInstanceFromBody(env, body, request) {
  const id = readInstanceId(body, request);
  return assertInstanceActive(env, id, { requireId: false });
}

function publicInstance(row) {
  if (!row) return null;
  return {
    id: row.id,
    repo_id: row.repo_id,
    label: row.label || null,
    status: row.status,
    created_at: row.created_at,
    updated_at: row.updated_at,
    funded_at: row.funded_at || null,
    activated_at: row.activated_at || null,
    paused_at: row.paused_at || null,
    retired_at: row.retired_at || null,
    pause_reason: row.pause_reason || null,
  };
}

async function logInstanceEvent(env, request, kind, row, reason, meta) {
  try {
    await recordSecurityEvent(
      env,
      {
        kind,
        severity: kind.includes("freeze") || kind === "agent.retire" ? "warn" : "info",
        user_id: row.user_id,
        repo_id: row.repo_id,
        reason: reason || null,
        meta: Object.assign({ instance_id: row.id, status: row.status }, meta || {}),
        // instance_id column (securityLog supports it)
        instance_id: row.id,
      },
      request
    );
  } catch (e) {
    console.log("instance_sec_event", e && e.message);
  }
}

export async function handleInstanceCreate(request, env) {
  const user = await getSessionUser(request, env);
  if (!user) return bad(request, "Sign in required", 401);
  const limited = await checkRateLimit(
    env,
    "inst:create:" + user.id,
    RL_INSTANCE_CREATE_MAX || 20,
    RL_INSTANCE_CREATE_WINDOW_SEC || 3600
  );
  if (limited) {
    return bad(request, "Rate limit: instance create", 429, {
      retry_after_sec: limited.retry_after_sec,
    });
  }
  let body = {};
  try {
    body = await request.json();
  } catch {
    body = {};
  }
  const repo = parseRepo(body.repo || body.repo_id || body.default_repo);
  if (!repo) return bad(request, "repo must be owner/repo");
  const label = body.label ? String(body.label).slice(0, 64) : null;
  await ensureAgentInstanceTable(env);
  try {
    const c = await env.DB.prepare(
      `SELECT COUNT(*) AS c FROM agent_instances WHERE user_id = ?1 AND status != 'retired'`
    )
      .bind(user.id)
      .first();
    if ((c && Number(c.c)) >= (MAX_AGENT_INSTANCES_PER_USER || 50)) {
      return bad(request, "Max agent instances reached", 429, { code: "instance_cap" });
    }
  } catch (_) {}
  const id = "ainst_" + randomId(16);
  try {
    await env.DB.prepare(
      `INSERT INTO agent_instances (id, user_id, repo_id, label, status, created_at, updated_at)
       VALUES (?1, ?2, ?3, ?4, 'created', datetime('now'), datetime('now'))`
    )
      .bind(id, user.id, repo, label)
      .run();
  } catch (e) {
    return bad(request, "Create failed: " + (e.message || e), 500);
  }
  const row = await loadInstance(env, id);
  await logInstanceEvent(env, request, "agent.create", row || { id, user_id: user.id, repo_id: repo, status: "created" }, "dashboard_create");
  return json(request, { ok: true, instance: publicInstance(row) });
}

export async function handleInstanceList(request, url, env) {
  const user = await getSessionUser(request, env);
  if (!user) return bad(request, "Sign in required", 401);
  await ensureAgentInstanceTable(env);
  const limit = Math.min(Math.max(Number(url.searchParams.get("limit") || 50), 1), 100);
  const status = (url.searchParams.get("status") || "").trim().toLowerCase();
  let sql = `SELECT * FROM agent_instances WHERE user_id = ?1`;
  const binds = [user.id];
  if (status && (AGENT_INSTANCE_STATUSES || []).includes(status)) {
    sql += ` AND status = ?2`;
    binds.push(status);
    sql += ` ORDER BY created_at DESC LIMIT ?3`;
    binds.push(limit);
  } else {
    sql += ` ORDER BY created_at DESC LIMIT ?2`;
    binds.push(limit);
  }
  try {
    const { results } = await env.DB.prepare(sql).bind(...binds).all();
    return json(request, {
      ok: true,
      count: (results || []).length,
      instances: (results || []).map(publicInstance),
    });
  } catch (e) {
    return bad(request, "List failed: " + (e.message || e), 500);
  }
}

export async function handleInstanceGet(request, env, id) {
  const user = await getSessionUser(request, env);
  if (!user) return bad(request, "Sign in required", 401);
  const row = await loadInstance(env, id);
  if (!row || row.user_id !== user.id) return bad(request, "Not found", 404);
  return json(request, { ok: true, instance: publicInstance(row) });
}

export async function handleInstanceFund(request, env, id) {
  const user = await getSessionUser(request, env);
  if (!user) return bad(request, "Sign in required", 401);
  const row = await loadInstance(env, id);
  if (!row || row.user_id !== user.id) return bad(request, "Not found", 404);
  if (row.status === "retired") return bad(request, "Retired instance", 400, { code: "instance_retired" });
  let body = {};
  try {
    body = await request.json();
  } catch {
    body = {};
  }
  const amount = parseAmount(body.amount != null ? body.amount : 1);
  const activate = body.activate === true || body.activate === "true";
  if (amount == null || amount <= 0) return bad(request, "amount invalid");
  if (amount > FAUCET_MAX_PER_CALL) {
    return bad(request, "Max faucet per call is $" + FAUCET_MAX_PER_CALL);
  }
  await ensureAccount(env, row.repo_id);
  const updated = await env.DB.prepare(
    `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now')
     WHERE repo_id = ?2 AND (balance + ?1) <= ?3 RETURNING balance`
  )
    .bind(amount, row.repo_id, FAUCET_ACCOUNT_CAP)
    .first();
  if (!updated) {
    return bad(request, "Faucet cap reached", 429);
  }
  await env.DB.prepare(
    `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
     VALUES (?1, ?2, ?3, ?4, 'success', 0)`
  )
    .bind(SYSTEM_FAUCET, row.repo_id, amount, "instance-fund:" + id)
    .run()
    .catch(() => {});

  let newStatus = row.status === "created" ? "funded" : row.status;
  if (activate || body.activate !== false) {
    if (newStatus === "funded" || newStatus === "created") newStatus = "active";
  }
  await env.DB.prepare(
    `UPDATE agent_instances SET
       status = ?2,
       funded_at = COALESCE(funded_at, datetime('now')),
       activated_at = CASE WHEN ?2 = 'active' THEN COALESCE(activated_at, datetime('now')) ELSE activated_at END,
       updated_at = datetime('now')
     WHERE id = ?1`
  )
    .bind(id, newStatus)
    .run();

  const next = await loadInstance(env, id);
  await logInstanceEvent(env, request, "agent.fund", next, "fund", { amount });
  if (newStatus === "active") {
    await logInstanceEvent(env, request, "agent.activate", next, "fund_activate");
  }
  return json(request, {
    ok: true,
    instance: publicInstance(next),
    balance: Number(updated.balance),
    amount,
  });
}

export async function handleInstanceActivate(request, env, id) {
  const user = await getSessionUser(request, env);
  if (!user) return bad(request, "Sign in required", 401);
  const row = await loadInstance(env, id);
  if (!row || row.user_id !== user.id) return bad(request, "Not found", 404);
  if (row.status === "retired") return bad(request, "Cannot activate retired", 400);
  if (row.status === "paused") {
    return bad(request, "Use resume for paused instances", 400, { code: "use_resume" });
  }
  await env.DB.prepare(
    `UPDATE agent_instances SET status = 'active', activated_at = COALESCE(activated_at, datetime('now')), updated_at = datetime('now')
     WHERE id = ?1`
  )
    .bind(id)
    .run();
  const next = await loadInstance(env, id);
  await logInstanceEvent(env, request, "agent.activate", next, "activate");
  return json(request, { ok: true, instance: publicInstance(next) });
}

export async function handleInstancePause(request, env, id) {
  const user = await getSessionUser(request, env);
  if (!user) return bad(request, "Sign in required", 401);
  const row = await loadInstance(env, id);
  if (!row || row.user_id !== user.id) return bad(request, "Not found", 404);
  if (row.status === "retired") return bad(request, "Already retired", 400);
  if (row.status === "paused") {
    return json(request, { ok: true, instance: publicInstance(row), already: true });
  }
  let body = {};
  try {
    body = await request.json();
  } catch {
    body = {};
  }
  const reason = body.reason ? String(body.reason).slice(0, 200) : "operator_pause";
  await env.DB.prepare(
    `UPDATE agent_instances SET status = 'paused', paused_at = datetime('now'), pause_reason = ?2, updated_at = datetime('now')
     WHERE id = ?1`
  )
    .bind(id, reason)
    .run();
  const next = await loadInstance(env, id);
  await logInstanceEvent(env, request, "agent.pause", next, reason);
  return json(request, { ok: true, instance: publicInstance(next) });
}

export async function handleInstanceResume(request, env, id) {
  const user = await getSessionUser(request, env);
  if (!user) return bad(request, "Sign in required", 401);
  const row = await loadInstance(env, id);
  if (!row || row.user_id !== user.id) return bad(request, "Not found", 404);
  if (row.status === "retired") return bad(request, "Cannot resume retired", 400);
  if (row.status !== "paused") {
    return json(request, { ok: true, instance: publicInstance(row), already: true });
  }
  await env.DB.prepare(
    `UPDATE agent_instances SET status = 'active', pause_reason = NULL, updated_at = datetime('now')
     WHERE id = ?1`
  )
    .bind(id)
    .run();
  const next = await loadInstance(env, id);
  await logInstanceEvent(env, request, "agent.resume", next, "operator_resume");
  return json(request, { ok: true, instance: publicInstance(next) });
}

export async function handleInstanceRetire(request, env, id) {
  const user = await getSessionUser(request, env);
  if (!user) return bad(request, "Sign in required", 401);
  const row = await loadInstance(env, id);
  if (!row || row.user_id !== user.id) return bad(request, "Not found", 404);
  if (row.status === "retired") {
    return json(request, { ok: true, instance: publicInstance(row), already: true });
  }
  await env.DB.prepare(
    `UPDATE agent_instances SET status = 'retired', retired_at = datetime('now'), updated_at = datetime('now')
     WHERE id = ?1`
  )
    .bind(id)
    .run();
  const next = await loadInstance(env, id);
  await logInstanceEvent(env, request, "agent.retire", next, "operator_retire");
  return json(request, { ok: true, instance: publicInstance(next) });
}

/** Emergency freeze: one instance or all under account */
export async function handleInstanceFreeze(request, env) {
  const user = await getSessionUser(request, env);
  if (!user) return bad(request, "Sign in required", 401);
  let body = {};
  try {
    body = await request.json();
  } catch {
    body = {};
  }
  const one = String(body.instance_id || body.id || "").trim();
  await ensureAgentInstanceTable(env);
  const reason = body.reason ? String(body.reason).slice(0, 200) : "emergency_freeze";
  let paused = 0;
  if (one) {
    const row = await loadInstance(env, one);
    if (!row || row.user_id !== user.id) return bad(request, "Not found", 404);
    if (row.status !== "retired" && row.status !== "paused") {
      await env.DB.prepare(
        `UPDATE agent_instances SET status = 'paused', paused_at = datetime('now'), pause_reason = ?2, updated_at = datetime('now')
         WHERE id = ?1`
      )
        .bind(one, reason)
        .run();
      paused = 1;
      const next = await loadInstance(env, one);
      await logInstanceEvent(env, request, "agent.freeze", next, reason);
    }
  } else {
    const r = await env.DB.prepare(
      `UPDATE agent_instances SET status = 'paused', paused_at = datetime('now'), pause_reason = ?2, updated_at = datetime('now')
       WHERE user_id = ?1 AND status IN ('created','funded','active')`
    )
      .bind(user.id, reason)
      .run();
    paused = (r && r.meta && r.meta.changes) || 0;
    await recordSecurityEvent(
      env,
      {
        kind: "agent.freeze_all",
        severity: "critical",
        user_id: user.id,
        reason,
        meta: { paused },
      },
      request
    );
  }
  return json(request, { ok: true, paused, reason });
}

export { publicInstance };
