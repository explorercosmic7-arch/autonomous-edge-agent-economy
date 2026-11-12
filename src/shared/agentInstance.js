/**
 * Day 03 · Agent Lifecycle
 *
 * Agents are first-class instances (not bare repo strings).
 * State: created → funded → active → paused → retired
 *
 * Routes (wire in index.js):
 *   POST /api/instances              create
 *   GET  /api/instances              list mine
 *   GET  /api/instances/:id          get one
 *   POST /api/instances/:id/fund     created|funded → funded (optionally auto-active)
 *   POST /api/instances/:id/activate funded → active
 *   POST /api/instances/:id/pause    active → paused
 *   POST /api/instances/:id/resume   paused → active
 *   POST /api/instances/:id/retire   * → retired (terminal)
 *   POST /api/instances/freeze       emergency: pause one or all under account
 *
 * Gate helper: assertInstanceOperable(env, instanceId) — use from pay / hire / work
 */
import { json, bad } from "./http.js";
import { parseRepo, parseAmount, randomId } from "./utils.js";
import { getSessionUser, getAuthUser } from "./auth.js";
import { ensureAccount } from "./accounts.js";
import { checkRateLimit } from "./rateLimit.js";
import { recordSecurityEvent } from "./securityLog.js";
import {
  AGENT_INSTANCE_STATUSES,
  AGENT_INSTANCE_OPERABLE,
  MAX_AGENT_INSTANCES_PER_USER,
  RL_INSTANCE_CREATE_MAX,
  RL_INSTANCE_CREATE_WINDOW_SEC,
} from "./constants.js";

const CREATE_SQL =
  "CREATE TABLE IF NOT EXISTS agent_instances (" +
  "id TEXT PRIMARY KEY, " +
  "owner_user_id TEXT NOT NULL, " +
  "repo_id TEXT NOT NULL, " +
  "label TEXT, " +
  "status TEXT NOT NULL DEFAULT 'created', " +
  "funded_usd REAL NOT NULL DEFAULT 0, " +
  "meta_json TEXT, " +
  "created_at TEXT NOT NULL DEFAULT (datetime('now')), " +
  "updated_at TEXT NOT NULL DEFAULT (datetime('now')), " +
  "funded_at TEXT, " +
  "activated_at TEXT, " +
  "paused_at TEXT, " +
  "retired_at TEXT" +
  ")";

let _tableReady = false;

export async function ensureAgentInstancesTable(env) {
  if (!env || !env.DB) return false;
  if (_tableReady) return true;
  try {
    await env.DB.prepare(CREATE_SQL).run();
    try {
      await env.DB.prepare(
        "CREATE INDEX IF NOT EXISTS idx_agent_inst_owner ON agent_instances(owner_user_id, created_at)"
      ).run();
    } catch (_) {}
    try {
      await env.DB.prepare(
        "CREATE INDEX IF NOT EXISTS idx_agent_inst_owner_status ON agent_instances(owner_user_id, status)"
      ).run();
    } catch (_) {}
    _tableReady = true;
    return true;
  } catch (e) {
    console.log("agent_instances_ensure", e && e.message);
    return false;
  }
}

function rowPublic(r) {
  if (!r) return null;
  let meta = null;
  try {
    meta = r.meta_json ? JSON.parse(r.meta_json) : null;
  } catch {
    meta = null;
  }
  return {
    id: r.id,
    owner_user_id: r.owner_user_id,
    repo_id: r.repo_id,
    label: r.label || null,
    status: r.status,
    funded_usd: r.funded_usd != null ? Number(r.funded_usd) : 0,
    meta,
    created_at: r.created_at,
    updated_at: r.updated_at,
    funded_at: r.funded_at || null,
    activated_at: r.activated_at || null,
    paused_at: r.paused_at || null,
    retired_at: r.retired_at || null,
  };
}

export async function getInstanceById(env, id) {
  await ensureAgentInstancesTable(env);
  const row = await env.DB.prepare(
    `SELECT * FROM agent_instances WHERE id = ?1`
  )
    .bind(id)
    .first();
  return row || null;
}

/**
 * Gate for pay / hire / work.
 * @returns {{ ok: true, instance } | { ok: false, error, code, status }}
 */
export async function assertInstanceOperable(env, instanceId, opts = {}) {
  const allow = opts.allowStatuses || AGENT_INSTANCE_OPERABLE || ["active"];
  if (!instanceId) {
    return {
      ok: false,
      error: "instance_id required",
      code: "instance_required",
      status: 400,
    };
  }
  const row = await getInstanceById(env, String(instanceId).slice(0, 64));
  if (!row) {
    return {
      ok: false,
      error: "Agent instance not found",
      code: "instance_not_found",
      status: 404,
    };
  }
  if (!allow.includes(row.status)) {
    return {
      ok: false,
      error:
        row.status === "paused"
          ? "Agent instance is paused — cannot spend or take new work"
          : row.status === "retired"
            ? "Agent instance is retired — permanently blocked"
            : `Agent instance status '${row.status}' cannot operate (need: ${allow.join("|")})`,
      code: "instance_" + row.status,
      status: 403,
      instance: rowPublic(row),
    };
  }
  return { ok: true, instance: rowPublic(row) };
}

/** Optional gate: if body has instance_id, enforce; if missing, allow (legacy). */
export async function maybeAssertInstanceFromBody(env, body, opts) {
  const id =
    body &&
    (body.instance_id || body.instanceId || body.agent_instance_id || null);
  if (!id) return { ok: true, instance: null, instance_id: null };
  const r = await assertInstanceOperable(env, id, opts);
  if (!r.ok) return r;
  return { ok: true, instance: r.instance, instance_id: r.instance.id };
}

function ownerId(user) {
  return user && (user.id || user.user_id);
}

async function requireSession(request, env) {
  const user = await getSessionUser(request, env);
  if (!user) return { error: bad(request, "Sign in required", 401) };
  return { user };
}

async function requireOwnerInstance(request, env, id) {
  const { user, error } = await requireSession(request, env);
  if (error) return { error };
  const row = await getInstanceById(env, id);
  if (!row) return { error: bad(request, "Instance not found", 404) };
  if (row.owner_user_id !== user.id) {
    return { error: bad(request, "Not your instance", 403) };
  }
  return { user, row };
}

/* ─── Routes ─── */

/** POST /api/instances  { repo, label?, meta? } */
export async function handleInstanceCreate(request, env) {
  const { user, error } = await requireSession(request, env);
  if (error) return error;

  const limited = await checkRateLimit(
    env,
    "instcreate:" + user.id,
    RL_INSTANCE_CREATE_MAX || 20,
    RL_INSTANCE_CREATE_WINDOW_SEC || 3600
  );
  if (limited) {
    return bad(request, "Rate limit: too many instance creates", 429, {
      retry_after_sec: limited.retry_after_sec,
    });
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return bad(request, "Invalid JSON body");
  }

  const repo = parseRepo(body.repo || body.repo_id || body.default_repo);
  if (!repo) return bad(request, "repo must be owner/repo");

  const label = body.label != null ? String(body.label).slice(0, 120) : null;
  let metaJson = null;
  if (body.meta != null) {
    try {
      metaJson = JSON.stringify(body.meta).slice(0, 4000);
    } catch {
      metaJson = null;
    }
  }

  await ensureAgentInstancesTable(env);

  const max = MAX_AGENT_INSTANCES_PER_USER || 50;
  try {
    const cnt = await env.DB.prepare(
      `SELECT COUNT(*) AS c FROM agent_instances WHERE owner_user_id = ?1 AND status != 'retired'`
    )
      .bind(user.id)
      .first();
    if (Number(cnt && cnt.c) >= max) {
      return bad(request, "Max agent instances reached (" + max + ")", 400, {
        code: "instance_limit",
      });
    }
  } catch (_) {}

  const id = "ainst_" + randomId(12);
  await ensureAccount(env, repo);

  await env.DB.prepare(
    `INSERT INTO agent_instances (
       id, owner_user_id, repo_id, label, status, funded_usd, meta_json,
       created_at, updated_at
     ) VALUES (?1, ?2, ?3, ?4, 'created', 0, ?5, datetime('now'), datetime('now'))`
  )
    .bind(id, user.id, repo, label, metaJson)
    .run();

  await recordSecurityEvent(
    env,
    {
      kind: "agent.create",
      severity: "info",
      user_id: user.id,
      repo_id: repo,
      reason: "instance_create",
      meta: { instance_id: id, label },
    },
    request
  ).catch(() => {});

  const row = await getInstanceById(env, id);
  return json(request, { ok: true, instance: rowPublic(row) });
}

/** GET /api/instances?status=&limit= */
export async function handleInstanceList(request, url, env) {
  const { user, error } = await requireSession(request, env);
  if (error) return error;
  await ensureAgentInstancesTable(env);

  const status = (url.searchParams.get("status") || "").trim().toLowerCase();
  const limit = Math.min(
    Math.max(Number(url.searchParams.get("limit") || 50), 1),
    100
  );

  let rows;
  if (status && (AGENT_INSTANCE_STATUSES || []).includes(status)) {
    const { results } = await env.DB.prepare(
      `SELECT * FROM agent_instances
       WHERE owner_user_id = ?1 AND status = ?2
       ORDER BY created_at DESC LIMIT ?3`
    )
      .bind(user.id, status, limit)
      .all();
    rows = results || [];
  } else {
    const { results } = await env.DB.prepare(
      `SELECT * FROM agent_instances
       WHERE owner_user_id = ?1
       ORDER BY created_at DESC LIMIT ?2`
    )
      .bind(user.id, limit)
      .all();
    rows = results || [];
  }

  return json(request, {
    ok: true,
    count: rows.length,
    instances: rows.map(rowPublic),
  });
}

/** GET /api/instances/:id */
export async function handleInstanceGet(request, env, id) {
  const { user, row, error } = await requireOwnerInstance(request, env, id);
  if (error) return error;
  return json(request, { ok: true, instance: rowPublic(row) });
}

/**
 * POST /api/instances/:id/fund
 * Body: { amount?, activate?: true }
 * created|funded → funded; if activate, → active
 * Note: does not move ledger cash by itself — marks lifecycle + optional ensureAccount.
 * Optional amount is recorded on the instance as funded_usd (cumulative).
 */
export async function handleInstanceFund(request, env, id) {
  const { user, row, error } = await requireOwnerInstance(request, env, id);
  if (error) return error;

  if (row.status === "retired") {
    return bad(request, "Retired instance cannot be funded", 403, {
      code: "instance_retired",
    });
  }
  if (row.status === "paused") {
    return bad(request, "Paused instance — resume before funding", 403, {
      code: "instance_paused",
    });
  }

  let body = {};
  try {
    body = await request.json();
  } catch {
    body = {};
  }

  const amount = parseAmount(body.amount);
  const activate = !!(body.activate || body.auto_activate);

  await ensureAccount(env, row.repo_id);

  const add = amount != null ? amount : 0;
  const newFunded = Number(row.funded_usd || 0) + add;
  let nextStatus = "funded";
  if (activate || row.status === "active") {
    nextStatus = activate ? "active" : row.status === "active" ? "active" : "funded";
  }
  if (row.status === "active") nextStatus = "active";

  await env.DB.prepare(
    `UPDATE agent_instances SET
       status = ?2,
       funded_usd = ?3,
       funded_at = COALESCE(funded_at, datetime('now')),
       activated_at = CASE WHEN ?2 = 'active' THEN COALESCE(activated_at, datetime('now')) ELSE activated_at END,
       updated_at = datetime('now')
     WHERE id = ?1`
  )
    .bind(id, nextStatus, newFunded)
    .run();

  await recordSecurityEvent(
    env,
    {
      kind: "agent.fund",
      severity: "info",
      user_id: user.id,
      repo_id: row.repo_id,
      amount_usd: add || null,
      reason: "instance_fund",
      meta: { instance_id: id, status: nextStatus },
    },
    request
  ).catch(() => {});

  const updated = await getInstanceById(env, id);
  return json(request, { ok: true, instance: rowPublic(updated) });
}

/** POST /api/instances/:id/activate  funded → active */
export async function handleInstanceActivate(request, env, id) {
  const { user, row, error } = await requireOwnerInstance(request, env, id);
  if (error) return error;

  if (row.status === "active") {
    return json(request, { ok: true, instance: rowPublic(row), already: true });
  }
  if (row.status === "retired") {
    return bad(request, "Cannot activate retired instance", 403);
  }
  if (row.status === "paused") {
    return bad(request, "Use resume for paused instances", 400, {
      code: "use_resume",
    });
  }
  if (row.status !== "funded" && row.status !== "created") {
    return bad(request, "Can only activate from created/funded", 400);
  }
  // Prefer funded first, but allow created → active for lab speed if body.force
  let body = {};
  try {
    body = await request.json();
  } catch {
    body = {};
  }
  if (row.status === "created" && !body.force) {
    return bad(
      request,
      "Fund the instance first (or pass force:true for lab)",
      400,
      { code: "need_fund" }
    );
  }

  await env.DB.prepare(
    `UPDATE agent_instances SET
       status = 'active',
       activated_at = COALESCE(activated_at, datetime('now')),
       updated_at = datetime('now')
     WHERE id = ?1`
  )
    .bind(id)
    .run();

  await recordSecurityEvent(
    env,
    {
      kind: "agent.activate",
      severity: "info",
      user_id: user.id,
      repo_id: row.repo_id,
      reason: "instance_activate",
      meta: { instance_id: id },
    },
    request
  ).catch(() => {});

  return json(request, {
    ok: true,
    instance: rowPublic(await getInstanceById(env, id)),
  });
}

/** POST /api/instances/:id/pause */
export async function handleInstancePause(request, env, id) {
  const { user, row, error } = await requireOwnerInstance(request, env, id);
  if (error) return error;

  if (row.status === "retired") {
    return bad(request, "Retired instance cannot be paused", 403);
  }
  if (row.status === "paused") {
    return json(request, { ok: true, instance: rowPublic(row), already: true });
  }

  await env.DB.prepare(
    `UPDATE agent_instances SET
       status = 'paused',
       paused_at = datetime('now'),
       updated_at = datetime('now')
     WHERE id = ?1`
  )
    .bind(id)
    .run();

  await recordSecurityEvent(
    env,
    {
      kind: "agent.pause",
      severity: "warn",
      user_id: user.id,
      repo_id: row.repo_id,
      reason: "instance_pause",
      meta: { instance_id: id, from: row.status },
    },
    request
  ).catch(() => {});

  return json(request, {
    ok: true,
    instance: rowPublic(await getInstanceById(env, id)),
  });
}

/** POST /api/instances/:id/resume  paused → active */
export async function handleInstanceResume(request, env, id) {
  const { user, row, error } = await requireOwnerInstance(request, env, id);
  if (error) return error;

  if (row.status !== "paused") {
    return bad(request, "Only paused instances can be resumed", 400, {
      code: "not_paused",
      status: row.status,
    });
  }

  await env.DB.prepare(
    `UPDATE agent_instances SET
       status = 'active',
       paused_at = NULL,
       updated_at = datetime('now')
     WHERE id = ?1`
  )
    .bind(id)
    .run();

  await recordSecurityEvent(
    env,
    {
      kind: "agent.resume",
      severity: "info",
      user_id: user.id,
      repo_id: row.repo_id,
      reason: "instance_resume",
      meta: { instance_id: id },
    },
    request
  ).catch(() => {});

  return json(request, {
    ok: true,
    instance: rowPublic(await getInstanceById(env, id)),
  });
}

/** POST /api/instances/:id/retire  terminal */
export async function handleInstanceRetire(request, env, id) {
  const { user, row, error } = await requireOwnerInstance(request, env, id);
  if (error) return error;

  if (row.status === "retired") {
    return json(request, { ok: true, instance: rowPublic(row), already: true });
  }

  await env.DB.prepare(
    `UPDATE agent_instances SET
       status = 'retired',
       retired_at = datetime('now'),
       updated_at = datetime('now')
     WHERE id = ?1`
  )
    .bind(id)
    .run();

  await recordSecurityEvent(
    env,
    {
      kind: "agent.retire",
      severity: "warn",
      user_id: user.id,
      repo_id: row.repo_id,
      reason: "instance_retire",
      meta: { instance_id: id, from: row.status },
    },
    request
  ).catch(() => {});

  return json(request, {
    ok: true,
    instance: rowPublic(await getInstanceById(env, id)),
  });
}

/**
 * POST /api/instances/freeze
 * Body: { instance_id? } — one id, or omit to pause ALL non-retired under account
 * Emergency freeze.
 */
export async function handleInstanceFreeze(request, env) {
  const { user, error } = await requireSession(request, env);
  if (error) return error;
  await ensureAgentInstancesTable(env);

  let body = {};
  try {
    body = await request.json();
  } catch {
    body = {};
  }

  const one = body.instance_id || body.instanceId || null;

  if (one) {
    const row = await getInstanceById(env, String(one));
    if (!row || row.owner_user_id !== user.id) {
      return bad(request, "Instance not found", 404);
    }
    if (row.status === "retired") {
      return bad(request, "Already retired", 400);
    }
    if (row.status !== "paused") {
      await env.DB.prepare(
        `UPDATE agent_instances SET status = 'paused', paused_at = datetime('now'), updated_at = datetime('now') WHERE id = ?1`
      )
        .bind(row.id)
        .run();
    }
    await recordSecurityEvent(
      env,
      {
        kind: "agent.freeze",
        severity: "critical",
        user_id: user.id,
        repo_id: row.repo_id,
        reason: "emergency_freeze_one",
        meta: { instance_id: row.id },
      },
      request
    ).catch(() => {});
    return json(request, {
      ok: true,
      frozen: 1,
      instances: [rowPublic(await getInstanceById(env, row.id))],
    });
  }

  // All under account
  const { results } = await env.DB.prepare(
    `SELECT id FROM agent_instances
     WHERE owner_user_id = ?1 AND status NOT IN ('paused', 'retired')`
  )
    .bind(user.id)
    .all();
  const ids = (results || []).map((r) => r.id);
  for (const iid of ids) {
    await env.DB.prepare(
      `UPDATE agent_instances SET status = 'paused', paused_at = datetime('now'), updated_at = datetime('now') WHERE id = ?1`
    )
      .bind(iid)
      .run();
  }

  await recordSecurityEvent(
    env,
    {
      kind: "agent.freeze",
      severity: "critical",
      user_id: user.id,
      reason: "emergency_freeze_all",
      meta: { count: ids.length, ids },
    },
    request
  ).catch(() => {});

  const { results: after } = await env.DB.prepare(
    `SELECT * FROM agent_instances WHERE owner_user_id = ?1 ORDER BY created_at DESC LIMIT 50`
  )
    .bind(user.id)
    .all();

  return json(request, {
    ok: true,
    frozen: ids.length,
    instances: (after || []).map(rowPublic),
  });
}
