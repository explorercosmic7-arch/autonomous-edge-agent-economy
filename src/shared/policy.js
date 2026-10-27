/**
 * Shared policy-as-code — allow/deny to, max_amount, task prefix.
 */
import { parseRepo } from "./utils.js";
import { getSessionUser } from "./auth.js";
import { logSafetyEvent } from "./safety.js";
import { json, bad } from "./http.js";

/* ─── Policy-as-code spend rules ───
 * JSON policy on agent_policies.repo_id:
 * {
 *   version: 1,
 *   blocked: false,
 *   max_amount: 5.0,           // per tx (null = no cap beyond safety)
 *   allow_to: ["acme/*", "bob/tool"],  // empty = allow all (unless deny)
 *   deny_to: ["scam/*"],
 *   require_task_prefix: ["job-", "task-"],  // empty = any task
 *   notes: "..."
 * }
 * Glob: * matches any segment remainder (owner/* or star/name or *).
 */
export function matchRepoGlob(pattern, repo) {
  if (!pattern || !repo) return false;
  const p = String(pattern).trim();
  const r = String(repo).trim();
  if (p === "*") return true;
  if (p === r) return true;
  // prefix*
  if (p.endsWith("*") && !p.slice(0, -1).includes("*")) {
    return r.startsWith(p.slice(0, -1));
  }
  // owner/*
  if (p.includes("/*")) {
    const owner = p.split("/")[0];
    return r.startsWith(owner + "/");
  }
  return false;
}

export function normalizePolicy(raw) {
  let p = raw;
  if (typeof raw === "string") {
    try { p = JSON.parse(raw); } catch { p = {}; }
  }
  if (!p || typeof p !== "object") p = {};
  const arr = (v) => (Array.isArray(v) ? v.map((x) => String(x).trim()).filter(Boolean) : []);
  return {
    version: Number(p.version) || 1,
    blocked: !!p.blocked,
    max_amount: p.max_amount == null || p.max_amount === "" ? null : Number(p.max_amount),
    allow_to: arr(p.allow_to),
    deny_to: arr(p.deny_to),
    require_task_prefix: arr(p.require_task_prefix),
    notes: p.notes ? String(p.notes).slice(0, 500) : "",
  };
}

export async export function getAgentPolicy(env, repoId) {
  if (!repoId) return normalizePolicy({});
  try {
    const row = await env.DB.prepare(
      `SELECT policy_json, version, updated_at, updated_by FROM agent_policies WHERE repo_id = ?1`
    )
      .bind(repoId)
      .first();
    if (!row) return normalizePolicy({});
    const pol = normalizePolicy(row.policy_json);
    pol._version = row.version;
    pol._updated_at = row.updated_at;
    pol._updated_by = row.updated_by;
    return pol;
  } catch (e) {
    console.log("policy_load_error", e && e.message);
    return normalizePolicy({});
  }
}

/** Returns null if allowed, or { code, error }. */
export async export function checkSpendPolicy(env, fromRepo, amount, toRepo, task) {
  const pol = await getAgentPolicy(env, fromRepo);
  if (pol.blocked) {
    return { code: "policy_blocked", error: "Spend policy: agent is blocked by policy-as-code" };
  }
  if (pol.max_amount != null && Number.isFinite(pol.max_amount) && Number(amount) > pol.max_amount) {
    return {
      code: "policy_max_amount",
      error: "Spend policy: amount $" + Number(amount).toFixed(6) + " exceeds max_amount $" + pol.max_amount,
    };
  }
  if (toRepo) {
    if (pol.deny_to.length) {
      for (const g of pol.deny_to) {
        if (matchRepoGlob(g, toRepo)) {
          return {
            code: "policy_deny_to",
            error: "Spend policy: to_repo denied by rule " + g,
          };
        }
      }
    }
    if (pol.allow_to.length) {
      let ok = false;
      for (const g of pol.allow_to) {
        if (matchRepoGlob(g, toRepo)) {
          ok = true;
          break;
        }
      }
      if (!ok) {
        return {
          code: "policy_allow_to",
          error: "Spend policy: to_repo not in allow_to list",
        };
      }
    }
  }
  if (pol.require_task_prefix.length) {
    const t = String(task || "");
    const ok = pol.require_task_prefix.some((pref) => t.startsWith(pref));
    if (!ok) {
      return {
        code: "policy_task_prefix",
        error:
          "Spend policy: task must start with one of: " +
          pol.require_task_prefix.join(", "),
      };
    }
  }
  return null;
}

export async export function handleMePolicyGet(request, env) {
  const user = await getSessionUser(request, env);
  if (!user) return bad(request, "Sign in required", 401);
  const repo = user.default_repo ? parseRepo(user.default_repo) : null;
  if (!repo) {
    return json(request, {
      ok: true,
      default_repo: null,
      policy: normalizePolicy({}),
      hint: "Bind a default agent first",
    });
  }
  const pol = await getAgentPolicy(env, repo);
  return json(request, {
    ok: true,
    default_repo: repo,
    policy: {
      version: pol.version,
      blocked: pol.blocked,
      max_amount: pol.max_amount,
      allow_to: pol.allow_to,
      deny_to: pol.deny_to,
      require_task_prefix: pol.require_task_prefix,
      notes: pol.notes,
    },
    meta: {
      stored_version: pol._version || null,
      updated_at: pol._updated_at || null,
      updated_by: pol._updated_by || null,
    },
    schema: {
      blocked: "boolean — hard stop all spends",
      max_amount: "number|null — max USD per operation",
      allow_to: "string[] — globs e.g. acme/* ; empty = all allowed",
      deny_to: "string[] — globs denied even if allow matches",
      require_task_prefix: "string[] — task must start with one",
      notes: "string",
    },
  });
}

export async export function handleMePolicySet(request, env) {
  const user = await getSessionUser(request, env);
  if (!user) return bad(request, "Sign in required", 401);
  const repo = user.default_repo ? parseRepo(user.default_repo) : null;
  if (!repo) return bad(request, "Bind a default agent first");

  let body;
  try {
    body = await request.json();
  } catch {
    return bad(request, "Invalid JSON body");
  }

  // Accept nested policy or flat body
  const src = body.policy && typeof body.policy === "object" ? body.policy : body;
  const pol = normalizePolicy(src);

  if (pol.max_amount != null && (!Number.isFinite(pol.max_amount) || pol.max_amount < 0)) {
    return bad(request, "max_amount invalid");
  }

  const jsonStr = JSON.stringify({
    version: 1,
    blocked: pol.blocked,
    max_amount: pol.max_amount,
    allow_to: pol.allow_to,
    deny_to: pol.deny_to,
    require_task_prefix: pol.require_task_prefix,
    notes: pol.notes,
  });

  try {
    await env.DB.prepare(
      `INSERT INTO agent_policies (repo_id, policy_json, version, updated_by, updated_at)
       VALUES (?1, ?2, 1, ?3, datetime('now'))
       ON CONFLICT(repo_id) DO UPDATE SET
         policy_json = excluded.policy_json,
         version = agent_policies.version + 1,
         updated_by = excluded.updated_by,
         updated_at = datetime('now')`
    )
      .bind(repo, jsonStr, user.id)
      .run();
  } catch (e) {
    return bad(
      request,
      "agent_policies table missing — run d1-policy-migration.sql: " + (e.message || e),
      500
    );
  }

  await logSafetyEvent(env, "policy.updated", {
    repo_id: repo,
    user_id: user.id,
    reason: "dashboard",
    meta: pol,
  });

  const saved = await getAgentPolicy(env, repo);
  return json(request, {
    ok: true,
    default_repo: repo,
    policy: {
      version: saved.version,
      blocked: saved.blocked,
      max_amount: saved.max_amount,
      allow_to: saved.allow_to,
      deny_to: saved.deny_to,
      require_task_prefix: saved.require_task_prefix,
      notes: saved.notes,
    },
  });
}

