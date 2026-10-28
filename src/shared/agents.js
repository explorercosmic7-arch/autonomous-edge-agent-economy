/**
 * Agents catalog — me/agent, GitHub/GitLab repos, capabilities index, search/rank/scan
 */
import { json, bad } from "./http.js";
import { parseRepo, randomId } from "./utils.js";
import { checkRateLimit } from "./rateLimit.js";
import { getSessionUser, getAuthUser } from "./auth.js";
import { ensureAccount } from "./accounts.js";
import {
  RL_GITHUB_REPOS_MAX,
  RL_GITHUB_REPOS_WINDOW_SEC,
} from "./constants.js";

/* ─── Me / agent ─── */

export async function handleMeAgent(request, env) {
  const user = await getSessionUser(request, env);
  if (!user) return bad(request, "Sign in required", 401);

  let body;
  try {
    body = await request.json();
  } catch {
    return bad(request, "Invalid JSON body");
  }

  let repo = body.repo;
  if (repo === null || repo === "" || repo === undefined) {
    repo = null;
  } else {
    repo = parseRepo(repo);
    if (!repo) return bad(request, "repo must be owner/repo or null to clear");
  }

  await env.DB.prepare(
    `UPDATE users SET default_repo = ?1, updated_at = datetime('now') WHERE id = ?2`
  )
    .bind(repo, user.id)
    .run();

  if (repo) await ensureAccount(env, repo);
  return json(request, { ok: true, default_repo: repo, user_id: user.id });
}

/** List GitHub repos for signed-in user (requires prior GitHub OAuth with read:user). */
export async function handleMeGithubRepos(request, env) {
  const user = await getSessionUser(request, env);
  if (!user) return bad(request, "Sign in required", 401);

  const limited = await checkRateLimit(
    env,
    "githubrepos:" + user.id,
    RL_GITHUB_REPOS_MAX,
    RL_GITHUB_REPOS_WINDOW_SEC
  );
  if (limited) {
    return bad(
      request,
      "Rate limit: max " +
        RL_GITHUB_REPOS_MAX +
        " GitHub repo fetches per hour",
      429,
      {
        code: "rate_limited",
        retry_after_sec: limited.retry_after_sec,
      }
    );
  }

  let row;
  try {
    row = await env.DB.prepare(
      `SELECT github_access_token, github_login FROM users WHERE id = ?1`
    )
      .bind(user.id)
      .first();
  } catch (e) {
    return bad(
      request,
      "D1 missing github_access_token / github_login — run ALTER TABLE",
      500
    );
  }

  const token = row?.github_access_token;
  if (!token) {
    return bad(
      request,
      "GitHub not linked. Log out, then Sign in with GitHub once to enable repo picker.",
      400,
      { code: "github_not_linked" }
    );
  }

  const all = [];
  let page = 1;
  const maxPages = 3;
  while (page <= maxPages) {
    const res = await fetch(
      `https://api.github.com/user/repos?per_page=100&page=${page}&sort=updated&affiliation=owner,collaborator,organization_member`,
      {
        headers: {
          Authorization: `Bearer ${token}`,
          Accept: "application/vnd.github+json",
          "User-Agent": "AgentPay-Worker",
        },
      }
    );
    if (res.status === 401 || res.status === 403) {
      return bad(
        request,
        "GitHub token expired or revoked. Log out and Sign in with GitHub again.",
        401,
        { code: "github_token_invalid" }
      );
    }
    if (!res.ok) {
      return bad(request, "GitHub API error HTTP " + res.status, 502);
    }
    const batch = await res.json();
    if (!Array.isArray(batch) || batch.length === 0) break;
    for (const r of batch) {
      if (r && r.full_name) {
        all.push({
          full_name: String(r.full_name),
          private: !!r.private,
          description: r.description ? String(r.description).slice(0, 120) : null,
          updated_at: r.updated_at || null,
        });
      }
    }
    if (batch.length < 100) break;
    page += 1;
  }

  for (const r of all) {
    r.provider = "github";
  }
  const withCaps = await attachCachedCapabilities(env, all);
  return json(request, {
    ok: true,
    provider: "github",
    github_login: row.github_login || null,
    count: withCaps.length,
    repos: withCaps,
  });
}


/* ─── GitLab project list (parity with GitHub repo picker) ─── */

const RL_GITLAB_REPOS_MAX = 12;
const RL_GITLAB_REPOS_WINDOW_SEC = 3600;
const RL_AGENTS_SCAN_MAX = 30;
const RL_AGENTS_SCAN_WINDOW_SEC = 3600;

export async function handleMeGitlabRepos(request, env) {
  const user = await getSessionUser(request, env);
  if (!user) return bad(request, "Sign in required", 401);

  const limited = await checkRateLimit(
    env,
    "gitlabrepos:" + user.id,
    RL_GITLAB_REPOS_MAX,
    RL_GITLAB_REPOS_WINDOW_SEC
  );
  if (limited) {
    return bad(
      request,
      "Rate limit: max " + RL_GITLAB_REPOS_MAX + " GitLab project fetches per hour",
      429,
      { code: "rate_limited", retry_after_sec: limited.retry_after_sec }
    );
  }

  let row;
  try {
    row = await env.DB.prepare(
      `SELECT gitlab_access_token, gitlab_username FROM users WHERE id = ?1`
    )
      .bind(user.id)
      .first();
  } catch (e) {
    return bad(
      request,
      "D1 missing gitlab_access_token / gitlab_username — run ALTER TABLE",
      500
    );
  }

  const token = row?.gitlab_access_token;
  if (!token) {
    return bad(
      request,
      "GitLab not linked. Log out, then Sign in with GitLab once to enable project picker.",
      400,
      { code: "gitlab_not_linked" }
    );
  }

  const all = [];
  let page = 1;
  const maxPages = 3;
  while (page <= maxPages) {
    const res = await fetch(
      `https://gitlab.com/api/v4/projects?membership=true&simple=true&order_by=last_activity_at&per_page=100&page=${page}`,
      {
        headers: {
          Authorization: `Bearer ${token}`,
          Accept: "application/json",
          "User-Agent": "AgentPay-Worker",
        },
      }
    );
    if (res.status === 401 || res.status === 403) {
      return bad(
        request,
        "GitLab token expired or revoked. Log out and Sign in with GitLab again (needs read_api).",
        401,
        { code: "gitlab_token_invalid" }
      );
    }
    if (!res.ok) {
      return bad(request, "GitLab API error HTTP " + res.status, 502);
    }
    const batch = await res.json();
    if (!Array.isArray(batch) || batch.length === 0) break;
    for (const r of batch) {
      if (r && r.path_with_namespace) {
        all.push({
          full_name: String(r.path_with_namespace),
          private: r.visibility === "private" || r.visibility === "internal",
          description: r.description ? String(r.description).slice(0, 120) : null,
          updated_at: r.last_activity_at || null,
          provider: "gitlab",
          web_url: r.web_url || null,
        });
      }
    }
    if (batch.length < 100) break;
    page += 1;
  }

  // Attach cached capabilities from agent_index
  const withCaps = await attachCachedCapabilities(env, all);

  return json(request, {
    ok: true,
    provider: "gitlab",
    gitlab_username: row.gitlab_username || null,
    count: withCaps.length,
    repos: withCaps,
  });
}

/** Unified: GitHub + GitLab repos the user can bind as agents */
export async function handleMeReposUnified(request, env) {
  const user = await getSessionUser(request, env);
  if (!user) return bad(request, "Sign in required", 401);

  const out = { ok: true, repos: [], sources: {} };

  // GitHub
  try {
    const row = await env.DB.prepare(
      `SELECT github_access_token, github_login FROM users WHERE id = ?1`
    )
      .bind(user.id)
      .first();
    if (row?.github_access_token) {
      const res = await fetch(
        "https://api.github.com/user/repos?per_page=100&page=1&sort=updated&affiliation=owner,collaborator,organization_member",
        {
          headers: {
            Authorization: `Bearer ${row.github_access_token}`,
            Accept: "application/vnd.github+json",
            "User-Agent": "AgentPay-Worker",
          },
        }
      );
      if (res.ok) {
        const batch = await res.json();
        for (const r of batch || []) {
          if (r?.full_name) {
            out.repos.push({
              full_name: String(r.full_name),
              private: !!r.private,
              description: r.description ? String(r.description).slice(0, 120) : null,
              updated_at: r.updated_at || null,
              provider: "github",
            });
          }
        }
        out.sources.github = { ok: true, login: row.github_login, count: (batch || []).length };
      } else {
        out.sources.github = { ok: false, status: res.status };
      }
    } else {
      out.sources.github = { ok: false, code: "github_not_linked" };
    }
  } catch (e) {
    out.sources.github = { ok: false, error: (e && e.message) || "error" };
  }

  // GitLab
  try {
    const row = await env.DB.prepare(
      `SELECT gitlab_access_token, gitlab_username FROM users WHERE id = ?1`
    )
      .bind(user.id)
      .first();
    if (row?.gitlab_access_token) {
      const res = await fetch(
        "https://gitlab.com/api/v4/projects?membership=true&simple=true&order_by=last_activity_at&per_page=100&page=1",
        {
          headers: {
            Authorization: `Bearer ${row.gitlab_access_token}`,
            Accept: "application/json",
            "User-Agent": "AgentPay-Worker",
          },
        }
      );
      if (res.ok) {
        const batch = await res.json();
        for (const r of batch || []) {
          if (r?.path_with_namespace) {
            out.repos.push({
              full_name: String(r.path_with_namespace),
              private: r.visibility === "private" || r.visibility === "internal",
              description: r.description ? String(r.description).slice(0, 120) : null,
              updated_at: r.last_activity_at || null,
              provider: "gitlab",
              web_url: r.web_url || null,
            });
          }
        }
        out.sources.gitlab = {
          ok: true,
          username: row.gitlab_username,
          count: (batch || []).length,
        };
      } else {
        out.sources.gitlab = { ok: false, status: res.status };
      }
    } else {
      out.sources.gitlab = { ok: false, code: "gitlab_not_linked" };
    }
  } catch (e) {
    out.sources.gitlab = { ok: false, error: (e && e.message) || "error" };
  }

  out.repos = await attachCachedCapabilities(env, out.repos);
  out.count = out.repos.length;
  return json(request, out);
}

export async function attachCachedCapabilities(env, repos) {
  if (!repos || !repos.length) return repos || [];
  try {
    const names = repos.map((r) => r.full_name).filter(Boolean).slice(0, 120);
    if (!names.length) return repos;
    // batch lookup
    const placeholders = names.map((_, i) => "?" + (i + 1)).join(",");
    const { results } = await env.DB.prepare(
      `SELECT repo_id, capabilities_json, capabilities_text, source, hireable
       FROM agent_index WHERE repo_id IN (${placeholders})`
    )
      .bind(...names)
      .all();
    const map = {};
    for (const row of results || []) {
      map[row.repo_id] = row;
    }
    return repos.map((r) => {
      const c = map[r.full_name];
      if (!c) return r;
      let caps = [];
      try {
        caps = JSON.parse(c.capabilities_json || "[]");
      } catch (_) {}
      return {
        ...r,
        capabilities: caps,
        capabilities_text: c.capabilities_text || "",
        cap_source: c.source || null,
        hireable: Number(c.hireable) === 1,
      };
    });
  } catch (_) {
    return repos;
  }
}

/* ─── Capabilities-Aware Agent Index ───
 * Parse AP-Capabilities / .agentpay/capabilities.json / wrangler.toml
 * so agents can hire by capability in O(1) without scanning 500 repos.
 */

export async function ensureAgentIndexTable(env) {
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS agent_index (
       repo_id TEXT PRIMARY KEY,
       provider TEXT,
       owner_user_id TEXT,
       display_name TEXT,
       description TEXT,
       capabilities_json TEXT,
       capabilities_text TEXT,
       source TEXT,
       hireable INTEGER DEFAULT 1,
       meta_json TEXT,
       updated_at TEXT,
       indexed_at TEXT
     )`
  ).run();
  try {
    await env.DB.prepare(
      `CREATE INDEX IF NOT EXISTS idx_agent_index_caps ON agent_index(capabilities_text)`
    ).run();
  } catch (_) {}
  try {
    await env.DB.prepare(
      `CREATE INDEX IF NOT EXISTS idx_agent_index_provider ON agent_index(provider)`
    ).run();
  } catch (_) {}
}

export function normalizeCapabilities(list) {
  const out = [];
  const seen = new Set();
  for (const raw of list || []) {
    let s = String(raw || "")
      .trim()
      .toLowerCase()
      .replace(/\s+/g, "");
    if (!s) continue;
    // allow model/vision, api:tool, skill.foo
    s = s.replace(/[^a-z0-9_.:/-]/g, "");
    if (!s || s.length > 64) continue;
    if (seen.has(s)) continue;
    seen.add(s);
    out.push(s);
  }
  return out.slice(0, 40);
}

export function parseCapabilitiesJson(text) {
  try {
    const j = JSON.parse(text);
    if (Array.isArray(j)) return normalizeCapabilities(j);
    if (j && Array.isArray(j.capabilities)) return normalizeCapabilities(j.capabilities);
    if (j && typeof j === "object") {
      const keys = Object.keys(j).filter((k) => j[k]);
      return normalizeCapabilities(keys);
    }
  } catch (_) {}
  return [];
}

export function parseApCapabilitiesFile(text) {
  // one capability per line or comma-separated; ignore comments
  const caps = [];
  for (const line of String(text || "").split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith("//")) continue;
    for (const part of trimmed.split(/[,;]/)) {
      if (part.trim()) caps.push(part.trim());
    }
  }
  return normalizeCapabilities(caps);
}

export function parseWranglerTomlCapabilities(text) {
  const caps = [];
  const t = String(text || "");
  // name = "foo"
  const nameM = t.match(/^\s*name\s*=\s*["']([^"']+)["']/m);
  if (nameM) caps.push("worker:" + nameM[1].toLowerCase().replace(/\s+/g, "-"));
  // compatibility_date implies cloudflare-worker
  if (/compatibility_date\s*=/.test(t)) caps.push("runtime:cloudflare-worker");
  if (/\[\[d1_databases\]\]/.test(t) || /d1_databases/.test(t)) caps.push("storage:d1");
  if (/\[\[kv_namespaces\]\]/.test(t) || /kv_namespaces/.test(t)) caps.push("storage:kv");
  if (/\[\[r2_buckets\]\]/.test(t) || /r2_buckets/.test(t)) caps.push("storage:r2");
  if (/ai\s*=/.test(t) || /\[ai\]/.test(t)) caps.push("model:workers-ai");
  // custom [agentpay.capabilities] style: capabilities = ["a","b"]
  const block = t.match(/\[agentpay(?:\.capabilities)?\][\s\S]*?(?=\n\[|$)/i);
  if (block) {
    const arr = block[0].match(/capabilities\s*=\s*\[([^\]]*)\]/i);
    if (arr) {
      const parts = arr[1].match(/["']([^"']+)["']/g) || [];
      for (const p of parts) caps.push(p.replace(/["']/g, ""));
    }
  }
  return normalizeCapabilities(caps);
}

export async function fetchGithubRaw(token, fullName, path) {
  const url = `https://api.github.com/repos/${fullName}/contents/${path}`;
  const res = await fetch(url, {
    headers: {
      Authorization: token ? `Bearer ${token}` : undefined,
      Accept: "application/vnd.github.raw",
      "User-Agent": "AgentPay-Worker",
    },
  });
  if (!res.ok) return null;
  return await res.text();
}

export async function fetchGitlabRaw(token, pathWithNamespace, path, ref = "HEAD") {
  // GET /projects/:id/repository/files/:file_path/raw
  const project = encodeURIComponent(pathWithNamespace);
  const filePath = encodeURIComponent(path);
  const url = `https://gitlab.com/api/v4/projects/${project}/repository/files/${filePath}/raw?ref=${encodeURIComponent(ref)}`;
  const res = await fetch(url, {
    headers: {
      Authorization: token ? `Bearer ${token}` : undefined,
      Accept: "application/json",
      "User-Agent": "AgentPay-Worker",
    },
  });
  if (!res.ok) return null;
  return await res.text();
}

export async function scanRepoCapabilities(env, { full_name, provider, token }) {
  const pathsJson = [
    ".agentpay/capabilities.json",
    "agentpay.capabilities.json",
    "AP-Capabilities.json",
  ];
  const pathsText = ["AP-Capabilities", ".agentpay/capabilities", "CAPABILITIES"];
  const pathsToml = ["wrangler.toml"];

  let source = null;
  let caps = [];
  let meta = {};

  const fetchRaw = async (path) => {
    if (provider === "gitlab") return fetchGitlabRaw(token, full_name, path);
    return fetchGithubRaw(token, full_name, path);
  };

  for (const p of pathsJson) {
    const text = await fetchRaw(p);
    if (text) {
      caps = parseCapabilitiesJson(text);
      if (caps.length) {
        source = p;
        break;
      }
    }
  }
  if (!caps.length) {
    for (const p of pathsText) {
      const text = await fetchRaw(p);
      if (text) {
        caps = parseApCapabilitiesFile(text);
        if (caps.length) {
          source = p;
          break;
        }
      }
    }
  }
  if (!caps.length) {
    for (const p of pathsToml) {
      const text = await fetchRaw(p);
      if (text) {
        caps = parseWranglerTomlCapabilities(text);
        if (caps.length) {
          source = "wrangler.toml";
          meta.wrangler_hint = true;
          break;
        }
      }
    }
  }

  // Always tag provider
  if (provider === "gitlab" && !caps.includes("vcs:gitlab")) caps.push("vcs:gitlab");
  if (provider === "github" && !caps.includes("vcs:github")) caps.push("vcs:github");
  caps = normalizeCapabilities(caps);

  return { capabilities: caps, source: source || (caps.length ? "inferred" : "none"), meta };
}

export async function upsertAgentIndex(env, row) {
  await ensureAgentIndexTable(env);
  const capsJson = JSON.stringify(row.capabilities || []);
  const capsText = (row.capabilities || []).join(" ");
  await env.DB.prepare(
    `INSERT INTO agent_index (
       repo_id, provider, owner_user_id, display_name, description,
       capabilities_json, capabilities_text, source, hireable, meta_json,
       updated_at, indexed_at
     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, datetime('now'), datetime('now'))
     ON CONFLICT(repo_id) DO UPDATE SET
       provider = excluded.provider,
       owner_user_id = COALESCE(excluded.owner_user_id, agent_index.owner_user_id),
       display_name = COALESCE(excluded.display_name, agent_index.display_name),
       description = COALESCE(excluded.description, agent_index.description),
       capabilities_json = excluded.capabilities_json,
       capabilities_text = excluded.capabilities_text,
       source = excluded.source,
       hireable = excluded.hireable,
       meta_json = excluded.meta_json,
       updated_at = datetime('now'),
       indexed_at = datetime('now')`
  )
    .bind(
      row.repo_id,
      row.provider || null,
      row.owner_user_id || null,
      row.display_name || null,
      row.description || null,
      capsJson,
      capsText,
      row.source || null,
      row.hireable != null ? (row.hireable ? 1 : 0) : 1,
      row.meta ? JSON.stringify(row.meta) : null
    )
    .run();
}

export async function handleAgentsScan(request, env, ctx) {
  const authUser = await getAuthUser(request, env);
  if (!authUser) return bad(request, "Sign in or API key required", 401);

  const limited = await checkRateLimit(
    env,
    "agentscan:" + (authUser.key_id || authUser.id),
    RL_AGENTS_SCAN_MAX,
    RL_AGENTS_SCAN_WINDOW_SEC
  );
  if (limited) {
    return bad(request, "Rate limit: agent scan", 429, {
      retry_after_sec: limited.retry_after_sec,
    });
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return bad(request, "Invalid JSON body");
  }

  const full_name = parseRepo(body.repo || body.full_name || body.repo_id);
  if (!full_name) return bad(request, "repo must be owner/repo");
  let provider = String(body.provider || "").toLowerCase();
  if (!["github", "gitlab"].includes(provider)) {
    // infer from tokens
    provider = "github";
  }

  // Resolve token from session user row
  let token = null;
  const uid = authUser.id;
  try {
    if (provider === "gitlab") {
      const row = await env.DB.prepare(
        `SELECT gitlab_access_token FROM users WHERE id = ?1`
      )
        .bind(uid)
        .first();
      token = row?.gitlab_access_token || null;
      if (!token) {
        // try github fallback only if provider forced wrong
        return bad(request, "GitLab token missing — sign in with GitLab", 400, {
          code: "gitlab_not_linked",
        });
      }
    } else {
      const row = await env.DB.prepare(
        `SELECT github_access_token FROM users WHERE id = ?1`
      )
        .bind(uid)
        .first();
      token = row?.github_access_token || null;
      if (!token) {
        return bad(request, "GitHub token missing — sign in with GitHub", 400, {
          code: "github_not_linked",
        });
      }
    }
  } catch (e) {
    return bad(request, "Token lookup failed: " + (e.message || e), 500);
  }

  const scanned = await scanRepoCapabilities(env, {
    full_name,
    provider,
    token,
  });

  await upsertAgentIndex(env, {
    repo_id: full_name,
    provider,
    owner_user_id: uid,
    display_name: body.display_name || full_name,
    description: body.description || null,
    capabilities: scanned.capabilities,
    source: scanned.source,
    hireable: body.hireable !== false,
    meta: scanned.meta,
  });

  // Optional: ensure account exists so agent is hireable on ledger
  await ensureAccount(env, full_name).catch(() => {});

  return json(request, {
    ok: true,
    repo_id: full_name,
    provider,
    capabilities: scanned.capabilities,
    source: scanned.source,
    hireable: true,
    hint: "Other agents can GET /api/agents/search?capability=model/vision",
  });
}

export async function handleAgentsList(request, url, env) {
  await ensureAgentIndexTable(env).catch(() => {});
  const limit = Math.min(Math.max(Number(url.searchParams.get("limit") || 50), 1), 200);
  const provider = (url.searchParams.get("provider") || "").trim().toLowerCase();
  const hireable = url.searchParams.get("hireable");
  const capability = (url.searchParams.get("capability") || url.searchParams.get("q") || "")
    .trim()
    .toLowerCase();
  const sort = (url.searchParams.get("sort") || "rank").toLowerCase();

  let sql = `SELECT a.repo_id, a.provider, a.display_name, a.description,
                    a.capabilities_json, a.capabilities_text, a.source, a.hireable, a.indexed_at,
                    COALESCE(l.rep_score, 0) AS rep_score,
                    COALESCE(l.locked, 0) AS locked,
                    COALESCE(acc.balance, 0) AS balance
             FROM agent_index a
             LEFT JOIN agent_limits l ON l.repo_id = a.repo_id
             LEFT JOIN accounts acc ON acc.repo_id = a.repo_id
             WHERE 1=1`;
  const binds = [];
  if (provider === "github" || provider === "gitlab") {
    sql += ` AND a.provider = ?`;
    binds.push(provider);
  }
  if (hireable === "1" || hireable === "true") {
    sql += ` AND a.hireable = 1`;
  }
  if (capability) {
    sql += ` AND (a.capabilities_text LIKE ? OR a.capabilities_json LIKE ? OR a.repo_id LIKE ?)`;
    const like = "%" + capability + "%";
    binds.push(like, like, like);
  }
  sql += ` ORDER BY a.indexed_at DESC LIMIT ?`;
  binds.push(Math.min(limit * 3, 300));

  try {
    const { results } = await env.DB.prepare(sql).bind(...binds).all();
    let agents = (results || []).map((r) => scoreAgentRow(r, capability));
    agents = sortAgents(agents, sort).slice(0, limit);
    return json(request, {
      ok: true,
      count: agents.length,
      sort,
      query: capability || null,
      agents,
    });
  } catch (e) {
    return bad(
      request,
      "agent_index missing — first scan creates it: " + (e.message || e),
      500
    );
  }
}

export async function handleAgentsSearch(request, url, env) {
  await ensureAgentIndexTable(env).catch(() => {});
  const capability = (url.searchParams.get("capability") || url.searchParams.get("q") || "")
    .trim()
    .toLowerCase();
  const limit = Math.min(Math.max(Number(url.searchParams.get("limit") || 20), 1), 100);
  const sort = (url.searchParams.get("sort") || "rank").toLowerCase();

  if (!capability) {
    return bad(request, "capability or q required (e.g. model/vision)");
  }

  try {
    const { results } = await env.DB.prepare(
      `SELECT a.repo_id, a.provider, a.display_name, a.description,
              a.capabilities_json, a.capabilities_text, a.source, a.hireable, a.indexed_at,
              COALESCE(l.rep_score, 0) AS rep_score,
              COALESCE(l.locked, 0) AS locked,
              COALESCE(acc.balance, 0) AS balance
       FROM agent_index a
       LEFT JOIN agent_limits l ON l.repo_id = a.repo_id
       LEFT JOIN accounts acc ON acc.repo_id = a.repo_id
       WHERE a.hireable = 1
         AND (
           a.capabilities_text LIKE ?1
           OR a.capabilities_json LIKE ?2
           OR a.repo_id LIKE ?3
         )
       ORDER BY a.indexed_at DESC
       LIMIT ?4`
    )
      .bind("%" + capability + "%", "%" + capability + "%", "%" + capability + "%", Math.min(limit * 3, 200))
      .all();

    let agents = (results || []).map((r) => scoreAgentRow(r, capability));
    agents = sortAgents(agents, sort).slice(0, limit);

    return json(request, {
      ok: true,
      query: capability,
      count: agents.length,
      sort,
      agents,
      latency_hint_ms: "ranked index lookup — no repo tree scan",
    });
  } catch (e) {
    return bad(request, "Search failed: " + (e.message || e), 500);
  }
}

/** Public ranked discovery for humans + agents (Find Agents page). */
export async function handleAgentsRank(request, url, env) {
  await ensureAgentIndexTable(env).catch(() => {});
  const capability = (url.searchParams.get("capability") || url.searchParams.get("q") || "")
    .trim()
    .toLowerCase();
  const provider = (url.searchParams.get("provider") || "").trim().toLowerCase();
  const limit = Math.min(Math.max(Number(url.searchParams.get("limit") || 24), 1), 100);
  const hireableOnly = url.searchParams.get("hireable") !== "0";

  let sql = `SELECT a.repo_id, a.provider, a.display_name, a.description,
                    a.capabilities_json, a.capabilities_text, a.source, a.hireable, a.indexed_at,
                    COALESCE(l.rep_score, 0) AS rep_score,
                    COALESCE(l.locked, 0) AS locked,
                    COALESCE(l.credit_limit, 0) AS credit_limit,
                    COALESCE(acc.balance, 0) AS balance
             FROM agent_index a
             LEFT JOIN agent_limits l ON l.repo_id = a.repo_id
             LEFT JOIN accounts acc ON acc.repo_id = a.repo_id
             WHERE 1=1`;
  const binds = [];
  if (hireableOnly) {
    sql += ` AND a.hireable = 1`;
  }
  if (provider === "github" || provider === "gitlab") {
    sql += ` AND a.provider = ?`;
    binds.push(provider);
  }
  if (capability) {
    sql += ` AND (a.capabilities_text LIKE ? OR a.capabilities_json LIKE ? OR a.repo_id LIKE ? OR a.description LIKE ?)`;
    const like = "%" + capability + "%";
    binds.push(like, like, like, like);
  }
  sql += ` ORDER BY a.indexed_at DESC LIMIT ?`;
  binds.push(Math.min(limit * 4, 400));

  try {
    const t0 = Date.now();
    const { results } = await env.DB.prepare(sql).bind(...binds).all();
    let agents = (results || []).map((r) => scoreAgentRow(r, capability));
    agents = sortAgents(agents, "rank").slice(0, limit);
    return json(request, {
      ok: true,
      query: capability || null,
      provider: provider || null,
      count: agents.length,
      agents,
      algorithm: {
        factors: [
          "capability_match (exact > prefix > substring)",
          "rep_score from agent_limits",
          "hireable flag",
          "not locked",
          "indexed recency",
          "soft balance signal",
        ],
        note: "Rank is advisory for discovery; always verify work/attestations before large pays.",
      },
      latency_ms: Date.now() - t0,
    });
  } catch (e) {
    return bad(request, "Rank failed: " + (e.message || e), 500);
  }
}

export function scoreAgentRow(r, capability) {
  let capabilities = [];
  try {
    capabilities = JSON.parse(r.capabilities_json || "[]");
  } catch (_) {}
  const caps = capabilities.map((c) => String(c).toLowerCase());
  const q = (capability || "").toLowerCase();
  let matchScore = 0;
  if (q) {
    if (caps.some((c) => c === q)) matchScore = 100;
    else if (caps.some((c) => c.startsWith(q) || q.startsWith(c))) matchScore = 70;
    else if (caps.some((c) => c.includes(q))) matchScore = 45;
    else if (String(r.repo_id || "").toLowerCase().includes(q)) matchScore = 25;
    else if (String(r.description || "").toLowerCase().includes(q)) matchScore = 15;
    else matchScore = 5;
  } else {
    matchScore = 20 + Math.min(30, caps.length * 3);
  }
  const rep = Number(r.rep_score || 0);
  const locked = Number(r.locked) === 1;
  const hireable = Number(r.hireable) === 1;
  const balance = Number(r.balance || 0);
  // Weighted rank 0–100 scale (approx)
  let rank =
    matchScore * 0.45 +
    Math.min(40, rep * 0.04) +
    (hireable ? 12 : 0) +
    (locked ? -25 : 8) +
    Math.min(8, Math.log10(balance + 1) * 3);
  rank = Math.round(Math.max(0, Math.min(100, rank)) * 10) / 10;
  return {
    repo_id: r.repo_id,
    provider: r.provider,
    display_name: r.display_name,
    description: r.description,
    capabilities,
    source: r.source,
    hireable,
    locked,
    rep_score: rep,
    balance,
    match_score: matchScore,
    rank_score: rank,
    indexed_at: r.indexed_at,
    match: q || undefined,
  };
}

export function sortAgents(agents, sort) {
  const s = (sort || "rank").toLowerCase();
  const copy = agents.slice();
  if (s === "rep") {
    copy.sort((a, b) => (b.rep_score || 0) - (a.rep_score || 0) || (b.rank_score || 0) - (a.rank_score || 0));
  } else if (s === "recent") {
    copy.sort((a, b) => String(b.indexed_at || "").localeCompare(String(a.indexed_at || "")));
  } else if (s === "name") {
    copy.sort((a, b) => String(a.repo_id).localeCompare(String(b.repo_id)));
  } else {
    copy.sort(
      (a, b) =>
        (b.rank_score || 0) - (a.rank_score || 0) ||
        (b.match_score || 0) - (a.match_score || 0) ||
        (b.rep_score || 0) - (a.rep_score || 0)
    );
  }
  return copy;
}

export async function handleMeBalance(request, env) {
  const user = await getAuthUser(request, env);
  if (!user) return bad(request, "Sign in required", 401);

  const repo = user.default_repo ? parseRepo(user.default_repo) : null;
  if (!repo) {
    return json(request, {
      ok: true,
      default_repo: null,
      balance: 0,
      exists: false,
      error: "no_default_repo",
    });
  }

  const row = await env.DB.prepare(
    `SELECT repo_id, balance, created_at, updated_at FROM accounts WHERE repo_id = ?`
  )
    .bind(repo)
    .first();

  if (!row) {
    return json(request, {
      ok: true,
      default_repo: repo,
      repo_id: repo,
      balance: 0,
      exists: false,
    });
  }
  return json(request, { ok: true, default_repo: repo, ...row, exists: true });
}
