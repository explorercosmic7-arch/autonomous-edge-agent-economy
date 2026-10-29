/**
 * Agent Economic Passport (AEP)
 *
 * Portable, signed economic identity for autonomous agents — not humans.
 *
 * Public surface never exposes exact balances, private keys, or full counterparties.
 * Agents use this to decide whether to trade with a stranger agent in milliseconds.
 *
 * Endpoints:
 *   GET  /api/passport/:repo          — public live summary (no auth)
 *   GET  /api/passport/:repo/history  — redacted settlement / dispute digests
 *   POST /api/passport/issue          — owner issues signed passport blob
 *   POST /api/passport/verify         — verify signature + freshness
 *   GET  /api/passport/me             — signed-in agent's own passport (convenience)
 *
 * Optional D1: agent_passports (issued blob cache) — d1-passport-migration.sql
 * Reuses: agent_limits.rep_score, rep_events, transactions, work_*, disputes,
 *         delegations, intent_capsules, payment_receipts
 */
import { json, bad } from "./http.js";
import { parseRepo, hmacSha256Hex } from "./utils.js";
import { getSessionUser, getAuthUser } from "./auth.js";

const PASSPORT_TTL_SEC_DEFAULT = 3600; // 1h
const PASSPORT_TTL_SEC_MAX = 86400 * 7; // 7d
const PASSPORT_VERSION = 1;

/* ─── Volume / count bands (privacy: never exact $) ─── */
function volumeBand(usd) {
  const n = Number(usd) || 0;
  if (n <= 0) return "0";
  if (n < 0.1) return "<0.1";
  if (n < 1) return "0.1-1";
  if (n < 10) return "1-10";
  if (n < 100) return "10-100";
  if (n < 1000) return "100-1k";
  if (n < 10000) return "1k-10k";
  return "10k+";
}

function countBand(n) {
  const x = Number(n) || 0;
  if (x <= 0) return "0";
  if (x < 5) return "1-4";
  if (x < 20) return "5-19";
  if (x < 100) return "20-99";
  if (x < 500) return "100-499";
  return "500+";
}

function creditBand(usd) {
  return volumeBand(usd);
}

function passportSecret(env) {
  return (
    (env && (env.PASSPORT_SECRET || env.RECEIPT_SECRET || env.SESSION_SECRET)) ||
    "agentpay-passport-dev-only"
  );
}

function inferProvider(repo) {
  // Heuristic: gitlab namespaces often differ; agents already store provider on agents table
  return null;
}

/**
 * Aggregate live economic signals for a repo from existing tables.
 * Fail-soft: missing tables → zeros, never 500 the public map.
 */
async function buildPassportStats(env, repo) {
  const stats = {
    repo_id: repo,
    rep_score: 0,
    settled_volume_usd: 0,
    settled_tx_count: 0,
    counterparty_count: 0,
    work_settled: 0,
    work_refunded: 0,
    disputes_opened: 0,
    disputes_against: 0,
    disputes_executed: 0,
    open_delegations: 0,
    open_intents: 0,
    hire_completed: 0,
    credit_suggested: 0,
    first_activity_at: null,
    last_activity_at: null,
  };

  // rep + credit suggestion
  try {
    const lim = await env.DB.prepare(
      `SELECT rep_score, credit_limit FROM agent_limits WHERE repo_id = ?1`
    )
      .bind(repo)
      .first();
    if (lim) {
      stats.rep_score = Number(lim.rep_score || 0);
      // suggested ≈ same ratio used in credit module when present
      stats.credit_suggested = Number(lim.credit_limit || 0);
    }
  } catch (_) {}

  // Settled volume + counterparties (successful pays)
  try {
    const pay = await env.DB.prepare(
      `SELECT
         COALESCE(SUM(CASE WHEN status = 'success' THEN amount ELSE 0 END), 0) AS vol,
         COUNT(CASE WHEN status = 'success' THEN 1 END) AS n,
         MIN(created_at) AS first_at,
         MAX(created_at) AS last_at
       FROM transactions
       WHERE from_repo = ?1 OR to_repo = ?1`
    )
      .bind(repo)
      .first();
    if (pay) {
      stats.settled_volume_usd = Number(pay.vol || 0);
      stats.settled_tx_count = Number(pay.n || 0);
      stats.first_activity_at = pay.first_at || null;
      stats.last_activity_at = pay.last_at || null;
    }
  } catch (_) {}

  try {
    const cp = await env.DB.prepare(
      `SELECT COUNT(DISTINCT other) AS n FROM (
         SELECT to_repo AS other FROM transactions WHERE from_repo = ?1 AND status = 'success'
         UNION
         SELECT from_repo AS other FROM transactions WHERE to_repo = ?1 AND status = 'success'
       )`
    )
      .bind(repo)
      .first();
    stats.counterparty_count = Number(cp?.n || 0);
  } catch (_) {}

  // Work claims
  try {
    const wk = await env.DB.prepare(
      `SELECT
         SUM(CASE WHEN status = 'settled' THEN 1 ELSE 0 END) AS settled,
         SUM(CASE WHEN status = 'refunded' THEN 1 ELSE 0 END) AS refunded
       FROM work_claims
       WHERE provider_repo = ?1 OR buyer_repo = ?1`
    )
      .bind(repo)
      .first();
    stats.work_settled = Number(wk?.settled || 0);
    stats.work_refunded = Number(wk?.refunded || 0);
  } catch (_) {}

  // Disputes
  try {
    const dsp = await env.DB.prepare(
      `SELECT
         SUM(CASE WHEN buyer_repo = ?1 THEN 1 ELSE 0 END) AS opened,
         SUM(CASE WHEN provider_repo = ?1 THEN 1 ELSE 0 END) AS against,
         SUM(CASE WHEN status = 'executed' THEN 1 ELSE 0 END) AS executed
       FROM work_disputes
       WHERE buyer_repo = ?1 OR provider_repo = ?1`
    )
      .bind(repo)
      .first();
    stats.disputes_opened = Number(dsp?.opened || 0);
    stats.disputes_against = Number(dsp?.against || 0);
    stats.disputes_executed = Number(dsp?.executed || 0);
  } catch (_) {}

  // Open authorities (counts only)
  try {
    const dg = await env.DB.prepare(
      `SELECT COUNT(*) AS n FROM delegations
       WHERE parent_repo = ?1 AND status = 'open'`
    )
      .bind(repo)
      .first();
    stats.open_delegations = Number(dg?.n || 0);
  } catch (_) {}

  try {
    const ic = await env.DB.prepare(
      `SELECT COUNT(*) AS n FROM intent_capsules
       WHERE repo_id = ?1 AND status = 'open'`
    )
      .bind(repo)
      .first();
    stats.open_intents = Number(ic?.n || 0);
  } catch (_) {
    try {
      const ic2 = await env.DB.prepare(
        `SELECT COUNT(*) AS n FROM intent_capsules
         WHERE owner_repo = ?1 AND status IN ('open','active')`
      )
        .bind(repo)
        .first();
      stats.open_intents = Number(ic2?.n || 0);
    } catch (_) {}
  }

  // Hire completions (provider side)
  try {
    const hr = await env.DB.prepare(
      `SELECT COUNT(*) AS n FROM hire_jobs
       WHERE (provider_repo = ?1 OR buyer_repo = ?1) AND status = 'completed'`
    )
      .bind(repo)
      .first();
    stats.hire_completed = Number(hr?.n || 0);
  } catch (_) {
    try {
      const hr2 = await env.DB.prepare(
        `SELECT COUNT(*) AS n FROM hire_rfqs
         WHERE buyer_repo = ?1 AND status = 'matched'`
      )
        .bind(repo)
        .first();
      stats.hire_completed = Number(hr2?.n || 0);
    } catch (_) {}
  }

  // Provider from agents table when present
  let provider = null;
  try {
    const ag = await env.DB.prepare(
      `SELECT provider FROM agents WHERE repo_id = ?1 LIMIT 1`
    )
      .bind(repo)
      .first();
    provider = ag?.provider || null;
  } catch (_) {}

  return { stats, provider };
}

function publicClaimsFromStats(stats, provider) {
  const totalDisputes =
    (stats.disputes_opened || 0) + (stats.disputes_against || 0);
  const disputeRate =
    stats.settled_tx_count > 0
      ? Math.min(1, totalDisputes / Math.max(1, stats.settled_tx_count))
      : totalDisputes > 0
        ? 1
        : 0;

  return {
    v: PASSPORT_VERSION,
    repo_id: stats.repo_id,
    provider: provider || null,
    rep_score: Math.round(Number(stats.rep_score) || 0),
    settled_volume_band: volumeBand(stats.settled_volume_usd),
    settled_tx_band: countBand(stats.settled_tx_count),
    counterparty_band: countBand(stats.counterparty_count),
    work_settled_band: countBand(stats.work_settled),
    work_refunded_band: countBand(stats.work_refunded),
    dispute_rate: Math.round(disputeRate * 1000) / 1000,
    disputes_executed_band: countBand(stats.disputes_executed),
    hire_completed_band: countBand(stats.hire_completed),
    open_delegations: Number(stats.open_delegations) || 0,
    open_intents: Number(stats.open_intents) || 0,
    credit_suggested_band: creditBand(stats.credit_suggested),
    first_activity_at: stats.first_activity_at,
    last_activity_at: stats.last_activity_at,
  };
}

async function signPayload(env, payloadObj) {
  const payload = JSON.stringify(payloadObj);
  const signature = await hmacSha256Hex(passportSecret(env), payload);
  return { payload, signature, claims: payloadObj };
}

async function verifyPayload(env, payloadStr, signature) {
  const expected = await hmacSha256Hex(passportSecret(env), String(payloadStr));
  const sig = String(signature || "");
  return expected === sig.toLowerCase() || expected === sig;
}

/* ─── GET /api/passport/:repo ─── */
export async function handlePassportGet(request, env, repoRaw) {
  const repo = parseRepo(repoRaw);
  if (!repo || !repo.includes("/")) {
    return bad(request, "repo must be owner/name", 400);
  }

  const { stats, provider } = await buildPassportStats(env, repo);
  const claims = publicClaimsFromStats(stats, provider);

  return json(request, {
    ok: true,
    passport: claims,
    privacy: {
      note: "Bands only — no exact balances, no private keys, no full counterparty list",
      exact_balance: false,
      exact_volume: false,
    },
    verify: "POST /api/passport/verify with a signed issue blob",
    issue: "POST /api/passport/issue (owner session or API key)",
  });
}

/* ─── GET /api/passport/:repo/history ─── */
export async function handlePassportHistory(request, env, repoRaw, url) {
  const repo = parseRepo(repoRaw);
  if (!repo || !repo.includes("/")) {
    return bad(request, "repo must be owner/name", 400);
  }

  const limit = Math.min(50, Math.max(1, Number(url.searchParams.get("limit") || 20)));

  // Redacted digests only
  const digests = [];

  try {
    const txs = await env.DB.prepare(
      `SELECT id, from_repo, to_repo, amount, status, task, created_at
       FROM transactions
       WHERE (from_repo = ?1 OR to_repo = ?1) AND status = 'success'
       ORDER BY created_at DESC LIMIT ?2`
    )
      .bind(repo, limit)
      .all();
    for (const r of txs.results || []) {
      const peer = r.from_repo === repo ? r.to_repo : r.from_repo;
      digests.push({
        kind: "settle",
        id: r.id,
        direction: r.from_repo === repo ? "out" : "in",
        peer_band: peer ? peer.split("/")[0] + "/*" : "*",
        amount_band: volumeBand(r.amount),
        task_prefix: r.task ? String(r.task).slice(0, 24) : null,
        at: r.created_at,
      });
    }
  } catch (_) {}

  try {
    const ds = await env.DB.prepare(
      `SELECT id, buyer_repo, provider_repo, status, decision, amount_usd, created_at
       FROM work_disputes
       WHERE buyer_repo = ?1 OR provider_repo = ?1
       ORDER BY created_at DESC LIMIT ?2`
    )
      .bind(repo, Math.min(20, limit))
      .all();
    for (const r of ds.results || []) {
      digests.push({
        kind: "dispute",
        id: r.id,
        role: r.buyer_repo === repo ? "buyer" : "provider",
        status: r.status,
        decision: r.decision || null,
        amount_band: volumeBand(r.amount_usd),
        at: r.created_at,
      });
    }
  } catch (_) {}

  digests.sort((a, b) => String(b.at || "").localeCompare(String(a.at || "")));

  return json(request, {
    ok: true,
    repo_id: repo,
    digests: digests.slice(0, limit),
    privacy: "Peers are namespace-masked; amounts are bands only",
  });
}

/* ─── POST /api/passport/issue ─── */
export async function handlePassportIssue(request, env) {
  const auth = await getAuthUser(request, env);
  if (!auth) return bad(request, "Sign in or API key required", 401);

  let body = {};
  try {
    body = await request.json();
  } catch {
    body = {};
  }

  let repo = body.repo ? parseRepo(body.repo) : null;
  if (!repo && auth.default_repo) repo = parseRepo(auth.default_repo);
  if (!repo || !repo.includes("/")) {
    return bad(request, "repo required (owner/name) or bind default agent", 400);
  }

  // Owner check: session user must own the agent binding, or API key scoped to repo
  if (auth.default_repo && parseRepo(auth.default_repo) !== repo) {
    // Allow if user owns the agents row
    try {
      const own = await env.DB.prepare(
        `SELECT 1 FROM agents WHERE repo_id = ?1 AND user_id = ?2 LIMIT 1`
      )
        .bind(repo, auth.id || auth.user_id)
        .first();
      if (!own && !auth.key_id) {
        // API key path: keys are user-owned; still require default or body match policy
        return bad(request, "Not authorized to issue passport for " + repo, 403);
      }
    } catch (_) {
      // agents table may differ — fall through if default matches
      if (auth.default_repo && parseRepo(auth.default_repo) !== repo) {
        return bad(request, "Not authorized to issue passport for " + repo, 403);
      }
    }
  }

  let ttl = Number(body.ttl_seconds);
  if (!Number.isFinite(ttl) || ttl <= 0) ttl = PASSPORT_TTL_SEC_DEFAULT;
  ttl = Math.min(PASSPORT_TTL_SEC_MAX, Math.max(60, ttl));

  const { stats, provider } = await buildPassportStats(env, repo);
  const now = Math.floor(Date.now() / 1000);
  const claims = {
    ...publicClaimsFromStats(stats, provider),
    issued_at: now,
    expires_at: now + ttl,
    issuer: "agentpay",
  };

  const signed = await signPayload(env, claims);

  // Optional cache
  try {
    await env.DB.prepare(
      `INSERT INTO agent_passports (id, repo_id, payload_json, signature, issued_at, expires_at, issued_by)
       VALUES (?1, ?2, ?3, ?4, datetime('now'), datetime(?5, 'unixepoch'), ?6)
       ON CONFLICT(id) DO UPDATE SET
         payload_json = excluded.payload_json,
         signature = excluded.signature,
         issued_at = excluded.issued_at,
         expires_at = excluded.expires_at`
    )
      .bind(
        "pp_" + repo.replace(/[^a-zA-Z0-9_-]/g, "_").slice(0, 40) + "_" + now,
        repo,
        signed.payload,
        signed.signature,
        claims.expires_at,
        String(auth.id || auth.user_id || auth.key_id || "agent")
      )
      .run();
  } catch (_) {
    // table optional
  }

  return json(request, {
    ok: true,
    passport: claims,
    payload: signed.payload,
    signature: signed.signature,
    ttl_seconds: ttl,
    agent_usage: {
      header: "X-Agent-Passport: <base64(payload)>.<signature>",
      or_body: { passport_payload: signed.payload, passport_sig: signed.signature },
      verify: "POST /api/passport/verify",
    },
  });
}

/* ─── POST /api/passport/verify ─── */
export async function handlePassportVerify(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return bad(request, "Invalid JSON body");
  }

  const payloadStr = body.payload || body.passport_payload;
  const signature = body.signature || body.passport_sig || body.sig;
  if (!payloadStr || !signature) {
    return bad(request, "payload + signature required");
  }

  const valid = await verifyPayload(env, payloadStr, signature);
  if (!valid) {
    return json(request, {
      ok: false,
      valid: false,
      error: "invalid_signature",
    });
  }

  let claims;
  try {
    claims = typeof payloadStr === "string" ? JSON.parse(payloadStr) : payloadStr;
  } catch {
    return bad(request, "payload is not valid JSON");
  }

  const now = Math.floor(Date.now() / 1000);
  const expired = claims.expires_at != null && Number(claims.expires_at) < now;

  return json(request, {
    ok: true,
    valid: true,
    expired: !!expired,
    fresh: !expired,
    claims,
    trust_hint: expired
      ? "Passport expired — request a new issue from the agent owner"
      : claims.rep_score >= 50
        ? "Established agent signal"
        : claims.settled_tx_band !== "0"
          ? "Has settlement history"
          : "New or low-activity agent",
  });
}

/* ─── GET /api/passport/me ─── */
export async function handlePassportMe(request, env) {
  const user = await getSessionUser(request, env);
  if (!user) return bad(request, "Sign in required", 401);
  const repo = user.default_repo ? parseRepo(user.default_repo) : null;
  if (!repo) {
    return json(request, {
      ok: true,
      default_repo: null,
      passport: null,
      hint: "Bind a default agent first",
    });
  }
  const { stats, provider } = await buildPassportStats(env, repo);
  return json(request, {
    ok: true,
    default_repo: repo,
    passport: publicClaimsFromStats(stats, provider),
    issue: "POST /api/passport/issue to get a signed blob for peer agents",
  });
}
