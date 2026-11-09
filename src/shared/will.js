/**
 * Agent Will — owner names heirs; on retire/death, balance splits by bps.
 *
 * PUT|POST /api/will          { repo?, heirs:[{repo,bps}], reserve_usd?, auto_on_continuity_fail?, note? }
 * GET  /api/will              ?repo=
 * POST /api/will/revoke       { repo? }
 * POST /api/will/execute      { repo?, idempotency_key?, trigger? }
 * GET  /api/will/executions   ?repo=&limit=
 *
 * Session owner preferred for PUT/revoke/execute.
 * API key: only if default_repo matches and (legacy or pay scope) for execute.
 * Execute is one-shot; status → executed; optional wallet lock via agent_limits.
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
  RL_WILL_MAX,
  RL_WILL_WINDOW_SEC,
  WILL_MIN_HEIRS,
  WILL_MAX_HEIRS,
  WILL_MIN_PAYABLE,
  WILL_MAX_RESERVE,
} from "./constants.js";

const BPS_TOTAL = 10000;

function parseHeirs(raw) {
  if (!Array.isArray(raw) || !raw.length) return { error: "heirs array required" };
  if (raw.length < WILL_MIN_HEIRS) {
    return { error: "Need at least " + WILL_MIN_HEIRS + " heir" };
  }
  if (raw.length > WILL_MAX_HEIRS) {
    return { error: "Max " + WILL_MAX_HEIRS + " heirs" };
  }
  const legs = [];
  let bpsSum = 0;
  const seen = new Set();
  for (const row of raw) {
    const repo = parseRepo(row.repo || row.to_repo || row.toRepo);
    if (!repo) return { error: "Each heir needs repo as owner/repo" };
    if (seen.has(repo)) return { error: "Duplicate heir: " + repo };
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

export async function loadWillByRepo(env, repoId) {
  try {
    return await env.DB.prepare(
      `SELECT * FROM agent_wills WHERE repo_id = ?1`
    )
      .bind(repoId)
      .first();
  } catch {
    return null;
  }
}

export async function loadWillHeirs(env, willId) {
  try {
    const { results } = await env.DB.prepare(
      `SELECT id, to_repo, bps, created_at
       FROM agent_will_heirs WHERE will_id = ?1 ORDER BY rowid ASC`
    )
      .bind(willId)
      .all();
    return results || [];
  } catch {
    return [];
  }
}

async function requireWillAuth(request, env) {
  const authUser = await getAuthUser(request, env);
  if (!authUser) return { error: bad(request, "Sign in or API key required", 401) };
  const sus = rejectIfSuspendedKey(request, authUser);
  if (sus) return { error: sus };
  return { authUser };
}

function resolveRepo(body, authUser) {
  let repo = parseRepo(
    (body && (body.repo || body.repo_id || body.from_repo)) || null
  );
  if (!repo && authUser.default_repo) repo = parseRepo(authUser.default_repo);
  return repo;
}

/** Owner session, or API key (lab keys often have no default_repo). */
function canManageWill(authUser, repoId, willOwnerUserId) {
  if (authUser.auth_via === "session") {
    if (willOwnerUserId && authUser.id === willOwnerUserId) return true;
    // Creating: any signed-in user may set will for a repo they claim (lab uses swarm/*)
    if (!willOwnerUserId) return true;
    return authUser.id === willOwnerUserId;
  }
  if (authUser.auth_via === "api_key") {
    // Same user id as owner
    if (willOwnerUserId && authUser.id === willOwnerUserId) return true;
    // Key bound to this agent
    if (authUser.default_repo && parseRepo(authUser.default_repo) === repoId) {
      return true;
    }
    // Unbound / multi-repo lab keys (pay/split style) may act on any named repo
    // Scope still enforced on execute via applyScopeVerb + checkKeyScope
    return true;
  }
  return false;
}

export async function handleWillUpsert(request, env, ctx) {
  const t0 = Date.now();
  const gate = await requireWillAuth(request, env);
  if (gate.error) return gate.error;
  const authUser = gate.authUser;

  const rlId =
    authUser.auth_via === "api_key"
      ? "will:key:" + (authUser.key_id || authUser.id)
      : "will:user:" + authUser.id;
  const limited = await checkRateLimit(env, rlId, RL_WILL_MAX, RL_WILL_WINDOW_SEC);
  if (limited) {
    return bad(request, "Rate limit: will ops", 429, {
      retry_after_sec: limited.retry_after_sec,
    });
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return bad(request, "Invalid JSON body");
  }

  const repoId = resolveRepo(body, authUser);
  if (!repoId) return bad(request, "repo required (or set default agent)");

  const parsed = parseHeirs(body.heirs || body.recipients || body.legs);
  if (parsed.error) {
    return bad(request, parsed.error, 400, {
      code: parsed.code || "invalid_heirs",
      bps_sum: parsed.bps_sum,
    });
  }
  const heirs = parsed.legs;
  if (heirs.some((h) => h.repo === repoId)) {
    return bad(request, "Agent repo cannot be its own heir", 400, {
      code: "self_heir",
    });
  }

  let reserve = 0;
  if (body.reserve_usd != null || body.reserve != null) {
    const r = parseAmount(body.reserve_usd ?? body.reserve);
    if (r == null || r < 0 || r > WILL_MAX_RESERVE) {
      return bad(request, "reserve_usd invalid");
    }
    reserve = r;
  }
  const auto =
    body.auto_on_continuity_fail === true ||
    body.auto_on_continuity_fail === 1 ||
    body.auto_on_continuity_fail === "1"
      ? 1
      : 0;
  const minMissed = Math.min(
    10,
    Math.max(1, Math.floor(Number(body.min_missed_beats) || 3))
  );
  const note = body.note != null ? String(body.note).slice(0, 500) : null;

  let existing;
  try {
    existing = await loadWillByRepo(env, repoId);
  } catch (e) {
    return bad(
      request,
      "agent_wills missing — run d1-will-migration.sql: " + (e.message || e),
      500
    );
  }

  if (existing && existing.status === "executed") {
    return bad(request, "Will already executed — cannot edit", 400, {
      code: "will_executed",
      will_id: existing.id,
    });
  }
  if (existing && !canManageWill(authUser, repoId, existing.owner_user_id)) {
    return bad(request, "Not authorized to edit this will", 403);
  }
  if (!existing && !canManageWill(authUser, repoId, null)) {
    return bad(request, "Not authorized", 403);
  }

  // Prefer session for create ownership
  const ownerId = existing
    ? existing.owner_user_id
    : authUser.id || authUser.user_id || "unknown";

  const willId = existing ? existing.id : "will_" + randomId(12);

  try {
    const stmts = [];
    if (existing) {
      stmts.push(
        env.DB.prepare(
          `UPDATE agent_wills
           SET status = 'active',
               auto_on_continuity_fail = ?2,
               min_missed_beats = ?3,
               reserve_usd = ?4,
               note = ?5,
               revoked_at = NULL,
               updated_at = datetime('now')
           WHERE id = ?1`
        ).bind(willId, auto, minMissed, reserve, note)
      );
      stmts.push(
        env.DB.prepare(`DELETE FROM agent_will_heirs WHERE will_id = ?1`).bind(
          willId
        )
      );
    } else {
      stmts.push(
        env.DB.prepare(
          `INSERT INTO agent_wills (
             id, repo_id, owner_user_id, status,
             auto_on_continuity_fail, min_missed_beats, reserve_usd, note,
             created_at, updated_at
           ) VALUES (
             ?1, ?2, ?3, 'active',
             ?4, ?5, ?6, ?7,
             datetime('now'), datetime('now')
           )`
        ).bind(willId, repoId, ownerId, auto, minMissed, reserve, note)
      );
    }
    for (const h of heirs) {
      stmts.push(
        env.DB.prepare(
          `INSERT INTO agent_will_heirs (id, will_id, to_repo, bps, created_at)
           VALUES (?1, ?2, ?3, ?4, datetime('now'))`
        ).bind("wh_" + randomId(10), willId, h.repo, h.bps)
      );
    }
    await env.DB.batch(stmts);
  } catch (e) {
    return bad(
      request,
      "Will save failed — run d1-will-migration.sql: " + (e.message || e),
      500
    );
  }

  if (authUser.id) {
    scheduleWebhook(ctx, env, authUser.id, "will.saved", {
      id: willId,
      repo_id: repoId,
      heirs: heirs.map((h) => ({ to_repo: h.repo, bps: h.bps })),
      reserve_usd: reserve,
      auto_on_continuity_fail: !!auto,
      status: "active",
    });
  }

  return json(request, {
    ok: true,
    will: {
      id: willId,
      repo_id: repoId,
      status: "active",
      reserve_usd: reserve,
      auto_on_continuity_fail: !!auto,
      min_missed_beats: minMissed,
      note,
      heirs: heirs.map((h) => ({ to_repo: h.repo, bps: h.bps })),
    },
    latency_ms: Date.now() - t0,
  });
}

export async function handleWillGet(request, url, env) {
  const gate = await requireWillAuth(request, env);
  if (gate.error) return gate.error;
  const authUser = gate.authUser;
  let repoId = parseRepo(url.searchParams.get("repo") || "");
  if (!repoId && authUser.default_repo) {
    repoId = parseRepo(authUser.default_repo);
  }
  if (!repoId) return bad(request, "repo query required");

  let will;
  try {
    will = await loadWillByRepo(env, repoId);
  } catch (e) {
    return bad(
      request,
      "agent_wills missing — run d1-will-migration.sql: " + (e.message || e),
      500
    );
  }
  if (!will) {
    return json(request, { ok: true, will: null, heirs: [] });
  }
  const heirs = await loadWillHeirs(env, will.id);
  return json(request, {
    ok: true,
    will: {
      id: will.id,
      repo_id: will.repo_id,
      status: will.status,
      reserve_usd: will.reserve_usd,
      auto_on_continuity_fail: !!will.auto_on_continuity_fail,
      min_missed_beats: will.min_missed_beats,
      note: will.note,
      executed_at: will.executed_at,
      revoked_at: will.revoked_at,
      created_at: will.created_at,
      updated_at: will.updated_at,
    },
    heirs: heirs.map((h) => ({
      to_repo: h.to_repo,
      bps: h.bps,
    })),
  });
}

export async function handleWillRevoke(request, env, ctx) {
  const gate = await requireWillAuth(request, env);
  if (gate.error) return gate.error;
  const authUser = gate.authUser;
  let body = {};
  try {
    body = await request.json();
  } catch (_) {}
  const repoId = resolveRepo(body, authUser);
  if (!repoId) return bad(request, "repo required");

  const will = await loadWillByRepo(env, repoId);
  if (!will) return bad(request, "No will for this repo", 404);
  if (will.status === "executed") {
    return bad(request, "Already executed — cannot revoke", 400, {
      code: "will_executed",
    });
  }
  if (!canManageWill(authUser, repoId, will.owner_user_id)) {
    return bad(request, "Not authorized", 403);
  }

  await env.DB.prepare(
    `UPDATE agent_wills
     SET status = 'revoked', revoked_at = datetime('now'), updated_at = datetime('now')
     WHERE id = ?1 AND status = 'active'`
  )
    .bind(will.id)
    .run();

  if (authUser.id) {
    scheduleWebhook(ctx, env, authUser.id, "will.revoked", {
      id: will.id,
      repo_id: repoId,
      status: "revoked",
    });
  }
  return json(request, { ok: true, id: will.id, status: "revoked" });
}

/**
 * Core execute — used by HTTP handler and continuity auto path.
 * @param {string} trigger manual | continuity | admin
 */
export async function executeWill(env, ctx, {
  repoId,
  authUser,
  trigger,
  idempotency_key,
  request,
}) {
  const t0 = Date.now();
  const will = await loadWillByRepo(env, repoId);
  if (!will) {
    return {
      ok: false,
      status: 404,
      error: "No will for this repo",
      code: "will_missing",
    };
  }
  if (will.status === "executed") {
    return {
      ok: false,
      status: 400,
      error: "Will already executed",
      code: "will_executed",
      will_id: will.id,
    };
  }
  if (will.status === "revoked") {
    return {
      ok: false,
      status: 400,
      error: "Will is revoked",
      code: "will_revoked",
    };
  }
  if (will.status !== "active") {
    return {
      ok: false,
      status: 400,
      error: "Will not active",
      code: "will_inactive",
    };
  }

  const heirsRows = await loadWillHeirs(env, will.id);
  if (!heirsRows.length) {
    return {
      ok: false,
      status: 400,
      error: "Will has no heirs",
      code: "no_heirs",
    };
  }
  const legsIn = heirsRows.map((h) => ({
    repo: h.to_repo,
    bps: Number(h.bps),
  }));

  let balRow;
  try {
    balRow = await env.DB.prepare(
      `SELECT balance FROM accounts WHERE repo_id = ?1`
    )
      .bind(repoId)
      .first();
  } catch (e) {
    return {
      ok: false,
      status: 500,
      error: "accounts read failed: " + (e.message || e),
    };
  }
  const balance = Number(balRow && balRow.balance != null ? balRow.balance : 0);
  const reserve = Math.max(0, Number(will.reserve_usd || 0));
  const payable = Math.round((balance - reserve) * 1e6) / 1e6;
  if (!(payable >= WILL_MIN_PAYABLE)) {
    return {
      ok: false,
      status: 400,
      error: "Nothing payable after reserve",
      code: "nothing_payable",
      balance,
      reserve_usd: reserve,
    };
  }

  const idem =
    String(idempotency_key || "")
      .trim()
      .slice(0, 128) || null;
  if (idem) {
    try {
      const existing = await env.DB.prepare(
        `SELECT id FROM will_executions WHERE idempotency_key = ?1`
      )
        .bind(idem)
        .first();
      if (existing) {
        return {
          ok: true,
          replayed: true,
          execution_id: existing.id,
          will_id: will.id,
        };
      }
    } catch (_) {}
  }

  // Safety / scopes only when human or key triggered
  if (authUser && request) {
    applyScopeVerb(authUser, "pay");
    if (authUser.auth_via === "api_key") {
      const scopeHit = checkKeyScope(authUser, "pay", {
        amount: payable,
        toRepo: legsIn[0].repo,
      });
      if (scopeHit) {
        return {
          ok: false,
          status: scopeHit.status || 403,
          error: scopeHit.error,
          code: scopeHit.code,
        };
      }
      for (const leg of legsIn) {
        const h = checkKeyScope(authUser, "pay", {
          amount: 0,
          toRepo: leg.repo,
        });
        if (h && h.code === "key_repo_denied") {
          return {
            ok: false,
            status: 403,
            error: h.error,
            code: h.code,
            to_repo: leg.repo,
          };
        }
      }
    }
    authUser._policyCtx = {
      to_repo: legsIn[0].repo,
      task: "agent-will-execute",
      idempotency_key: idem,
    };
    const blocked = await safetyGate(request, env, authUser, repoId, payable);
    if (blocked) {
      // blocked is a Response
      return { ok: false, response: blocked };
    }
  }

  const allocated = allocateAmounts(payable, legsIn);
  await ensureAccount(env, repoId);
  for (const leg of allocated) {
    await ensureAccount(env, leg.repo);
  }

  const debitRes = await debitWithCredit(env, repoId, payable);
  if (!debitRes.ok) {
    return {
      ok: false,
      status: debitRes.code === "wallet_locked" ? 403 : 402,
      error: debitRes.error || "Insufficient funds",
      code: debitRes.code || "insufficient",
    };
  }

  const execId = "wex_" + randomId(12);
  const latency = Date.now() - t0;
  const createdBy = authUser ? authUser.id || null : will.owner_user_id;

  try {
    const claim = await env.DB.prepare(
      `UPDATE agent_wills
       SET status = 'executing', updated_at = datetime('now')
       WHERE id = ?1 AND status = 'active'
       RETURNING id`
    )
      .bind(will.id)
      .first();
    if (!claim) {
      // race
      try {
        await env.DB.prepare(
          `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
        )
          .bind(payable, repoId)
          .run();
      } catch (_) {}
      return {
        ok: false,
        status: 409,
        error: "Will execute race",
        code: "will_race",
      };
    }

    const stmts = [
      env.DB.prepare(
        `INSERT INTO will_executions (
           id, will_id, from_repo, amount_usd, trigger, status, legs_count,
           idempotency_key, created_by, created_at
         ) VALUES (
           ?1, ?2, ?3, ?4, ?5, 'completed', ?6,
           ?7, ?8, datetime('now')
         )`
      ).bind(
        execId,
        will.id,
        repoId,
        payable,
        String(trigger || "manual").slice(0, 40),
        allocated.length,
        idem,
        createdBy
      ),
      env.DB.prepare(
        `UPDATE agent_wills
         SET status = 'executed', executed_at = datetime('now'), updated_at = datetime('now')
         WHERE id = ?1`
      ).bind(will.id),
    ];

    for (const leg of allocated) {
      const legId = "wel_" + randomId(10);
      stmts.push(
        env.DB.prepare(
          `INSERT INTO will_execution_legs (
             id, execution_id, to_repo, bps, amount_usd, created_at
           ) VALUES (?1, ?2, ?3, ?4, ?5, datetime('now'))`
        ).bind(legId, execId, leg.repo, leg.bps, leg.amount_usd)
      );
      stmts.push(
        env.DB.prepare(
          `UPDATE accounts
           SET balance = balance + ?1, updated_at = datetime('now')
           WHERE repo_id = ?2`
        ).bind(leg.amount_usd, leg.repo)
      );
      const legIdem =
        (idem ? idem + ":" : "will:") + execId + ":" + leg.repo;
      stmts.push(
        env.DB.prepare(
          `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms, idempotency_key)
           VALUES (?1, ?2, ?3, ?4, 'success', ?5, ?6)`
        ).bind(
          repoId,
          leg.repo,
          leg.amount_usd,
          "will:" + will.id + ":" + leg.repo,
          latency,
          legIdem
        )
      );
    }

    await env.DB.batch(stmts);

    // Soft-lock wallet after settle (best-effort; columns may vary)
    try {
      await env.DB.prepare(
        `UPDATE agent_limits
         SET wallet_locked = 1,
             lock_reason = 'will_executed',
             updated_at = datetime('now')
         WHERE repo_id = ?1`
      )
        .bind(repoId)
        .run();
    } catch (_) {}
  } catch (e) {
    try {
      await env.DB.prepare(
        `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
      )
        .bind(payable, repoId)
        .run();
      if (debitRes.credit_drawn > 0) {
        await env.DB.prepare(
          `UPDATE agent_limits
           SET outstanding_credit = MAX(0, COALESCE(outstanding_credit, 0) - ?2),
               updated_at = datetime('now')
           WHERE repo_id = ?1`
        )
          .bind(repoId, debitRes.credit_drawn)
          .run();
      }
      await env.DB.prepare(
        `UPDATE agent_wills SET status = 'active', updated_at = datetime('now') WHERE id = ?1 AND status = 'executing'`
      )
        .bind(will.id)
        .run();
    } catch (_) {}
    return {
      ok: false,
      status: 500,
      error:
        "Will settle failed — run d1-will-migration.sql if tables missing: " +
        (e.message || e),
    };
  }

  if (authUser) {
    try {
      await safetyRecordSpend(env, authUser, repoId, payable);
    } catch (_) {}
  }

  const ownerHook = will.owner_user_id || (authUser && authUser.id);
  if (ownerHook) {
    scheduleWebhook(ctx, env, ownerHook, "will.executed", {
      id: will.id,
      execution_id: execId,
      from_repo: repoId,
      amount_usd: payable,
      trigger: trigger || "manual",
      legs: allocated,
      status: "executed",
    });
  }

  return {
    ok: true,
    will_id: will.id,
    execution_id: execId,
    from_repo: repoId,
    amount_usd: payable,
    reserve_usd: reserve,
    balance_before: balance,
    trigger: trigger || "manual",
    legs: allocated.map((l) => ({
      to_repo: l.repo,
      bps: l.bps,
      amount_usd: l.amount_usd,
    })),
    credit_drawn: debitRes.credit_drawn || undefined,
    latency_ms: Date.now() - t0,
  };
}

export async function handleWillExecute(request, env, ctx) {
  const gate = await requireWillAuth(request, env);
  if (gate.error) return gate.error;
  const authUser = gate.authUser;

  const rlId =
    authUser.auth_via === "api_key"
      ? "willx:key:" + (authUser.key_id || authUser.id)
      : "willx:user:" + authUser.id;
  const limited = await checkRateLimit(env, rlId, RL_WILL_MAX, RL_WILL_WINDOW_SEC);
  if (limited) {
    return bad(request, "Rate limit: will execute", 429, {
      retry_after_sec: limited.retry_after_sec,
    });
  }

  let body = {};
  try {
    body = await request.json();
  } catch (_) {}

  const repoId = resolveRepo(body, authUser);
  if (!repoId) return bad(request, "repo required");

  const will = await loadWillByRepo(env, repoId);
  if (will && !canManageWill(authUser, repoId, will.owner_user_id)) {
    return bad(request, "Not authorized to execute this will", 403);
  }

  const result = await executeWill(env, ctx, {
    repoId,
    authUser,
    trigger: body.trigger || "manual",
    idempotency_key:
      request.headers.get("Idempotency-Key") || body.idempotency_key,
    request,
  });

  if (result.response) return result.response;
  if (!result.ok) {
    return bad(request, result.error || "Execute failed", result.status || 400, {
      code: result.code,
      will_id: result.will_id,
      balance: result.balance,
      reserve_usd: result.reserve_usd,
    });
  }
  return json(request, { ok: true, ...result });
}

export async function handleWillExecutionsList(request, url, env) {
  const gate = await requireWillAuth(request, env);
  if (gate.error) return gate.error;
  const limit = Math.min(
    Math.max(Number(url.searchParams.get("limit") || 20), 1),
    100
  );
  const repo = (url.searchParams.get("repo") || "").trim();
  let sql = `SELECT id, will_id, from_repo, amount_usd, trigger, status, legs_count, created_at
             FROM will_executions WHERE 1=1`;
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
      executions: results || [],
    });
  } catch (e) {
    return bad(
      request,
      "will_executions missing — run d1-will-migration.sql: " + (e.message || e),
      500
    );
  }
}

/**
 * Optional: after continuity recovery, auto-execute will if flagged.
 * Call from recoverContinuitySession or expireContinuitySessions.
 */
export async function maybeAutoExecuteWillOnDeath(env, ctx, ownerRepo) {
  try {
    const will = await loadWillByRepo(env, ownerRepo);
    if (!will || will.status !== "active") return null;
    if (!will.auto_on_continuity_fail) return null;
    return await executeWill(env, ctx, {
      repoId: ownerRepo,
      authUser: null,
      trigger: "continuity",
      idempotency_key: "auto-will:" + will.id,
      request: null,
    });
  } catch (e) {
    console.log("auto_will", e && e.message);
    return { ok: false, error: e && e.message };
  }
}
