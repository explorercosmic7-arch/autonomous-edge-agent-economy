/**
 * Me credit — GET|POST /api/me/credit, POST /api/me/credit/repay
 */
import { json, bad } from "./http.js";
import { parseRepo, parseAmount } from "./utils.js";
import { getSessionUser } from "./auth.js";
import {
  getCreditState,
  repayCredit,
} from "./credit.js";
import {
  ensureAgentLimits,
  logSafetyEvent,
} from "./safety.js";
import {
  CREDIT_MAX_LIMIT,
  CREDIT_REP_TO_LIMIT_RATIO,
} from "./constants.js";

/* ─── Safety controls (dashboard / API) ─── */


export async function handleMeCreditGet(request, env) {
  const user = await getSessionUser(request, env);
  if (!user) return bad(request, "Sign in required", 401);
  const repo = user.default_repo ? parseRepo(user.default_repo) : null;
  if (!repo) {
    return json(request, {
      ok: true,
      default_repo: null,
      credit: null,
      hint: "Bind a default agent first",
    });
  }
  const state = await getCreditState(env, repo);
  let recent = [];
  try {
    const q = await env.DB.prepare(
      `SELECT delta, score_after, reason, ref_id, created_at
       FROM rep_events WHERE repo_id = ?1 ORDER BY created_at DESC LIMIT 12`
    )
      .bind(repo)
      .all();
    recent = q.results || [];
  } catch (_) {}
  return json(request, {
    ok: true,
    default_repo: repo,
    credit: state,
    recent_rep: recent,
    schema: {
      credit_limit: "Max outstanding borrow (USD)",
      outstanding_credit: "Current drawn credit",
      available_credit: "credit_limit - outstanding",
      rep_score: "Reputation points (earned on successful activity)",
      suggested_limit: "rep_score * " + CREDIT_REP_TO_LIMIT_RATIO,
    },
  });
}

export async function handleMeCreditSet(request, env) {
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

  await ensureAgentLimits(env, repo);
  const sets = [];
  const binds = [];
  if ("credit_limit" in body) {
    let lim = body.credit_limit;
    if (lim === null || lim === "") lim = 0;
    lim = Number(lim);
    if (!Number.isFinite(lim) || lim < 0 || lim > CREDIT_MAX_LIMIT) {
      return bad(request, "credit_limit must be 0.." + CREDIT_MAX_LIMIT);
    }
    // Cannot set below outstanding
    const st = await getCreditState(env, repo);
    if (lim < st.outstanding_credit) {
      return bad(
        request,
        "credit_limit cannot be below outstanding_credit ($" + st.outstanding_credit.toFixed(6) + ")"
      );
    }
    sets.push("credit_limit = ?" + (binds.length + 1));
    binds.push(lim);
  }
  if (!sets.length) return bad(request, "Provide credit_limit");
  sets.push("updated_at = datetime('now')");
  binds.push(repo);
  await env.DB.prepare(
    `UPDATE agent_limits SET ${sets.join(", ")} WHERE repo_id = ?${binds.length}`
  )
    .bind(...binds)
    .run();

  await logSafetyEvent(env, "credit.updated", {
    repo_id: repo,
    user_id: user.id,
    reason: "dashboard",
    meta: body,
  });
  const state = await getCreditState(env, repo);
  return json(request, { ok: true, default_repo: repo, credit: state });
}

export async function handleMeCreditRepay(request, env) {
  const user = await getSessionUser(request, env);
  if (!user) return bad(request, "Sign in required", 401);
  const repo = user.default_repo ? parseRepo(user.default_repo) : null;
  if (!repo) return bad(request, "Bind a default agent first");

  let body;
  try {
    body = await request.json();
  } catch {
    body = {};
  }
  let amount = body.amount != null ? parseAmount(body.amount) : null;
  if (amount == null) {
    // repay all possible from balance
    const acc = await env.DB.prepare(`SELECT balance FROM accounts WHERE repo_id = ?1`)
      .bind(repo)
      .first();
    const st = await getCreditState(env, repo);
    amount = Math.min(Number(acc?.balance || 0), st.outstanding_credit);
    amount = Math.round(amount * 1e6) / 1e6;
  }
  if (!(amount > 0)) return bad(request, "Nothing to repay or amount invalid");

  const result = await repayCredit(env, repo, amount);
  if (!result.ok) return bad(request, result.error, result.code === "insufficient" ? 402 : 400);
  await env.DB.prepare(
    `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
     VALUES (?1, ?2, ?3, ?4, 'success', 0)`
  )
    .bind(repo, "system/credit", result.repaid, "credit-repay")
    .run()
    .catch(() => {});
  return json(request, { ok: true, default_repo: repo, ...result });
}
