/**
 * Me safety — GET|POST /api/me/safety, POST /api/me/safety/unlock
 */
import { json, bad } from "./http.js";
import { parseRepo } from "./utils.js";
import { getSessionUser } from "./auth.js";
import {
  ensureAgentLimits,
  getAgentLimits,
  unlockWallet,
  logSafetyEvent,
} from "./safety.js";
import {
  SAFETY_DEFAULT_VELOCITY_MAX_TX,
  SAFETY_DEFAULT_VELOCITY_TX_WINDOW_SEC,
  SAFETY_DEFAULT_VELOCITY_MAX_USD,
  SAFETY_DEFAULT_VELOCITY_USD_WINDOW_SEC,
  SAFETY_SPIKE_TX_PER_SEC,
} from "./constants.js";

export async function handleMeSafetyGet(request, env) {
  const user = await getSessionUser(request, env);
  if (!user) return bad(request, "Sign in required", 401);

  const repo = user.default_repo ? parseRepo(user.default_repo) : null;
  if (!repo) {
    return json(request, {
      ok: true,
      default_repo: null,
      limits: null,
      defaults: {
        velocity_max_tx: SAFETY_DEFAULT_VELOCITY_MAX_TX,
        velocity_tx_window_sec: SAFETY_DEFAULT_VELOCITY_TX_WINDOW_SEC,
        velocity_max_usd: SAFETY_DEFAULT_VELOCITY_MAX_USD,
        velocity_window_sec: SAFETY_DEFAULT_VELOCITY_USD_WINDOW_SEC,
        spike_tx_per_sec: SAFETY_SPIKE_TX_PER_SEC,
      },
    });
  }

  const lim = await getAgentLimits(env, repo);
  let recent = [];
  try {
    const { results } = await env.DB.prepare(
      `SELECT event, reason, created_at FROM safety_events
       WHERE repo_id = ?1 ORDER BY created_at DESC LIMIT 10`
    )
      .bind(repo)
      .all();
    recent = results || [];
  } catch (_) {}

  return json(request, {
    ok: true,
    default_repo: repo,
    limits: lim
      ? {
          repo_id: lim.repo_id,
          daily_budget: lim.daily_budget,
          daily_spent: lim.daily_spent,
          daily_window_start: lim.daily_window_start,
          velocity_max_usd: lim.velocity_max_usd,
          velocity_window_sec: lim.velocity_window_sec,
          velocity_max_tx: lim.velocity_max_tx,
          velocity_tx_window_sec: lim.velocity_tx_window_sec,
          locked: Number(lim.locked) === 1,
          locked_at: lim.locked_at,
          lock_reason: lim.lock_reason,
          updated_at: lim.updated_at,
        }
      : null,
    defaults: {
      velocity_max_tx: SAFETY_DEFAULT_VELOCITY_MAX_TX,
      velocity_tx_window_sec: SAFETY_DEFAULT_VELOCITY_TX_WINDOW_SEC,
      velocity_max_usd: SAFETY_DEFAULT_VELOCITY_MAX_USD,
      velocity_window_sec: SAFETY_DEFAULT_VELOCITY_USD_WINDOW_SEC,
      spike_tx_per_sec: SAFETY_SPIKE_TX_PER_SEC,
    },
    recent_events: recent,
  });
}

export async function handleMeSafetySet(request, env) {
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

  // null / "" clears optional caps
  const parseOpt = (v) => {
    if (v === null || v === "" || v === undefined) return null;
    const n = Number(v);
    if (!Number.isFinite(n) || n < 0) return undefined; // invalid
    return n;
  };

  const daily = parseOpt(body.daily_budget);
  const vmaxUsd = parseOpt(body.velocity_max_usd);
  const vwinUsd = parseOpt(body.velocity_window_sec);
  const vmaxTx = parseOpt(body.velocity_max_tx);
  const vwinTx = parseOpt(body.velocity_tx_window_sec);

  if (daily === undefined) return bad(request, "daily_budget invalid");
  if (vmaxUsd === undefined) return bad(request, "velocity_max_usd invalid");
  if (vwinUsd === undefined) return bad(request, "velocity_window_sec invalid");
  if (vmaxTx === undefined) return bad(request, "velocity_max_tx invalid");
  if (vwinTx === undefined) return bad(request, "velocity_tx_window_sec invalid");

  // Only update fields present in body
  const sets = [];
  const binds = [];
  const add = (col, val, present) => {
    if (!present) return;
    sets.push(col + " = ?" + (binds.length + 1));
    binds.push(val);
  };

  add("daily_budget", daily, "daily_budget" in body);
  add("velocity_max_usd", vmaxUsd, "velocity_max_usd" in body);
  add(
    "velocity_window_sec",
    vwinUsd != null ? Math.floor(vwinUsd) : null,
    "velocity_window_sec" in body
  );
  add(
    "velocity_max_tx",
    vmaxTx != null ? Math.floor(vmaxTx) : null,
    "velocity_max_tx" in body
  );
  add(
    "velocity_tx_window_sec",
    vwinTx != null ? Math.floor(vwinTx) : null,
    "velocity_tx_window_sec" in body
  );

  if (!sets.length) return bad(request, "No fields to update");

  sets.push("updated_at = datetime('now')");
  binds.push(repo);

  await env.DB.prepare(
    `UPDATE agent_limits SET ${sets.join(", ")} WHERE repo_id = ?${binds.length}`
  )
    .bind(...binds)
    .run();

  await logSafetyEvent(env, "limits.updated", {
    repo_id: repo,
    user_id: user.id,
    reason: "dashboard",
    meta: body,
  });

  const lim = await getAgentLimits(env, repo);
  return json(request, {
    ok: true,
    repo_id: repo,
    limits: lim,
  });
}

export async function handleMeSafetyUnlock(request, env) {
  const user = await getSessionUser(request, env);
  if (!user) return bad(request, "Sign in required", 401);

  const repo = user.default_repo ? parseRepo(user.default_repo) : null;
  if (!repo) return bad(request, "Bind a default agent first");

  await unlockWallet(env, repo, { user_id: user.id });
  return json(request, { ok: true, unlocked: true, repo_id: repo });
}
