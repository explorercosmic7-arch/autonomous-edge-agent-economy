/**
 * Me fleet — GET|POST /api/me/fleet
 * Account-wide daily/monthly spend caps (fleet_limits).
 */
import { json, bad } from "./http.js";
import { getAuthUser, rejectIfSuspendedKey } from "./auth.js";
import {
  ensureFleetLimits,
  fleetStatus,
  logSafetyEvent,
} from "./safety.js";

async function requireFleetUser(request, env) {
  const user = await getAuthUser(request, env);
  if (!user) return { error: bad(request, "Sign in required", 401) };
  const sus = rejectIfSuspendedKey(request, user);
  if (sus) return { error: sus };
  if (user.edge_blocked || user._edge_blocked) {
    return {
      error: bad(request, user._edge_error || "Edge binding blocked", 403, {
        code: user._edge_code || "edge_bound",
      }),
    };
  }
  if (!user.id) return { error: bad(request, "Sign in required", 401) };
  return { user };
}

export async function handleMeFleetGet(request, env) {
  const auth = await requireFleetUser(request, env);
  if (auth.error) return auth.error;
  const user = auth.user;

  const fleet = await fleetStatus(env, user.id);
  return json(request, {
    ok: true,
    user_id: user.id,
    auth_via: user.auth_via || "session",
    fleet: fleet || {
      daily_budget: null,
      monthly_budget: null,
      daily_spent: 0,
      monthly_spent: 0,
      daily_remaining: null,
      monthly_remaining: null,
      warn_bps: 8000,
      at_warn: false,
    },
  });
}

export async function handleMeFleetSet(request, env) {
  const auth = await requireFleetUser(request, env);
  if (auth.error) return auth.error;
  const user = auth.user;

  if (user.auth_via === "api_key") {
    return bad(request, "Fleet limits can only be changed from the signed-in dashboard", 403, {
      code: "fleet_session_only",
    });
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return bad(request, "Invalid JSON body");
  }

  await ensureFleetLimits(env, user.id);

  const parseOpt = (v) => {
    if (v === null || v === "" || v === undefined) return null;
    const n = Number(v);
    if (!Number.isFinite(n) || n < 0) return undefined;
    return n;
  };

  const daily = parseOpt(body.daily_budget);
  const monthly = parseOpt(body.monthly_budget);
  const warnRaw = parseOpt(body.warn_bps);

  if ("daily_budget" in body && daily === undefined) return bad(request, "daily_budget invalid");
  if ("monthly_budget" in body && monthly === undefined) return bad(request, "monthly_budget invalid");
  if ("warn_bps" in body && warnRaw === undefined) return bad(request, "warn_bps invalid");

  let warnBps = null;
  if ("warn_bps" in body) {
    warnBps = Math.floor(warnRaw);
    if (warnBps < 1000 || warnBps > 9900) {
      return bad(request, "warn_bps must be 1000–9900 (10%–99%)");
    }
  }

  const sets = [];
  const binds = [];
  const add = (col, val, present) => {
    if (!present) return;
    sets.push(col + " = ?" + (binds.length + 1));
    binds.push(val);
  };

  add("daily_budget", daily, "daily_budget" in body);
  add("monthly_budget", monthly, "monthly_budget" in body);
  add("warn_bps", warnBps, "warn_bps" in body);

  if (!sets.length) return bad(request, "No fields to update");

  sets.push("updated_at = datetime('now')");
  binds.push(user.id);

  await env.DB.prepare(
    `UPDATE fleet_limits SET ${sets.join(", ")} WHERE user_id = ?${binds.length}`
  )
    .bind(...binds)
    .run();

  await logSafetyEvent(env, "fleet.limits_updated", {
    user_id: user.id,
    reason: "dashboard",
    meta: body,
  });

  const fleet = await fleetStatus(env, user.id);
  return json(request, { ok: true, user_id: user.id, fleet });
}
