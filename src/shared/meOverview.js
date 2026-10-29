/**
 * Me overview — GET /api/me/overview
 *
 * One-shot aggregate for dashboard Home:
 * balance · safety · credit · shield · keys · open escrow count · checklist hints
 *
 * Read-only. No D1 migration. Touches existing tables only.
 */
import { json, bad } from "./http.js";
import { parseRepo } from "./utils.js";
import { getSessionUser } from "./auth.js";
import { getAgentLimits } from "./safety.js";
import { getCreditState } from "./credit.js";
import { getShield } from "./shield.js";

const SHIELD_LEVEL_NAMES = {
  0: "normal",
  1: "watch",
  2: "throttle",
  3: "freeze",
  4: "emergency",
};

export async function handleMeOverview(request, env) {
  const user = await getSessionUser(request, env);
  if (!user) return bad(request, "Sign in required", 401);

  const repo = user.default_repo ? parseRepo(user.default_repo) : null;

  // ── Balance ──────────────────────────────────────────────
  let balance = 0;
  let balance_exists = false;
  if (repo) {
    try {
      const row = await env.DB.prepare(
        `SELECT balance FROM accounts WHERE repo_id = ?1`
      )
        .bind(repo)
        .first();
      if (row) {
        balance = Number(row.balance || 0);
        balance_exists = true;
      }
    } catch (_) {}
  }

  // ── Safety ───────────────────────────────────────────────
  let safety = null;
  if (repo) {
    try {
      const lim = await getAgentLimits(env, repo);
      if (lim) {
        safety = {
          locked: Number(lim.locked) === 1,
          lock_reason: lim.lock_reason || null,
          daily_budget: lim.daily_budget != null ? Number(lim.daily_budget) : null,
          daily_spent: Number(lim.daily_spent || 0),
        };
      } else {
        safety = {
          locked: false,
          lock_reason: null,
          daily_budget: null,
          daily_spent: 0,
        };
      }
    } catch (_) {
      safety = { locked: false, lock_reason: null, daily_budget: null, daily_spent: 0 };
    }
  }

  // ── Credit ───────────────────────────────────────────────
  let credit = null;
  if (repo) {
    try {
      credit = await getCreditState(env, repo);
    } catch (_) {
      credit = null;
    }
  }

  // ── Shield ───────────────────────────────────────────────
  let shield = { global_level: 0, global_name: "normal", agent_level: 0, agent_name: "normal" };
  try {
    const g = await getShield(env, "global");
    const gLevel = Number(g?.level || 0);
    shield.global_level = gLevel;
    shield.global_name = SHIELD_LEVEL_NAMES[gLevel] || "normal";
    if (repo) {
      const local = await getShield(env, repo);
      const aLevel = Number(local?.level || 0);
      shield.agent_level = aLevel;
      shield.agent_name = SHIELD_LEVEL_NAMES[aLevel] || "normal";
      shield.agent_reason = local?.reason || null;
    }
  } catch (_) {}

  // ── Keys ─────────────────────────────────────────────────
  let keys = { total: 0, active: 0, bound: 0 };
  try {
    const q = await env.DB.prepare(
      `SELECT
         COUNT(*) AS total,
         SUM(CASE WHEN revoked_at IS NULL AND (suspended_at IS NULL OR suspended_at = '') THEN 1 ELSE 0 END) AS active,
         SUM(CASE WHEN bind_mode IS NOT NULL AND bind_mode != '' AND revoked_at IS NULL THEN 1 ELSE 0 END) AS bound
       FROM api_keys WHERE user_id = ?1`
    )
      .bind(user.id)
      .first();
    if (q) {
      keys = {
        total: Number(q.total || 0),
        active: Number(q.active || 0),
        bound: Number(q.bound || 0),
      };
    }
  } catch (_) {
    // Older schema without bind_mode / suspended_at
    try {
      const q2 = await env.DB.prepare(
        `SELECT COUNT(*) AS total,
                SUM(CASE WHEN revoked_at IS NULL THEN 1 ELSE 0 END) AS active
         FROM api_keys WHERE user_id = ?1`
      )
        .bind(user.id)
        .first();
      if (q2) {
        keys = {
          total: Number(q2.total || 0),
          active: Number(q2.active || 0),
          bound: 0,
        };
      }
    } catch (_) {}
  }

  // ── Open escrows (held) ──────────────────────────────────
  let open_escrows = 0;
  if (repo) {
    try {
      const er = await env.DB.prepare(
        `SELECT COUNT(*) AS n FROM escrows
         WHERE status = 'held' AND (from_repo = ?1 OR to_repo = ?1)`
      )
        .bind(repo)
        .first();
      open_escrows = Number(er?.n || 0);
    } catch (_) {}
  }

  // ── Checklist (product onboarding) ───────────────────────
  const checklist = {
    agent_bound: !!repo,
    has_key: keys.active > 0,
    has_balance: balance > 0 || balance_exists,
    // pay/hire are client-tracked; server can only hint from ledger if needed
  };

  const secure =
    !safety?.locked &&
    shield.global_level < 3 &&
    shield.agent_level < 3;

  return json(request, {
    ok: true,
    user: {
      id: user.id,
      email: user.email || null,
      name: user.name || null,
      provider: user.provider || null,
    },
    default_repo: repo,
    balance,
    balance_exists,
    safety,
    credit,
    shield,
    keys,
    open_escrows,
    checklist,
    status: {
      secure,
      label: secure ? "Secure" : safety?.locked ? "Wallet locked" : "Shield elevated",
    },
  });
}
