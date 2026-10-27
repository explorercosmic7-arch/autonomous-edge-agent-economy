/**
 * Shared security handlers — public status map, integrity audit, sandbox cleanup.
 */
import {
  json,
  bad,
  MAX_JSON_BODY_BYTES,
} from "./http.js";
import { checkRateLimit } from "./rateLimit.js";
import { assertAdminSecret } from "./admin.js";
import { getShield } from "./shield.js";
import { ensureAccount } from "./accounts.js";
import { logSafetyEvent } from "./safety.js";
import { randomId } from "./utils.js";
import {
  RL_IP_POST_MAX,
  RL_IP_POST_WINDOW_SEC,
  RL_PAY_MAX,
  RL_PAY_WINDOW_SEC,
  WORK_BLOCK_SELF_ATTEST,
  WORK_REQUIRE_DISTINCT_ATTESTORS,
  INTEGRITY_SAMPLE_LIMIT,
  SYSTEM_FAUCET,
  SYSTEM_ESCROW,
  SYSTEM_STREAM,
  SYSTEM_SUBWALLET,
  SYSTEM_DISPUTE,
} from "./constants.js";

/* ─── Security status (public, read-only defense map) ─── */
export async function handleSecurityStatus(request, env) {
  let globalShield = { level: 0, reason: null, cools_at: null };
  try {
    globalShield = await getShield(env, "global");
  } catch (_) {}

  return json(request, {
    ok: true,
    product: "AgentPay Secure Gateway",
    security_tier: "bank-grade-v1",
    as_of: new Date().toISOString(),
    network: {
      global_shield_level: Number(globalShield.level || 0),
      global_shield_reason: globalShield.reason || null,
      global_shield_cools_at: globalShield.cools_at || null,
    },
    controls: {
      body_max_bytes: MAX_JSON_BODY_BYTES,
      ip_post_rate_limit: { max: RL_IP_POST_MAX, window_sec: RL_IP_POST_WINDOW_SEC },
      pay_rate_limit: { max: RL_PAY_MAX, window_sec: RL_PAY_WINDOW_SEC },
      security_headers: true,
      timing_safe_admin: true,
      idempotency_on_pay: true,
      safety_gate: [
        "wallet_lock",
        "edge_shield",
        "policy_as_code",
        "daily_budget",
        "velocity_tx",
        "velocity_usd",
        "spike_kill_switch",
        "rep_credit_draw",
      ],
      key_binding: ["colo", "ip", "either", "both", "learn"],
      work_attestation_diversity: {
        block_self_attest: WORK_BLOCK_SELF_ATTEST,
        require_distinct_attestors: WORK_REQUIRE_DISTINCT_ATTESTORS,
      },
      dispute_court: true,
      zero_loss_instruments: [
        "escrow",
        "stream",
        "subwallet",
        "intent_capsule",
        "commit_reveal",
        "work_settlement",
        "dispute_bonds",
      ],
    },
    admin: {
      integrity: "POST /api/admin/integrity (X-Admin-Cleanup-Key)",
      shield: "POST /api/admin/shield",
      sandbox_cleanup: "POST /api/admin/sandbox-cleanup",
    },
    hint: "Public map only — no balances or secrets exposed.",
  });
}

/**
 * Ledger integrity audit (admin-only).
 * Checks: non-negative balances, locked+spendable consistency signals,
 * orphaned held instruments sample, system account presence.
 * Does NOT mutate ledger.
 */
export async function handleAdminIntegrity(request, env) {
  const t0 = Date.now();
  let body = {};
  try {
    body = await request.json();
  } catch {
    body = {};
  }
  const admin = await assertAdminSecret(request, env, body);
  if (!admin.ok) return admin.response;

  const rl = await checkRateLimit(env, "admin:integrity", 10, 3600);
  if (rl) {
    return bad(request, "Integrity rate limit: max 10/hour", 429, {
      code: "integrity_rate_limited",
      retry_after_sec: rl.retry_after_sec,
    });
  }

  const findings = [];
  const stats = {
    accounts_scanned: 0,
    negative_balances: 0,
    locked_wallets: 0,
    system_accounts_ok: 0,
    held_escrows: 0,
    open_disputes: 0,
  };

  // System accounts must exist (create if missing for audit readiness)
  const systemRepos = [
    SYSTEM_FAUCET,
    SYSTEM_ESCROW,
    SYSTEM_STREAM,
    SYSTEM_SUBWALLET,
    SYSTEM_DISPUTE,
  ];
  for (const repo of systemRepos) {
    try {
      await ensureAccount(env, repo);
      stats.system_accounts_ok += 1;
    } catch (e) {
      findings.push({ severity: "high", code: "system_account", repo, error: e.message });
    }
  }

  // Sample accounts for negative balance
  try {
    const { results } = await env.DB.prepare(
      `SELECT repo_id, balance FROM accounts
       ORDER BY updated_at DESC LIMIT ?1`
    )
      .bind(INTEGRITY_SAMPLE_LIMIT)
      .all();
    for (const row of results || []) {
      stats.accounts_scanned += 1;
      if (Number(row.balance) < -0.0000005) {
        stats.negative_balances += 1;
        findings.push({
          severity: "critical",
          code: "negative_balance",
          repo_id: row.repo_id,
          balance: Number(row.balance),
        });
      }
    }
  } catch (e) {
    findings.push({ severity: "high", code: "accounts_scan_failed", error: e.message });
  }

  try {
    const lockRow = await env.DB.prepare(
      `SELECT COUNT(*) AS c FROM agent_limits WHERE locked = 1`
    ).first();
    stats.locked_wallets = Number(lockRow?.c || 0);
  } catch (_) {}

  try {
    const esc = await env.DB.prepare(
      `SELECT COUNT(*) AS c FROM escrows WHERE status = 'held'`
    ).first();
    stats.held_escrows = Number(esc?.c || 0);
  } catch (_) {}

  try {
    const dsp = await env.DB.prepare(
      `SELECT COUNT(*) AS c FROM work_disputes WHERE status IN ('open', 'voting', 'accepted')`
    ).first();
    stats.open_disputes = Number(dsp?.c || 0);
  } catch (_) {}

  // Outstanding credit vs limit sanity
  try {
    const badCredit = await env.DB.prepare(
      `SELECT repo_id, credit_limit, outstanding_credit FROM agent_limits
       WHERE COALESCE(outstanding_credit, 0) > COALESCE(credit_limit, 0) + 0.000001
       LIMIT 20`
    ).all();
    for (const row of badCredit.results || []) {
      findings.push({
        severity: "high",
        code: "credit_overdraw",
        repo_id: row.repo_id,
        credit_limit: Number(row.credit_limit),
        outstanding_credit: Number(row.outstanding_credit),
      });
    }
  } catch (_) {}

  const critical = findings.filter((f) => f.severity === "critical").length;
  const high = findings.filter((f) => f.severity === "high").length;

  try {
    await logSafetyEvent(env, "integrity.scan", {
      reason: critical > 0 ? "findings_critical" : "ok",
      meta: { critical, high, accounts_scanned: stats.accounts_scanned },
    });
  } catch (_) {}

  return json(request, {
    ok: critical === 0,
    integrity: critical === 0 ? "pass" : "fail",
    stats,
    findings,
    summary: {
      critical,
      high,
      message:
        critical === 0
          ? "No critical ledger anomalies in sample."
          : "Critical findings — investigate before increasing limits.",
    },
    latency_ms: Date.now() - t0,
  });
}


/* ─── Sandbox D1 cleanup (ADMIN_CLEANUP_SECRET required) ───
 * Temporary while AgentPay is in testing. Remove before real-user production.
 * Does NOT drop schema. Does NOT delete users / sessions / api_keys by default.
 * Clears ledger noise, held instruments, telemetry. Resets non-system balances to 0.
 */
export async function handleAdminSandboxCleanup(request, env) {
  const t0 = Date.now();
  let body = {};
  try {
    body = await request.json();
  } catch {
    body = {};
  }

  const admin = await assertAdminSecret(request, env, body);
  if (!admin.ok) return admin.response;

  if (body.confirm !== true && body.confirm !== "SANDBOX_RESET") {
    return bad(
      request,
      'Send JSON { "secret":"…", "confirm": true } or confirm: "SANDBOX_RESET"',
      400,
      { code: "confirm_required" }
    );
  }

  // Anti-loop: max 3 cleanups / hour
  const rl = await checkRateLimit(env, "admin:sandbox-cleanup", 3, 3600);
  if (rl) {
    return bad(request, "Cleanup rate limit: max 3 per hour (anti-loop protection)", 429, {
      code: "cleanup_rate_limited",
      retry_after_sec: rl.retry_after_sec,
    });
  }

  const results = {};
  let wiped = 0;
  let skipped = 0;
  let failed = 0;

  async function wipe(label, sql) {
    try {
      const r = await env.DB.prepare(sql).run();
      const changes = (r.meta && r.meta.changes) || 0;
      results[label] = { ok: true, status: "wiped", changes };
      wiped += 1;
    } catch (e) {
      const msg = (e && e.message) || String(e);
      if (/no such table/i.test(msg)) {
        results[label] = { ok: true, status: "skipped", reason: "table_not_present" };
        skipped += 1;
      } else {
        results[label] = { ok: false, status: "error", error: msg };
        failed += 1;
      }
    }
  }

  await wipe("velocity_events", `DELETE FROM velocity_events`);
  await wipe("safety_events", `DELETE FROM safety_events`);
  await wipe("rate_limits", `DELETE FROM rate_limits WHERE bucket_key != 'admin:sandbox-cleanup'`);
  await wipe("webhook_deliveries", `DELETE FROM webhook_deliveries`);
  await wipe("idempotency", `DELETE FROM idempotency`);
  await wipe("rep_events", `DELETE FROM rep_events`);

  await wipe("transactions", `DELETE FROM transactions`);
  await wipe("escrows", `DELETE FROM escrows`);
  await wipe("streams", `DELETE FROM streams`);
  await wipe("sub_wallets", `DELETE FROM sub_wallets`);
  await wipe("payment_receipts", `DELETE FROM payment_receipts`);
  await wipe("payment_commits", `DELETE FROM payment_commits`);
  await wipe("commit_events", `DELETE FROM commit_events`);
  await wipe("capability_tickets", `DELETE FROM capability_tickets`);
  await wipe("ticket_events", `DELETE FROM ticket_events`);
  await wipe("intent_bonds", `DELETE FROM intent_bonds`);
  await wipe("bond_events", `DELETE FROM bond_events`);
  await wipe("payment_sagas", `DELETE FROM payment_sagas`);
  await wipe("saga_steps", `DELETE FROM saga_steps`);
  await wipe("saga_events", `DELETE FROM saga_events`);
  await wipe("netting_runs", `DELETE FROM netting_runs`);
  await wipe("netting_settlements", `DELETE FROM netting_settlements`);
  await wipe("clearing_batches", `DELETE FROM clearing_batches`);
  await wipe("clearing_positions", `DELETE FROM clearing_positions`);
  await wipe("work_claims", `DELETE FROM work_claims`);
  await wipe("work_attestations", `DELETE FROM work_attestations`);
  await wipe("work_events", `DELETE FROM work_events`);
  await wipe("continuity_sessions", `DELETE FROM continuity_sessions`);
  await wipe("continuity_events", `DELETE FROM continuity_events`);
  await wipe("pool_events", `DELETE FROM pool_events`);
  await wipe("pool_contributions", `DELETE FROM pool_contributions`);
  await wipe("collaborative_pools", `DELETE FROM collaborative_pools`);
  await wipe("shield_events", `DELETE FROM shield_events`);
  await wipe("edge_shield", `DELETE FROM edge_shield`);
  await wipe("agent_index", `DELETE FROM agent_index`);
  await wipe("delegation_events", `DELETE FROM delegation_events`);
  await wipe("delegations", `DELETE FROM delegations`);
  await wipe("dispute_events", `DELETE FROM dispute_events`);
  await wipe("dispute_arbiters", `DELETE FROM dispute_arbiters`);
  await wipe("work_disputes", `DELETE FROM work_disputes`);

  await wipe(
    "agent_limits_reset",
    `UPDATE agent_limits SET
       daily_spent = 0,
       daily_window_start = NULL,
       outstanding_credit = 0,
       locked = 0,
       locked_at = NULL,
       lock_reason = NULL,
       updated_at = datetime('now')`
  );

  await wipe(
    "accounts_zero",
    `UPDATE accounts SET balance = 0, updated_at = datetime('now')
     WHERE repo_id NOT LIKE 'system/%'`
  );

  if (body.wipe_keys === true) {
    await wipe(
      "api_keys_revoke",
      `UPDATE api_keys SET revoked_at = datetime('now')
       WHERE revoked_at IS NULL`
    );
  }

  try {
    await env.DB.prepare(
      `INSERT INTO safety_events (id, event, repo_id, api_key_id, user_id, reason, meta_json, created_at)
       VALUES (?1, 'sandbox.cleanup', NULL, NULL, NULL, ?2, ?3, datetime('now'))`
    )
      .bind(
        randomId(12),
        "operator_cleanup",
        JSON.stringify({ wiped, skipped, failed, wipe_keys: !!body.wipe_keys })
      )
      .run();
  } catch (_) {}

  return json(request, {
    ok: failed === 0,
    sandbox: true,
    message:
      failed === 0
        ? "Sandbox ledger cleaned. Users/sessions kept. Re-fund via Faucet. Max 3 cleanups/hour."
        : "Cleanup finished with some real errors (see results).",
    summary: {
      wiped,
      skipped_missing_tables: skipped,
      failed,
      note:
        skipped > 0
          ? "Skipped tables were never migrated — normal, not a problem."
          : undefined,
    },
    results,
    latency_ms: Date.now() - t0,
  });
}


