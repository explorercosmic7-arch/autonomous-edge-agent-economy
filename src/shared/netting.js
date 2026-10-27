/**
 * Shared Netting — bilateral obligation netting (soft/hard settle).
 */
import { json, bad } from "./http.js";
import {
  parseRepo,
  randomId,
  MIN_AMOUNT,
} from "./utils.js";
import { checkRateLimit } from "./rateLimit.js";
import { getAuthUser } from "./auth.js";
import { ensureAccount } from "./accounts.js";
import {
  SYSTEM_NETTING,
  NETTING_DEFAULT_WINDOW_HOURS,
  NETTING_MIN_WINDOW_HOURS,
  NETTING_MAX_WINDOW_HOURS,
  NETTING_MAX_PAIRS,
  RL_NETTING_MAX,
  RL_NETTING_WINDOW_SEC,
} from "./constants.js";

/* ─── Obligation netting (bilateral batch settlement) ───
 * Soft net by default (report + ledger annotation). Pass apply_balances:true to move funds.
 */

export async function handleNettingRun(request, env) {
  const t0 = Date.now();
  const authUser = await getAuthUser(request, env);
  if (!authUser) return bad(request, "Sign in or API key required", 401);

  const rlId =
    authUser.auth_via === "api_key"
      ? "net:key:" + (authUser.key_id || authUser.id)
      : "net:user:" + authUser.id;
  const limited = await checkRateLimit(env, rlId, RL_NETTING_MAX, RL_NETTING_WINDOW_SEC);
  if (limited) {
    return bad(request, "Rate limit: netting runs", 429, {
      retry_after_sec: limited.retry_after_sec,
    });
  }

  let body = {};
  try {
    if (request.headers.get("Content-Type")?.includes("json")) {
      body = await request.json();
    }
  } catch {
    body = {};
  }

  let windowHours = Number(body.window_hours ?? body.window ?? NETTING_DEFAULT_WINDOW_HOURS);
  if (!Number.isFinite(windowHours)) windowHours = NETTING_DEFAULT_WINDOW_HOURS;
  windowHours = Math.max(
    NETTING_MIN_WINDOW_HOURS,
    Math.min(NETTING_MAX_WINDOW_HOURS, Math.floor(windowHours))
  );
  const applyBalances = !!body.apply_balances;
  const repoFilter = body.repo
    ? parseRepo(body.repo)
    : authUser.default_repo
      ? parseRepo(authUser.default_repo)
      : null;

  let rows;
  try {
    let sql = `
      SELECT from_repo, to_repo, SUM(amount) AS gross, COUNT(*) AS n
      FROM transactions
      WHERE status = 'success'
        AND created_at >= datetime('now', ?)
        AND from_repo NOT LIKE 'system/%'
        AND to_repo NOT LIKE 'system/%'
        AND from_repo != to_repo
    `;
    const binds = ["-" + windowHours + " hours"];
    if (repoFilter) {
      sql += ` AND (from_repo = ? OR to_repo = ?)`;
      binds.push(repoFilter, repoFilter);
    }
    sql += ` GROUP BY from_repo, to_repo`;
    const q = await env.DB.prepare(sql).bind(...binds).all();
    rows = q.results || [];
  } catch (e) {
    return bad(request, "ledger query failed: " + (e.message || e), 500);
  }

  const pairMap = new Map();
  for (const r of rows) {
    const a = r.from_repo;
    const b = r.to_repo;
    const gross = Number(r.gross) || 0;
    const n = Number(r.n) || 0;
    if (!a || !b || gross <= 0) continue;
    const [lo, hi] = a < b ? [a, b] : [b, a];
    const key = lo + "\0" + hi;
    let p = pairMap.get(key);
    if (!p) {
      p = {
        party_a: lo,
        party_b: hi,
        gross_a_to_b: 0,
        gross_b_to_a: 0,
        tx_count_a_to_b: 0,
        tx_count_b_to_a: 0,
      };
      pairMap.set(key, p);
    }
    if (a === lo && b === hi) {
      p.gross_a_to_b += gross;
      p.tx_count_a_to_b += n;
    } else {
      p.gross_b_to_a += gross;
      p.tx_count_b_to_a += n;
    }
  }

  const pairs = [...pairMap.values()].slice(0, NETTING_MAX_PAIRS);
  const runId = "net_" + randomId(12);
  let pairsNetted = 0;
  let volumeGross = 0;
  let volumeNetted = 0;
  const settlements = [];

  for (const p of pairs) {
    const gab = Math.round(p.gross_a_to_b * 1e6) / 1e6;
    const gba = Math.round(p.gross_b_to_a * 1e6) / 1e6;
    volumeGross += gab + gba;
    const net = Math.round((gab - gba) * 1e6) / 1e6;
    if (Math.abs(net) < MIN_AMOUNT) continue;
    if (gab < MIN_AMOUNT || gba < MIN_AMOUNT) continue;

    const netFrom = net > 0 ? p.party_a : p.party_b;
    const netTo = net > 0 ? p.party_b : p.party_a;
    const netAmt = Math.abs(net);
    volumeNetted += netAmt;
    pairsNetted += 1;

    const sid = "ns_" + randomId(10);
    settlements.push({
      id: sid,
      party_a: p.party_a,
      party_b: p.party_b,
      gross_a_to_b: gab,
      gross_b_to_a: gba,
      net_amount: netAmt,
      net_from: netFrom,
      net_to: netTo,
      tx_count_a_to_b: p.tx_count_a_to_b,
      tx_count_b_to_a: p.tx_count_b_to_a,
    });

    try {
      await env.DB.prepare(
        `INSERT INTO netting_settlements (
           id, run_id, party_a, party_b, gross_a_to_b, gross_b_to_a,
           net_amount, net_from, net_to, tx_count_a_to_b, tx_count_b_to_a,
           status, created_at
         ) VALUES (
           ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 'settled', datetime('now')
         )`
      )
        .bind(
          sid, runId, p.party_a, p.party_b, gab, gba, netAmt,
          netFrom, netTo, p.tx_count_a_to_b, p.tx_count_b_to_a
        )
        .run();
    } catch (e) {
      return bad(
        request,
        "netting tables missing — run d1-netting-migration.sql: " + (e.message || e),
        500
      );
    }

    await env.DB.prepare(
      `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
       VALUES (?1, ?2, ?3, ?4, 'success', ?5)`
    )
      .bind(SYSTEM_NETTING, netTo, netAmt, "net:" + sid + ":" + netFrom + "→" + netTo, Date.now() - t0)
      .run()
      .catch(() => {});

    if (applyBalances) {
      try {
        await ensureAccount(env, netFrom);
        await ensureAccount(env, netTo);
        const debit = await env.DB.prepare(
          `UPDATE accounts SET balance = balance - ?1, updated_at = datetime('now')
           WHERE repo_id = ?2 AND balance >= ?1 RETURNING balance`
        )
          .bind(netAmt, netFrom)
          .first();
        if (debit) {
          await env.DB.prepare(
            `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now')
             WHERE repo_id = ?2`
          )
            .bind(netAmt, netTo)
            .run();
        }
      } catch (_) {}
    }
  }

  try {
    await env.DB.prepare(
      `INSERT INTO netting_runs (
         id, window_hours, pairs_scanned, pairs_netted,
         volume_gross, volume_netted, status, created_by, created_at
       ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'done', ?7, datetime('now'))`
    )
      .bind(
        runId, windowHours, pairs.length, pairsNetted,
        Math.round(volumeGross * 1e6) / 1e6,
        Math.round(volumeNetted * 1e6) / 1e6,
        authUser.id
      )
      .run();
  } catch (e) {
    return bad(
      request,
      "netting tables missing — run d1-netting-migration.sql: " + (e.message || e),
      500
    );
  }

  const saved = Math.round((volumeGross - volumeNetted) * 1e6) / 1e6;
  return json(request, {
    ok: true,
    run_id: runId,
    window_hours: windowHours,
    pairs_scanned: pairs.length,
    pairs_netted: pairsNetted,
    volume_gross: Math.round(volumeGross * 1e6) / 1e6,
    volume_net: Math.round(volumeNetted * 1e6) / 1e6,
    volume_saved: saved,
    apply_balances: applyBalances,
    settlements: settlements.slice(0, 50),
    latency_ms: Date.now() - t0,
    hint: applyBalances
      ? "Hard settle applied (balances moved)."
      : "Soft net: report + ledger annotation only. Pass apply_balances:true to move funds.",
  });
}

export async function handleNettingList(request, url, env) {
  const limit = Math.min(Math.max(Number(url.searchParams.get("limit") || 10), 1), 50);
  try {
    const { results: runs } = await env.DB.prepare(
      `SELECT id, window_hours, pairs_scanned, pairs_netted, volume_gross, volume_netted, status, created_at
       FROM netting_runs ORDER BY created_at DESC LIMIT ?1`
    )
      .bind(limit)
      .all();
    const runIds = (runs || []).map((r) => r.id);
    let settlements = [];
    if (runIds.length) {
      const placeholders = runIds.map(() => "?").join(",");
      const q = await env.DB.prepare(
        `SELECT id, run_id, party_a, party_b, gross_a_to_b, gross_b_to_a, net_amount, net_from, net_to, created_at
         FROM netting_settlements WHERE run_id IN (${placeholders})
         ORDER BY created_at DESC LIMIT 100`
      )
        .bind(...runIds)
        .all();
      settlements = q.results || [];
    }
    return json(request, { ok: true, runs: runs || [], settlements });
  } catch (e) {
    return bad(
      request,
      "netting tables missing — run d1-netting-migration.sql: " + (e.message || e),
      500
    );
  }
}


