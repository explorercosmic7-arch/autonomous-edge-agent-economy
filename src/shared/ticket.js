/**
 * Shared Ticket — capability tickets (mint/transfer/redeem) + expireTickets cron.
 */
import { json, bad } from "./http.js";
import {
  parseRepo,
  parseAmount,
  randomId,
} from "./utils.js";
import { checkRateLimit } from "./rateLimit.js";
import { getAuthUser } from "./auth.js";
import { ensureAccount } from "./accounts.js";
import { safetyGate, safetyRecordSpend } from "./gate.js";
import {
  SYSTEM_TICKET,
  TICKET_MIN_UNITS,
  TICKET_MAX_UNITS,
  TICKET_DEFAULT_TTL_SEC,
  TICKET_MIN_TTL_SEC,
  TICKET_MAX_TTL_SEC,
  RL_TICKET_MAX,
  RL_TICKET_WINDOW_SEC,
  EXPIRE_TICKET_BATCH,
} from "./constants.js";

/* ─── Capability tickets (spendable rights) ───
 * Mint: issuer debits optional USD bond + grants units of a capability string.
 * Transfer: holder → new holder (no unit change).
 * Redeem: burn units (and optional USD to service repo).
 * Capability is free-form: "model/gpt-tool", "api:vision", "can_call:foo".
 */
export function parseTicketTtl(body) {
  const sec = Number(body.ttl_seconds ?? body.ttl);
  if (Number.isFinite(sec)) {
    if (sec < TICKET_MIN_TTL_SEC || sec > TICKET_MAX_TTL_SEC) return null;
    return Math.floor(sec);
  }
  return TICKET_DEFAULT_TTL_SEC;
}

export function parseUnits(v) {
  const n = Number(v);
  if (!Number.isFinite(n) || n < TICKET_MIN_UNITS || n > TICKET_MAX_UNITS) return null;
  return Math.round(n * 1e6) / 1e6;
}

export function parseCapability(v) {
  const s = String(v || "").trim().slice(0, 128);
  if (!s || !/^[A-Za-z0-9_.:\-\/]+$/.test(s)) return null;
  return s;
}

export async function loadTicket(env, id) {
  try {
    return await env.DB.prepare(`SELECT * FROM capability_tickets WHERE id = ?1`).bind(id).first();
  } catch {
    return null;
  }
}

export async function logTicketEvent(env, ticketId, event, { from_repo, to_repo, units, amount_usd, task } = {}) {
  try {
    await env.DB.prepare(
      `INSERT INTO ticket_events (id, ticket_id, event, from_repo, to_repo, units, amount_usd, task, created_at)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, datetime('now'))`
    )
      .bind(
        randomId(10),
        ticketId,
        event,
        from_repo || null,
        to_repo || null,
        units != null ? Number(units) : null,
        amount_usd != null ? Number(amount_usd) : null,
        task || null
      )
      .run();
  } catch (e) {
    console.log("ticket_event_err", e && e.message);
  }
}

export async function handleTicketMint(request, env) {
  const t0 = Date.now();
  const authUser = await getAuthUser(request, env);
  if (!authUser) return bad(request, "Sign in or API key required", 401);

  const rlId =
    authUser.auth_via === "api_key"
      ? "tk:key:" + (authUser.key_id || authUser.id)
      : "tk:user:" + authUser.id;
  const limited = await checkRateLimit(env, rlId, RL_TICKET_MAX, RL_TICKET_WINDOW_SEC);
  if (limited) {
    return bad(request, "Rate limit: ticket ops", 429, { retry_after_sec: limited.retry_after_sec });
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return bad(request, "Invalid JSON body");
  }

  let issuer = parseRepo(body.issuer_repo || body.from_repo || body.fromRepo);
  if (!issuer && authUser.default_repo) issuer = parseRepo(authUser.default_repo);
  const holder = parseRepo(body.holder_repo || body.to_repo || body.toRepo) || issuer;
  const capability = parseCapability(body.capability || body.cap);
  const units = parseUnits(body.units ?? body.budget);
  const ttlSec = parseTicketTtl(body);
  const bond = body.bond_usd != null || body.amount != null ? parseAmount(body.bond_usd ?? body.amount) : null;
  const maxAmt =
    body.max_amount_usd != null && body.max_amount_usd !== ""
      ? parseAmount(body.max_amount_usd)
      : null;
  const task = String(body.task || "ticket-mint").slice(0, 500);

  if (!issuer) return bad(request, "issuer_repo required (or set default agent)");
  if (!holder) return bad(request, "holder_repo invalid");
  if (!capability) return bad(request, "capability required (e.g. model/vision or api:tool)");
  if (units == null) return bad(request, "units must be between " + TICKET_MIN_UNITS + " and " + TICKET_MAX_UNITS);
  if (ttlSec == null) {
    return bad(
      request,
      "ttl_seconds out of range (min " + TICKET_MIN_TTL_SEC + "s, max " + TICKET_MAX_TTL_SEC + "s)"
    );
  }

  // Optional USD bond locked from issuer (skin in the game)
  if (bond != null && bond > 0) {
    authUser._policyCtx = { to_repo: SYSTEM_TICKET, task };
    const blocked = await safetyGate(request, env, authUser, issuer, bond);
    if (blocked) return blocked;
  }

  if (bond != null && bond > 0) {
    await ensureAccount(env, issuer);
    const debit = await env.DB.prepare(
      `UPDATE accounts SET balance = balance - ?1, updated_at = datetime('now')
       WHERE repo_id = ?2 AND balance >= ?1 RETURNING balance`
    )
      .bind(bond, issuer)
      .first();
    if (!debit) return bad(request, "Insufficient funds for ticket bond", 402);
  }

  const id = "tk_" + randomId(12);
  const modifier = "+" + ttlSec + " seconds";
  const meta = body.meta && typeof body.meta === "object" ? JSON.stringify(body.meta).slice(0, 2000) : null;

  try {
    await env.DB.prepare(
      `INSERT INTO capability_tickets (
         id, issuer_repo, holder_repo, capability, units_total, units_remaining,
         max_amount_usd, status, created_by, expires_at, meta_json, created_at, updated_at
       ) VALUES (
         ?1, ?2, ?3, ?4, ?5, ?5, ?6, 'open', ?7,
         datetime('now', ?8), ?9, datetime('now'), datetime('now')
       )`
    )
      .bind(id, issuer, holder, capability, units, maxAmt, authUser.id, modifier, meta)
      .run();
  } catch (e) {
    if (bond != null && bond > 0) {
      await env.DB.prepare(
        `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
      )
        .bind(bond, issuer)
        .run();
    }
    return bad(
      request,
      "capability_tickets table missing — run d1-tickets-migration.sql: " + (e.message || e),
      500
    );
  }

  if (bond != null && bond > 0) {
    await env.DB.prepare(
      `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
       VALUES (?1, ?2, ?3, ?4, 'success', ?5)`
    )
      .bind(issuer, SYSTEM_TICKET, bond, "ticket-bond:" + id, Date.now() - t0)
      .run();
    await safetyRecordSpend(env, authUser, issuer, bond);
  }

  await logTicketEvent(env, id, "minted", {
    from_repo: issuer,
    to_repo: holder,
    units,
    amount_usd: bond || 0,
    task,
  });

  const row = await loadTicket(env, id);
  return json(request, {
    ok: true,
    ticket: {
      id,
      issuer_repo: issuer,
      holder_repo: holder,
      capability,
      units_total: units,
      units_remaining: units,
      max_amount_usd: maxAmt,
      bond_usd: bond || 0,
      status: "open",
      expires_at: row?.expires_at || null,
      ttl_seconds: ttlSec,
    },
    latency_ms: Date.now() - t0,
    hint: "Holder redeems via POST /api/ticket/redeem { id, units }. Transfer with POST /api/ticket/transfer.",
  });
}

export async function handleTicketTransfer(request, env) {
  const t0 = Date.now();
  const authUser = await getAuthUser(request, env);
  if (!authUser) return bad(request, "Sign in or API key required", 401);

  let body;
  try {
    body = await request.json();
  } catch {
    return bad(request, "Invalid JSON body");
  }

  const id = String(body.id || "").trim();
  const toRepo = parseRepo(body.to_repo || body.toRepo || body.holder_repo);
  if (!id) return bad(request, "id required");
  if (!toRepo) return bad(request, "to_repo required");

  let row;
  try {
    row = await env.DB.prepare(`SELECT * FROM capability_tickets WHERE id = ?1`).bind(id).first();
  } catch {
    return bad(request, "capability_tickets table missing — run d1-tickets-migration.sql", 500);
  }
  if (!row) return bad(request, "Ticket not found", 404);
  if (row.status !== "open") {
    return bad(request, "Ticket not open (status=" + row.status + ")", 400, { code: "ticket_closed" });
  }
  if (row.expires_at) {
    const expMs = Date.parse(String(row.expires_at).replace(" ", "T") + "Z");
    if (Number.isFinite(expMs) && expMs < Date.now()) {
      return bad(request, "Ticket expired", 400, { code: "ticket_expired" });
    }
  }

  const allowed =
    authUser.id === row.created_by ||
    (authUser.default_repo &&
      (authUser.default_repo === row.holder_repo || authUser.default_repo === row.issuer_repo));
  if (!allowed) return bad(request, "Not authorized to transfer this ticket", 403);

  const fromHolder = row.holder_repo;
  await env.DB.prepare(
    `UPDATE capability_tickets
     SET holder_repo = ?2, updated_at = datetime('now')
     WHERE id = ?1 AND status = 'open'`
  )
    .bind(id, toRepo)
    .run();

  await logTicketEvent(env, id, "transferred", {
    from_repo: fromHolder,
    to_repo: toRepo,
    units: row.units_remaining,
  });

  return json(request, {
    ok: true,
    id,
    holder_repo: toRepo,
    from_holder: fromHolder,
    capability: row.capability,
    units_remaining: row.units_remaining,
    latency_ms: Date.now() - t0,
  });
}

export async function handleTicketRedeem(request, env) {
  const t0 = Date.now();
  const authUser = await getAuthUser(request, env);
  if (!authUser) return bad(request, "Sign in or API key required", 401);

  let body;
  try {
    body = await request.json();
  } catch {
    return bad(request, "Invalid JSON body");
  }

  const id = String(body.id || "").trim();
  const units = parseUnits(body.units);
  const task = String(body.task || "ticket-redeem").slice(0, 500);
  const payTo = body.to_repo || body.toRepo ? parseRepo(body.to_repo || body.toRepo) : null;
  const amountUsd = body.amount != null ? parseAmount(body.amount) : null;

  if (!id) return bad(request, "id required");
  if (units == null) return bad(request, "units required");

  let row;
  try {
    row = await env.DB.prepare(`SELECT * FROM capability_tickets WHERE id = ?1`).bind(id).first();
  } catch {
    return bad(request, "capability_tickets table missing — run d1-tickets-migration.sql", 500);
  }
  if (!row) return bad(request, "Ticket not found", 404);
  if (row.status !== "open") {
    return bad(request, "Ticket not open (status=" + row.status + ")", 400, { code: "ticket_closed" });
  }
  if (row.expires_at) {
    const expMs = Date.parse(String(row.expires_at).replace(" ", "T") + "Z");
    if (Number.isFinite(expMs) && expMs < Date.now()) {
      return bad(request, "Ticket expired", 400, { code: "ticket_expired" });
    }
  }

  const allowed =
    authUser.id === row.created_by ||
    (authUser.default_repo && authUser.default_repo === row.holder_repo);
  if (!allowed) return bad(request, "Not authorized to redeem this ticket", 403);

  const remaining = Number(row.units_remaining);
  if (units > remaining) {
    return bad(request, "Insufficient ticket units (remaining " + remaining + ")", 402, {
      code: "ticket_insufficient",
      remaining,
    });
  }

  if (amountUsd != null && amountUsd > 0) {
    if (row.max_amount_usd != null && amountUsd > Number(row.max_amount_usd)) {
      return bad(request, "amount exceeds ticket max_amount_usd", 403, { code: "ticket_max_amount" });
    }
  }

  const claim = await env.DB.prepare(
    `UPDATE capability_tickets
     SET units_remaining = units_remaining - ?1,
         status = CASE WHEN units_remaining - ?1 <= 0.0000005 THEN 'exhausted' ELSE 'open' END,
         updated_at = datetime('now'),
         closed_at = CASE WHEN units_remaining - ?1 <= 0.0000005 THEN datetime('now') ELSE closed_at END,
         close_reason = CASE WHEN units_remaining - ?1 <= 0.0000005 THEN 'exhausted' ELSE close_reason END
     WHERE id = ?2 AND status = 'open' AND units_remaining >= ?1
     RETURNING id, units_remaining, status, capability, holder_repo, issuer_repo`
  )
    .bind(units, id)
    .first();

  if (!claim) return bad(request, "Redeem failed (race or insufficient)", 409);

  // Optional USD settlement to service provider
  if (amountUsd != null && amountUsd > 0 && payTo) {
    await ensureAccount(env, SYSTEM_TICKET);
    await ensureAccount(env, payTo);
    // Pay from system/ticket bond pool if funded; else from holder (soft fail)
    const fromBond = await env.DB.prepare(
      `UPDATE accounts SET balance = balance - ?1, updated_at = datetime('now')
       WHERE repo_id = ?2 AND balance >= ?1 RETURNING balance`
    )
      .bind(amountUsd, SYSTEM_TICKET)
      .first();
    if (fromBond) {
      await env.DB.prepare(
        `UPDATE accounts SET balance = balance + ?1, updated_at = datetime('now') WHERE repo_id = ?2`
      )
        .bind(amountUsd, payTo)
        .run();
      await env.DB.prepare(
        `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
         VALUES (?1, ?2, ?3, ?4, 'success', ?5)`
      )
        .bind(SYSTEM_TICKET, payTo, amountUsd, "ticket-redeem:" + id + ":" + task.slice(0, 40), Date.now() - t0)
        .run();
    }
  }

  await logTicketEvent(env, id, "redeemed", {
    from_repo: claim.holder_repo,
    to_repo: payTo,
    units,
    amount_usd: amountUsd || 0,
    task,
  });

  await env.DB.prepare(
    `INSERT INTO transactions (from_repo, to_repo, amount, task, status, latency_ms)
     VALUES (?1, ?2, ?3, ?4, 'success', ?5)`
  )
    .bind(
      claim.holder_repo,
      SYSTEM_TICKET,
      0,
      "ticket-units:" + id + ":" + units + ":" + claim.capability,
      Date.now() - t0
    )
    .run()
    .catch(() => {});

  return json(request, {
    ok: true,
    id,
    capability: claim.capability,
    units_burned: units,
    units_remaining: Math.max(0, Number(claim.units_remaining)),
    status: claim.status,
    amount_usd: amountUsd || 0,
    to_repo: payTo,
    latency_ms: Date.now() - t0,
  });
}

export async function handleTicketGet(request, env, id) {
  id = String(id || "").trim();
  if (!id) return bad(request, "id required");
  const row = await loadTicket(env, id);
  if (!row) {
    // distinguish missing table
    try {
      await env.DB.prepare(`SELECT 1 FROM capability_tickets LIMIT 1`).first();
    } catch (e) {
      return bad(request, "capability_tickets table missing — run d1-tickets-migration.sql", 500);
    }
    return bad(request, "Ticket not found", 404);
  }
  let events = [];
  try {
    const q = await env.DB.prepare(
      `SELECT event, from_repo, to_repo, units, amount_usd, task, created_at
       FROM ticket_events WHERE ticket_id = ?1 ORDER BY created_at DESC LIMIT 30`
    )
      .bind(id)
      .all();
    events = q.results || [];
  } catch (_) {}
  return json(request, { ok: true, ticket: row, events });
}

export async function handleTicketList(request, url, env) {
  const limit = Math.min(Math.max(Number(url.searchParams.get("limit") || 25), 1), 100);
  const repo = (url.searchParams.get("repo") || "").trim();
  const status = (url.searchParams.get("status") || "").trim();
  const capability = (url.searchParams.get("capability") || "").trim();

  let sql = `SELECT id, issuer_repo, holder_repo, capability, units_total, units_remaining,
                    max_amount_usd, status, expires_at, created_at
             FROM capability_tickets WHERE 1=1`;
  const binds = [];
  if (repo) {
    if (!parseRepo(repo)) return bad(request, "repo must be owner/repo");
    sql += ` AND (issuer_repo = ? OR holder_repo = ?)`;
    binds.push(repo, repo);
  }
  if (status && ["open", "exhausted", "expired", "closed"].includes(status)) {
    sql += ` AND status = ?`;
    binds.push(status);
  }
  if (capability) {
    sql += ` AND capability = ?`;
    binds.push(capability.slice(0, 128));
  }
  sql += ` ORDER BY created_at DESC LIMIT ?`;
  binds.push(limit);

  try {
    const { results } = await env.DB.prepare(sql).bind(...binds).all();
    return json(request, { ok: true, count: results.length, tickets: results });
  } catch (e) {
    return bad(
      request,
      "capability_tickets table missing — run d1-tickets-migration.sql: " + (e.message || e),
      500
    );
  }
}

export async function expireTickets(env) {
  const t0 = Date.now();
  let results;
  try {
    const q = await env.DB.prepare(
      `SELECT id FROM capability_tickets
       WHERE status = 'open'
         AND expires_at IS NOT NULL
         AND expires_at < datetime('now')
       ORDER BY expires_at ASC
       LIMIT ?1`
    )
      .bind(EXPIRE_TICKET_BATCH)
      .all();
    results = q.results || [];
  } catch (e) {
    return { expired: 0, scanned: 0, error: e.message, latency_ms: Date.now() - t0 };
  }
  let expired = 0;
  for (const r of results) {
    try {
      const claim = await env.DB.prepare(
        `UPDATE capability_tickets
         SET status = 'expired', closed_at = datetime('now'), close_reason = 'expired',
             updated_at = datetime('now')
         WHERE id = ?1 AND status = 'open'
         RETURNING id`
      )
        .bind(r.id)
        .first();
      if (claim) {
        expired += 1;
        await logTicketEvent(env, r.id, "expired", {});
      }
    } catch (e) {
      console.log("ticket_expire_err", r.id, e && e.message);
    }
  }
  return { expired, scanned: results.length, latency_ms: Date.now() - t0 };
}


