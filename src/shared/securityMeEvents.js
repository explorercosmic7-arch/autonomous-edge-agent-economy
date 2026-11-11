/**
 * Dashboard: GET /api/me/security-events
 * Optional: ?probe=1 inserts a system.probe event for this user (debug).
 */
import { json, bad } from "./http.js";
import { getSessionUser } from "./auth.js";
import {
  listSecurityEventsForUser,
  countSecurityEventsAll,
  recordSecurityEvent,
  getLastSecurityError,
  ensureSecurityEventsTable,
} from "./securityLog.js";
import { SECURITY_EVENTS_LIST_MAX } from "./constants.js";

export async function handleMeSecurityEvents(request, url, env) {
  const user = await getSessionUser(request, env);
  if (!user) return bad(request, "Sign in required", 401);

  const limit = Math.min(
    Math.max(Number(url.searchParams.get("limit") || SECURITY_EVENTS_LIST_MAX || 50), 1),
    100
  );

  const tableOk = await ensureSecurityEventsTable(env);

  // Optional probe so you can force one row without creating a key
  if (url.searchParams.get("probe") === "1") {
    await recordSecurityEvent(
      env,
      {
        kind: "system.probe",
        severity: "info",
        user_id: user.id,
        reason: "dashboard_probe",
        meta: { source: "security-events?probe=1" },
      },
      request
    );
  }

  const events = await listSecurityEventsForUser(env, user.id, limit);
  let totalAll = -1;
  try {
    totalAll = await countSecurityEventsAll(env);
  } catch (_) {}

  const lastErr = getLastSecurityError();

  return json(request, {
    ok: true,
    count: events.length,
    events,
    debug: {
      user_id: user.id,
      table_ok: tableOk,
      table_total: totalAll,
      limit,
      last_error: lastErr,
    },
    hint:
      events.length === 0
        ? lastErr
          ? "Security DB error: " + lastErr
          : totalAll > 0
            ? "Events exist but none for this account. Sign out and sign in again."
            : "Table empty. Open this URL with ?probe=1 once, or create/rotate a key, then Refresh."
        : null,
  });
}
