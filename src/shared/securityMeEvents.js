/**
 * Dashboard: GET /api/me/security-events
 * Day 04: ?instance_id= filter, ?probe=1 debug insert
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
    200
  );
  const instanceId = (url.searchParams.get("instance_id") || "").trim() || null;

  const tableOk = await ensureSecurityEventsTable(env);

  if (url.searchParams.get("probe") === "1") {
    await recordSecurityEvent(
      env,
      {
        kind: "system.probe",
        severity: "info",
        user_id: user.id,
        reason: "dashboard_probe",
        instance_id: instanceId || null,
        meta: { source: "security-events?probe=1", instance_id: instanceId },
      },
      request
    );
  }

  const events = await listSecurityEventsForUser(env, user.id, limit, {
    instance_id: instanceId,
  });
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
      instance_id: instanceId,
      last_error: lastErr,
    },
    hint:
      events.length === 0
        ? lastErr
          ? "Security DB error: " + lastErr
          : totalAll > 0
            ? "Events exist but none for this account (or instance filter). Try without instance_id."
            : "Table empty. Open with ?probe=1 once, or create/rotate a key, then Refresh."
        : null,
  });
}
