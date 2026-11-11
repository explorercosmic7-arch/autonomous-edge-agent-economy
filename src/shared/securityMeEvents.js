/**
 * Dashboard: GET /api/me/security-events
 */
import { json, bad } from "./http.js";
import { getSessionUser } from "./auth.js";
import {
  listSecurityEventsForUser,
  countSecurityEventsAll,
} from "./securityLog.js";
import { SECURITY_EVENTS_LIST_MAX } from "./constants.js";

export async function handleMeSecurityEvents(request, url, env) {
  const user = await getSessionUser(request, env);
  if (!user) return bad(request, "Sign in required", 401);

  const limit = Math.min(
    Math.max(Number(url.searchParams.get("limit") || SECURITY_EVENTS_LIST_MAX), 1),
    100
  );

  const events = await listSecurityEventsForUser(env, user.id, limit);
  let totalAll = -1;
  try {
    totalAll = await countSecurityEventsAll(env);
  } catch (_) {}

  return json(request, {
    ok: true,
    count: events.length,
    events,
    debug: {
      user_id: user.id,
      table_total: totalAll,
      limit,
    },
    hint:
      events.length === 0
        ? totalAll > 0
          ? "Events exist in DB but none for this account. Sign out/in and retry."
          : totalAll === 0
            ? "Table empty. Create or rotate a key, then Refresh."
            : "Could not read security_events. Check worker logs (security_event_*)."
        : null,
  });
}
