/**
 * Dashboard: GET /api/me/security-events
 * Merge into security.js or import from index.js.
 */
import { json, bad } from "./http.js";
import { getSessionUser } from "./auth.js";
import { listSecurityEventsForUser } from "./securityLog.js";
import { SECURITY_EVENTS_LIST_MAX } from "./constants.js";

export async function handleMeSecurityEvents(request, url, env) {
  const user = await getSessionUser(request, env);
  if (!user) return bad(request, "Sign in required", 401);
  const limit = Math.min(
    Math.max(Number(url.searchParams.get("limit") || SECURITY_EVENTS_LIST_MAX), 1),
    100
  );
  const events = await listSecurityEventsForUser(env, user.id, limit);
  return json(request, {
    ok: true,
    count: events.length,
    events,
  });
}
