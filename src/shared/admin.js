/**
 * Admin auth helpers.
 * Requires ADMIN_CLEANUP_SECRET (16+ chars) via header X-Admin-Cleanup-Key or body.secret/key.
 */

import { bad, timingSafeEqualString } from "./http.js";

export async function assertAdminSecret(request, env, body) {
  const secret = String(env.ADMIN_CLEANUP_SECRET || "").trim();
  if (!secret || secret.length < 16) {
    return {
      ok: false,
      response: bad(request, "Admin disabled: set ADMIN_CLEANUP_SECRET (16+ chars)", 503, {
        code: "admin_disabled",
      }),
    };
  }
  const provided =
    (request.headers.get("X-Admin-Cleanup-Key") || "").trim() ||
    String((body && (body.secret || body.key)) || "").trim();
  if (!provided || !timingSafeEqualString(provided, secret)) {
    return {
      ok: false,
      response: bad(request, "Invalid admin key", 403, { code: "bad_admin_key" }),
    };
  }
  return { ok: true };
}
