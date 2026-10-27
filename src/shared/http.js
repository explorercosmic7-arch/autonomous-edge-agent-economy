/**
 * Shared HTTP helpers — CORS, JSON responses, security headers, body limits.
 * Used by all routes. No DB / auth / business logic here.
 */

const ALLOWED_ORIGINS = new Set([
  "https://edgerail.pages.dev",
  "https://newhorizons-beyondhorizon.pages.dev",
  "https://autonomous-edge-agent-economy.explorercosmic7.workers.dev",
]);

export const MAX_JSON_BODY_BYTES = 256 * 1024; // 256 KiB

export function securityHeaders() {
  return {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    "Cache-Control": "no-store",
    "X-AgentPay-Security": "bank-grade-v1",
  };
}

export function corsHeaders(request) {
  const origin = request.headers.get("Origin") || "";
  const allow = ALLOWED_ORIGINS.has(origin) ? origin : "https://edgerail.pages.dev";
  return {
    "Access-Control-Allow-Origin": allow,
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers":
      "Content-Type, Authorization, Idempotency-Key, X-Admin-Cleanup-Key",
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Max-Age": "86400",
    Vary: "Origin",
  };
}

export function json(request, data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      ...securityHeaders(),
      ...corsHeaders(request),
      ...extraHeaders,
    },
  });
}

export function bad(request, message, status = 400, extra = {}) {
  return json(request, { ok: false, error: message, ...extra }, status);
}

/** Constant-time string compare for admin secrets (length must match first). */
export function timingSafeEqualString(a, b) {
  const s1 = String(a || "");
  const s2 = String(b || "");
  if (s1.length !== s2.length) return false;
  let out = 0;
  for (let i = 0; i < s1.length; i++) {
    out |= s1.charCodeAt(i) ^ s2.charCodeAt(i);
  }
  return out === 0;
}

/** Reject oversized bodies early (Content-Length). Returns Response or null. */
export function rejectOversizedBody(request) {
  if (request.method !== "POST" && request.method !== "PUT" && request.method !== "PATCH") {
    return null;
  }
  const cl = request.headers.get("Content-Length");
  if (cl == null || cl === "") return null;
  const n = Number(cl);
  if (!Number.isFinite(n) || n < 0) {
    return bad(request, "Invalid Content-Length", 400, { code: "bad_content_length" });
  }
  if (n > MAX_JSON_BODY_BYTES) {
    return bad(request, "Request body too large (max " + MAX_JSON_BODY_BYTES + " bytes)", 413, {
      code: "body_too_large",
      max_bytes: MAX_JSON_BODY_BYTES,
    });
  }
  return null;
}

export function clientIp(request) {
  return (
    request.headers.get("CF-Connecting-IP") ||
    request.headers.get("True-Client-IP") ||
    (request.headers.get("X-Forwarded-For") || "").split(",")[0].trim() ||
    "unknown"
  );
}
