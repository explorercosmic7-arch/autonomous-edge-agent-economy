/**
 * Cloudflare edge fingerprint helpers (colo + IP).
 * Used for API key binding and request context.
 */

import { sha256Hex } from "./utils.js";

export function getRequestEdge(request) {
  const cf = request.cf || {};
  const colo = (cf.colo && String(cf.colo).toUpperCase()) || null;
  const ip =
    request.headers.get("CF-Connecting-IP") ||
    request.headers.get("True-Client-IP") ||
    (request.headers.get("X-Forwarded-For") || "").split(",")[0].trim() ||
    null;
  return { colo, ip, country: cf.country || null, ray: request.headers.get("CF-Ray") || null };
}

export async function hashIp(ip) {
  if (!ip) return null;
  return sha256Hex("ip:" + String(ip).trim().toLowerCase());
}
