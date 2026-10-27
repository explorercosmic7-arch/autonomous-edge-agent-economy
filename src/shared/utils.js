/**
 * Shared pure utils — ids, parsing, cookies, crypto.
 * No DB / routes / business logic.
 */

export const REPO_RE = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
export const MIN_AMOUNT = 0.000001;
export const MAX_AMOUNT = 1_000_000;
export const COOKIE_NAME = "a2a_session";

const ESCROW_DEFAULT_TTL_HOURS = 72;
const ESCROW_MIN_TTL_SEC = 10;
const ESCROW_MAX_TTL_SEC = 720 * 3600;

export function parseRepo(v) {
  const s = String(v || "").trim();
  return REPO_RE.test(s) ? s : null;
}

export function parseAmount(v) {
  const n = Number(v);
  if (!Number.isFinite(n) || n < MIN_AMOUNT || n > MAX_AMOUNT) return null;
  return Math.round(n * 1e6) / 1e6;
}

export function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export function randomId(bytes = 16) {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  return [...arr].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function parseCookies(header) {
  const out = {};
  if (!header) return out;
  header.split(";").forEach((part) => {
    const i = part.indexOf("=");
    if (i === -1) return;
    const k = part.slice(0, i).trim();
    const v = part.slice(i + 1).trim();
    out[k] = decodeURIComponent(v);
  });
  return out;
}

export function sessionCookie(value, maxAgeSec) {
  return `${COOKIE_NAME}=${encodeURIComponent(value)}; Path=/; HttpOnly; Secure; SameSite=None; Max-Age=${maxAgeSec}`;
}

export function clearSessionCookie() {
  return `${COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=None; Max-Age=0`;
}

export async function sha256Hex(text) {
  const data = new TextEncoder().encode(text);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return [...new Uint8Array(hash)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export async function hmacSha256Hex(secret, message) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** Escrow-style TTL: ttl_seconds or ttl_hours → seconds, or default hours. */
export function parseTtlSeconds(body) {
  const sec = Number(body.ttl_seconds);
  if (Number.isFinite(sec)) {
    if (sec < ESCROW_MIN_TTL_SEC || sec > ESCROW_MAX_TTL_SEC) return null;
    return Math.floor(sec);
  }
  const hours = Number(body.ttl_hours);
  const h = Number.isFinite(hours) && hours > 0 ? hours : ESCROW_DEFAULT_TTL_HOURS;
  const out = Math.floor(h * 3600);
  if (out < ESCROW_MIN_TTL_SEC || out > ESCROW_MAX_TTL_SEC) return null;
  return out;
}

/** HTTPS only public webhook URL */
export function parseWebhookUrl(v) {
  try {
    const u = new URL(String(v || "").trim());
    if (u.protocol !== "https:") return null;
    if (!u.hostname || u.hostname === "localhost") return null;
    return u.toString();
  } catch {
    return null;
  }
}
