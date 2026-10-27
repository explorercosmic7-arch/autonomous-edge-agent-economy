/**
 * D1 fixed-window rate limiter.
 * Returns null if allowed, or { retry_after_sec } if limited.
 */

export async function checkRateLimit(env, bucketKey, max, windowSec) {
  const now = Date.now();
  const row = await env.DB.prepare(
    `SELECT count, window_start FROM rate_limits WHERE bucket_key = ?1`
  )
    .bind(bucketKey)
    .first();

  if (!row) {
    await env.DB.prepare(
      `INSERT INTO rate_limits (bucket_key, count, window_start, updated_at)
       VALUES (?1, 1, datetime('now'), datetime('now'))`
    )
      .bind(bucketKey)
      .run();
    return null;
  }

  const startMs = new Date(row.window_start + "Z").getTime();
  const start = Number.isFinite(startMs)
    ? startMs
    : Date.parse(String(row.window_start).replace(" ", "T") + "Z");

  if (!Number.isFinite(start) || now - start >= windowSec * 1000) {
    await env.DB.prepare(
      `UPDATE rate_limits
       SET count = 1, window_start = datetime('now'), updated_at = datetime('now')
       WHERE bucket_key = ?1`
    )
      .bind(bucketKey)
      .run();
    return null;
  }

  if (row.count >= max) {
    const retry = Math.max(1, Math.ceil((windowSec * 1000 - (now - start)) / 1000));
    return { retry_after_sec: retry };
  }

  await env.DB.prepare(
    `UPDATE rate_limits
     SET count = count + 1, updated_at = datetime('now')
     WHERE bucket_key = ?1`
  )
    .bind(bucketKey)
    .run();
  return null;
}
