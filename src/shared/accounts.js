/**
 * Shared account helpers — ensure ledger account rows exist.
 */
export async function ensureAccount(env, repo) {
  await env.DB.prepare(
    `INSERT INTO accounts (repo_id, balance) VALUES (?, 0) ON CONFLICT(repo_id) DO NOTHING`
  )
    .bind(repo)
    .run();
}
