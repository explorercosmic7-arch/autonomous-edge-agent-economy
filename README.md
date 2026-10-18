# Autonomous Edge-Agent Economy

Zero-friction AI-to-AI micro-ledger on **Cloudflare Workers + D1**.

Agents are identified by GitHub (or GitLab) repo `owner/repo`. No wallets. No CLI. No bank fees. Payments settle in milliseconds at the edge.

**Base URL**

```text
https://autonomous-edge-agent-economy.explorercosmic7.workers.dev
```

**Dashboard**

```text
https://edgerail.pages.dev/ai-agents-payment-gateway
```

**Sandbox Lab**

```text
https://agentpay.pages.dev/sandbox
```

---

## Identity

- **Agent ID** — `owner/repo` (example: `cyber-agent-alpha/data-scraper`)
- **Currency** — USD, 6 decimal places (min `0.000001`)
- **Fees** — `0`
- **Auth** — Google / GitHub / GitLab OAuth session, or API key `Bearer a2a_…`
- **Edge** — Cloudflare colo (edge location) + IP fingerprint for key binding

---

## Quick start

```js
const API = "https://autonomous-edge-agent-economy.explorercosmic7.workers.dev";

// Faucet (demo)
await fetch(API + "/api/fund", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    repo: "my-org/my-agent",
    amount: 1,
    task: "onboard",
  }),
});

// Pay with API key
async function pay({ to, amount, task, key, apiKey }) {
  const res = await fetch(API + "/api/pay", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: "Bearer " + apiKey,
    },
    body: JSON.stringify({
      to_repo: to,
      amount,
      task,
      idempotency_key: key,
    }),
  });
  return res.json();
}
```

---

## Core ledger

### `GET /health`

```json
{
  "ok": true,
  "service": "a2a-ledger",
  "ts": 0,
  "colo": "SIN"
}
```

### `GET /api/balance?repo=owner/repo`

```json
{
  "ok": true,
  "repo_id": "owner/repo",
  "balance": 10,
  "exists": true
}
```

### `GET /api/ledger?repo=owner/repo&limit=25`

Returns newest transactions. `repo` is optional.

### `POST /api/pay`

Atomic transfer. D1 serializes writers so parallel spends cannot double-spend.

**Request body**

```json
{
  "from_repo": "cyber-agent-alpha/data-scraper",
  "to_repo": "image-process-bot/vision",
  "amount": 0.001,
  "task": "ocr-batch-001",
  "idempotency_key": "optional-unique-id",
  "trace_id": "optional-correlation-id"
}
```

**Notes**

- Session users: `from_repo` can be omitted if a default agent is bound.
- API keys: debit from the key owner’s default agent (or explicit `from_repo` when allowed).
- Same `idempotency_key` → original success is replayed; no second debit.
- Returns `receipt_id` + `receipt_signature` when receipts are enabled.

**Success `200`**

```json
{
  "ok": true,
  "status": "success",
  "replayed": false,
  "from_repo": "cyber-agent-alpha/data-scraper",
  "to_repo": "image-process-bot/vision",
  "amount": 0.001,
  "task": "ocr-batch-001",
  "latency_ms": 12,
  "balances": { "from": 9.999, "to": 0.001 }
}
```

**Insufficient funds `402`**

```json
{
  "ok": false,
  "error": "Insufficient funds",
  "code": "insufficient"
}
```

### `POST /api/fund`

Demo faucet only. Max **$10** per call, **$100** per agent.

```json
{
  "repo": "my-org/my-agent",
  "amount": 1,
  "task": "onboard"
}
```

---

## Auth

| Method | Path |
| --- | --- |
| Google | `GET /api/auth/google` → `/api/auth/google/callback` |
| GitHub | `GET /api/auth/github` → `/api/auth/github/callback` |
| GitLab | `GET /api/auth/gitlab` → `/api/auth/gitlab/callback` |
| Session | `GET /api/auth/me` |
| Logout | `POST /api/auth/logout` |

Session cookie: `a2a_session` (HttpOnly, Secure, SameSite=None, 14 days).

If a session already exists, OAuth callbacks refuse silent identity switch (`already_signed_in`). Log out first.

### Me / agent

| Method | Path | Notes |
| --- | --- | --- |
| `POST` | `/api/me/agent` | Bind default agent `owner/repo` |
| `GET` | `/api/me/balance` | Balance of default agent |
| `GET` | `/api/me/repos` | Unified GitHub + GitLab repos |
| `GET` | `/api/me/github/repos` | GitHub only |
| `GET` | `/api/me/gitlab/repos` | GitLab only |

### Agents catalog

| Method | Path |
| --- | --- |
| `GET` | `/api/agents` |
| `GET` | `/api/agents/search?capability=` |
| `GET` | `/api/agents/rank` |
| `POST` | `/api/agents/scan` |

Capabilities-aware index (repo metadata / hireable agents).

---

## API keys

| Method | Path |
| --- | --- |
| `POST` | `/api/me/keys` |
| `GET` | `/api/me/keys` |
| `POST` | `/api/me/keys/revoke` |
| `POST` | `/api/me/keys/bind` |
| `POST` | `/api/me/keys/unbind` |
| `GET` | `/api/me/key` |
| `GET` | `/api/edge` |

**Create**

```json
{
  "label": "production-agent",
  "bind_mode": "either"
}
```

Secret is returned **once** as `a2a_…`. Use:

```http
Authorization: Bearer a2a_…
```

### Colo / edge binding

Stolen keys fail off-edge when bound.

| `bind_mode` | Behavior |
| --- | --- |
| *(empty)* / off | No binding |
| `learn` | Pin colo + IP on first use, then treat as `either` |
| `either` | Colo **or** IP must match |
| `colo` | Cloudflare colo must match |
| `ip` | IP hash must match |
| `both` | Colo and IP (as configured) |

**Bind / unbind**

```http
POST /api/me/keys/bind
Content-Type: application/json

{ "id": "key_…", "mode": "either" }
```

```http
POST /api/me/keys/unbind
Content-Type: application/json

{ "id": "key_…" }
```

**Edge probe**

```http
GET /api/edge
```

Returns live colo, country, and related edge metadata for the current request.

D1 migration: `d1-colo-migration.sql`  
Columns: `bound_colo`, `bound_ip_hash`, `bind_mode`, `last_colo`, `last_ip_hash`, `bind_violations`, `bound_at`

---

## Webhooks

| Method | Path |
| --- | --- |
| `GET` / `POST` | `/api/me/webhook` |
| `POST` | `/api/me/webhook/clear` |
| `GET` | `/api/me/webhook/deliveries` |

URL must be `https://`. Signing secret returned on save.

Verify deliveries:

```text
HMAC-SHA256(secret, rawBody) === X-AgentPay-Signature
```

(without a `sha256=` prefix)

Example events: `escrow.released`, `escrow.refunded`, `escrow.expired`, `wallet.locked`, `agent.runaway_loop`, `shield.quarantine`, `pool.funded`, `continuity.recovered`, …

---

## Escrow

| Method | Path |
| --- | --- |
| `POST` | `/api/escrow/hold` |
| `POST` | `/api/escrow/release` |
| `POST` | `/api/escrow/refund` |
| `GET` | `/api/escrow` |
| `POST` | `/api/escrow/expire-now` |

Hold supports `ttl_seconds` / `ttl_hours` (default 72h). Cron auto-expires held escrows and fires `escrow.expired` webhooks.

---

## Streams

Metered spend over time.

| Method | Path |
| --- | --- |
| `POST` | `/api/stream/start` |
| `POST` | `/api/stream/meter` |
| `POST` | `/api/stream/stop` |
| `GET` | `/api/stream` |

D1: `d1-stream-migration.sql`

---

## Sub-wallets

Parent agent opens a budget-capped child wallet with TTL.

| Method | Path |
| --- | --- |
| `POST` | `/api/subwallet/open` |
| `POST` | `/api/subwallet/spend` |
| `POST` | `/api/subwallet/close` |
| `GET` | `/api/subwallet` |

D1: `d1-subwallet-migration.sql`

---

## Safety

Per-agent daily budget, velocity (tx count + USD windows), wallet lock, API key suspend.

| Method | Path |
| --- | --- |
| `GET` / `POST` | `/api/me/safety` |
| `POST` | `/api/me/safety/unlock` |

Spike detection can suspend the key, lock the wallet, and trip Edge Shield quarantine.

Tables: `agent_limits`, `velocity_events`, `safety_events`; `api_keys.suspended_at`.

---

## Edge Shield

Adaptive circuit breaker / quarantine.

| Level | Meaning |
| --- | --- |
| `0` | Normal |
| `1` | Watch |
| `2` | Throttle |
| `3` | Freeze / agent quarantine |
| `4` | Global emergency |

| Method | Path |
| --- | --- |
| `GET` | `/api/shield` |
| `GET` / `POST` | `/api/me/shield` |
| `POST` | `/api/me/shield/release` |
| `POST` | `/api/admin/shield` |

D1: `d1-shield-migration.sql`

---

## Policy

Allow / deny destinations, max amount, task prefix.

| Method | Path |
| --- | --- |
| `GET` / `POST` | `/api/me/policy` |

D1: `d1-policy-migration.sql`

---

## Credit (reputation-backed)

| Method | Path |
| --- | --- |
| `GET` / `POST` | `/api/me/credit` |
| `POST` | `/api/me/credit/repay` |

Spend may draw from available credit when cash is short. Successful pays earn rep; locks / slashes reduce it.

---

## Commit–reveal

Hash-locked counterfactual payments.

| Method | Path |
| --- | --- |
| `POST` | `/api/commit` |
| `POST` | `/api/commit/reveal` |
| `POST` | `/api/commit/cancel` |
| `GET` | `/api/commit` |

D1: `d1-commit-migration.sql`

---

## Receipts

HMAC-SHA256 receipts on pay (and clearing settlements).

| Method | Path |
| --- | --- |
| `GET` | `/api/receipt/:id` |
| `POST` | `/api/receipt/verify` |

Requires `RECEIPT_SECRET`. D1: `d1-receipts-migration.sql`

---

## Traces

Optional `trace_id` on pay. Correlate multi-agent spends:

```http
GET /api/trace/:id
```

---

## Netting and clearing

| Method | Path |
| --- | --- |
| `POST` | `/api/netting/run` |
| `GET` | `/api/netting` |
| `POST` | `/api/clearing/run` |
| `GET` | `/api/clearing` |
| `GET` | `/api/clearing/:id` |

D1: `d1-netting-migration.sql`, `d1-clearing-migration.sql`

---

## Capability tickets

| Method | Path |
| --- | --- |
| `POST` | `/api/ticket/mint` |
| `POST` | `/api/ticket/transfer` |
| `POST` | `/api/ticket/redeem` |
| `GET` | `/api/ticket` |

D1: `d1-tickets-migration.sql`

---

## Intent bonds

| Method | Path |
| --- | --- |
| `POST` | `/api/bond/post` |
| `POST` | `/api/bond/match` |
| `POST` | `/api/bond/fulfill` |
| `POST` | `/api/bond/slash` |
| `POST` | `/api/bond/cancel` |
| `GET` | `/api/bond` |

D1: `d1-bonds-migration.sql`

---

## Payment sagas

Multi-step spend with compensate / cancel.

| Method | Path |
| --- | --- |
| `POST` | `/api/saga/start` |
| `POST` | `/api/saga/advance` |
| `POST` | `/api/saga/compensate` |
| `POST` | `/api/saga/cancel` |
| `GET` | `/api/saga` |

D1: `d1-saga-migration.sql`

---

## Verifiable work settlement

Claim → lock → attest → settle (or refund). Self-attest blocked; distinct attestors required.

| Method | Path |
| --- | --- |
| `POST` | `/api/work/claim` |
| `POST` | `/api/work/lock` |
| `POST` | `/api/work/attest` |
| `POST` | `/api/work/settle` |
| `POST` | `/api/work/refund` |
| `GET` | `/api/work` |

D1: `d1-work-migration.sql`, optional `d1-work-attest-diversity.sql`

---

## Continuity (heartbeat / dead-agent recovery)

| Method | Path |
| --- | --- |
| `POST` | `/api/continuity/open` |
| `POST` | `/api/continuity/beat` |
| `POST` | `/api/continuity/close` |
| `POST` | `/api/continuity/recover` |
| `GET` | `/api/continuity` |
| `GET` | `/api/continuity/:id` |

Recovery actions: `refund` | `successor` | `slash_refund`. Cron expires missed deadlines.

D1: `d1-continuity-migration.sql`

---

## Collaborative pools (swarm co-funding)

| Method | Path |
| --- | --- |
| `POST` | `/api/pool/open` |
| `POST` | `/api/pool/contribute` |
| `POST` | `/api/pool/release` |
| `POST` | `/api/pool/refund` |
| `GET` | `/api/pool` |
| `GET` | `/api/pool/:id` |

Cron expires open pools and refunds held contributions.

D1: `d1-pool-migration.sql`

---

## Spend Intent Capsules

Time-boxed, amount-capped pre-auth envelopes.

| Method | Path |
| --- | --- |
| `POST` | `/api/intent/create` |
| `POST` | `/api/intent/spend` |
| `POST` | `/api/intent/cancel` |
| `GET` | `/api/intent` |
| `GET` | `/api/intent/:id` |

D1: `d1-intent-migration.sql`

---

## Admin

| Method | Path | Auth |
| --- | --- | --- |
| `POST` | `/api/admin/sandbox-cleanup` | `ADMIN_CLEANUP_SECRET` / `X-Admin-Cleanup-Key` |
| `POST` | `/api/admin/shield` | same |

Sandbox cleanup wipes ledger-style data (rate-limited). Confirm body + secret required.

---

## Cron (`scheduled()`)

- Expire held escrows (+ `escrow.expired` webhooks)
- Prune velocity / telemetry
- Expire sub-wallets
- Expire continuity sessions (miss → recover)
- Expire collaborative pools
- Expire intent capsules
- Related expiry batches for tickets, bonds, sagas, work (as configured)

---

## Errors

| Status | Meaning |
| --- | --- |
| `400` | Bad `owner/repo`, amount, or body |
| `401` | Sign-in or API key required |
| `402` | Insufficient funds / credit |
| `403` | Wallet locked, policy deny, shield quarantine, key edge mismatch |
| `404` | Unknown path or resource |
| `409` | Race on claim/release |
| `429` | Rate limit or daily budget / velocity |
| `500` | Ledger / migration missing |
| `503` | Global shield freeze / emergency |

Common `code` values: `insufficient`, `insufficient_credit`, `wallet_locked`, `key_edge_mismatch`, `shield_quarantine`, `shield_freeze`, `velocity_tx`, `daily_budget`, `policy_denied`.

---

## CORS

Allowlist includes:

- `https://edgerail.pages.dev`
- `https://newhorizons-beyondhorizon.pages.dev`
- `https://agentpay.pages.dev`
- Worker origin

Server-side agents do not need CORS.

---

## Stack

| Piece | Detail |
| --- | --- |
| Worker | Vanilla JS (`worker.js`) |
| Ledger | Cloudflare D1 |
| Deploy | GitHub → Cloudflare Workers Builds (`wrangler.toml`) |
| Dashboard | Static HTML (Pages) |
| Lab | Sandbox HTML with anycast edge map (Leaflet + free tiles) |

### Required / optional secrets

| Env | Use |
| --- | --- |
| `DB` | D1 binding |
| OAuth client IDs/secrets | Google / GitHub / GitLab |
| `RECEIPT_SECRET` | Receipt HMAC |
| `ADMIN_CLEANUP_SECRET` | Admin cleanup + admin shield |

### D1 migrations (apply as needed)

```text
d1-stream-migration.sql
d1-subwallet-migration.sql
d1-receipts-migration.sql
d1-policy-migration.sql
d1-netting-migration.sql
d1-tickets-migration.sql
d1-bonds-migration.sql
d1-saga-migration.sql
d1-credit-migration.sql
d1-commit-migration.sql
d1-clearing-migration.sql
d1-work-migration.sql
d1-work-attest-diversity.sql
d1-continuity-migration.sql
d1-pool-migration.sql
d1-shield-migration.sql
d1-intent-migration.sql
d1-colo-migration.sql
```

Plus base schema for `users`, `sessions`, `accounts`, `transactions`, `api_keys`, `rate_limits`, escrow tables, and related tables.

---

## Dashboard features

- Home, My agent, Ledger
- Pay, Faucet, Escrow, Stream, Sub-wallets, Intents, Balance
- Safety, Continuity, Policy, Credit, API keys, Webhooks
- Work, Pools, Commit, Clearing, Netting, Bonds, Tickets, Sagas
- **Colo edge** — live colo probe, bind mode segment control, Leaflet map (free tiles, no map API key)
- Edge Shield status / release

## Lab features

- Squad bots, fund / pay / escrow / pool / work / continuity scenarios
- Chaos Monkey (kill mid-work, network fault, escrow kill) with compensating refunds
- Anycast edge heatmap (markers appear on live traffic)
- HMAC bank vault receipt viewer
- Intent capsule, colo bind, and shield proof runners

---

## Design principles

1. **Agents are repos** — identity is `owner/repo`, not a blockchain address.
2. **Edge-first** — colo-aware binding, shield, and low-latency settle on Workers.
3. **Idempotent money** — keys prevent double-spend under retries.
4. **Compensating paths** — escrow refund, work refund, chaos intercept, pool expire.
5. **Observable** — receipts, traces, webhooks, safety/shield events, ledger.

---

## Ops notes

Demo faucet is for sandbox only. Production should disable or tightly gate `/api/fund`, rotate `RECEIPT_SECRET` / admin secrets, and restrict CORS to your real frontends.
