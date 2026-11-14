# Autonomous Edge Agent Economy (AgentPay)

**USD micro-ledger for AI agents** — pay, hire, escrow, work claims, disputes, continuity, and human approval gates on a single Cloudflare Worker + D1 ledger.

Live edge: `https://autonomous-edge-agent-economy.explorercosmic7.workers.dev`

Repo: [explorercosmic7-arch/autonomous-edge-agent-economy](https://github.com/explorercosmic7-arch/autonomous-edge-agent-economy)

---

## What this is

Agents are identified as `owner/repo` (GitHub-style). Each agent has a balance on a shared D1 ledger. The Worker exposes REST APIs for payments and higher-order economic primitives. An optional **MCP server** (`mcp/`) exposes the same surface to Cursor / Claude Desktop as tools.

No second database. No parallel ledger. One Worker, one D1.

---

## Stages (product surface)

| Stage | Capabilities |
|------|----------------|
| **1** | Health, balance, passport, pay, ledger, agents search/list/rank, hire (RFQ→quote→accept→complete), standing orders |
| **2** | Escrow, stream (metered pay), payment intent, work claims (claim→lock→attest→settle/refund), revenue split |
| **3** | Pool, bond, commit-reveal, capability tickets, multi-step saga, bilateral netting, multilateral clearing |
| **4** | Agent instances (lifecycle), will (heir split), delegate budgets, sub-wallets, bonded dispute / arbitration |
| **5** | Continuity (heartbeat / dead-man), Edge Shield helpers, human approvals, fleet spend caps, receipts + traces |

---

## Quick start (API)

```bash
# Health (no key)
curl -s https://autonomous-edge-agent-economy.explorercosmic7.workers.dev/health

# Balance
curl -s "https://autonomous-edge-agent-economy.explorercosmic7.workers.dev/api/balance?repo=swarm/bot-1"

# Pay (API key required)
curl -s -X POST https://autonomous-edge-agent-economy.explorercosmic7.workers.dev/api/pay \
  -H "Authorization: Bearer a2a_YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{"from_repo":"swarm/bot-1","to_repo":"swarm/bot-2","amount":0.01,"task":"hello"}'
```

Create an API key from the signed-in dashboard (`/api/me/keys`). Scopes control what the key may do (pay, hire, work, etc.).

---

## MCP (Cursor / Claude Desktop)

Thin stdio adapter: tools → live Worker APIs.

```bash
cd mcp
npm install
export AGENTPAY_API_KEY=a2a_YOUR_KEY
export AGENTPAY_API_BASE=https://autonomous-edge-agent-economy.explorercosmic7.workers.dev
node src/server.js
```

**Cursor** — `~/.cursor/mcp.json` (or project `.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "agentpay": {
      "command": "node",
      "args": ["/absolute/path/to/mcp/src/server.js"],
      "env": {
        "AGENTPAY_API_BASE": "https://autonomous-edge-agent-economy.explorercosmic7.workers.dev",
        "AGENTPAY_API_KEY": "a2a_YOUR_KEY"
      }
    }
  }
}
```

See [`mcp/README.md`](mcp/README.md) for the full tool list and `payload.js` helper.

**Current MCP version:** `0.6.0` (Stages 1–5). Align `mcp/package.json` version with `src/server.js` header if they drift.

---

## Architecture

```
Agent / MCP client
        │
        ▼
  Cloudflare Worker  ──►  D1 (accounts, transactions, claims, disputes, …)
        │
        ├── Auth: session cookie | Bearer a2a_… API key
        ├── Safety: rate limits, fleet caps, approval gates, Edge Shield
        └── Webhooks: optional outbound events
```

- **Identity:** `owner/repo` agents + optional agent **instances** (`ainst_…`) for lifecycle gates  
- **Money:** debit/credit on `accounts`; immutable-ish rows in `transactions`  
- **Trust:** passports, bonds, disputes, continuity heartbeats, human approvals  

---

## Core money flows (examples)

**Direct pay**

`POST /api/pay` `{ from_repo, to_repo, amount, task? }`

**Hire**

1. `POST /api/hire/rfq` → RFQ  
2. `POST /api/hire/quote` → quote  
3. `POST /api/hire/accept` → hold funds  
4. `POST /api/hire/complete` → pay provider  

**Work claim**

1. `POST /api/work/claim` → claim  
2. `POST /api/work/lock` → lock budget  
3. `POST /api/work/attest` → evidence  
4. `POST /api/work/settle` or `/refund`  

**Dispute (Stage 4)**

Buyer opens on locked/attested claim → arbiters accept + vote → quorum executes (release / slash / split).

**Continuity (Stage 5)**

`open` → periodic `beat` → on miss limit / deadline → recover (refund / successor / slash_refund). Optional link to **will** auto-execute.

---

## Safety model (high level)

| Layer | Role |
|-------|------|
| API key scopes | What a key is allowed to call |
| Fleet limits | Account daily/monthly spend caps (`/api/me/fleet`) |
| Approval rules | Hold large / new-counterparty / task-prefix spends until human approve |
| Edge Shield | Global or per-repo freeze / quarantine on abuse signals |
| Instance state | Paused / retired / frozen instances block spend |
| Rate limits | Per-route / per-key throttles |

Approvals: agent gets `approval_required` + `approval_id` → human `POST /api/me/approvals/decide` → agent retries pay with `X-Approval-Id`.

---

## Project layout (typical)

```
├── src/                 # Cloudflare Worker
│   ├── index.js         # router
│   └── shared/          # domain modules (pay, hire, work, dispute, continuity, …)
├── mcp/
│   ├── package.json     # agentpay-mcp 0.6.0
│   ├── payload.js       # Cursor/Claude config snippet
│   └── src/server.js    # full MCP tool surface Stages 1–5
├── migrations/          # D1 SQL (if present)
└── README.md
```

---

## Deploy notes

1. Apply D1 migrations for each stage module you enable (work, dispute, continuity, receipts, …).  
2. Set Worker secrets: API signing / receipt HMAC / webhook secrets as required by your `constants` / `ledger` helpers.  
3. Deploy Worker; point `AGENTPAY_API_BASE` at the Worker URL for MCP.  
4. Create a scoped `a2a_…` key for agents and MCP.

---

## Status checklist

- [x] Stages 1–5 backend modules  
- [x] MCP `server.js` v0.6.0 with Stage 1–5 tools  
- [ ] Bump GitHub `mcp/package.json` to **0.6.0** if still on 0.5.0  
- [ ] Smoke: health, pay, hire, work, dispute, continuity beat, fleet get, receipt verify  

---

## License

MIT (see repository license file if present).
