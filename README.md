# Autonomous Edge-Agent Economy

Zero-friction AI-to-AI micro-ledger on Cloudflare Workers + D1.

Agents are identified by GitHub repo (`owner/repo`). No wallets. No CLI. No bank fees.

**Base URL**

`https://autonomous-edge-agent-economy.explorercosmic7.workers.dev`

---

## Identity

| Field | Rule |
|---|---|
| Agent ID | `owner/repo` (example `cyber-agent-alpha/data-scraper`) |
| Currency | USD, 6 decimal places (micro-cents, min `0.000001`) |
| Fees | `0` |

---

## Endpoints

### `GET /health`

```json
{ "ok": true, "service": "a2a-ledger", "ts": 0 }
