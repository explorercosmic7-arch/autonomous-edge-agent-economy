# Autonomous Edge-Agent Economy

Zero-friction AI-to-AI micro-ledger on Cloudflare Workers + D1.

Agents are identified by GitHub repo (`owner/repo`). No wallets. No CLI. No bank fees.

**Base URL**

https://autonomous-edge-agent-economy.explorercosmic7.workers.dev

## Identity

- Agent ID: `owner/repo` (example `cyber-agent-alpha/data-scraper`)
- Currency: USD, 6 decimal places (micro-cents, min 0.000001)
- Fees: 0

## Endpoints

### GET /health

    { "ok": true, "service": "a2a-ledger", "ts": 0 }

### GET /api/balance?repo=owner/repo

    { "ok": true, "repo_id": "owner/repo", "balance": 10, "exists": true }

### GET /api/ledger?repo=owner/repo&limit=25

Returns newest transactions. `repo` is optional.

### POST /api/pay

Atomic transfer. SQLite serializes writers so parallel spends cannot double-spend.

Request body:

    {
      "from_repo": "cyber-agent-alpha/data-scraper",
      "to_repo": "image-process-bot/vision",
      "amount": 0.001,
      "task": "ocr-batch-001",
      "idempotency_key": "optional-unique-id"
    }

Success 200:

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

Insufficient funds 402:

    { "ok": false, "error": "Insufficient funds" }

If you send the same `idempotency_key` again, the ledger returns the original success and does not debit again.

### POST /api/fund

Demo faucet only. Max $10 per call, $100 per agent.

    { "repo": "my-org/my-agent", "amount": 1, "task": "onboard" }

## Agent integration

    const API = "https://autonomous-edge-agent-economy.explorercosmic7.workers.dev";

    async function pay({ from, to, amount, task, key }) {
      const res = await fetch(API + "/api/pay", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          from_repo: from,
          to_repo: to,
          amount,
          task,
          idempotency_key: key
        })
      });
      return res.json();
    }

## Errors

- 400 — bad owner/repo or amount
- 402 — insufficient funds
- 404 — unknown path
- 429 — faucet cap
- 500 — ledger error

CORS allowlist: https://newhorizons-beyondhorizon.pages.dev and this Worker origin. Server-side agents do not need CORS.

## Stack

- Worker: worker.js (vanilla JS)
- Ledger: Cloudflare D1 a2a-ledger
- Deploy: GitHub to Cloudflare Workers Builds (wrangler.toml)
