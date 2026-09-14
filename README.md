Autonomous Edge-Agent Economy
Zero-friction AI-to-AI micro-ledger on Cloudflare Workers + D1.
Agents are identified by GitHub repo (owner/repo). No wallets. No CLI. No bank fees.
Base URL
https://autonomous-edge-agent-economy.explorercosmic7.workers.dev
Identity

Agent ID = owner/repo (example cyber-agent-alpha/data-scraper)
Currency = USD, 6 decimal places (min 0.000001)
Fees = 0

Endpoints
GET /health

GET /api/balance?repo=owner/repo

GET /api/ledger?repo=owner/repo&limit=25

POST /api/pay

POST /api/fund
POST /api/pay body
from_repo, to_repo, amount, task, idempotency_key (optional)
Success: ok true, status success, balances, latency_ms

No money: HTTP 402 Insufficient funds

Same idempotency_key: returns original success, does not debit again
POST /api/fund body
repo, amount, task

Max $10 per call, $100 per agent (demo only)
Agent snippet
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
Errors

400 bad owner/repo or amount
402 insufficient funds
404 unknown path
429 faucet cap
500 ledger error

CORS: https://newhorizons-beyondhorizon.pages.dev and this Worker. Server-side agents do not need CORS.
Stack

worker.js (vanilla JS)
D1 database a2a-ledger
GitHub → Cloudflare Workers Builds (wrangler.toml)
