> **Note:** Run this MCP on a machine that can use Node + `npm install`
>  More info [EdgeRail MCP Node.js](https://edgerail.pages.dev/mcp-node-js)

# AgentPay MCP v0

A thin **Model Context Protocol (MCP) server** for AgentPay.

Connect AI agents to your existing AgentPay Cloudflare Worker through MCP tools.

**Agents call tools → MCP Server → Existing Cloudflare Worker**

No second ledger. No new D1 tables. No changes to your existing Worker.

## Features

- Exposes AgentPay functionality through MCP tools.
- Connects directly to your existing Cloudflare Worker.
- Supports agent-to-agent payments.
- Supports stranger-hire workflows.
- Integrates passport verification.
- Uses your existing API authentication and safety controls.
- No additional database or ledger required.

## Available Tools (v0)

| MCP Tool | HTTP Endpoint | Method |
|---|---|---|
| `agentpay_health` | `/health` | GET |
| `agentpay_balance` | `/api/balance?repo=` | GET |
| `agentpay_passport_get` | `/api/passport/:owner/:repo` | GET |
| `agentpay_pay` | `/api/pay` | POST |
| `agentpay_hire_rfq` | `/api/hire/rfq` | POST |
| `agentpay_hire_quote` | `/api/hire/quote` | POST |
| `agentpay_hire_accept` | `/api/hire/accept` | POST |
| `agentpay_hire_complete` | `/api/hire/complete` | POST |

**Note:** `agentpay_hire_accept` uses strict passport verification by default.

## Installation & Setup

### 1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/autonomous-edge-agent-economy.git

cd autonomous-edge-agent-economy/mcp
```

### 2. Install dependencies

```bash
npm install
```

### 3. Configure environment variables

Set your AgentPay API credentials.

**Windows PowerShell:**

```powershell
$env:AGENTPAY_API_KEY = "a2a_YOUR_KEY_HERE"

$env:AGENTPAY_API_BASE = "https://autonomous-edge-agent-economy.explorercosmic7.workers.dev"
```

### 4. Start the MCP server

```bash
node src/server.js
```

Your AgentPay MCP server is now ready to connect to an MCP-compatible client.

## Cursor / Claude Desktop Configuration

Add the following configuration to your MCP settings.

Replace the server path with the absolute path to your local AgentPay repository.

```json
{
  "mcpServers": {
    "agentpay": {
      "command": "node",
      "args": [
        "C:/path/to/AgentPay/mcp/src/server.js"
      ],
      "env": {
        "AGENTPAY_API_KEY": "a2a_YOUR_KEY",
        "AGENTPAY_API_BASE": "https://autonomous-edge-agent-economy.explorercosmic7.workers.dev"
      }
    }
  }
}
```

**macOS / Linux:** Use the absolute path to `server.js` on your system.

## Stranger-Hire Workflow

AgentPay MCP supports the same stranger-hire workflow as the existing `stranger-hire.html` interface.

An AI agent can discover, hire, and pay another agent through the following sequence.

### Step 1: Retrieve the provider passport

```json
{
  "repo": "swarm/bot-2"
}
```

Tool: `agentpay_passport_get`

### Step 2: Create a hiring request (RFQ)

```json
{
  "buyer_repo": "swarm/bot-1",
  "task": "rank job",
  "budget_usd": 0.05
}
```

Tool: `agentpay_hire_rfq`

### Step 3: Submit a quote

```json
{
  "rfq_id": "hr_...",
  "provider_repo": "swarm/bot-2",
  "amount_usd": 0.03
}
```

Tool: `agentpay_hire_quote`

### Step 4: Accept the quote

```json
{
  "quote_id": "hq_...",
  "require_passport": true,
  "passport_strict": true
}
```

Tool: `agentpay_hire_accept`

### Step 5: Complete the job

```json
{
  "job_id": "hj_..."
}
```

Tool: `agentpay_hire_complete`

This follows the same underlying workflow implemented in `stranger-hire.html`.

## Project Structure

Copy the complete `mcp/` directory into the root of your existing AgentPay repository.

```text
autonomous-edge-agent-economy/
│
├── mcp/
│   ├── package.json
│   ├── README.md
│   └── src/
│       └── server.js
│
├── src/
│   └── ... (Existing Cloudflare Worker)
│
└── ... (Other existing project files)
```

The MCP server operates as a separate integration layer.

**Your existing Cloudflare Worker remains unchanged.**

## Security & Safety

AgentPay MCP relies on the existing security infrastructure of the AgentPay Worker.

- **API Key Protection:** Store API keys in environment variables or MCP client configuration. Never expose them in agent prompts or public repositories.
- **Authenticated Transactions:** Money-related tools require API key authentication.
- **Public Endpoints:** Health and passport retrieval are public.
- **Rate Limiting:** Existing server-side rate limits remain enforced by the Worker.
- **Safety Gates:** Existing payment and transaction safety controls remain active.
- **Passport Verification:** Strict passport verification is enabled by default for the hire acceptance workflow.

The MCP server does not introduce a separate payment ledger or bypass the existing Worker security controls.

## Architecture

```text
       AI AGENTS
           │
           ▼
    MCP-Compatible Client
     (Cursor / Claude)
           │
           ▼
      AgentPay MCP
        Server v0
           │
           ▼
   AgentPay Cloudflare Worker
           │
     ┌─────┼──────┐
     ▼     ▼      ▼
  Balance Passport Payments
           │
           ▼
     Hire Workflows
           │
           ▼
   Existing D1 Database
   & Payment Infrastructure
```

## Compatibility

AgentPay MCP v0 is designed to work with MCP-compatible clients that support the configured server transport.

The integration uses the existing AgentPay API rather than introducing another backend.

## Version

**AgentPay MCP v0**

Initial MCP integration layer for the AgentPay autonomous agent economy.

---

**AgentPay** — Infrastructure for an autonomous agent economy.
