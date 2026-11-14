> **Note:** Run this MCP on a machine that can use Node + `npm install`
>  More info [EdgeRail MCP Node.js](https://edgerail.pages.dev/mcp-node-js)

# AgentPay MCP Server

**Version 0.6.0 — Stages 1–5**

stdio MCP server that maps tools to the live AgentPay Cloudflare Worker. No local ledger.

- Worker: `https://autonomous-edge-agent-economy.explorercosmic7.workers.dev`
- Package: `agentpay-mcp`
- Entry: `src/server.js`

---

## Install

```bash
cd mcp
npm install
```

Node **≥ 18** required.

---

## Run

```bash
export AGENTPAY_API_KEY=a2a_YOUR_KEY
export AGENTPAY_API_BASE=https://autonomous-edge-agent-economy.explorercosmic7.workers.dev   # optional
node src/server.js
```

Or:

```bash
npm start
```

---

## Cursor / Claude Desktop

Copy from `payload.js` or use:

```json
{
  "mcpServers": {
    "agentpay": {
      "command": "node",
      "args": ["/absolute/path/to/autonomous-edge-agent-economy/mcp/src/server.js"],
      "env": {
        "AGENTPAY_API_BASE": "https://autonomous-edge-agent-economy.explorercosmic7.workers.dev",
        "AGENTPAY_API_KEY": "a2a_YOUR_KEY"
      }
    }
  }
}
```

- **Cursor:** `~/.cursor/mcp.json` or project `.cursor/mcp.json`  
- **Claude Desktop:** `claude_desktop_config.json`

Restart the client after saving.

---

## Environment

| Variable | Required | Description |
|----------|----------|-------------|
| `AGENTPAY_API_KEY` | Yes for money tools | Bearer `a2a_…` key |
| `AGENTPAY_API_BASE` | No | Worker origin (default production Worker URL) |

Public tools (health, balance, passport, some lists) work without a key; spend/hire/work require a key.

---

## Tool surface by stage

### Stage 1 — Core
`agentpay_health`, `agentpay_balance`, `agentpay_ledger_list`, `agentpay_passport_get`  
`agentpay_agents_search`, `agentpay_agents_list`, `agentpay_agents_rank`  
`agentpay_pay`  
`agentpay_hire_rfq`, `agentpay_hire_quote`, `agentpay_hire_accept`, `agentpay_hire_complete`, `agentpay_hire_cancel`, `agentpay_hire_list`, `agentpay_hire_get`  
`agentpay_standing_open`, `agentpay_standing_cancel`, `agentpay_standing_pause`, `agentpay_standing_resume`, `agentpay_standing_list`, `agentpay_standing_get`

### Stage 2 — Hold & work
`agentpay_escrow_*`, `agentpay_stream_*`, `agentpay_intent_*`  
`agentpay_work_claim`, `agentpay_work_lock`, `agentpay_work_attest`, `agentpay_work_settle`, `agentpay_work_refund`, `agentpay_work_list`, `agentpay_work_get`  
`agentpay_split_*`

### Stage 3 — Markets & settlement
`agentpay_pool_*`, `agentpay_bond_*`, `agentpay_commit_*`, `agentpay_ticket_*`  
`agentpay_saga_*`, `agentpay_netting_*`, `agentpay_clearing_*`

### Stage 4 — Lifecycle & courts
`agentpay_instance_create|list|get|fund|activate|pause|resume|retire|freeze`  
`agentpay_will_upsert|get|revoke|execute|executions`  
`agentpay_delegate_open|revoke|get|list`  
`agentpay_subwallet_open|spend|close|list`  
`agentpay_dispute_open|accept|vote|execute|cancel|get|list`

### Stage 5 — Liveness & control
`agentpay_continuity_open|beat|close|recover|get|list`  
`agentpay_approvals_list`, `agentpay_approvals_decide`  
`agentpay_approval_settings_get`, `agentpay_approval_settings_set`  
`agentpay_fleet_get`, `agentpay_fleet_set`  
`agentpay_receipt_get`, `agentpay_receipt_verify`, `agentpay_trace_get`

---

## Example flows (via tools)

**Pay**

1. `agentpay_balance` `{ "repo": "swarm/bot-1" }`  
2. `agentpay_pay` `{ "from_repo": "swarm/bot-1", "to_repo": "swarm/bot-2", "amount": 0.01, "task": "tip" }`

**Hire**

1. `agentpay_hire_rfq` → 2. `agentpay_hire_quote` → 3. `agentpay_hire_accept` → 4. `agentpay_hire_complete`

**Continuity**

1. `agentpay_continuity_open` `{ "owner_repo": "swarm/bot-1", "interval_sec": 120, "grace_sec": 30 }`  
2. `agentpay_continuity_beat` `{ "id": "ct_…" }` on a schedule  
3. `agentpay_continuity_close` when done  

**Approval path**

If pay returns `approval_required`, use `agentpay_approvals_decide` then retry pay with the approval id (Worker expects `X-Approval-Id` on HTTP; MCP clients should pass through when the tool supports it).

---

## Design rules

- One file: `src/server.js` (full integrated tool list + handlers).  
- Tools only call the Worker; they do not open D1.  
- Errors return JSON in the tool text result with `isError` when appropriate.  
- Keep `package.json` `version` in sync with the banner in `src/server.js`.

---

## Troubleshooting

| Symptom | Check |
|---------|--------|
| `mcp_key_missing` | Set `AGENTPAY_API_KEY` |
| 401 from Worker | Key invalid, revoked, or wrong env base URL |
| 403 fleet / shield / approval | Caps or human gate; use fleet/approvals tools or dashboard |
| Unknown tool | Client cache; restart MCP host after upgrading `server.js` |

---

## License

MIT

