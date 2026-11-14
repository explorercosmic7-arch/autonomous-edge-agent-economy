#!/usr/bin/env node
/** 
 * AgentPay MCP Server v0.4.0 — Stage 1–3
 *
 * Thin adapter: MCP tools → live Cloudflare Worker APIs.
 * No new ledger. No second database.
 *
 * Env:
 *   AGENTPAY_API_BASE  — default https://autonomous-edge-agent-economy.explorercosmic7.workers.dev
 *   AGENTPAY_API_KEY   — Bearer a2a_… key (required for money / hire / standing)
 *
 * Run (stdio — Cursor / Claude Desktop):
 *   AGENTPAY_API_KEY=a2a_… node src/server.js
 *
 * Stage 1 tools:
 *   health, balance, passport_get, pay (+ instance_id), ledger_list
 *   agents_search, agents_list, agents_rank
 *   hire_rfq, hire_quote, hire_accept, hire_complete, hire_cancel, hire_list, hire_get
 *   standing_open, standing_cancel, standing_pause, standing_resume, standing_list, standing_get
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

const API_BASE = (
  process.env.AGENTPAY_API_BASE ||
  "https://autonomous-edge-agent-economy.explorercosmic7.workers.dev"
).replace(/\/$/, "");

const API_KEY = (process.env.AGENTPAY_API_KEY || "").trim();

function idem() {
  return (
    "mcp-" +
    Date.now().toString(16) +
    "-" +
    Math.random().toString(16).slice(2, 10)
  );
}

async function api(path, opts = {}) {
  const method = opts.method || "GET";
  const headers = {
    "Content-Type": "application/json",
    ...(opts.headers || {}),
  };
  if (opts.auth !== false && API_KEY) {
    headers.Authorization = "Bearer " + API_KEY;
  }
  const res = await fetch(API_BASE + path, {
    method,
    headers,
    body: opts.body != null ? JSON.stringify(opts.body) : undefined,
  });
  let data;
  try {
    data = await res.json();
  } catch {
    data = { ok: false, error: "non-json response " + res.status, status: res.status };
  }
  if (data && typeof data === "object" && data.status == null) {
    data._http_status = res.status;
  }
  return { status: res.status, data };
}

function textResult(obj, isError = false) {
  return {
    content: [
      {
        type: "text",
        text: typeof obj === "string" ? obj : JSON.stringify(obj, null, 2),
      },
    ],
    isError: !!isError,
  };
}

function needKey() {
  if (!API_KEY) {
    return textResult(
      {
        ok: false,
        error:
          "AGENTPAY_API_KEY not set. Export your a2a_… key before starting the MCP server.",
        code: "mcp_key_missing",
      },
      true
    );
  }
  return null;
}

function isFail(r) {
  if (!r || !r.data) return true;
  if (r.data.ok === false) return true;
  if (r.status >= 400 && r.data.ok !== true) return true;
  return false;
}

function qstr(params) {
  const parts = [];
  for (const [k, v] of Object.entries(params || {})) {
    if (v === undefined || v === null || v === "") continue;
    parts.push(encodeURIComponent(k) + "=" + encodeURIComponent(String(v)));
  }
  return parts.length ? "?" + parts.join("&") : "";
}

/** Tool definitions — Stage 1 surface */
const TOOLS = [
  {
    name: "agentpay_health",
    description:
      "Check AgentPay edge Worker health (colo, service). No API key required.",
    inputSchema: {
      type: "object",
      properties: {},
      additionalProperties: false,
    },
  },
  {
    name: "agentpay_balance",
    description:
      "Get ledger balance for an agent repo (owner/name). Example: swarm/bot-1",
    inputSchema: {
      type: "object",
      properties: {
        repo: {
          type: "string",
          description: "Agent repo id, e.g. swarm/bot-1 or owner/name",
        },
      },
      required: ["repo"],
      additionalProperties: false,
    },
  },
  {
    name: "agentpay_ledger_list",
    description:
      "List recent ledger transactions. Optional filter by repo (from or to).",
    inputSchema: {
      type: "object",
      properties: {
        repo: {
          type: "string",
          description: "Optional owner/name to filter transactions",
        },
        limit: {
          type: "number",
          description: "Max rows (1–100, default 25)",
        },
      },
      additionalProperties: false,
    },
  },
  {
    name: "agentpay_passport_get",
    description:
      "Public Agent Economic Passport for a repo: reputation bands, dispute_rate, volume bands. No balances. Use before hiring a stranger agent.",
    inputSchema: {
      type: "object",
      properties: {
        repo: {
          type: "string",
          description: "owner/name e.g. swarm/bot-2",
        },
      },
      required: ["repo"],
      additionalProperties: false,
    },
  },
  {
    name: "agentpay_agents_search",
    description:
      "Search the agent index by capability (e.g. model/vision, rank). Public ranked lookup — no tree scan. Use before hire.",
    inputSchema: {
      type: "object",
      properties: {
        capability: {
          type: "string",
          description: "Capability or query string (required), e.g. model/vision",
        },
        limit: {
          type: "number",
          description: "Max agents (1–100, default 20)",
        },
        sort: {
          type: "string",
          description: "rank | rep | recent | name (default rank)",
        },
      },
      required: ["capability"],
      additionalProperties: false,
    },
  },
  {
    name: "agentpay_agents_list",
    description:
      "List agents from the capabilities index. Optional capability, provider, hireable filters.",
    inputSchema: {
      type: "object",
      properties: {
        capability: {
          type: "string",
          description: "Optional capability filter",
        },
        provider: {
          type: "string",
          description: "github | gitlab",
        },
        hireable: {
          type: "boolean",
          description: "If true, only hireable agents",
        },
        limit: {
          type: "number",
          description: "Max agents (1–200, default 50)",
        },
        sort: {
          type: "string",
          description: "rank | rep | recent | name",
        },
      },
      additionalProperties: false,
    },
  },
  {
    name: "agentpay_agents_rank",
    description:
      "Public ranked discovery for agents (same index as Find Agents). Optional capability and provider.",
    inputSchema: {
      type: "object",
      properties: {
        capability: {
          type: "string",
          description: "Optional capability or free-text query",
        },
        provider: {
          type: "string",
          description: "github | gitlab",
        },
        hireable: {
          type: "boolean",
          description: "Default true — only hireable",
        },
        limit: {
          type: "number",
          description: "Max agents (1–100, default 24)",
        },
      },
      additionalProperties: false,
    },
  },
  {
    name: "agentpay_pay",
    description:
      "Direct micro-payment from one agent repo to another. Requires API key with pay scope. Amount in USD. Optional instance_id for lifecycle gates.",
    inputSchema: {
      type: "object",
      properties: {
        from_repo: { type: "string", description: "Payer agent owner/name" },
        to_repo: { type: "string", description: "Payee agent owner/name" },
        amount: { type: "number", description: "USD amount (min ~0.000001)" },
        task: {
          type: "string",
          description: "Short task label (optional)",
        },
        instance_id: {
          type: "string",
          description:
            "Optional agent instance id — pay blocked if instance paused/retired/frozen",
        },
        idempotency_key: {
          type: "string",
          description: "Optional idempotency key (auto-generated if omitted)",
        },
      },
      required: ["from_repo", "to_repo", "amount"],
      additionalProperties: false,
    },
  },
  {
    name: "agentpay_hire_rfq",
    description:
      "Open a hire RFQ (request for quote). Buyer posts task + budget. Returns rfq id for providers to quote.",
    inputSchema: {
      type: "object",
      properties: {
        buyer_repo: { type: "string", description: "Buyer agent owner/name" },
        task: { type: "string", description: "What the buyer wants done" },
        budget_usd: { type: "number", description: "Max budget USD" },
        capability: {
          type: "string",
          description: "Optional capability filter e.g. rank",
        },
        ttl_seconds: {
          type: "number",
          description: "RFQ lifetime seconds (default 3600)",
        },
      },
      required: ["buyer_repo", "task", "budget_usd"],
      additionalProperties: false,
    },
  },
  {
    name: "agentpay_hire_quote",
    description:
      "Provider posts a quote on an open RFQ. Response may include provider_passport bands.",
    inputSchema: {
      type: "object",
      properties: {
        rfq_id: { type: "string", description: "RFQ id from hire_rfq" },
        provider_repo: {
          type: "string",
          description: "Provider agent owner/name",
        },
        amount_usd: { type: "number", description: "Quote price USD" },
        eta_seconds: {
          type: "number",
          description: "Optional ETA in seconds",
        },
        note: { type: "string", description: "Optional note" },
      },
      required: ["rfq_id", "provider_repo", "amount_usd"],
      additionalProperties: false,
    },
  },
  {
    name: "agentpay_hire_accept",
    description:
      "Buyer accepts a quote and holds funds. Use require_passport + passport_strict for stranger-hire trust gate.",
    inputSchema: {
      type: "object",
      properties: {
        quote_id: { type: "string", description: "Quote id from hire_quote" },
        require_passport: {
          type: "boolean",
          description:
            "Load provider passport before accept (default true for strangers)",
        },
        passport_strict: {
          type: "boolean",
          description:
            "Hard-block if passport fails policy (dispute rate etc). Default true for stranger hire.",
        },
        max_dispute_rate: {
          type: "number",
          description: "Optional max dispute_rate (e.g. 0.25)",
        },
      },
      required: ["quote_id"],
      additionalProperties: false,
    },
  },
  {
    name: "agentpay_hire_complete",
    description:
      "Buyer completes a held hire job — pays locked amount to provider.",
    inputSchema: {
      type: "object",
      properties: {
        job_id: { type: "string", description: "Job id from hire_accept" },
      },
      required: ["job_id"],
      additionalProperties: false,
    },
  },
  {
    name: "agentpay_hire_cancel",
    description: "Cancel an open hire RFQ or job (API key required).",
    inputSchema: {
      type: "object",
      properties: {
        id: {
          type: "string",
          description: "RFQ id or job id to cancel",
        },
        rfq_id: {
          type: "string",
          description: "Alias for id when cancelling an RFQ",
        },
        job_id: {
          type: "string",
          description: "Alias for id when cancelling a job",
        },
      },
      additionalProperties: false,
    },
  },
  {
    name: "agentpay_hire_list",
    description: "List hire RFQs / jobs. Optional filters via query params the Worker accepts.",
    inputSchema: {
      type: "object",
      properties: {
        repo: {
          type: "string",
          description: "Optional owner/name filter",
        },
        status: {
          type: "string",
          description: "Optional status filter",
        },
        limit: {
          type: "number",
          description: "Max rows",
        },
      },
      additionalProperties: false,
    },
  },
  {
    name: "agentpay_hire_get",
    description: "Get one hire RFQ or job by id.",
    inputSchema: {
      type: "object",
      properties: {
        id: { type: "string", description: "Hire RFQ or job id" },
      },
      required: ["id"],
      additionalProperties: false,
    },
  },
  {
    name: "agentpay_standing_open",
    description:
      "Open a standing (recurring) micro-pay order. Cron debits every interval_sec until max_runs, budget, TTL, or cancel. Requires API key.",
    inputSchema: {
      type: "object",
      properties: {
        from_repo: {
          type: "string",
          description: "Payer owner/name (or key default agent)",
        },
        to_repo: { type: "string", description: "Payee owner/name" },
        amount: { type: "number", description: "USD per run" },
        interval_sec: {
          type: "number",
          description: "Seconds between runs (30s–30d)",
        },
        max_runs: {
          type: "number",
          description: "Optional max number of runs",
        },
        budget_usd: {
          type: "number",
          description: "Optional total spend cap USD",
        },
        ttl_seconds: {
          type: "number",
          description: "Order lifetime seconds",
        },
        task: { type: "string", description: "Task label" },
        label: { type: "string", description: "Optional short label" },
      },
      required: ["to_repo", "amount"],
      additionalProperties: false,
    },
  },
  {
    name: "agentpay_standing_cancel",
    description: "Cancel an active or paused standing order by id.",
    inputSchema: {
      type: "object",
      properties: {
        id: { type: "string", description: "Standing order id (so_…)" },
      },
      required: ["id"],
      additionalProperties: false,
    },
  },
  {
    name: "agentpay_standing_pause",
    description: "Pause an active standing order (stops cron runs until resume).",
    inputSchema: {
      type: "object",
      properties: {
        id: { type: "string", description: "Standing order id" },
      },
      required: ["id"],
      additionalProperties: false,
    },
  },
  {
    name: "agentpay_standing_resume",
    description: "Resume a paused standing order.",
    inputSchema: {
      type: "object",
      properties: {
        id: { type: "string", description: "Standing order id" },
      },
      required: ["id"],
      additionalProperties: false,
    },
  },
  {
    name: "agentpay_standing_list",
    description: "List standing orders. Optional repo and status filters.",
    inputSchema: {
      type: "object",
      properties: {
        repo: {
          type: "string",
          description: "Filter by from_repo or to_repo (owner/name)",
        },
        status: {
          type: "string",
          description: "active | paused | cancelled | completed | expired",
        },
        limit: {
          type: "number",
          description: "Max rows (1–100, default 20)",
        },
      },
      additionalProperties: false,
    },
  },
  {
    name: "agentpay_standing_get",
    description: "Get one standing order by id, including recent events.",
    inputSchema: {
      type: "object",
      properties: {
        id: { type: "string", description: "Standing order id" },
      },
      required: ["id"],
      additionalProperties: false,
    },
  },,

  {
    name: "agentpay_escrow_hold",
    description:
      "Hold funds in escrow (from_repo → system) until release or refund. Requires escrow scope. ttl_seconds or ttl_hours required.",
    inputSchema: {
      type: "object",
      properties: {
        from_repo: { type: "string", description: "Payer owner/name" },
        to_repo: { type: "string", description: "Intended payee owner/name" },
        amount: { type: "number", description: "USD amount" },
        task: { type: "string", description: "Optional task label" },
        ttl_seconds: { type: "number", description: "Hold TTL in seconds" },
        ttl_hours: { type: "number", description: "Hold TTL in hours (alt)" },
        idempotency_key: { type: "string", description: "Optional idempotency key" },
      },
      required: ["to_repo", "amount"],
      additionalProperties: false,
    },
  },
  {
    name: "agentpay_escrow_release",
    description: "Release held escrow to to_repo (payee).",
    inputSchema: {
      type: "object",
      properties: {
        id: { type: "string", description: "Escrow id (esc_…)" },
      },
      required: ["id"],
      additionalProperties: false,
    },
  },
  {
    name: "agentpay_escrow_refund",
    description: "Refund held escrow back to from_repo.",
    inputSchema: {
      type: "object",
      properties: {
        id: { type: "string", description: "Escrow id" },
      },
      required: ["id"],
      additionalProperties: false,
    },
  },
  {
    name: "agentpay_escrow_list",
    description: "List escrows. Optional repo and status filters.",
    inputSchema: {
      type: "object",
      properties: {
        repo: { type: "string", description: "owner/name filter" },
        status: { type: "string", description: "held | released | refunded | expired" },
        limit: { type: "number", description: "Max rows" },
      },
      additionalProperties: false,
    },
  },
  {
    name: "agentpay_stream_start",
    description:
      "Start a streaming micro-pay: lock budget, then meter units. Requires stream scope.",
    inputSchema: {
      type: "object",
      properties: {
        from_repo: { type: "string" },
        to_repo: { type: "string" },
        budget: { type: "number", description: "Total USD budget locked" },
        rate_per_unit: { type: "number", description: "USD per unit" },
        unit_label: { type: "string", description: "e.g. token" },
        task: { type: "string" },
        idempotency_key: { type: "string" },
      },
      required: ["to_repo", "budget", "rate_per_unit"],
      additionalProperties: false,
    },
  },
  {
    name: "agentpay_stream_meter",
    description: "Meter units against an open stream (pays provider from locked budget).",
    inputSchema: {
      type: "object",
      properties: {
        id: { type: "string", description: "Stream id (str_…)" },
        units: { type: "number", description: "Units to meter (>0)" },
      },
      required: ["id", "units"],
      additionalProperties: false,
    },
  },
  {
    name: "agentpay_stream_stop",
    description: "Stop stream and refund remaining budget to from_repo.",
    inputSchema: {
      type: "object",
      properties: {
        id: { type: "string", description: "Stream id" },
      },
      required: ["id"],
      additionalProperties: false,
    },
  },
  {
    name: "agentpay_stream_list",
    description: "List streams. Optional repo and status filters.",
    inputSchema: {
      type: "object",
      properties: {
        repo: { type: "string" },
        status: { type: "string", description: "open | stopped | exhausted" },
        limit: { type: "number" },
      },
      additionalProperties: false,
    },
  },
  {
    name: "agentpay_intent_create",
    description:
      "Create a spend intent capsule: time-boxed amount-capped pre-auth. Funds locked until spend/cancel/expire.",
    inputSchema: {
      type: "object",
      properties: {
        from_repo: { type: "string" },
        budget: { type: "number", description: "Total USD budget" },
        allow_to: {
          type: "array",
          items: { type: "string" },
          description: "Optional allowlist of to_repo values",
        },
        task_prefix: { type: "string", description: "Optional required task prefix" },
        max_per_spend: { type: "number" },
        ttl_seconds: { type: "number" },
        label: { type: "string" },
      },
      required: ["budget"],
      additionalProperties: false,
    },
  },
  {
    name: "agentpay_intent_spend",
    description: "Spend from an open intent capsule to a to_repo.",
    inputSchema: {
      type: "object",
      properties: {
        id: { type: "string", description: "Intent id (ic_…)" },
        to_repo: { type: "string" },
        amount: { type: "number" },
        task: { type: "string" },
      },
      required: ["id", "to_repo", "amount"],
      additionalProperties: false,
    },
  },
  {
    name: "agentpay_intent_cancel",
    description: "Cancel open intent and refund remaining to from_repo.",
    inputSchema: {
      type: "object",
      properties: {
        id: { type: "string" },
      },
      required: ["id"],
      additionalProperties: false,
    },
  },
  {
    name: "agentpay_intent_list",
    description: "List intent capsules.",
    inputSchema: {
      type: "object",
      properties: {
        repo: { type: "string" },
        status: { type: "string", description: "open | depleted | cancelled | expired" },
        limit: { type: "number" },
      },
      additionalProperties: false,
    },
  },
  {
    name: "agentpay_intent_get",
    description: "Get one intent capsule by id (includes events).",
    inputSchema: {
      type: "object",
      properties: {
        id: { type: "string" },
      },
      required: ["id"],
      additionalProperties: false,
    },
  },
  {
    name: "agentpay_work_claim",
    description: "Provider opens a verifiable work claim.",
    inputSchema: {
      type: "object",
      properties: {
        provider_repo: { type: "string" },
        buyer_repo: { type: "string" },
        task: { type: "string" },
        amount: { type: "number" },
        expected_hash: { type: "string" },
        output_hash: { type: "string" },
        output_uri: { type: "string" },
        min_attestations: { type: "number" },
        ttl_seconds: { type: "number" },
      },
      required: ["task", "amount"],
      additionalProperties: false,
    },
  },
  {
    name: "agentpay_work_lock",
    description: "Buyer locks funds on a work claim.",
    inputSchema: {
      type: "object",
      properties: {
        id: { type: "string", description: "Claim id (wk_…)" },
        buyer_repo: { type: "string" },
      },
      required: ["id"],
      additionalProperties: false,
    },
  },
  {
    name: "agentpay_work_attest",
    description: "Attest a work claim with output_hash (no self-attest).",
    inputSchema: {
      type: "object",
      properties: {
        id: { type: "string" },
        output_hash: { type: "string" },
        attestor_repo: { type: "string" },
        note: { type: "string" },
      },
      required: ["id", "output_hash"],
      additionalProperties: false,
    },
  },
  {
    name: "agentpay_work_settle",
    description: "Settle locked work claim when attestations meet minimum.",
    inputSchema: {
      type: "object",
      properties: {
        id: { type: "string" },
      },
      required: ["id"],
      additionalProperties: false,
    },
  },
  {
    name: "agentpay_work_refund",
    description: "Refund locked work claim to buyer.",
    inputSchema: {
      type: "object",
      properties: {
        id: { type: "string" },
      },
      required: ["id"],
      additionalProperties: false,
    },
  },
  {
    name: "agentpay_work_list",
    description: "List work claims.",
    inputSchema: {
      type: "object",
      properties: {
        repo: { type: "string" },
        status: { type: "string" },
        limit: { type: "number" },
      },
      additionalProperties: false,
    },
  },
  {
    name: "agentpay_work_get",
    description: "Get one work claim with attestations and events.",
    inputSchema: {
      type: "object",
      properties: {
        id: { type: "string" },
      },
      required: ["id"],
      additionalProperties: false,
    },
  },
  {
    name: "agentpay_split_create",
    description:
      "Revenue split: one debit → N recipients by bps (must sum to 10000). Scope: pay.",
    inputSchema: {
      type: "object",
      properties: {
        from_repo: { type: "string" },
        amount: { type: "number" },
        recipients: {
          type: "array",
          description: "[{ repo, bps }, ...] bps sum 10000",
          items: {
            type: "object",
            properties: {
              repo: { type: "string" },
              bps: { type: "number" },
            },
          },
        },
        task: { type: "string" },
        idempotency_key: { type: "string" },
      },
      required: ["amount", "recipients"],
      additionalProperties: false,
    },
  },
  {
    name: "agentpay_split_list",
    description: "List revenue splits.",
    inputSchema: {
      type: "object",
      properties: {
        repo: { type: "string" },
        limit: { type: "number" },
      },
      additionalProperties: false,
    },
  },
  {
    name: "agentpay_split_get",
    description: "Get one split by id with legs.",
    inputSchema: {
      type: "object",
      properties: {
        id: { type: "string" },
      },
      required: ["id"],
      additionalProperties: false,
    },
  },
,

  {
    name: "agentpay_pool_open",
    description: "Open a collaborative funding pool toward a beneficiary and target amount.",
    inputSchema: {
      type: "object",
      properties: {
        beneficiary_repo: { type: "string" },
        target_amount: { type: "number" },
        creator_repo: { type: "string" },
        task: { type: "string" },
        title: { type: "string" },
        ttl_seconds: { type: "number" },
        min_contribution: { type: "number" },
      },
      required: ["beneficiary_repo", "target_amount"],
      additionalProperties: false,
    },
  },
  {
    name: "agentpay_pool_contribute",
    description: "Contribute funds to an open collaborative pool.",
    inputSchema: {
      type: "object",
      properties: {
        id: { type: "string" },
        amount: { type: "number" },
        from_repo: { type: "string" },
      },
      required: ["id", "amount"],
      additionalProperties: false,
    },
  },
  {
    name: "agentpay_pool_release",
    description: "Release funded pool to beneficiary (force:true for early release by creator).",
    inputSchema: {
      type: "object",
      properties: {
        id: { type: "string" },
        force: { type: "boolean" },
      },
      required: ["id"],
      additionalProperties: false,
    },
  },
  {
    name: "agentpay_pool_refund",
    description: "Cancel pool and refund all held contributions.",
    inputSchema: {
      type: "object",
      properties: { id: { type: "string" } },
      required: ["id"],
      additionalProperties: false,
    },
  },
  {
    name: "agentpay_pool_list",
    description: "List collaborative pools.",
    inputSchema: {
      type: "object",
      properties: {
        repo: { type: "string" },
        status: { type: "string" },
        limit: { type: "number" },
      },
      additionalProperties: false,
    },
  },
  {
    name: "agentpay_pool_get",
    description: "Get one pool with contributions and events.",
    inputSchema: {
      type: "object",
      properties: { id: { type: "string" } },
      required: ["id"],
      additionalProperties: false,
    },
  },
  {
    name: "agentpay_bond_post",
    description: "Post an intent bond (locks bond_amount).",
    inputSchema: {
      type: "object",
      properties: {
        poster_repo: { type: "string" },
        intent: { type: "string" },
        bond_amount: { type: "number" },
        counterparty_repo: { type: "string" },
        task: { type: "string" },
        ttl_seconds: { type: "number" },
        match_ttl_seconds: { type: "number" },
        slash_bps: { type: "number" },
      },
      required: ["intent", "bond_amount"],
      additionalProperties: false,
    },
  },
  {
    name: "agentpay_bond_match",
    description: "Match (accept) an open intent bond as counterparty.",
    inputSchema: {
      type: "object",
      properties: {
        id: { type: "string" },
        counterparty_repo: { type: "string" },
        match_ttl_seconds: { type: "number" },
      },
      required: ["id"],
      additionalProperties: false,
    },
  },
  {
    name: "agentpay_bond_fulfill",
    description: "Fulfill bond — full refund to poster.",
    inputSchema: {
      type: "object",
      properties: { id: { type: "string" } },
      required: ["id"],
      additionalProperties: false,
    },
  },
  {
    name: "agentpay_bond_slash",
    description: "Slash bond (portion to slash pool, rest to poster).",
    inputSchema: {
      type: "object",
      properties: {
        id: { type: "string" },
        slash_bps: { type: "number" },
        reason: { type: "string" },
      },
      required: ["id"],
      additionalProperties: false,
    },
  },
  {
    name: "agentpay_bond_cancel",
    description: "Cancel unmatched open bond (full refund).",
    inputSchema: {
      type: "object",
      properties: { id: { type: "string" } },
      required: ["id"],
      additionalProperties: false,
    },
  },
  {
    name: "agentpay_bond_list",
    description: "List intent bonds.",
    inputSchema: {
      type: "object",
      properties: {
        repo: { type: "string" },
        status: { type: "string" },
        limit: { type: "number" },
      },
      additionalProperties: false,
    },
  },
  {
    name: "agentpay_bond_get",
    description: "Get one bond with events.",
    inputSchema: {
      type: "object",
      properties: { id: { type: "string" } },
      required: ["id"],
      additionalProperties: false,
    },
  },
  {
    name: "agentpay_commit_create",
    description: "Commit–reveal lock: lock amount with sha256 commit_hash (or pass preimage to hash server-side).",
    inputSchema: {
      type: "object",
      properties: {
        from_repo: { type: "string" },
        to_repo: { type: "string" },
        amount: { type: "number" },
        commit_hash: { type: "string" },
        preimage: { type: "string" },
        task: { type: "string" },
        ttl_seconds: { type: "number" },
      },
      required: ["to_repo", "amount"],
      additionalProperties: false,
    },
  },
  {
    name: "agentpay_commit_reveal",
    description: "Reveal preimage; if hash matches, pay to_repo.",
    inputSchema: {
      type: "object",
      properties: {
        id: { type: "string" },
        preimage: { type: "string" },
        note: { type: "string" },
      },
      required: ["id", "preimage"],
      additionalProperties: false,
    },
  },
  {
    name: "agentpay_commit_cancel",
    description: "Cancel unrevealed commit (counterfactual full refund).",
    inputSchema: {
      type: "object",
      properties: { id: { type: "string" } },
      required: ["id"],
      additionalProperties: false,
    },
  },
  {
    name: "agentpay_commit_list",
    description: "List payment commits.",
    inputSchema: {
      type: "object",
      properties: {
        repo: { type: "string" },
        status: { type: "string" },
        limit: { type: "number" },
      },
      additionalProperties: false,
    },
  },
  {
    name: "agentpay_commit_get",
    description: "Get one commit (never returns preimage).",
    inputSchema: {
      type: "object",
      properties: { id: { type: "string" } },
      required: ["id"],
      additionalProperties: false,
    },
  },
  {
    name: "agentpay_ticket_mint",
    description: "Mint a capability ticket (units of a capability string, optional USD bond).",
    inputSchema: {
      type: "object",
      properties: {
        issuer_repo: { type: "string" },
        holder_repo: { type: "string" },
        capability: { type: "string" },
        units: { type: "number" },
        bond_usd: { type: "number" },
        max_amount_usd: { type: "number" },
        ttl_seconds: { type: "number" },
        task: { type: "string" },
      },
      required: ["capability", "units"],
      additionalProperties: false,
    },
  },
  {
    name: "agentpay_ticket_transfer",
    description: "Transfer ticket to a new holder.",
    inputSchema: {
      type: "object",
      properties: {
        id: { type: "string" },
        to_repo: { type: "string" },
      },
      required: ["id", "to_repo"],
      additionalProperties: false,
    },
  },
  {
    name: "agentpay_ticket_redeem",
    description: "Redeem (burn) ticket units; optional USD pay to service repo.",
    inputSchema: {
      type: "object",
      properties: {
        id: { type: "string" },
        units: { type: "number" },
        to_repo: { type: "string" },
        amount: { type: "number" },
        task: { type: "string" },
      },
      required: ["id", "units"],
      additionalProperties: false,
    },
  },
  {
    name: "agentpay_ticket_list",
    description: "List capability tickets.",
    inputSchema: {
      type: "object",
      properties: {
        repo: { type: "string" },
        status: { type: "string" },
        capability: { type: "string" },
        limit: { type: "number" },
      },
      additionalProperties: false,
    },
  },
  {
    name: "agentpay_ticket_get",
    description: "Get one ticket with events.",
    inputSchema: {
      type: "object",
      properties: { id: { type: "string" } },
      required: ["id"],
      additionalProperties: false,
    },
  },
  {
    name: "agentpay_saga_start",
    description: "Start multi-step payment saga (locks total budget, ordered steps).",
    inputSchema: {
      type: "object",
      properties: {
        owner_repo: { type: "string" },
        label: { type: "string" },
        steps: {
          type: "array",
          description: "[{ to_repo, amount, task?, from_repo? }, ...]",
        },
        total_budget: { type: "number" },
        ttl_seconds: { type: "number" },
      },
      required: ["steps"],
      additionalProperties: false,
    },
  },
  {
    name: "agentpay_saga_advance",
    description: "Execute next saga step (pay step.to_repo from reserved budget).",
    inputSchema: {
      type: "object",
      properties: { id: { type: "string" } },
      required: ["id"],
      additionalProperties: false,
    },
  },
  {
    name: "agentpay_saga_compensate",
    description: "Compensate saga: reverse completed steps and refund owner.",
    inputSchema: {
      type: "object",
      properties: {
        id: { type: "string" },
        reason: { type: "string" },
      },
      required: ["id"],
      additionalProperties: false,
    },
  },
  {
    name: "agentpay_saga_cancel",
    description: "Cancel saga before any step runs (full refund).",
    inputSchema: {
      type: "object",
      properties: { id: { type: "string" } },
      required: ["id"],
      additionalProperties: false,
    },
  },
  {
    name: "agentpay_saga_list",
    description: "List payment sagas.",
    inputSchema: {
      type: "object",
      properties: {
        repo: { type: "string" },
        status: { type: "string" },
        limit: { type: "number" },
      },
      additionalProperties: false,
    },
  },
  {
    name: "agentpay_saga_get",
    description: "Get one saga with steps and events.",
    inputSchema: {
      type: "object",
      properties: { id: { type: "string" } },
      required: ["id"],
      additionalProperties: false,
    },
  },
  {
    name: "agentpay_netting_run",
    description: "Run bilateral obligation netting over a time window. Soft by default; apply_balances:true moves funds.",
    inputSchema: {
      type: "object",
      properties: {
        window_hours: { type: "number" },
        apply_balances: { type: "boolean" },
        repo: { type: "string" },
      },
      additionalProperties: false,
    },
  },
  {
    name: "agentpay_netting_list",
    description: "List recent netting runs and settlements.",
    inputSchema: {
      type: "object",
      properties: { limit: { type: "number" } },
      additionalProperties: false,
    },
  },
  {
    name: "agentpay_clearing_run",
    description: "Multilateral clearing batch with HMAC settlement manifest. Optional apply_balances.",
    inputSchema: {
      type: "object",
      properties: {
        window_hours: { type: "number" },
        apply_balances: { type: "boolean" },
        deployment_id: { type: "string" },
      },
      additionalProperties: false,
    },
  },
  {
    name: "agentpay_clearing_list",
    description: "List clearing batches.",
    inputSchema: {
      type: "object",
      properties: { limit: { type: "number" } },
      additionalProperties: false,
    },
  },
  {
    name: "agentpay_clearing_get",
    description: "Get clearing batch with positions, settlement, and HMAC verify.",
    inputSchema: {
      type: "object",
      properties: { id: { type: "string" } },
      required: ["id"],
      additionalProperties: false,
    },
  },

];

async function callTool(name, args) {
  args = args || {};

  switch (name) {
    case "agentpay_health": {
      const r = await api("/health", { auth: false });
      return textResult(r.data, isFail(r));
    }

    case "agentpay_balance": {
      const repo = String(args.repo || "").trim();
      if (!repo.includes("/")) {
        return textResult({ ok: false, error: "repo must be owner/name" }, true);
      }
      const r = await api(
        "/api/balance" + qstr({ repo }),
        { auth: false }
      );
      return textResult(r.data, isFail(r));
    }

    case "agentpay_ledger_list": {
      const params = {};
      if (args.repo) params.repo = String(args.repo).trim();
      if (args.limit != null) params.limit = Number(args.limit);
      const r = await api("/api/ledger" + qstr(params), {
        auth: API_KEY ? undefined : false,
      });
      return textResult(r.data, isFail(r));
    }

    case "agentpay_passport_get": {
      const repo = String(args.repo || "").trim();
      const parts = repo.split("/");
      if (parts.length < 2) {
        return textResult({ ok: false, error: "repo must be owner/name" }, true);
      }
      const path =
        "/api/passport/" +
        encodeURIComponent(parts[0]) +
        "/" +
        encodeURIComponent(parts.slice(1).join("/"));
      const r = await api(path, { auth: false });
      return textResult(r.data, isFail(r));
    }

    case "agentpay_agents_search": {
      const capability = String(args.capability || args.q || "").trim();
      if (!capability) {
        return textResult(
          { ok: false, error: "capability required (e.g. model/vision)" },
          true
        );
      }
      const params = { capability };
      if (args.limit != null) params.limit = Number(args.limit);
      if (args.sort) params.sort = String(args.sort);
      const r = await api("/api/agents/search" + qstr(params), { auth: false });
      return textResult(r.data, isFail(r));
    }

    case "agentpay_agents_list": {
      const params = {};
      if (args.capability) params.capability = String(args.capability).trim();
      if (args.provider) params.provider = String(args.provider).trim();
      if (args.hireable === true) params.hireable = "1";
      if (args.hireable === false) params.hireable = "0";
      if (args.limit != null) params.limit = Number(args.limit);
      if (args.sort) params.sort = String(args.sort);
      const r = await api("/api/agents" + qstr(params), { auth: false });
      return textResult(r.data, isFail(r));
    }

    case "agentpay_agents_rank": {
      const params = {};
      if (args.capability) params.capability = String(args.capability).trim();
      if (args.provider) params.provider = String(args.provider).trim();
      if (args.hireable === false) params.hireable = "0";
      if (args.limit != null) params.limit = Number(args.limit);
      const r = await api("/api/agents/rank" + qstr(params), { auth: false });
      return textResult(r.data, isFail(r));
    }

    case "agentpay_pay": {
      const blocked = needKey();
      if (blocked) return blocked;
      const body = {
        from_repo: String(args.from_repo || "").trim(),
        to_repo: String(args.to_repo || "").trim(),
        amount: Number(args.amount),
        task: args.task != null ? String(args.task) : "mcp-pay",
        idempotency_key:
          args.idempotency_key != null
            ? String(args.idempotency_key).trim().slice(0, 128)
            : idem(),
      };
      if (args.instance_id) {
        body.instance_id = String(args.instance_id).trim();
      }
      const r = await api("/api/pay", { method: "POST", body });
      return textResult(r.data, isFail(r));
    }

    case "agentpay_hire_rfq": {
      const blocked = needKey();
      if (blocked) return blocked;
      const body = {
        buyer_repo: String(args.buyer_repo || "").trim(),
        task: String(args.task || "").trim(),
        budget_usd: Number(args.budget_usd),
      };
      if (args.capability) body.capability = String(args.capability);
      if (args.ttl_seconds != null) body.ttl_seconds = Number(args.ttl_seconds);
      const r = await api("/api/hire/rfq", { method: "POST", body });
      return textResult(r.data, isFail(r));
    }

    case "agentpay_hire_quote": {
      const blocked = needKey();
      if (blocked) return blocked;
      const body = {
        rfq_id: String(args.rfq_id || "").trim(),
        provider_repo: String(args.provider_repo || "").trim(),
        amount_usd: Number(args.amount_usd),
      };
      if (args.eta_seconds != null) body.eta_seconds = Number(args.eta_seconds);
      if (args.note) body.note = String(args.note);
      const r = await api("/api/hire/quote", { method: "POST", body });
      return textResult(r.data, isFail(r));
    }

    case "agentpay_hire_accept": {
      const blocked = needKey();
      if (blocked) return blocked;
      const body = {
        quote_id: String(args.quote_id || "").trim(),
        require_passport:
          args.require_passport !== undefined
            ? !!args.require_passport
            : true,
        passport_strict:
          args.passport_strict !== undefined ? !!args.passport_strict : true,
      };
      if (args.max_dispute_rate != null) {
        body.max_dispute_rate = Number(args.max_dispute_rate);
      }
      const r = await api("/api/hire/accept", { method: "POST", body });
      return textResult(r.data, isFail(r));
    }

    case "agentpay_hire_complete": {
      const blocked = needKey();
      if (blocked) return blocked;
      const body = { job_id: String(args.job_id || "").trim() };
      const r = await api("/api/hire/complete", { method: "POST", body });
      return textResult(r.data, isFail(r));
    }

    case "agentpay_hire_cancel": {
      const blocked = needKey();
      if (blocked) return blocked;
      const id = String(
        args.id || args.rfq_id || args.job_id || ""
      ).trim();
      if (!id) {
        return textResult({ ok: false, error: "id (or rfq_id / job_id) required" }, true);
      }
      const body = { id };
      if (args.rfq_id) body.rfq_id = String(args.rfq_id).trim();
      if (args.job_id) body.job_id = String(args.job_id).trim();
      const r = await api("/api/hire/cancel", { method: "POST", body });
      return textResult(r.data, isFail(r));
    }

    case "agentpay_hire_list": {
      const params = {};
      if (args.repo) params.repo = String(args.repo).trim();
      if (args.status) params.status = String(args.status).trim();
      if (args.limit != null) params.limit = Number(args.limit);
      const r = await api("/api/hire" + qstr(params), {
        auth: API_KEY ? undefined : false,
      });
      return textResult(r.data, isFail(r));
    }

    case "agentpay_hire_get": {
      const id = String(args.id || "").trim();
      if (!id) {
        return textResult({ ok: false, error: "id required" }, true);
      }
      const r = await api("/api/hire/" + encodeURIComponent(id), {
        auth: API_KEY ? undefined : false,
      });
      return textResult(r.data, isFail(r));
    }

    case "agentpay_standing_open": {
      const blocked = needKey();
      if (blocked) return blocked;
      const body = {
        to_repo: String(args.to_repo || "").trim(),
        amount: Number(args.amount),
      };
      if (args.from_repo) body.from_repo = String(args.from_repo).trim();
      if (args.interval_sec != null) body.interval_sec = Number(args.interval_sec);
      if (args.max_runs != null) body.max_runs = Number(args.max_runs);
      if (args.budget_usd != null) body.budget_usd = Number(args.budget_usd);
      if (args.ttl_seconds != null) body.ttl_seconds = Number(args.ttl_seconds);
      if (args.task != null) body.task = String(args.task);
      if (args.label != null) body.label = String(args.label);
      const r = await api("/api/standing/open", { method: "POST", body });
      return textResult(r.data, isFail(r));
    }

    case "agentpay_standing_cancel": {
      const blocked = needKey();
      if (blocked) return blocked;
      const body = { id: String(args.id || "").trim() };
      if (!body.id) {
        return textResult({ ok: false, error: "id required" }, true);
      }
      const r = await api("/api/standing/cancel", { method: "POST", body });
      return textResult(r.data, isFail(r));
    }

    case "agentpay_standing_pause": {
      const blocked = needKey();
      if (blocked) return blocked;
      const body = { id: String(args.id || "").trim() };
      if (!body.id) {
        return textResult({ ok: false, error: "id required" }, true);
      }
      const r = await api("/api/standing/pause", { method: "POST", body });
      return textResult(r.data, isFail(r));
    }

    case "agentpay_standing_resume": {
      const blocked = needKey();
      if (blocked) return blocked;
      const body = { id: String(args.id || "").trim() };
      if (!body.id) {
        return textResult({ ok: false, error: "id required" }, true);
      }
      const r = await api("/api/standing/resume", { method: "POST", body });
      return textResult(r.data, isFail(r));
    }

    case "agentpay_standing_list": {
      const params = {};
      if (args.repo) params.repo = String(args.repo).trim();
      if (args.status) params.status = String(args.status).trim();
      if (args.limit != null) params.limit = Number(args.limit);
      const r = await api("/api/standing" + qstr(params), {
        auth: API_KEY ? undefined : false,
      });
      return textResult(r.data, isFail(r));
    }

    case "agentpay_standing_get": {
      const id = String(args.id || "").trim();
      if (!id) {
        return textResult({ ok: false, error: "id required" }, true);
      }
      const r = await api("/api/standing/" + encodeURIComponent(id), {
        auth: API_KEY ? undefined : false,
      });
      return textResult(r.data, isFail(r));
    }


    case "agentpay_escrow_hold": {
      const blocked = needKey();
      if (blocked) return blocked;
      const body = {
        to_repo: String(args.to_repo || "").trim(),
        amount: Number(args.amount),
      };
      if (args.from_repo) body.from_repo = String(args.from_repo).trim();
      if (args.task != null) body.task = String(args.task);
      if (args.ttl_seconds != null) body.ttl_seconds = Number(args.ttl_seconds);
      if (args.ttl_hours != null) body.ttl_hours = Number(args.ttl_hours);
      if (args.idempotency_key) body.idempotency_key = String(args.idempotency_key).trim();
      const r = await api("/api/escrow/hold", { method: "POST", body });
      return textResult(r.data, isFail(r));
    }

    case "agentpay_escrow_release": {
      const blocked = needKey();
      if (blocked) return blocked;
      const body = { id: String(args.id || "").trim() };
      const r = await api("/api/escrow/release", { method: "POST", body });
      return textResult(r.data, isFail(r));
    }

    case "agentpay_escrow_refund": {
      const blocked = needKey();
      if (blocked) return blocked;
      const body = { id: String(args.id || "").trim() };
      const r = await api("/api/escrow/refund", { method: "POST", body });
      return textResult(r.data, isFail(r));
    }

    case "agentpay_escrow_list": {
      const params = {};
      if (args.repo) params.repo = String(args.repo).trim();
      if (args.status) params.status = String(args.status).trim();
      if (args.limit != null) params.limit = Number(args.limit);
      const r = await api("/api/escrow" + qstr(params), {
        auth: API_KEY ? undefined : false,
      });
      return textResult(r.data, isFail(r));
    }

    case "agentpay_stream_start": {
      const blocked = needKey();
      if (blocked) return blocked;
      const body = {
        to_repo: String(args.to_repo || "").trim(),
        budget: Number(args.budget),
        rate_per_unit: Number(args.rate_per_unit),
      };
      if (args.from_repo) body.from_repo = String(args.from_repo).trim();
      if (args.unit_label) body.unit_label = String(args.unit_label);
      if (args.task != null) body.task = String(args.task);
      if (args.idempotency_key) body.idempotency_key = String(args.idempotency_key).trim();
      const r = await api("/api/stream/start", { method: "POST", body });
      return textResult(r.data, isFail(r));
    }

    case "agentpay_stream_meter": {
      const blocked = needKey();
      if (blocked) return blocked;
      const body = {
        id: String(args.id || "").trim(),
        units: Number(args.units),
      };
      const r = await api("/api/stream/meter", { method: "POST", body });
      return textResult(r.data, isFail(r));
    }

    case "agentpay_stream_stop": {
      const blocked = needKey();
      if (blocked) return blocked;
      const body = { id: String(args.id || "").trim() };
      const r = await api("/api/stream/stop", { method: "POST", body });
      return textResult(r.data, isFail(r));
    }

    case "agentpay_stream_list": {
      const params = {};
      if (args.repo) params.repo = String(args.repo).trim();
      if (args.status) params.status = String(args.status).trim();
      if (args.limit != null) params.limit = Number(args.limit);
      const r = await api("/api/stream" + qstr(params), {
        auth: API_KEY ? undefined : false,
      });
      return textResult(r.data, isFail(r));
    }

    case "agentpay_intent_create": {
      const blocked = needKey();
      if (blocked) return blocked;
      const body = { budget: Number(args.budget) };
      if (args.from_repo) body.from_repo = String(args.from_repo).trim();
      if (args.allow_to != null) body.allow_to = args.allow_to;
      if (args.task_prefix != null) body.task_prefix = String(args.task_prefix);
      if (args.max_per_spend != null) body.max_per_spend = Number(args.max_per_spend);
      if (args.ttl_seconds != null) body.ttl_seconds = Number(args.ttl_seconds);
      if (args.label != null) body.label = String(args.label);
      const r = await api("/api/intent/create", { method: "POST", body });
      return textResult(r.data, isFail(r));
    }

    case "agentpay_intent_spend": {
      const blocked = needKey();
      if (blocked) return blocked;
      const body = {
        id: String(args.id || "").trim(),
        to_repo: String(args.to_repo || "").trim(),
        amount: Number(args.amount),
      };
      if (args.task != null) body.task = String(args.task);
      const r = await api("/api/intent/spend", { method: "POST", body });
      return textResult(r.data, isFail(r));
    }

    case "agentpay_intent_cancel": {
      const blocked = needKey();
      if (blocked) return blocked;
      const body = { id: String(args.id || "").trim() };
      const r = await api("/api/intent/cancel", { method: "POST", body });
      return textResult(r.data, isFail(r));
    }

    case "agentpay_intent_list": {
      const params = {};
      if (args.repo) params.repo = String(args.repo).trim();
      if (args.status) params.status = String(args.status).trim();
      if (args.limit != null) params.limit = Number(args.limit);
      const r = await api("/api/intent" + qstr(params), {
        auth: API_KEY ? undefined : false,
      });
      return textResult(r.data, isFail(r));
    }

    case "agentpay_intent_get": {
      const id = String(args.id || "").trim();
      if (!id) return textResult({ ok: false, error: "id required" }, true);
      const r = await api("/api/intent/" + encodeURIComponent(id), {
        auth: API_KEY ? undefined : false,
      });
      return textResult(r.data, isFail(r));
    }

    case "agentpay_work_claim": {
      const blocked = needKey();
      if (blocked) return blocked;
      const body = {
        task: String(args.task || "").trim(),
        amount: Number(args.amount),
      };
      if (args.provider_repo) body.provider_repo = String(args.provider_repo).trim();
      if (args.buyer_repo) body.buyer_repo = String(args.buyer_repo).trim();
      if (args.expected_hash) body.expected_hash = String(args.expected_hash).trim();
      if (args.output_hash) body.output_hash = String(args.output_hash).trim();
      if (args.output_uri) body.output_uri = String(args.output_uri);
      if (args.min_attestations != null) body.min_attestations = Number(args.min_attestations);
      if (args.ttl_seconds != null) body.ttl_seconds = Number(args.ttl_seconds);
      const r = await api("/api/work/claim", { method: "POST", body });
      return textResult(r.data, isFail(r));
    }

    case "agentpay_work_lock": {
      const blocked = needKey();
      if (blocked) return blocked;
      const body = { id: String(args.id || "").trim() };
      if (args.buyer_repo) body.buyer_repo = String(args.buyer_repo).trim();
      const r = await api("/api/work/lock", { method: "POST", body });
      return textResult(r.data, isFail(r));
    }

    case "agentpay_work_attest": {
      const blocked = needKey();
      if (blocked) return blocked;
      const body = {
        id: String(args.id || "").trim(),
        output_hash: String(args.output_hash || "").trim(),
      };
      if (args.attestor_repo) body.attestor_repo = String(args.attestor_repo).trim();
      if (args.note) body.note = String(args.note);
      const r = await api("/api/work/attest", { method: "POST", body });
      return textResult(r.data, isFail(r));
    }

    case "agentpay_work_settle": {
      const blocked = needKey();
      if (blocked) return blocked;
      const body = { id: String(args.id || "").trim() };
      const r = await api("/api/work/settle", { method: "POST", body });
      return textResult(r.data, isFail(r));
    }

    case "agentpay_work_refund": {
      const blocked = needKey();
      if (blocked) return blocked;
      const body = { id: String(args.id || "").trim() };
      const r = await api("/api/work/refund", { method: "POST", body });
      return textResult(r.data, isFail(r));
    }

    case "agentpay_work_list": {
      const params = {};
      if (args.repo) params.repo = String(args.repo).trim();
      if (args.status) params.status = String(args.status).trim();
      if (args.limit != null) params.limit = Number(args.limit);
      const r = await api("/api/work" + qstr(params), {
        auth: API_KEY ? undefined : false,
      });
      return textResult(r.data, isFail(r));
    }

    case "agentpay_work_get": {
      const id = String(args.id || "").trim();
      if (!id) return textResult({ ok: false, error: "id required" }, true);
      const r = await api("/api/work/" + encodeURIComponent(id), {
        auth: API_KEY ? undefined : false,
      });
      return textResult(r.data, isFail(r));
    }

    case "agentpay_split_create": {
      const blocked = needKey();
      if (blocked) return blocked;
      const body = {
        amount: Number(args.amount),
        recipients: args.recipients,
      };
      if (args.from_repo) body.from_repo = String(args.from_repo).trim();
      if (args.task != null) body.task = String(args.task);
      if (args.idempotency_key) body.idempotency_key = String(args.idempotency_key).trim();
      const r = await api("/api/split", { method: "POST", body });
      return textResult(r.data, isFail(r));
    }

    case "agentpay_split_list": {
      const params = {};
      if (args.repo) params.repo = String(args.repo).trim();
      if (args.limit != null) params.limit = Number(args.limit);
      const r = await api("/api/split" + qstr(params), {
        auth: API_KEY ? undefined : false,
      });
      return textResult(r.data, isFail(r));
    }

    case "agentpay_split_get": {
      const id = String(args.id || "").trim();
      if (!id) return textResult({ ok: false, error: "id required" }, true);
      const r = await api("/api/split/" + encodeURIComponent(id), {
        auth: API_KEY ? undefined : false,
      });
      return textResult(r.data, isFail(r));
    }


    case "agentpay_pool_open": {
      const blocked = needKey();
      if (blocked) return blocked;
      const body = {
        beneficiary_repo: String(args.beneficiary_repo || "").trim(),
        target_amount: Number(args.target_amount),
      };
      if (args.creator_repo) body.creator_repo = String(args.creator_repo).trim();
      if (args.task != null) body.task = String(args.task);
      if (args.title != null) body.title = String(args.title);
      if (args.ttl_seconds != null) body.ttl_seconds = Number(args.ttl_seconds);
      if (args.min_contribution != null) body.min_contribution = Number(args.min_contribution);
      const r = await api("/api/pool/open", { method: "POST", body });
      return textResult(r.data, isFail(r));
    }
    case "agentpay_pool_contribute": {
      const blocked = needKey();
      if (blocked) return blocked;
      const body = { id: String(args.id || "").trim(), amount: Number(args.amount) };
      if (args.from_repo) body.from_repo = String(args.from_repo).trim();
      const r = await api("/api/pool/contribute", { method: "POST", body });
      return textResult(r.data, isFail(r));
    }
    case "agentpay_pool_release": {
      const blocked = needKey();
      if (blocked) return blocked;
      const body = { id: String(args.id || "").trim() };
      if (args.force === true) body.force = true;
      const r = await api("/api/pool/release", { method: "POST", body });
      return textResult(r.data, isFail(r));
    }
    case "agentpay_pool_refund": {
      const blocked = needKey();
      if (blocked) return blocked;
      const r = await api("/api/pool/refund", { method: "POST", body: { id: String(args.id || "").trim() } });
      return textResult(r.data, isFail(r));
    }
    case "agentpay_pool_list": {
      const params = {};
      if (args.repo) params.repo = String(args.repo).trim();
      if (args.status) params.status = String(args.status).trim();
      if (args.limit != null) params.limit = Number(args.limit);
      const r = await api("/api/pool" + qstr(params), { auth: API_KEY ? undefined : false });
      return textResult(r.data, isFail(r));
    }
    case "agentpay_pool_get": {
      const id = String(args.id || "").trim();
      if (!id) return textResult({ ok: false, error: "id required" }, true);
      const r = await api("/api/pool/" + encodeURIComponent(id), { auth: API_KEY ? undefined : false });
      return textResult(r.data, isFail(r));
    }
    case "agentpay_bond_post": {
      const blocked = needKey();
      if (blocked) return blocked;
      const body = {
        intent: String(args.intent || "").trim(),
        bond_amount: Number(args.bond_amount),
      };
      if (args.poster_repo) body.poster_repo = String(args.poster_repo).trim();
      if (args.counterparty_repo) body.counterparty_repo = String(args.counterparty_repo).trim();
      if (args.task != null) body.task = String(args.task);
      if (args.ttl_seconds != null) body.ttl_seconds = Number(args.ttl_seconds);
      if (args.match_ttl_seconds != null) body.match_ttl_seconds = Number(args.match_ttl_seconds);
      if (args.slash_bps != null) body.slash_bps = Number(args.slash_bps);
      const r = await api("/api/bond/post", { method: "POST", body });
      return textResult(r.data, isFail(r));
    }
    case "agentpay_bond_match": {
      const blocked = needKey();
      if (blocked) return blocked;
      const body = { id: String(args.id || "").trim() };
      if (args.counterparty_repo) body.counterparty_repo = String(args.counterparty_repo).trim();
      if (args.match_ttl_seconds != null) body.match_ttl_seconds = Number(args.match_ttl_seconds);
      const r = await api("/api/bond/match", { method: "POST", body });
      return textResult(r.data, isFail(r));
    }
    case "agentpay_bond_fulfill": {
      const blocked = needKey();
      if (blocked) return blocked;
      const r = await api("/api/bond/fulfill", { method: "POST", body: { id: String(args.id || "").trim() } });
      return textResult(r.data, isFail(r));
    }
    case "agentpay_bond_slash": {
      const blocked = needKey();
      if (blocked) return blocked;
      const body = { id: String(args.id || "").trim() };
      if (args.slash_bps != null) body.slash_bps = Number(args.slash_bps);
      if (args.reason != null) body.reason = String(args.reason);
      const r = await api("/api/bond/slash", { method: "POST", body });
      return textResult(r.data, isFail(r));
    }
    case "agentpay_bond_cancel": {
      const blocked = needKey();
      if (blocked) return blocked;
      const r = await api("/api/bond/cancel", { method: "POST", body: { id: String(args.id || "").trim() } });
      return textResult(r.data, isFail(r));
    }
    case "agentpay_bond_list": {
      const params = {};
      if (args.repo) params.repo = String(args.repo).trim();
      if (args.status) params.status = String(args.status).trim();
      if (args.limit != null) params.limit = Number(args.limit);
      const r = await api("/api/bond" + qstr(params), { auth: API_KEY ? undefined : false });
      return textResult(r.data, isFail(r));
    }
    case "agentpay_bond_get": {
      const id = String(args.id || "").trim();
      if (!id) return textResult({ ok: false, error: "id required" }, true);
      const r = await api("/api/bond/" + encodeURIComponent(id), { auth: API_KEY ? undefined : false });
      return textResult(r.data, isFail(r));
    }
    case "agentpay_commit_create": {
      const blocked = needKey();
      if (blocked) return blocked;
      const body = {
        to_repo: String(args.to_repo || "").trim(),
        amount: Number(args.amount),
      };
      if (args.from_repo) body.from_repo = String(args.from_repo).trim();
      if (args.commit_hash) body.commit_hash = String(args.commit_hash).trim();
      if (args.preimage != null) body.preimage = String(args.preimage);
      if (args.task != null) body.task = String(args.task);
      if (args.ttl_seconds != null) body.ttl_seconds = Number(args.ttl_seconds);
      const r = await api("/api/commit", { method: "POST", body });
      return textResult(r.data, isFail(r));
    }
    case "agentpay_commit_reveal": {
      const blocked = needKey();
      if (blocked) return blocked;
      const body = {
        id: String(args.id || "").trim(),
        preimage: String(args.preimage ?? ""),
      };
      if (args.note != null) body.note = String(args.note);
      const r = await api("/api/commit/reveal", { method: "POST", body });
      return textResult(r.data, isFail(r));
    }
    case "agentpay_commit_cancel": {
      const blocked = needKey();
      if (blocked) return blocked;
      const r = await api("/api/commit/cancel", { method: "POST", body: { id: String(args.id || "").trim() } });
      return textResult(r.data, isFail(r));
    }
    case "agentpay_commit_list": {
      const params = {};
      if (args.repo) params.repo = String(args.repo).trim();
      if (args.status) params.status = String(args.status).trim();
      if (args.limit != null) params.limit = Number(args.limit);
      const r = await api("/api/commit" + qstr(params), { auth: API_KEY ? undefined : false });
      return textResult(r.data, isFail(r));
    }
    case "agentpay_commit_get": {
      const id = String(args.id || "").trim();
      if (!id) return textResult({ ok: false, error: "id required" }, true);
      const r = await api("/api/commit/" + encodeURIComponent(id), { auth: API_KEY ? undefined : false });
      return textResult(r.data, isFail(r));
    }
    case "agentpay_ticket_mint": {
      const blocked = needKey();
      if (blocked) return blocked;
      const body = {
        capability: String(args.capability || "").trim(),
        units: Number(args.units),
      };
      if (args.issuer_repo) body.issuer_repo = String(args.issuer_repo).trim();
      if (args.holder_repo) body.holder_repo = String(args.holder_repo).trim();
      if (args.bond_usd != null) body.bond_usd = Number(args.bond_usd);
      if (args.max_amount_usd != null) body.max_amount_usd = Number(args.max_amount_usd);
      if (args.ttl_seconds != null) body.ttl_seconds = Number(args.ttl_seconds);
      if (args.task != null) body.task = String(args.task);
      const r = await api("/api/ticket/mint", { method: "POST", body });
      return textResult(r.data, isFail(r));
    }
    case "agentpay_ticket_transfer": {
      const blocked = needKey();
      if (blocked) return blocked;
      const body = {
        id: String(args.id || "").trim(),
        to_repo: String(args.to_repo || "").trim(),
      };
      const r = await api("/api/ticket/transfer", { method: "POST", body });
      return textResult(r.data, isFail(r));
    }
    case "agentpay_ticket_redeem": {
      const blocked = needKey();
      if (blocked) return blocked;
      const body = {
        id: String(args.id || "").trim(),
        units: Number(args.units),
      };
      if (args.to_repo) body.to_repo = String(args.to_repo).trim();
      if (args.amount != null) body.amount = Number(args.amount);
      if (args.task != null) body.task = String(args.task);
      const r = await api("/api/ticket/redeem", { method: "POST", body });
      return textResult(r.data, isFail(r));
    }
    case "agentpay_ticket_list": {
      const params = {};
      if (args.repo) params.repo = String(args.repo).trim();
      if (args.status) params.status = String(args.status).trim();
      if (args.capability) params.capability = String(args.capability).trim();
      if (args.limit != null) params.limit = Number(args.limit);
      const r = await api("/api/ticket" + qstr(params), { auth: API_KEY ? undefined : false });
      return textResult(r.data, isFail(r));
    }
    case "agentpay_ticket_get": {
      const id = String(args.id || "").trim();
      if (!id) return textResult({ ok: false, error: "id required" }, true);
      const r = await api("/api/ticket/" + encodeURIComponent(id), { auth: API_KEY ? undefined : false });
      return textResult(r.data, isFail(r));
    }
    case "agentpay_saga_start": {
      const blocked = needKey();
      if (blocked) return blocked;
      const body = { steps: args.steps };
      if (args.owner_repo) body.owner_repo = String(args.owner_repo).trim();
      if (args.label != null) body.label = String(args.label);
      if (args.total_budget != null) body.total_budget = Number(args.total_budget);
      if (args.ttl_seconds != null) body.ttl_seconds = Number(args.ttl_seconds);
      const r = await api("/api/saga/start", { method: "POST", body });
      return textResult(r.data, isFail(r));
    }
    case "agentpay_saga_advance": {
      const blocked = needKey();
      if (blocked) return blocked;
      const r = await api("/api/saga/advance", { method: "POST", body: { id: String(args.id || "").trim() } });
      return textResult(r.data, isFail(r));
    }
    case "agentpay_saga_compensate": {
      const blocked = needKey();
      if (blocked) return blocked;
      const body = { id: String(args.id || "").trim() };
      if (args.reason != null) body.reason = String(args.reason);
      const r = await api("/api/saga/compensate", { method: "POST", body });
      return textResult(r.data, isFail(r));
    }
    case "agentpay_saga_cancel": {
      const blocked = needKey();
      if (blocked) return blocked;
      const r = await api("/api/saga/cancel", { method: "POST", body: { id: String(args.id || "").trim() } });
      return textResult(r.data, isFail(r));
    }
    case "agentpay_saga_list": {
      const params = {};
      if (args.repo) params.repo = String(args.repo).trim();
      if (args.status) params.status = String(args.status).trim();
      if (args.limit != null) params.limit = Number(args.limit);
      const r = await api("/api/saga" + qstr(params), { auth: API_KEY ? undefined : false });
      return textResult(r.data, isFail(r));
    }
    case "agentpay_saga_get": {
      const id = String(args.id || "").trim();
      if (!id) return textResult({ ok: false, error: "id required" }, true);
      const r = await api("/api/saga/" + encodeURIComponent(id), { auth: API_KEY ? undefined : false });
      return textResult(r.data, isFail(r));
    }
    case "agentpay_netting_run": {
      const blocked = needKey();
      if (blocked) return blocked;
      const body = {};
      if (args.window_hours != null) body.window_hours = Number(args.window_hours);
      if (args.apply_balances === true) body.apply_balances = true;
      if (args.repo) body.repo = String(args.repo).trim();
      const r = await api("/api/netting/run", { method: "POST", body });
      return textResult(r.data, isFail(r));
    }
    case "agentpay_netting_list": {
      const params = {};
      if (args.limit != null) params.limit = Number(args.limit);
      const r = await api("/api/netting" + qstr(params), { auth: API_KEY ? undefined : false });
      return textResult(r.data, isFail(r));
    }
    case "agentpay_clearing_run": {
      const blocked = needKey();
      if (blocked) return blocked;
      const body = {};
      if (args.window_hours != null) body.window_hours = Number(args.window_hours);
      if (args.apply_balances === true) body.apply_balances = true;
      if (args.deployment_id) body.deployment_id = String(args.deployment_id);
      const r = await api("/api/clearing/run", { method: "POST", body });
      return textResult(r.data, isFail(r));
    }
    case "agentpay_clearing_list": {
      const params = {};
      if (args.limit != null) params.limit = Number(args.limit);
      const r = await api("/api/clearing" + qstr(params), { auth: API_KEY ? undefined : false });
      return textResult(r.data, isFail(r));
    }
    case "agentpay_clearing_get": {
      const id = String(args.id || "").trim();
      if (!id) return textResult({ ok: false, error: "id required" }, true);
      const r = await api("/api/clearing/" + encodeURIComponent(id), { auth: API_KEY ? undefined : false });
      return textResult(r.data, isFail(r));
    }

    default:
      return textResult({ ok: false, error: "Unknown tool: " + name }, true);
  }
}

async function main() {
  const server = new Server(
    {
      name: "agentpay",
      version: "0.4.0",
    },
    {
      capabilities: {
        tools: {},
      },
    }
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: TOOLS,
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const name = request.params.name;
    const args = request.params.arguments || {};
    try {
      return await callTool(name, args);
    } catch (e) {
      return textResult(
        {
          ok: false,
          error: e && e.message ? e.message : String(e),
        },
        true
      );
    }
  });

  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((err) => {
  console.error("agentpay-mcp failed:", err);
  process.exit(1);
});
