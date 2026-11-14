#!/usr/bin/env node
/**
 * AgentPay MCP Server v0.2.0 — Stage 1
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

    default:
      return textResult({ ok: false, error: "Unknown tool: " + name }, true);
  }
}

async function main() {
  const server = new Server(
    {
      name: "agentpay",
      version: "0.2.0",
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
