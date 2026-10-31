#!/usr/bin/env node
/**
 * AgentPay MCP Server v0
 *
 * Thin adapter: MCP tools → your existing Cloudflare Worker APIs.
 * No new ledger. No second database.
 *
 * Env:
 *   AGENTPAY_API_BASE  — default https://autonomous-edge-agent-economy.explorercosmic7.workers.dev
 *   AGENTPAY_API_KEY   — Bearer a2a_… key (required for money / hire)
 *
 * Run (stdio — Cursor / Claude Desktop):
 *   AGENTPAY_API_KEY=a2a_… node src/server.js
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
    data = { ok: false, error: "non-json response " + res.status };
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
      },
      true
    );
  }
  return null;
}

/** Tool definitions — keep v0 small (stranger-hire + identity + pay) */
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
    name: "agentpay_pay",
    description:
      "Direct micro-payment from one agent repo to another. Requires API key. Amount in USD (e.g. 0.01).",
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
          description: "Load provider passport before accept (default true for strangers)",
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
];

async function callTool(name, args) {
  args = args || {};

  switch (name) {
    case "agentpay_health": {
      const r = await api("/health", { auth: false });
      return textResult(r.data, !r.data?.ok && r.status >= 400);
    }

    case "agentpay_balance": {
      const repo = String(args.repo || "").trim();
      if (!repo.includes("/")) {
        return textResult({ ok: false, error: "repo must be owner/name" }, true);
      }
      const r = await api(
        "/api/balance?repo=" + encodeURIComponent(repo),
        { auth: false }
      );
      return textResult(r.data, !r.data?.ok);
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
      return textResult(r.data, !r.data?.ok);
    }

    case "agentpay_pay": {
      const blocked = needKey();
      if (blocked) return blocked;
      const body = {
        from_repo: String(args.from_repo || "").trim(),
        to_repo: String(args.to_repo || "").trim(),
        amount: Number(args.amount),
        task: args.task != null ? String(args.task) : "mcp-pay",
        idempotency_key: idem(),
      };
      const r = await api("/api/pay", { method: "POST", body });
      return textResult(r.data, !r.data?.ok);
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
      return textResult(r.data, !r.data?.ok);
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
      return textResult(r.data, !r.data?.ok);
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
      return textResult(r.data, !r.data?.ok);
    }

    case "agentpay_hire_complete": {
      const blocked = needKey();
      if (blocked) return blocked;
      const body = { job_id: String(args.job_id || "").trim() };
      const r = await api("/api/hire/complete", { method: "POST", body });
      return textResult(r.data, !r.data?.ok);
    }

    default:
      return textResult({ ok: false, error: "Unknown tool: " + name }, true);
  }
}

async function main() {
  const server = new Server(
    {
      name: "agentpay",
      version: "0.1.0",
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
