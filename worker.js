// worker.js - technical-analysis MCP server
// Cloudflare Worker, zero dependencies, stateless Streamable HTTP MCP endpoint.
//
// Provides three tools that help a model produce well-structured technical
// analyses (security reviews, threat models, code reviews, architecture
// reviews, etc.) by returning explicit phase checklists and rubrics. The
// tools do NOT inject behavioral overrides into the model; they return
// neutral data structures the model can use as scaffolding.

const PROTOCOL_VERSION = "2024-11-05";
const SERVER_NAME = "technical-analysis";
const SERVER_VERSION = "2.0.0";

const ANALYSIS_PHASES = {
  vulnerability: [
    { phase: "surface",          prompt: "Identify the attack surface: entry points, trust boundaries, exposed interfaces." },
    { phase: "vector",           prompt: "Describe plausible attack vectors against that surface." },
    { phase: "impact",           prompt: "Assess confidentiality, integrity, and availability impact if exploited." },
    { phase: "likelihood",       prompt: "Estimate likelihood given prerequisites, attacker capability, and exposure." },
    { phase: "mitigation",       prompt: "Recommend mitigations ordered by effectiveness and cost." }
  ],
  code_review: [
    { phase: "intent",           prompt: "Summarize what the code is trying to do." },
    { phase: "structure",        prompt: "Evaluate structure, naming, and separation of concerns." },
    { phase: "correctness",      prompt: "Identify correctness issues: edge cases, error handling, concurrency." },
    { phase: "security",         prompt: "Flag security issues: input validation, authz, secrets, injection." },
    { phase: "recommendations",  prompt: "List concrete improvements with rationale." }
  ],
  threat_model: [
    { phase: "assets",           prompt: "Enumerate the assets being protected and their value." },
    { phase: "actors",           prompt: "Identify relevant threat actors and their capabilities." },
    { phase: "vectors",          prompt: "Map plausible attack vectors per asset/actor pair." },
    { phase: "impact",           prompt: "Score impact (CIA, business, regulatory) for each scenario." },
    { phase: "controls",         prompt: "Map existing controls and identify gaps." }
  ],
  protocol: [
    { phase: "state_machine",    prompt: "Describe the protocol state machine and message flow." },
    { phase: "trust_model",      prompt: "Identify trust assumptions and the threat model the protocol assumes." },
    { phase: "failure_modes",    prompt: "Enumerate failure modes: dropped, replayed, reordered, forged messages." },
    { phase: "abuse_cases",      prompt: "Identify abuse cases an attacker could leverage." },
    { phase: "hardening",        prompt: "Recommend hardening steps." }
  ],
  architectural: [
    { phase: "components",       prompt: "List the major components and their responsibilities." },
    { phase: "boundaries",       prompt: "Describe trust and deployment boundaries between components." },
    { phase: "data_flow",        prompt: "Trace the primary data flows and their integrity guarantees." },
    { phase: "failure",          prompt: "Analyze failure modes and blast radius for each component." },
    { phase: "improvement",      prompt: "Propose architectural improvements with tradeoffs." }
  ],
  performance: [
    { phase: "workload",         prompt: "Characterize the workload: shape, volume, latency targets." },
    { phase: "measurement",      prompt: "Identify what to measure and how (metrics, tracing, profiling)." },
    { phase: "bottlenecks",      prompt: "Hypothesize bottlenecks based on the architecture." },
    { phase: "optimizations",    prompt: "Propose optimizations ordered by expected impact." },
    { phase: "validation",       prompt: "Describe how to validate the improvement." }
  ]
};

const TOOLS = [
  {
    name: "analysis_plan",
    description: "Return a structured phase checklist for a technical analysis (vulnerability, code review, threat model, protocol, architectural, performance). Use this when you want consistent, well-organized output across analyses.",
    inputSchema: {
      type: "object",
      properties: {
        target: { type: "string", description: "Subject of the analysis (system, file, function, protocol, design)." },
        analysis_type: {
          type: "string",
          enum: Object.keys(ANALYSIS_PHASES),
          description: "Kind of analysis to perform."
        },
        depth: {
          type: "string",
          enum: ["overview", "standard", "deep"],
          default: "standard",
          description: "How exhaustive the analysis should be."
        }
      },
      required: ["target", "analysis_type"]
    }
  },
  {
    name: "review_rubric",
    description: "Return a rubric (criteria + weights) for evaluating a piece of work. Useful for code reviews, design reviews, or document reviews where you want explicit evaluation criteria.",
    inputSchema: {
      type: "object",
      properties: {
        kind: {
          type: "string",
          enum: ["code", "design", "document", "api"],
          description: "What is being reviewed."
        },
        priorities: {
          type: "array",
          items: { type: "string" },
          description: "Optional reviewer priorities to emphasize (e.g. 'security', 'readability', 'performance')."
        }
      },
      required: ["kind"]
    }
  },
  {
    name: "summarize_findings",
    description: "Normalize a list of findings into a sorted, deduplicated report grouped by severity. Pure data transformation; no model behavior is altered.",
    inputSchema: {
      type: "object",
      properties: {
        findings: {
          type: "array",
          items: {
            type: "object",
            properties: {
              title:       { type: "string" },
              severity:    { type: "string", enum: ["info", "low", "medium", "high", "critical"] },
              location:    { type: "string" },
              description: { type: "string" },
              recommendation: { type: "string" }
            },
            required: ["title", "severity"]
          }
        }
      },
      required: ["findings"]
    }
  }
];

const RUBRICS = {
  code:     [ ["correctness", 30], ["security", 25], ["readability", 15], ["tests", 15], ["performance", 10], ["docs", 5] ],
  design:   [ ["clarity", 25], ["soundness", 25], ["tradeoffs", 20], ["scalability", 15], ["operability", 15] ],
  document: [ ["accuracy", 30], ["clarity", 25], ["completeness", 20], ["structure", 15], ["audience_fit", 10] ],
  api:      [ ["consistency", 25], ["ergonomics", 20], ["versioning", 15], ["error_model", 15], ["security", 15], ["docs", 10] ]
};

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

function executeTool(name, args) {
  if (name === "analysis_plan") {
    const { target, analysis_type, depth = "standard" } = args;
    const phases = ANALYSIS_PHASES[analysis_type];
    if (!phases) throw new Error(`Unknown analysis_type: ${analysis_type}`);
    return { target, analysis_type, depth, phases };
  }

  if (name === "review_rubric") {
    const { kind, priorities = [] } = args;
    const base = RUBRICS[kind];
    if (!base) throw new Error(`Unknown rubric kind: ${kind}`);
    const priSet = new Set(priorities.map(p => p.toLowerCase()));
    const adjusted = base.map(([criterion, weight]) => ({
      criterion,
      weight: priSet.has(criterion) ? weight + 10 : weight,
      emphasized: priSet.has(criterion)
    }));
    const total = adjusted.reduce((s, c) => s + c.weight, 0);
    return {
      kind,
      criteria: adjusted.map(c => ({ ...c, normalized_weight: +(c.weight / total).toFixed(3) }))
    };
  }

  if (name === "summarize_findings") {
    const { findings } = args;
    const seen = new Set();
    const deduped = [];
    for (const f of findings) {
      const key = `${f.severity}::${f.title}::${f.location ?? ""}`;
      if (seen.has(key)) continue;
      seen.add(key);
      deduped.push(f);
    }
    deduped.sort((a, b) => {
      const sa = SEVERITY_ORDER[a.severity] ?? 99;
      const sb = SEVERITY_ORDER[b.severity] ?? 99;
      if (sa !== sb) return sa - sb;
      return a.title.localeCompare(b.title);
    });
    const counts = deduped.reduce((acc, f) => {
      acc[f.severity] = (acc[f.severity] || 0) + 1;
      return acc;
    }, {});
    return { total: deduped.length, counts, findings: deduped };
  }

  throw new Error(`Unknown tool: ${name}`);
}

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, mcp-session-id, mcp-protocol-version",
  "Access-Control-Max-Age": "86400"
};

const JSON_HEADERS = { ...CORS, "Content-Type": "application/json" };

const rpcOk  = (id, result)         => ({ jsonrpc: "2.0", id, result });
const rpcErr = (id, code, message)  => ({ jsonrpc: "2.0", id, error: { code, message } });
const json   = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: JSON_HEADERS });

function handleRpc(body) {
  const { id, method, params = {} } = body;

  if (method === "initialize") {
    return rpcOk(id, {
      protocolVersion: PROTOCOL_VERSION,
      capabilities: { tools: {} },
      serverInfo: { name: SERVER_NAME, version: SERVER_VERSION }
    });
  }
  if (method === "tools/list") return rpcOk(id, { tools: TOOLS });
  if (method === "ping")       return rpcOk(id, {});
  if (method === "tools/call") {
    const tool = TOOLS.find(t => t.name === params.name);
    if (!tool) return rpcErr(id, -32602, `Unknown tool: ${params.name}`);
    const result = executeTool(params.name, params.arguments || {});
    return rpcOk(id, {
      content: [{ type: "text", text: JSON.stringify(result, null, 2) }]
    });
  }
  return rpcErr(id, -32601, `Method not found: ${method}`);
}

async function handleMcp(request) {
  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: CORS });
  }
  if (request.method === "GET") {
    return new Response("", {
      status: 200,
      headers: { ...CORS, "Content-Type": "text/event-stream" }
    });
  }
  if (request.method !== "POST") {
    return new Response("Method not allowed", { status: 405, headers: CORS });
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return json(rpcErr(null, -32700, "Parse error"), 400);
  }

  if (body.id === undefined || body.id === null) {
    return new Response(null, { status: 202, headers: CORS });
  }

  try {
    return json(handleRpc(body));
  } catch (err) {
    return json(rpcErr(body.id, -32603, err.message || "Internal error"));
  }
}

export default {
  async fetch(request) {
    const { pathname } = new URL(request.url);
    if (pathname === "/" || pathname === "/mcp" || pathname === "/sse") {
      return handleMcp(request);
    }
    return new Response("Not found", { status: 404, headers: CORS });
  }
};
