import * as fs from "node:fs"
import * as security from "../../index.ts"
import * as dispatch from "../../mcp_dispatch.ts"
import { PentestAgent } from "../../pentestgpt_agent.ts"
import { ContextGuard } from "../../context_guard.ts"
import { gateExecution } from "../../opsec_gate.ts"
import type { McpTool } from "../../mcp_tool_types.ts"
import { buildActionablePlan } from "../../pentest_plan_builder.ts"
import { runEngagementSlice } from "../../engagement_slice.ts"
import { runEngagementAutopilot } from "../../engagement_autopilot.ts"
import { readArtifact } from "../../mcp_artifacts.ts"
import { mcpContext } from "../context.ts"

export function buildReconTools(): McpTool[] {
  const { mcpLive, toolBroker, globalThrottleEngine } = mcpContext
  return [
    {
        name: "ares_recon",
        description: "AI-driven target reconnaissance: OSINT, employee enumeration, email pattern discovery, LinkedIn scraping, subdomain enumeration via crt.sh/HaveIBeenPwned/Shodan.",
        inputSchema: {
          type: "object",
          properties: {
            domain:    { type: "string", description: "Target domain or organization name" },
            deep:      { type: "string", description: "deep=true for full OSINT sweep", enum: ["true","false"] },
          },
          required: ["domain"],
        },
        async handler({ domain, deep }) {
          const live = mcpLive()
          return security.ai_recon.runRecon({ domain: String(domain), deep: deep === "true" }, { live })
        },
      },

    {
        name: "ares_bountyhunter",
        description: "Bug bounty recon: subdomain enumeration, endpoint discovery, JS secret scanning, vulnerability surface mapping.",
        inputSchema: {
          type: "object",
          properties: {
            target:    { type: "string", description: "Target domain or IP" },
            endpoints: { type: "string", description: "Comma-separated known endpoints (optional)" },
          },
          required: ["target"],
        },
        async handler({ target, endpoints }) {
          const live = mcpLive()
          const eps = String(endpoints ?? "").split(",").filter(Boolean)
          return security.bountyhunter.recon({ target: String(target), endpoints: eps }, { live })
        },
      },

    {
        name: "ares_scanner_parse",
        description: "Parse scanner output files: nmap XML, masscan JSON, nuclei JSON, nessus .nessus. Returns structured finding objects.",
        inputSchema: {
          type: "object",
          properties: {
            format:  { type: "string", description: "Scanner format", enum: ["nmap","masscan","nuclei","nessus"] },
            content: { type: "string", description: "Raw scanner output content to parse" },
          },
          required: ["format", "content"],
        },
        async handler({ format, content }) {
          return security.scanner_parsers.parse(String(format) as any, String(content))
        },
      },

    {
        name: "ares_vuln_research",
        description: "Research vulnerabilities: query NVD API for CVEs, search exploit-db, correlate CVE IDs with known PoC exploits.",
        inputSchema: {
          type: "object",
          properties: {
            query:  { type: "string", description: "CVE ID (e.g. CVE-2024-1234), product name, or keyword" },
            limit:  { type: "number", description: "Max results (default 10)" },
          },
          required: ["query"],
        },
        async handler({ query, limit }) {
          const live = mcpLive()
          return dispatch.vulnResearch({ query: String(query), limit: Number(limit ?? 10) }, { live })
        },
      },

    {
        name: "ares_auto_research",
        description: "Automated vulnerability research pipeline: CVE correlation, patch diff analysis, automated PoC generation candidates.",
        inputSchema: {
          type: "object",
          properties: {
            target:   { type: "string", description: "Target software, version, or CVE ID" },
            strategy: { type: "string", description: "Research strategy", enum: ["cve","patch_diff","exploit_chain"] },
          },
          required: ["target"],
        },
        async handler({ target, strategy }) {
          const live = mcpLive()
          return dispatch.autoResearch({ target: String(target), strategy: String(strategy ?? "cve") }, { live })
        },
      }
  ]
}
