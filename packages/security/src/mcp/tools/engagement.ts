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

export function buildEngagementTools(): McpTool[] {
  const { mcpLive, toolBroker, globalThrottleEngine } = mcpContext
  return [
    {
        name: "ares_pentest_plan",
        description: "Target-aware pentest plan (PentestGPT PTT-inspired): profiles target, infers objective, returns nextActions with exact MCP tool calls.",
        inputSchema: {
          type: "object",
          properties: {
            target:    { type: "string", description: "Target host, domain, or CIDR range" },
            scope:     { type: "string", description: "Comma-separated in-scope assets" },
            phase:     { type: "string", description: "Filter to a specific phase", enum: ["all","recon","initial_access","lateral_movement","priv_esc","persistence","exfiltration"] },
            objective: { type: "string", description: "Campaign objective hint: identity_first, ai_agent, supply_chain, cloud_ransom, ot_ics, telecom, ransomware_impact, standard" },
          },
          required: ["target"],
        },
        async handler({ target, scope, phase, objective }) {
          return buildActionablePlan(String(target), {
            scope: scope ? String(scope) : undefined,
            phase: phase ? String(phase) : undefined,
            objective: objective ? String(objective) : undefined,
          })
        },
      },

    {
        name: "ares_engagement_slice",
        description: "ONE autonomous engagement turn: buildActionablePlan + run first recommended phase + graph evidence (confirmed/candidates/blockers). Prefer this over plan+phase separately.",
        inputSchema: {
          type: "object",
          properties: {
            target:    { type: "string", description: "Target host, domain, or CIDR" },
            scope:     { type: "string", description: "Comma-separated in-scope assets" },
            objective: { type: "string", description: "Campaign objective hint (ot_ics, identity_first, hybrid_it_ot, etc.)" },
            actor:     { type: "string", description: "APT actor hint (Volt Typhoon, Lazarus, etc.)" },
            phase:     { type: "string", description: "Override first phase", enum: ["recon","identity","exploit","post_ex","apt"] },
          },
          required: ["target"],
        },
        async handler({ target, scope, objective, actor, phase }) {
          const live = mcpLive()
          return runEngagementSlice({
            target: String(target),
            live,
            scope: scope ? String(scope) : undefined,
            objective: objective ? String(objective) : undefined,
            aptHint: actor ? String(actor) : undefined,
            phase: phase ? String(phase) as import("./mcp_efficiency.ts").AresPhase : undefined,
          })
        },
      },

    {
        name: "ares_engagement_continue",
        description: "Resume multi-turn engagement from resumeToken — runs next uncompleted phase without re-planning. Use rt from prior slice/continue response.",
        inputSchema: {
          type: "object",
          properties: {
            resumeToken: { type: "string", description: "rt from prior ares_engagement_slice or ares_engagement_continue" },
            phase:       { type: "string", description: "Optional phase override", enum: ["recon","identity","exploit","post_ex","apt"] },
          },
          required: ["resumeToken"],
        },
        async handler({ resumeToken, phase }) {
          const { runEngagementContinue } = await import("./engagement_slice.ts")
          return runEngagementContinue({
            resumeToken: String(resumeToken),
            phase: phase ? String(phase) as import("./mcp_efficiency.ts").AresPhase : undefined,
          })
        },
      },

    {
        name: "ares_autopilot",
        description: "Autonomous tier-1 campaign loop: slice → graphNextActions → execute top action until maxPhases or scope/human blocker. ONE LLM turn replaces N manual phase turns.",
        inputSchema: {
          type: "object",
          properties: {
            target:     { type: "string", description: "Target host, domain, or CIDR" },
            scope:      { type: "string", description: "Comma-separated authorized CIDRs/domains" },
            maxPhases:  { type: "number", description: "Max server-side phase iterations (default 5)" },
          },
          required: ["target"],
        },
        async handler({ target, scope, maxPhases }) {
          const live = mcpLive()
          return runEngagementAutopilot({
            target: String(target),
            scope: scope ? String(scope) : undefined,
            maxPhases: maxPhases != null ? Number(maxPhases) : undefined,
            live,
          })
        },
      },

    {
        name: "ares_artifact_get",
        description: "Retrieve full MCP tool payload stored under .ourmine/ares/artifacts/ when compact response included artifactId.",
        inputSchema: {
          type: "object",
          properties: {
            id: { type: "string", description: "Artifact id from prior tool response" },
          },
          required: ["id"],
        },
        async handler({ id }) {
          const payload = readArtifact(String(id))
          if (payload == null) return { error: `artifact not found: ${id}`, summary: "not found" }
          return { artifactId: String(id), payload }
        },
      },

    {
        name: "ares_pentest_run",
        description: "Run the full autonomous PentestGPT agent: spawns parallel subagents for recon, AD attack, web exploit, and infrastructure escape, then synthesizes findings.",
        inputSchema: {
          type: "object",
          properties: {
            target: { type: "string", description: "Primary target (domain or IP)" },
            scope:  { type: "string", description: "Comma-separated in-scope assets" },
          },
          required: ["target"],
        },
        async handler({ target, scope }) {
          const live = mcpLive()
          const scopes = String(scope ?? target).split(",").map(s => s.trim())
          const agent = new PentestAgent({ target: String(target), scope: scopes, live })
          return agent.runAutonomous()
        },
      },

    {
        name: "ares_engagement_watch",
        description: "Run engagement watch cycle: snapshot, delta findings, persist graph.",
        inputSchema: {
          type: "object",
          properties: {
            target: { type: "string" },
            live: { type: "boolean" },
          },
          required: ["target"],
        },
        async handler({ target, live: liveArg }) {
          const live = liveArg ?? mcpLive()
          const { runWatchCycle } = await import("./engagement_watch.ts")
          return runWatchCycle({ target: String(target), intervalMinutes: 60, live })
        },
      },

    {
        name: "ares_retest_finding",
        description: "Retest a finding against watch history for remediation status.",
        inputSchema: {
          type: "object",
          properties: {
            target: { type: "string" },
            findingId: { type: "string" },
            live: { type: "boolean" },
          },
          required: ["target", "findingId"],
        },
        async handler({ target, findingId, live: liveArg }) {
          const live = liveArg ?? mcpLive()
          const { retestFinding } = await import("./engagement_watch.ts")
          return retestFinding(String(target), String(findingId), { live })
        },
      }
  ]
}
