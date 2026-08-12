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

export function buildShellTools(): McpTool[] {
  const { mcpLive, toolBroker, globalThrottleEngine } = mcpContext
  return [
    {
        name: "bash",
        description: "Execute a validated command from the allowed security tool registry (nmap, apt, wallet CLIs, etc.). For pipes/scripts/complex shell, use OpenCode native bash instead.",
        inputSchema: {
          type: "object",
          properties: {
            command:  { type: "string",  description: "Security tool command to execute (e.g. nmap -sV target.com)" },
            cwd:      { type: "string",  description: "Working directory" },
          },
          required: ["command"],
        },
        async handler({ command, cwd }) {
          const live = mcpLive()
          if (!live) {
            return { stdout: "", stderr: "dry-run: pass --live or run on Kali", exitCode: 0, dryRun: true }
          }
          const gate = await gateExecution({ tool: "bash", command: String(command), live: true })
          if (!gate.allowed) {
            return { stdout: "", stderr: gate.review.mitigations.join("; "), exitCode: 1, opsec_blocked: true }
          }
          const cmd = gate.mitigatedCommand ?? String(command)
    
          try {
            const result = await toolBroker.executeSafe(cmd, cwd ? String(cwd) : process.cwd())
            return {
              stdout: ContextGuard.wrapUntrustedData("bash_stdout", result.stdout),
              stderr: ContextGuard.wrapUntrustedData("bash_stderr", result.stderr),
              exitCode: result.exitCode,
            }
          } catch (err: any) {
            return {
              stdout: "",
              stderr: ContextGuard.wrapUntrustedData("bash_error", err?.message ?? String(err)),
              exitCode: 1,
            }
          }
        },
      }
  ]
}
