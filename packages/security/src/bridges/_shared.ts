import type { AgentToolContext, ToolRunResult } from "../agent_tools.ts"

export function result(
  tool: string,
  command: string,
  ctx: AgentToolContext,
  payload: unknown,
  success = true,
): ToolRunResult {
  return {
    tool,
    command,
    dryRun: !ctx.live,
    success,
    output: JSON.stringify(payload).slice(0, 8000),
  }
}

export async function agentToolBridge(
  ctx: AgentToolContext,
  tool: string,
  params: Record<string, unknown>,
  bridgeKey: string,
): Promise<ToolRunResult> {
  const { executeAgentTool } = await import("../agent_tools.ts")
  const r = await executeAgentTool(ctx, tool, params)
  let payload: unknown = r.output
  try {
    payload = JSON.parse(r.output)
  } catch {
    /* raw string */
  }
  return result(bridgeKey, r.command, ctx, payload, r.success)
}
