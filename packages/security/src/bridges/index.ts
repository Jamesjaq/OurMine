import { recon_bridge } from "./recon_bridge.ts"
import { identity_bridge } from "./identity_bridge.ts"
import { ot_bridge } from "./ot_bridge.ts"
import { raas_bridge } from "./raas_bridge.ts"
import { c2_bridge } from "./c2_bridge.ts"
import { audit_bridge } from "./audit_bridge.ts"
import { ares_bridge } from "./ares_bridge.ts"
import { tier1_bridge } from "./tier1_bridge.ts"
import type { AgentToolContext, ToolRunResult } from "../agent_tools.ts"

export const MODULE_BRIDGE: Record<
  string,
  (ctx: AgentToolContext, params: Record<string, unknown>) => Promise<ToolRunResult>
> = {
  ...recon_bridge,
  ...identity_bridge,
  ...ot_bridge,
  ...raas_bridge,
  ...c2_bridge,
  ...audit_bridge,
  ...ares_bridge,
  ...tier1_bridge,
}

export function bridgedToolNames(): string[] {
  return Object.keys(MODULE_BRIDGE)
}

export async function runBridgedModule(
  ctx: AgentToolContext,
  toolName: string,
  params: Record<string, unknown> = {},
): Promise<ToolRunResult | null> {
  const { normalizeModuleKey, MODULE_ALIASES } = await import("../module_registry.ts")
  const resolved = normalizeModuleKey(toolName)
  const fn = MODULE_BRIDGE[resolved] ?? MODULE_BRIDGE[toolName]
  if (!fn) return null
  const merged = { ...params }
  if (resolved !== toolName && MODULE_ALIASES[toolName] && resolved === "identity_playbooks" && !merged.playbook) {
    merged.playbook = toolName
  }
  return fn(ctx, merged)
}

export default { MODULE_BRIDGE, bridgedToolNames, runBridgedModule }
