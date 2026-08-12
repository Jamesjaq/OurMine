import type { McpTool } from "../mcp_tool_types.ts"
import { buildShellTools } from "./tools/shell.ts"
import { buildReconTools } from "./tools/recon.ts"
import { buildIdentityTools } from "./tools/identity.ts"
import { buildEngagementTools } from "./tools/engagement.ts"
import { buildIntelTools } from "./tools/intel.ts"
import { buildOffensiveTools } from "./tools/offensive.ts"
import { buildAuditTools } from "./tools/audit.ts"
import { buildOtTools } from "./tools/ot.ts"

/** Aggregate native MCP tool definitions from domain modules. */
export function buildNativeMcpTools(): McpTool[] {
  return [
    ...buildShellTools(),
    ...buildReconTools(),
    ...buildIdentityTools(),
    ...buildOffensiveTools(),
    ...buildOtTools(),
    ...buildAuditTools(),
    ...buildEngagementTools(),
    ...buildIntelTools(),
  ]
}

/** Sorted tool names for snapshot / drift tests. */
export function nativeMcpToolNames(): string[] {
  return buildNativeMcpTools().map((t) => t.name).sort()
}

export default { buildNativeMcpTools, nativeMcpToolNames }
