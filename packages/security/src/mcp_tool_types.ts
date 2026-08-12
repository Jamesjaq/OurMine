/**
 * Shared MCP tool type for mcp_server and bridged tool builder.
 */
export interface McpTool {
  name: string
  description: string
  inputSchema: {
    type: "object"
    properties: Record<string, { type: string; description: string; enum?: string[] }>
    required?: string[]
  }
  handler: (args: Record<string, unknown>) => Promise<unknown>
}

export default { McpTool: undefined as unknown as McpTool }
