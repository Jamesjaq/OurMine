/**
 * Thin backward-compat re-export — MCP bootstrap lives in mcp/server.ts.
 */
export { startMcpServer, allMcpToolNames } from "./mcp/server.ts"
export { buildNativeMcpTools, nativeMcpToolNames } from "./mcp/register_tools.ts"
