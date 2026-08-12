/**
 * @module mcp_progress
 * MCP progress notifications for long-running tools (ares_phase, hybrid_pivot, batch scan).
 */

export type ProgressLevel = "debug" | "info" | "warning"

let progressSink: ((line: string) => void) | null = null

/** Wire MCP server stdout sink (one JSON-RPC notification per line). */
export function setMcpProgressSink(sink: ((line: string) => void) | null): void {
  progressSink = sink
}

export function mcpProgress(message: string, level: ProgressLevel = "info"): void {
  process.stderr.write(`[ares] ${message}\n`)
  if (!progressSink) return
  progressSink(JSON.stringify({
    jsonrpc: "2.0",
    method: "notifications/message",
    params: { level, data: message },
  }))
}

export function mcpProgressStep(phase: string, module: string, status: string, detail?: string): void {
  const msg = detail
    ? `${phase}/${module}: ${status} — ${detail.slice(0, 120)}`
    : `${phase}/${module}: ${status}`
  mcpProgress(msg)
}

export default { setMcpProgressSink, mcpProgress, mcpProgressStep }
