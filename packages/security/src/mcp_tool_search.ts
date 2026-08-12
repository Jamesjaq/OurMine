/**
 * @module mcp_tool_search
 * Fuse-style on-demand tool discovery when full MCP catalog is too large for context.
 */
import type { McpTool } from "./mcp_tool_types.ts"

export interface ToolCatalogEntry {
  name: string
  description: string
}

function norm(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, " ")
}

/** Lightweight fuzzy search (no fuse dependency). */
export function searchToolCatalog(catalog: ToolCatalogEntry[], query: string, limit = 10): Array<ToolCatalogEntry & { score: number }> {
  const q = norm(query.trim())
  if (!q) return catalog.slice(0, limit).map((t) => ({ ...t, score: 1 }))

  const terms = q.split(/\s+/).filter(Boolean)
  const scored: Array<ToolCatalogEntry & { score: number }> = []

  for (const entry of catalog) {
    const name = norm(entry.name)
    const desc = norm(entry.description)
    let score = 0
    for (const term of terms) {
      if (name === term) score += 50
      else if (name.startsWith(term)) score += 30
      else if (name.includes(term)) score += 20
      else if (desc.includes(term)) score += 10
    }
    if (score > 0) scored.push({ ...entry, score })
  }

  scored.sort((a, b) => b.score - a.score)
  return scored.slice(0, limit)
}

export function buildToolSearchTools(
  fullToolMap: Map<string, McpTool>,
): McpTool[] {
  const catalog: ToolCatalogEntry[] = [...fullToolMap.values()].map((t) => ({
    name: t.name,
    description: t.description,
  }))

  return [
    {
      name: "ares_tool_search",
      description: "Search the full OurMine tool catalog by keyword (use before ares_tool_call when efficient mode is off)",
      inputSchema: {
        type: "object",
        properties: {
          query: { type: "string", description: "Keywords e.g. kerberos, fuzz, exfil, supply chain" },
          limit: { type: "string", description: "Max results (default 8)" },
        },
        required: ["query"],
      },
      async handler(args) {
        const query = String(args.query ?? "")
        const limit = Number(args.limit ?? 8)
        const results = searchToolCatalog(catalog, query, limit)
        return {
          query,
          count: results.length,
          results: results.map((r) => ({ name: r.name, description: r.description.slice(0, 120), score: r.score })),
          hint: results[0] ? `Call ares_tool_call with tool=${results[0].name}` : "Try broader keywords",
        }
      },
    },
    {
      name: "ares_tool_call",
      description: "Invoke any OurMine tool by exact name (pairs with ares_tool_search)",
      inputSchema: {
        type: "object",
        properties: {
          tool: { type: "string", description: "Exact tool name from ares_tool_search results" },
          arguments: { type: "string", description: "JSON object of tool arguments" },
        },
        required: ["tool"],
      },
      async handler(args) {
        const toolName = String(args.tool ?? "")
        const t = fullToolMap.get(toolName)
        if (!t) {
          return { error: `Unknown tool: ${toolName}`, hint: "Run ares_tool_search first" }
        }
        let toolArgs: Record<string, unknown> = {}
        if (args.arguments) {
          try {
            toolArgs = typeof args.arguments === "string"
              ? JSON.parse(args.arguments)
              : (args.arguments as Record<string, unknown>)
          } catch {
            return { error: "Invalid JSON in arguments" }
          }
        }
        for (const [k, v] of Object.entries(args)) {
          if (!["tool", "arguments"].includes(k)) toolArgs[k] = v
        }
        return t.handler(toolArgs)
      },
    },
  ]
}

export default { searchToolCatalog, buildToolSearchTools }
