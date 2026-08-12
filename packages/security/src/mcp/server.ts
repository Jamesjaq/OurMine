#!/usr/bin/env node
/**
 * OurMine ARES MCP Server bootstrap (split from legacy mcp_server.ts).
 */
import * as path from "node:path"
import { fileURLToPath } from "node:url"
import { buildBridgedMcpTools } from "../mcp_bridged_tools.ts"
import {
  efficientMcpInstructions,
  filterToolsForEfficiency,
  isEfficientMode,
  searchModeMcpInstructions,
} from "../mcp_efficiency.ts"
import { buildToolSearchTools } from "../mcp_tool_search.ts"
import { formatMcpToolResponse, shouldThrottleTool } from "../mcp_response.ts"
import { setMcpProgressSink } from "../mcp_progress.ts"
import { mcpLive, mcpContext } from "./context.ts"
import { buildNativeMcpTools } from "./register_tools.ts"

function send(obj: unknown) {
  process.stdout.write(JSON.stringify(obj) + "\n")
}

function ok(id: unknown, result: unknown) {
  send({ jsonrpc: "2.0", id, result })
}

function err(id: unknown, code: number, message: string) {
  send({ jsonrpc: "2.0", id, error: { code, message } })
}

const tools = buildNativeMcpTools()
const existingToolNames = new Set(tools.map((t) => t.name))
tools.push(...buildBridgedMcpTools(existingToolNames, mcpLive))

const allTools = tools
const baseExposed = filterToolsForEfficiency(allTools)
const fullToolMap = new Map(allTools.map((t) => [t.name, t]))
const searchTools = isEfficientMode() ? [] : buildToolSearchTools(fullToolMap)
const toolsExposed = isEfficientMode() ? baseExposed : [...baseExposed, ...searchTools]

const toolMap = new Map(toolsExposed.map((t) => [t.name, t]))
const { globalThrottleEngine } = mcpContext

async function handleRequest(req: any) {
  const { id, method, params } = req

  switch (method) {
    case "initialize":
      ok(id, {
        protocolVersion: "2024-11-05",
        serverInfo: { name: "ourmine-ares", version: "1.0.0" },
        capabilities: { tools: {} },
        instructions: isEfficientMode()
          ? efficientMcpInstructions(toolsExposed.length)
          : searchModeMcpInstructions(toolsExposed.length, allTools.length),
      })
      break

    case "notifications/initialized":
      break

    case "tools/list":
      ok(id, {
        tools: toolsExposed.map((t) => ({
          name: t.name,
          description: t.description,
          inputSchema: t.inputSchema,
        })),
      })
      break

    case "tools/call": {
      const toolName = params?.name
      const toolArgs = params?.arguments ?? {}

      if (shouldThrottleTool(String(toolName ?? ""))) {
        await globalThrottleEngine.paceExecution()
      }

      const tool = toolMap.get(toolName)

      if (!tool) {
        err(id, -32601, `Unknown tool: ${toolName}`)
        break
      }

      try {
        const result = await tool.handler(toolArgs)
        const text = formatMcpToolResponse(result, { kind: String(toolName) })
        ok(id, {
          content: [{ type: "text", text }],
        })
      } catch (e: any) {
        ok(id, {
          content: [{ type: "text", text: `Error: ${e?.message ?? String(e)}` }],
          isError: true,
        })
      }
      break
    }

    case "ping":
      ok(id, {})
      break

    default:
      err(id, -32601, `Method not found: ${method}`)
  }
}

/** Start the MCP JSON-RPC server on stdin/stdout. Safe to call from `ourmine serve`. */
export function startMcpServer(): void {
  setMcpProgressSink((line) => process.stdout.write(`${line}\n`))
  let buffer = ""
  process.stdin.setEncoding("utf8")
  process.stdin.on("data", async (chunk: string) => {
    buffer += chunk
    const lines = buffer.split("\n")
    buffer = lines.pop() ?? ""
    for (const line of lines) {
      const trimmed = line.trim()
      if (!trimmed) continue
      try {
        const req = JSON.parse(trimmed)
        await handleRequest(req)
      } catch {
        // malformed JSON — ignore
      }
    }
  })

  process.stdin.on("end", () => process.exit(0))
  process.stderr.write(
    `[ourmine-ares MCP] started — ${toolsExposed.length} tools (${allTools.length} total, efficient=${isEfficientMode()})\n`,
  )
}

/** All registered tool names (native + bridged) for snapshot tests. */
export function allMcpToolNames(): string[] {
  return allTools.map((t) => t.name).sort()
}

const isMain =
  typeof process.argv[1] === "string" &&
  fileURLToPath(import.meta.url) === path.resolve(process.argv[1])

if (isMain) {
  startMcpServer()
}

export { allTools, toolsExposed, toolMap }

export default { startMcpServer, allMcpToolNames }
