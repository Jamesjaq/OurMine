/**
 * MCP tool name snapshot — prevents drift after mcp/ split.
 */
import { test } from "node:test"
import assert from "node:assert/strict"
import fs from "node:fs"
import path from "node:path"
import { fileURLToPath } from "node:url"

const SNAPSHOT = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "fixtures/mcp_tool_names.snapshot.json",
)

test("MCP tool names match snapshot", async () => {
  const { allMcpToolNames } = await import("../src/mcp/server.ts")
  const names = allMcpToolNames()

  if (!fs.existsSync(SNAPSHOT)) {
    fs.mkdirSync(path.dirname(SNAPSHOT), { recursive: true })
    fs.writeFileSync(SNAPSHOT, JSON.stringify(names, null, 2) + "\n")
    assert.ok(names.length >= 60, `expected rich MCP surface, got ${names.length}`)
    return
  }

  const expected = JSON.parse(fs.readFileSync(SNAPSHOT, "utf8"))
  assert.deepEqual(names, expected, "MCP tool name list drifted — update snapshot intentionally if tools added/removed")
  assert.ok(names.includes("ares_engagement_slice"))
  assert.ok(names.includes("bash"))
})
