/**
 * MCP tool search meta-tools
 */
import { describe, test } from "node:test"
import assert from "node:assert/strict"
import { searchToolCatalog, buildToolSearchTools } from "../src/mcp_tool_search.ts"

describe("mcp_tool_search", () => {
  test("searchToolCatalog ranks kerberos hits", () => {
    const catalog = [
      { name: "ares_kerberos_advanced", description: "Golden ticket forging" },
      { name: "ares_recon", description: "OSINT recon" },
      { name: "ares_bash", description: "Shell" },
    ]
    const hits = searchToolCatalog(catalog, "kerberos golden")
    assert.equal(hits[0]?.name, "ares_kerberos_advanced")
  })

  test("ares_tool_call invokes catalog tool", async () => {
    const map = new Map([
      ["ares_demo", {
        name: "ares_demo",
        description: "demo",
        inputSchema: { type: "object", properties: {} },
        async handler(args) {
          return { ok: true, x: args.x }
        },
      }],
    ])
    const [search, call] = buildToolSearchTools(map)
    assert.equal(search.name, "ares_tool_search")
    assert.equal(call.name, "ares_tool_call")

    const found = await search.handler({ query: "demo" })
    assert.ok(found.results.some((r) => r.name === "ares_demo"))

    const out = await call.handler({ tool: "ares_demo", arguments: JSON.stringify({ x: 1 }) })
    assert.deepEqual(out, { ok: true, x: 1 })
  })
})
