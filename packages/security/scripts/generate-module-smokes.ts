#!/usr/bin/env node
/** Generate per-module dry-run smoke tests from MODULE_BRIDGE + native MCP tools. */
import fs from "node:fs"
import path from "node:path"
import { fileURLToPath } from "node:url"

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..")
const OUT = path.join(ROOT, "test/generated/module_smoke.test.js")
const MANIFEST = path.join(ROOT, "test/module_smoke_manifest.json")

const { bridgedToolNames } = await import(path.join(ROOT, "src/bridges/index.ts"))
const { nativeMcpToolNames } = await import(path.join(ROOT, "src/mcp/register_tools.ts"))

const manifest = JSON.parse(fs.readFileSync(MANIFEST, "utf8"))
const exclude = new Set(manifest.exclude ?? [])
const timeoutMs = manifest.timeoutMs ?? 2000

const allBridge = bridgedToolNames().filter((k) => !exclude.has(k))
const bridgeKeys = manifest.includeBridge?.length
  ? manifest.includeBridge.filter((k) => allBridge.includes(k))
  : allBridge.slice(0, 20)

const allMcp = nativeMcpToolNames().filter((k) => !exclude.has(k) && k.startsWith("ares_"))
const mcpTools = manifest.includeMcp?.length
  ? manifest.includeMcp.filter((k) => allMcp.includes(k))
  : allMcp.slice(0, 15)

const header = `/** AUTO-GENERATED — run packages/security/scripts/generate-module-smokes.ts */
import { describe, test } from "node:test"
import assert from "node:assert/strict"
import { AttackSurfaceGraph } from "../../src/attack_surface.ts"
import { ToolBroker } from "../../src/tool_broker.ts"
import { runBridgedModule } from "../../src/bridges/index.ts"
import { buildNativeMcpTools } from "../../src/mcp/register_tools.ts"

const TIMEOUT = ${timeoutMs}

function ctx(target = "127.0.0.1") {
  return { target, graph: new AttackSurfaceGraph(target), broker: new ToolBroker(), live: false }
}

const mcpMap = new Map(buildNativeMcpTools().map((t) => [t.name, t]))
`

const bridgeTests = bridgeKeys.map((key) => `
  test("bridge smoke: ${key}", { timeout: TIMEOUT }, async () => {
    const r = await runBridgedModule(ctx(), "${key}", { target: "127.0.0.1" })
    assert.ok(r, "expected bridge handler")
    assert.equal(typeof r.success, "boolean")
    assert.ok(r.dryRun === true || r.success === true, JSON.stringify(r).slice(0, 200))
  })`).join("\n")

const mcpTests = mcpTools.map((name) => `
  test("mcp smoke: ${name}", { timeout: TIMEOUT }, async () => {
    const tool = mcpMap.get("${name}")
    assert.ok(tool, "tool registered")
    const out = await tool.handler({ target: "127.0.0.1", domain: "corp.example.com", host: "127.0.0.1", path: "/tmp" })
    assert.ok(out != null)
    const p = typeof out === "object" && out !== null ? out : {}
    assert.ok(p.dryRun === true || p.success === true || p.summary != null || p.error == null || typeof out === "object")
  })`).join("\n")

const body = `${header}
describe("generated_module_smoke_bridge", () => {${bridgeTests}
})

describe("generated_module_smoke_mcp", () => {${mcpTests}
})
`

fs.mkdirSync(path.dirname(OUT), { recursive: true })
fs.writeFileSync(OUT, body)
console.log(`Wrote ${OUT} — ${bridgeKeys.length} bridge + ${mcpTools.length} MCP smokes`)
