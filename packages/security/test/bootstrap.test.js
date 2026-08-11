import test from "node:test"
import assert from "node:assert"
import fs from "node:fs"
import os from "node:os"
import path from "node:path"

test("bootstrapOpenCode wires ARES MCP and pentest agent", async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "ourmine-bootstrap-"))
  const configDir = path.join(tmp, "opencode")
  const prev = process.env.XDG_CONFIG_HOME
  process.env.XDG_CONFIG_HOME = tmp

  try {
    const { bootstrapOpenCode, mcpServerPath } = await import("../src/opencode_bootstrap.ts")
    assert.ok(fs.existsSync(mcpServerPath()), "mcp_server.ts should exist")

    const first = bootstrapOpenCode({ quiet: true })
    assert.ok(first.updated, "first bootstrap should write config")
    assert.ok(fs.existsSync(first.configPath), "opencode.json should exist")
    assert.ok(fs.existsSync(first.agentPath), "pentest agent should exist")

    const config = JSON.parse(fs.readFileSync(first.configPath, "utf8"))
    assert.strictEqual(config.default_agent, "pentest")
    assert.strictEqual(config.mcp?.ares?.type, "local")
    assert.ok(Array.isArray(config.mcp?.ares?.command))
    assert.ok(config.mcp.ares.command.some((c) => c.includes("mcp_server.ts")))

    const agent = fs.readFileSync(first.agentPath, "utf8")
    assert.ok(agent.includes("OurMine ARES"))
    assert.ok(agent.includes("mode: primary"))

    const second = bootstrapOpenCode({ quiet: true })
    assert.strictEqual(second.updated, false, "second bootstrap should be idempotent")
  } finally {
    if (prev === undefined) delete process.env.XDG_CONFIG_HOME
    else process.env.XDG_CONFIG_HOME = prev
    fs.rmSync(tmp, { recursive: true, force: true })
  }
})
