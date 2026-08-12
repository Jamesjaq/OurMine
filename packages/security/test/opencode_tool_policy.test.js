/**
 * OpenCode tool globs + pentest allowlist
 */
import { describe, test } from "node:test"
import assert from "node:assert/strict"
import {
  buildGlobalToolDenylist,
  buildPentestAgentToolAllowlist,
  mergeGhGrepMcp,
  mergeOpenCodeToolPolicy,
  opencodeNamespacedTool,
} from "../src/opencode_tool_policy.ts"

describe("opencode_tool_policy", () => {
  test("opencodeNamespacedTool prefixes server", () => {
    assert.equal(opencodeNamespacedTool("ares", "bash"), "ares_bash")
  })

  test("global denylist disables ares and gh_grep globs", () => {
    const deny = buildGlobalToolDenylist()
    assert.equal(deny["ares_*"], false)
    assert.equal(deny["gh_grep*"], false)
  })

  test("pentest allowlist re-enables curated ares tools", () => {
    const allow = buildPentestAgentToolAllowlist()
    assert.equal(allow.ares_bash, true)
    assert.equal(allow.ares_ares_phase, true)
    assert.equal(allow["gh_grep*"], true)
  })

  test("mergeOpenCodeToolPolicy wires agent.pentest.tools", () => {
    const out = mergeOpenCodeToolPolicy({ agent: { pentest: { mode: "primary" } } })
    assert.equal(out.tools["ares_*"], false)
    assert.equal(out.agent.pentest.tools.ares_bash, true)
  })

  test("mergeGhGrepMcp adds remote server", () => {
    const out = mergeGhGrepMcp({}, true)
    assert.equal(out.mcp.gh_grep.type, "remote")
    assert.equal(out.mcp.gh_grep.url, "https://mcp.grep.app")
  })
})
