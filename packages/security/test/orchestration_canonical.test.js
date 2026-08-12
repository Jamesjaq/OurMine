/**
 * orchestration_canonical — engagement_slice is the default campaign entry.
 */
import { describe, test } from "node:test"
import assert from "node:assert/strict"
import {
  CANONICAL_PENTEST_TOOLS,
  LEGACY_PENTEST_RUN_TOOL,
  buildPentestAgentToolAllowlist,
  opencodeNamespacedTool,
  OPENCODE_ARES_SERVER,
} from "../src/opencode_tool_policy.ts"
import { buildActionablePlan } from "../src/pentest_plan_builder.ts"

const CANONICAL_OBJECTIVES = ["identity_first", "cloud_ransom", "ot_ics"]

describe("orchestration_canonical", () => {
  test("pentest agent allowlist prefers slice/continue/autopilot over pentest_run", () => {
    delete process.env.OURMINE_PENTEST_RUN
    const allow = buildPentestAgentToolAllowlist()
    for (const tool of CANONICAL_PENTEST_TOOLS) {
      assert.equal(allow[opencodeNamespacedTool(OPENCODE_ARES_SERVER, tool)], true, tool)
    }
    assert.equal(
      allow[opencodeNamespacedTool(OPENCODE_ARES_SERVER, LEGACY_PENTEST_RUN_TOOL)],
      undefined,
      "ares_pentest_run should require explicit enable",
    )
  })

  test("pentest_run enabled only with OURMINE_PENTEST_RUN=1", () => {
    process.env.OURMINE_PENTEST_RUN = "1"
    const allow = buildPentestAgentToolAllowlist()
    assert.equal(
      allow[opencodeNamespacedTool(OPENCODE_ARES_SERVER, LEGACY_PENTEST_RUN_TOOL)],
      true,
    )
    delete process.env.OURMINE_PENTEST_RUN
  })

  for (const objective of CANONICAL_OBJECTIVES) {
    test(`plan for ${objective} recommends engagement_slice entry`, () => {
      const plan = buildActionablePlan("corp.example.com", { objective })
      const codes = (plan.nextActions ?? []).map((a) => a.code ?? "").join(" ")
      const labels = (plan.nextActions ?? []).map((a) => a.label ?? "").join(" ").toLowerCase()
      const recommendsSlice =
        codes.includes("engagement_slice")
        || codes.includes("ares_engagement_slice")
        || labels.includes("engagement")
        || (plan.recommendedEntry ?? "").includes("engagement_slice")
      assert.ok(
        recommendsSlice || plan.nextActions?.some((a) => a.tool === "ares_engagement_slice"),
        `expected engagement_slice path for ${objective}: ${JSON.stringify(plan.nextActions?.slice(0, 2))}`,
      )
    })
  }
})
