/**
 * Engagement autopilot dry-run tests
 */
import { describe, test } from "node:test"
import assert from "node:assert/strict"
import {
  runEngagementAutopilot,
  compareTurnEfficiency,
  hostInAuthorizedScope,
  requiresHumanIntervention,
  isActionInScope,
  pickAutopilotAction,
} from "../src/engagement_autopilot.ts"
import { readArtifact } from "../src/mcp_artifacts.ts"
import { buildFlowProfile } from "../src/target_flow.ts"
import { runEngagementSlice, runEngagementContinue } from "../src/engagement_slice.ts"
import { buildIntelNextActions } from "../src/intel_autonomous.ts"

describe("engagement_autopilot", () => {
  test("pickAutopilotAction skips gh_grep and picks next executable action", () => {
    const intelActions = buildIntelNextActions({
      target: "10.0.0.1",
      objective: "standard",
      stackCves: [{ cve: "CVE-2021-44228", product: "Log4j", cvss: 10, inKev: true, tools: ["nuclei_scan"] }],
      ransomActions: [],
      pocHints: [{ source: "gh_grep", query: "CVE-2021-44228 exploit poc", cve: "CVE-2021-44228" }],
      modules: [],
    })
    assert.ok(intelActions.some((a) => a.tool === "gh_grep"))
    const ghGrep = intelActions.find((a) => a.tool === "gh_grep")
    const actions = [
      ghGrep,
      {
        step: 99,
        label: "Continue engagement",
        tool: "ares_engagement_continue",
        args: { resumeToken: "eng_test" },
        phase: "exploit",
        rationale: "Server picks next uncompleted phase from resumeToken",
      },
    ]
    const picked = pickAutopilotAction(actions, "recon")
    assert.equal(picked?.tool, "ares_engagement_continue")
    assert.notEqual(picked?.tool, "gh_grep")
  })

  test("pickAutopilotAction returns null when only external tools present", () => {
    const picked = pickAutopilotAction([
      {
        step: 1,
        label: "GitHub PoC hunt",
        tool: "gh_grep",
        args: { query: "CVE-2021-44228" },
        phase: "exploit",
        rationale: "PoC research — use gh_grep MCP",
      },
    ])
    assert.equal(picked, null)
  })

  test("graphNextActions skips gh_grep from intel prefetch ordering", async () => {
    const r1 = await runEngagementSlice({
      target: "10.0.0.5",
      live: false,
      objective: "standard",
    })
    const withIntelGhGrep = [
      {
        step: 0,
        label: "GitHub PoC hunt",
        tool: "gh_grep",
        args: { query: "CVE test" },
        phase: "exploit",
        rationale: "intel prefetch",
      },
      ...r1.graphNextActions,
    ]
    const picked = pickAutopilotAction(withIntelGhGrep, r1.phaseResult.phase)
    assert.ok(picked)
    assert.notEqual(picked.tool, "gh_grep")
    assert.ok(r1.graphNextActions.some((a) => a.tool === "ares_engagement_continue"))
  })

  test("ares_engagement_continue advances phase (autopilot branch uses this path)", async () => {
    const r1 = await runEngagementSlice({
      target: "192.168.1.10",
      live: false,
      objective: "standard",
    })
    const continueAction = r1.graphNextActions.find((a) => a.tool === "ares_engagement_continue")
    assert.ok(continueAction)
    const r2 = await runEngagementContinue({
      resumeToken: String(continueAction.args.resumeToken ?? r1.resumeToken),
      phase: continueAction.args.phase,
    })
    assert.equal(r2.resumeToken, r1.resumeToken)
    assert.notEqual(r2.phaseResult.phase, r1.phaseResult.phase)
  })
  test("dry-run stops on live_required blocker", async () => {
    const r = await runEngagementAutopilot({
      target: "corp.example.com",
      scope: "corp.example.com,10.10.0.0/16",
      maxPhases: 5,
      live: false,
    })
    assert.ok(r.summary.includes("Autopilot"))
    assert.equal(r.dryRun, true)
    assert.equal(r.phasesRun, 1)
    assert.equal(r.stoppedReason, "live_required")
    assert.ok(r.artifactId)
    assert.equal(typeof r.confirmedCount, "number")
    assert.ok(r.blockers.some((b) => b.includes("dry-run")))

    const artifact = readArtifact(r.artifactId)
    assert.ok(artifact && typeof artifact === "object")
    assert.equal(artifact.phasesRun, 1)
  })

  test("AD domain infers identity_first objective in dry-run", async () => {
    const r = await runEngagementAutopilot({
      target: "corp.example.com",
      scope: "corp.example.com",
      maxPhases: 3,
      live: false,
    })
    const flow = buildFlowProfile("corp.example.com", "corp.example.com")
    assert.equal(flow.persona, "enterprise_ad")
    assert.equal(r.objective, "identity_first")
    assert.equal(r.persona, "enterprise_ad")
  })

  test("scope enforcement rejects out-of-scope pivot target", () => {
    const scope = ["corp.example.com", "10.10.0.0/16"]
    assert.equal(hostInAuthorizedScope("corp.example.com", scope), true)
    assert.equal(hostInAuthorizedScope("10.10.5.20", scope), true)
    assert.equal(hostInAuthorizedScope("evil.other.com", scope), false)
    assert.equal(hostInAuthorizedScope("192.168.1.5", scope), false)

    assert.equal(
      isActionInScope(
        {
          step: 1,
          label: "bad pivot",
          tool: "ares_dispatch",
          args: { module: "hybrid_pivot", target: "corp.example.com", plant_subnet: "192.168.50.0/24" },
          phase: "exploit",
          rationale: "test",
        },
        scope,
      ),
      false,
    )
  })

  test("requiresHumanIntervention detects blockers", () => {
    assert.ok(requiresHumanIntervention(["dry-run: live probes skipped — set OURMINE_LIVE=1"]))
    assert.ok(requiresHumanIntervention(["target foo outside declared scope: bar"]))
    assert.equal(requiresHumanIntervention(["module failed: timeout"]), null)
  })

  test("compareTurnEfficiency AD domain: 1 vs N turns", () => {
    const cmp = compareTurnEfficiency("corp.example.com", "corp.example.com,10.10.0.0/16")
    assert.equal(cmp.autopilotTurns, 1)
    assert.ok(cmp.manualTurns >= 4)
    assert.ok(cmp.manualWorkflow.includes("ares_engagement_slice"))
    assert.ok(cmp.manualWorkflow.some((w) => w.includes("campaign_loop") || w.includes("identity")))
    assert.ok(cmp.savings.includes("fewer LLM turns"))
  })
})
