/**
 * Tier-1 BAS goodies — RoE gate, report export, BloodHound, cred spray,
 * nuclei validation, passive intel, multi-target, T1451, sector plans.
 */
import { describe, test, beforeEach, afterEach } from "node:test"
import assert from "node:assert/strict"
import * as fs from "node:fs"
import * as path from "node:path"
import { AttackSurfaceGraph } from "../src/attack_surface.ts"
import { CredentialGraph } from "../src/credential_graph.ts"
import {
  evaluateRoeGate,
  isRoeSigned,
  hashScope,
} from "../src/roe_attestation.ts"
import {
  buildEngagementMarkdown,
  exportEngagementReport,
} from "../src/engagement_report.ts"
import {
  buildEngagementGraph,
  getNextActions,
  graphHasOpenSmb,
} from "../src/engagement_graph.ts"
import { runPassiveIntel, isPassiveIntelEnabled } from "../src/passive_intel.ts"
import { evaluateEngagementPolicy } from "../src/engagement_policy.ts"
import { buildFlowProfile } from "../src/target_flow.ts"
import { buildActionablePlan } from "../src/pentest_plan_builder.ts"
import { ValidationPlanner } from "../src/validation_planner.ts"
import { simSwapAwareness } from "../src/intel_autonomous.ts"
import { parseMultiTargets, requiresHumanIntervention, pickAutopilotAction } from "../src/engagement_autopilot.ts"
import { EXTERNAL_MODULES_BY_DESIGN } from "../src/module_registry.ts"
import { parseNucleiJson } from "../src/scanner_parsers.ts"

const ENV_BACKUP = { ...process.env }

beforeEach(() => {
  process.env = { ...ENV_BACKUP }
})

afterEach(() => {
  process.env = ENV_BACKUP
})

describe("bas goodies", () => {
  test("RoE gate blocks live without OURMINE_ROE_SIGNED=1", () => {
    delete process.env.OURMINE_ROE_SIGNED
    const blocked = evaluateRoeGate({ live: true, scope: ["corp.example.com"] })
    assert.equal(blocked.allowed, false)
    assert.ok(blocked.blockers[0].includes("OURMINE_ROE_SIGNED"))

    process.env.OURMINE_ROE_SIGNED = "1"
    const ok = evaluateRoeGate({ live: true, scope: ["corp.example.com"] })
    assert.equal(ok.allowed, true)
    assert.equal(isRoeSigned(), true)
    assert.ok(hashScope(["b.example.com", "a.example.com"]).length >= 8)
  })

  test("RoE gate wired into engagement_policy live blockers", () => {
    delete process.env.OURMINE_ROE_SIGNED
    const flow = buildFlowProfile("corp.example.com", "corp.example.com")
    const policy = evaluateEngagementPolicy({
      profile: flow,
      objective: "identity_first",
      live: true,
    })
    assert.ok(policy.blockers.some((b) => b.includes("RoE not attested")))
  })

  test("requiresHumanIntervention detects RoE blocker", () => {
    assert.ok(requiresHumanIntervention(["RoE not attested — set OURMINE_ROE_SIGNED=1"]))
  })

  test("pickAutopilotAction skips EXTERNAL_MODULES_BY_DESIGN (gh_grep)", () => {
    assert.ok(EXTERNAL_MODULES_BY_DESIGN.has("gh_grep"))
    const picked = pickAutopilotAction([
      {
        step: 1,
        label: "GitHub PoC hunt",
        tool: "gh_grep",
        args: { query: "CVE-2021-44228" },
        phase: "exploit",
        rationale: "MCP-only PoC search",
      },
      {
        step: 2,
        label: "Dispatch nuclei",
        tool: "ares_dispatch",
        args: { module: "nuclei_scan", target: "10.0.0.1" },
        phase: "exploit",
        rationale: "KEV validation",
      },
    ])
    assert.equal(picked?.tool, "ares_dispatch")
  })

  test("engagement report export produces markdown", () => {
    const eg = {
      target: "bank.example.com",
      objective: "identity_first",
      persona: "enterprise_ad",
      confirmed: [{ kind: "credential", label: "admin@CORP", detail: "harvest" }],
      candidates: [{ kind: "vuln", label: "Log4j", detail: "10.0.0.5:8080" }],
      blockers: [],
      otHosts: [],
    }
    const md = buildEngagementMarkdown(eg)
    assert.ok(md.includes("# Engagement Report"))
    assert.ok(md.includes("Confirmed Findings"))
    assert.ok(md.includes("admin@CORP"))

    const report = exportEngagementReport(eg)
    assert.ok(fs.existsSync(report.markdownPath))
    assert.ok(report.summary.includes("1 confirmed"))
  })

  test("BloodHound paths become engagement_graph candidates + nextAction", () => {
    const graph = new AttackSurfaceGraph("10.0.0.5")
    const credGraph = new CredentialGraph()
    credGraph.ingestBloodHoundPaths([
      { start: "user1", end: "DA", nodes: ["10.0.0.5", "DC01"], targetHosts: ["10.0.0.5"] },
    ])

    const eg = buildEngagementGraph({
      target: "corp.example.com",
      graph,
      credGraph,
      objective: "identity_first",
      live: false,
    })
    assert.ok(eg.candidates.some((c) => c.kind === "bloodhound_path"))

    const actions = getNextActions(eg, { credGraph })
    assert.ok(actions.some((a) => a.args.module === "pivot_replay"))
  })

  test("cred spray nextAction when creds + open SMB", () => {
    const graph = new AttackSurfaceGraph("10.0.0.5")
    const asset = graph.upsertAsset("10.0.0.5")
    asset.services.set(445, {
      port: 445,
      protocol: "tcp",
      state: "open",
      service: "microsoft-ds",
      version: "",
      evidence: [],
      vulns: [],
    })

    assert.ok(graphHasOpenSmb(graph))

    const credGraph = new CredentialGraph()
    credGraph.addCredential({
      type: "password",
      source: "harvest",
      username: "admin",
      domain: "CORP",
      value: "secret",
    })

    const eg = buildEngagementGraph({
      target: "10.0.0.5",
      graph,
      credGraph,
      objective: "identity_first",
      live: false,
    })

    const actions = getNextActions(eg, { credGraph, attackGraph: graph })
    assert.ok(actions.some((a) => a.args.module === "cred_spray"))
  })

  test("ValidationPlanner registers NUCLEI_PROBE for nuclei findings", () => {
    const planned = ValidationPlanner.plan({
      findingId: "vuln-1",
      templateId: "log4j-version-probe",
      service: "http",
      target: "127.0.0.1:8080",
      authorizedScope: "127.0.0.1",
    })
    assert.ok(planned.plan)
    assert.equal(planned.plan.strategy, "NUCLEI_PROBE")
    assert.ok(planned.plan.command?.includes("nuclei"))
  })

  test("passive intel cache-only when OURMINE_PASSIVE_INTEL=1 and no keys", async () => {
    process.env.OURMINE_PASSIVE_INTEL = "1"
    delete process.env.SHODAN_API_KEY
    delete process.env.CENSYS_API_ID
    delete process.env.CENSYS_API_SECRET

    const target = `bas-no-keys-${Date.now()}.example.com`
    const r = await runPassiveIntel(target, { live: false, forceRefresh: true })
    assert.equal(r.enabled, true)
    assert.equal(r.hits.length, 0)
    assert.ok(r.summary.includes("passive"))
  })

  test("parseMultiTargets splits scope list", () => {
    const targets = parseMultiTargets("a.example.com,b.example.com,10.0.0.0/24", "a.example.com")
    assert.equal(targets.length, 3)
    assert.ok(targets.includes("10.0.0.0/24"))
  })

  test("simSwapAwareness T1451 for finance hints (no execution)", () => {
    const hints = simSwapAwareness("generic_ip", "identity_first", "swift core banking")
    assert.ok(hints.length >= 2)
    assert.ok(hints.some((h) => h.includes("T1451")))
    assert.ok(hints.some((h) => h.includes("no automated execution")))
  })

  test("sector-specific nextActions for banking vs power plant", () => {
    const bankPlan = buildActionablePlan("bank.example.com", { objective: "swift iso20022 core banking" })
    assert.ok(bankPlan.nextActions.some((a) => a.args.module === "institutional_recon"))

    const plantPlan = buildActionablePlan("10.50.0.0/24", { objective: "ot_ics iec61850 substation" })
    assert.ok(plantPlan.nextActions.some((a) =>
      a.args.module === "ot_batch_scan" || plantPlan.objective === "ot_ics",
    ))
  })

  test("parseNucleiJson still parses for validation pipeline", () => {
    const raw = `{"template-id":"http-admin-path","info":{"name":"Admin","severity":"medium"},"matched-at":"http://127.0.0.1:8080/admin"}`
    const vulns = parseNucleiJson(raw)
    assert.equal(vulns.length, 1)
    assert.equal(vulns[0].id, "http-admin-path")
  })
})
