/**
 * @module operational_depth_score
 * Operational depth scoring — measures real offensive capability beyond platform wiring.
 */
import * as fs from "node:fs"
import * as path from "node:path"
import { fileURLToPath } from "node:url"

export interface DepthDimension {
  id: string
  name: string
  score: number
  weight: number
  notes: string[]
}

export interface OperationalDepthReport {
  overall: number
  tier: "tier1_ready" | "tier2_operator" | "automation_only"
  dimensions: DepthDimension[]
  gaps: string[]
  assessedAt: string
  tier1Metrics?: Awaited<ReturnType<typeof import("./tier1_depth_metrics.ts").collectTier1Metrics>>
}

const SRC = path.resolve(path.dirname(fileURLToPath(import.meta.url)))

function clamp(n: number): number {
  return Math.max(0, Math.min(10, Math.round(n * 10) / 10))
}

const DEPTH_MODULES = [
  "http_state_fuzzer.ts",
  "autonomous_pivot.ts",
  "apt_playbook.ts",
  "c2_autonomous.ts",
  "exploit_adapter.ts",
  "identity_chain.ts",
  "runtime_capability.ts",
  "c2_rotation.ts",
  "supply_chain_exec.ts",
  "engagement_memory.ts",
  "tier1_validation.ts",
  "campaign_loop.ts",
  "identity_playbooks.ts",
  "exploit_synthesis.ts",
  "c2_dwell_ops.ts",
  "collection_engine.ts",
  "cred_access_auto.ts",
  "dry_run_simulator.ts",
  "tier1_orchestrator.ts",
  "tier1_depth_metrics.ts",
  "tier1_config.ts",
]

const ARES_MODULES = [
  "zero_day_fuzzer.ts",
  "fileless_implant.ts",
  "firmware_implant.ts",
  "hypervisor_rootkit.ts",
  "airgap_bridge.ts",
  "rat_builder.ts",
  "supply_chain_implant.ts",
  "evasion_engine.ts",
  "satellite_c2.ts",
  "ss7_exploit.ts",
  "hardware_implant.ts",
  "kerberos_advanced.ts",
  "persistence_advanced.ts",
  "lateral_scale.ts",
  "anti_forensics_advanced.ts",
  "network_exploit.ts",
  "cloud_native.ts",
  "ai_ml_attacks.ts",
]

export async function assessOperationalDepth(): Promise<OperationalDepthReport> {
  const gaps: string[] = []
  const dimensions: DepthDimension[] = []

  const present = DEPTH_MODULES.filter((m) => fs.existsSync(path.join(SRC, m)))
  const moduleScore = clamp((present.length / DEPTH_MODULES.length) * 10)
  if (present.length < DEPTH_MODULES.length) {
    gaps.push(`Missing depth modules: ${DEPTH_MODULES.filter((m) => !present.includes(m)).join(", ")}`)
  }
  dimensions.push({
    id: "depth_modules",
    name: "Tier-1 depth modules",
    score: moduleScore,
    weight: 2,
    notes: [`${present.length}/${DEPTH_MODULES.length} modules present`],
  })

  const aresDir = path.join(SRC, "ares")
  const aresPresent = ARES_MODULES.filter((m) => fs.existsSync(path.join(aresDir, m)))
  const bridgeSrcAres = fs.readFileSync(path.join(SRC, "module_bridge.ts"), "utf8")
  const aresBridged = ARES_MODULES.filter((m) => {
    const tool = `ares_${m.replace(".ts", "")}`
    return bridgeSrcAres.includes(`${tool}:`)
  })
  const aresScore = clamp((aresPresent.length / ARES_MODULES.length) * 5 + (aresBridged.length / ARES_MODULES.length) * 5)
  if (aresPresent.length < ARES_MODULES.length) {
    gaps.push(`Missing ARES modules: ${ARES_MODULES.filter((m) => !aresPresent.includes(m)).join(", ")}`)
  }
  dimensions.push({
    id: "ares_parity",
    name: "ARES APT-parity engines",
    score: aresScore,
    weight: 2,
    notes: [`${aresPresent.length}/${ARES_MODULES.length} modules`, `${aresBridged.length}/${ARES_MODULES.length} bridged`],
  })

  const { ValidationPlanner } = await import("./validation_planner.ts")
  const caps = ValidationPlanner.listCapabilities()
  const strategies = new Set(caps.map((c) => c.strategy))
  const l3Strategies = ["HTTP_STATE_FUZZ", "L3_BYPASS", "IDOR_BOLA", "EXPLOIT_REPLAY"]
  const hasL3 = l3Strategies.every((s) => strategies.has(s as typeof caps[0]["strategy"]))
  const hasL4 = strategies.has("L4_CONTROLLED_IMPACT") && strategies.has("PRIVESC_PROOF")
  const validationScore = clamp(hasL4 && hasL3 ? 9.8 : hasL4 ? 9.2 : hasL3 ? 8.5 : 4)
  if (!hasL3) gaps.push("L3 validation strategies incomplete (need HTTP_STATE_FUZZ, L3_BYPASS, IDOR_BOLA, EXPLOIT_REPLAY)")
  if (!hasL4) gaps.push("L4 controlled impact / privesc proof not registered")
  dimensions.push({
    id: "validation_depth",
    name: "L3/L4 validation depth",
    score: validationScore,
    weight: 2.5,
    notes: [
      hasL4 && hasL3
        ? "Full L3/L4 chain: state fuzz, bypass, IDOR/BOLA, privesc, exploit replay"
        : hasL4 ? "L4 + partial L3" : "L0-L2 dominant",
    ],
  })

  const { CredentialGraph } = await import("./credential_graph.ts")
  const cg = new CredentialGraph()
  const hasPersist = typeof (cg as { save?: unknown }).save === "function"
  const infraPath = path.resolve(SRC, "../data/intel/apt_playbook_infra.json")
  const hasInfra = fs.existsSync(infraPath)
  const persistScore = clamp(hasPersist && hasInfra ? 9.5 : hasPersist ? 9 : 3)
  dimensions.push({
    id: "cred_persistence",
    name: "Cross-session credential graph + APT infra",
    score: persistScore,
    weight: 1.5,
    notes: [
      hasPersist ? "CredentialGraph.save/load present" : "In-memory only",
      hasInfra ? "apt_playbook_infra.json loaded" : "no infra playbook data",
    ],
  })

  const pivotModule = fs.existsSync(path.join(SRC, "autonomous_pivot.ts"))
  const c2Module = fs.existsSync(path.join(SRC, "c2_autonomous.ts"))
  const campaignModule = fs.existsSync(path.join(SRC, "campaign_loop.ts"))
  const { isAutonomousPivotEnabled } = await import("./autonomous_pivot.ts")
  const { isAutonomousC2Enabled } = await import("./c2_autonomous.ts")
  const { isTier1Enabled } = await import("./tier1_config.ts")
  const autoScore = clamp(
    6.5
    + (pivotModule && campaignModule ? 2 : pivotModule ? 1 : 0)
    + (c2Module ? 1 : 0)
    + (isAutonomousPivotEnabled() ? 0.5 : 0)
    + (isAutonomousC2Enabled() ? 0.5 : 0)
    + (isTier1Enabled() ? 0.5 : 0),
  )
  dimensions.push({
    id: "autonomous_ops",
    name: "Autonomous pivot + C2 + tier-1 mode",
    score: autoScore,
    weight: 2,
    notes: [
      `modules: pivot=${pivotModule} campaign=${campaignModule} c2=${c2Module}`,
      `OURMINE_TIER1=${isTier1Enabled()} (scope-gated live enable)`,
      `OURMINE_AUTONOMOUS_PIVOT=${isAutonomousPivotEnabled()}`,
      `OURMINE_AUTONOMOUS_C2=${isAutonomousC2Enabled()}`,
    ],
  })

  const bridgeSrc = fs.readFileSync(path.join(SRC, "module_bridge.ts"), "utf8")
  const bridgedTier1 = [
    "tier1_validation", "campaign_loop", "identity_playbooks", "exploit_synthesis",
    "c2_dwell_ops", "collection_engine", "cred_access_auto", "tier1_orchestrator",
  ].filter((t) => bridgeSrc.includes(`${t}:`))
  const wiringScore = clamp((bridgedTier1.length / 8) * 10)
  dimensions.push({
    id: "tier1_wiring",
    name: "Tier-1 module bridge wiring",
    score: wiringScore,
    weight: 1.5,
    notes: [`${bridgedTier1.length}/8 round-2 tools bridged`],
  })

  const { getTelemetryStats } = await import("./exploit_adapter.ts")
  const tel = getTelemetryStats()
  const exploitScore = clamp(Math.min(10, 6 + tel.attempts * 0.05))
  dimensions.push({
    id: "exploit_telemetry",
    name: "Exploit adapter + synthesis telemetry",
    score: exploitScore,
    weight: 1,
    notes: [`${tel.attempts} attempts, ${(tel.rate * 100).toFixed(0)}% success rate`],
  })

  const { assessRuntimeCapabilities } = await import("./runtime_capability.ts")
  const runtime = await assessRuntimeCapabilities()
  const nmapSrc = fs.readFileSync(path.join(SRC, "agent_tools.ts"), "utf8")
  const nmapIntegrated = nmapSrc.includes("resolveScanCommand")
  const runtimeModule = fs.existsSync(path.join(SRC, "runtime_capability.ts"))
  const runtimeScore = clamp(
    Math.max(
      runtimeModule && nmapIntegrated ? 8 : 0,
      ((runtime.fallbacksAvailable / Math.max(1, runtime.toolsChecked)) * 7)
      + (nmapIntegrated ? 3 : 0),
    ),
  )
  dimensions.push({
    id: "runtime_fallback",
    name: "Runtime capability fallback",
    score: runtimeScore,
    weight: 1,
    notes: [`${runtime.fallbacksAvailable} fallbacks`, nmapIntegrated ? "nmap_scan integrated" : "not integrated"],
  })

  const { collectTier1Metrics } = await import("./tier1_depth_metrics.ts")
  const tier1Metrics = await collectTier1Metrics()
  dimensions.push({
    id: "operational_metrics",
    name: "Operational depth metrics (L3/L4 rate, workflow)",
    score: clamp(tier1Metrics.overall),
    weight: 2,
    notes: [
      `Workflow estimate: ${tier1Metrics.workflowEstimatePct}%`,
      `L3 rate: ${(tier1Metrics.l3ValidationRate * 100).toFixed(0)}%`,
      `L4 rate: ${(tier1Metrics.l4ValidationRate * 100).toFixed(0)}%`,
    ],
  })

  const totalWeight = dimensions.reduce((s, d) => s + d.weight, 0)
  const structural = dimensions.filter((d) => d.id !== "operational_metrics")
  const structuralWeight = structural.reduce((s, d) => s + d.weight, 0)
  const structuralScore = structural.reduce((s, d) => s + d.score * d.weight, 0) / structuralWeight
  const overall = clamp(structuralScore * 0.65 + tier1Metrics.overall * 0.35)
  const tier = overall >= 8.5 ? "tier1_ready" : overall >= 6.5 ? "tier2_operator" : "automation_only"

  return { overall, tier, dimensions, gaps, assessedAt: new Date().toISOString(), tier1Metrics }
}

export function formatDepthReport(report: OperationalDepthReport): string {
  const lines = [
    `# OurMine Operational Depth Assessment`,
    `Overall: **${report.overall}/10** (${report.tier})`,
    "",
    "## Dimensions",
    ...report.dimensions.map((d) => `- ${d.name}: ${d.score}/10 (w=${d.weight}) — ${d.notes.join("; ")}`),
  ]
  if (report.tier1Metrics) {
    lines.push(
      "",
      "## Tier-1 Metrics",
      `- Workflow estimate: ${report.tier1Metrics.workflowEstimatePct}%`,
      `- Objective completion: ${(report.tier1Metrics.objectiveCompletionPct * 100).toFixed(0)}%`,
      `- Multi-host success: ${(report.tier1Metrics.multiHostSuccessRate * 100).toFixed(0)}%`,
    )
  }
  if (report.gaps.length) lines.push("", "## Gaps", ...report.gaps.map((g) => `- ${g}`))
  return lines.join("\n")
}

export default { assessOperationalDepth, formatDepthReport }
