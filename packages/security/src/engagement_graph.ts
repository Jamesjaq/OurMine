/**
 * @module engagement_graph
 * Unified read model: AttackSurfaceGraph + CredentialGraph + OT classifications.
 */
import type { AttackSurfaceGraph, VulnNode } from "./attack_surface.ts"
import type { CredentialGraph } from "./credential_graph.ts"
import type { OtHostClassification } from "./ot_batch_scan.ts"
import type { AresPhase } from "./mcp_efficiency.ts"
import type { PlanAction } from "./pentest_plan_builder.ts"
import { ValidationEngine } from "./validation_engine.ts"
import { ImpactDemonstrationEngine } from "./impact_engine.ts"
import { scoreOtSubnets, type SubnetScore } from "./pivot_scorer.ts"
import { evaluateEngagementPolicy } from "./engagement_policy.ts"
import { buildFlowProfile, inferFlowObjective, phasesForObjective, skipAdAutoChain } from "./target_flow.ts"
import { resolveLiveMode } from "./exec_options.ts"
import type { IntelPrefetchResult } from "./intel_autonomous.ts"
import { buildIntelNextActions } from "./intel_autonomous.ts"

export interface GetNextActionsOpts {
  resumeToken?: string
  engagementResumeToken?: string
  completedPhases?: AresPhase[]
  lastPhase?: AresPhase
  credGraph?: CredentialGraph
  attackGraph?: AttackSurfaceGraph
  intelPrefetch?: IntelPrefetchResult
}

function actionKey(a: PlanAction): string {
  return `${a.tool}|${JSON.stringify(a.args)}`
}

function pushUnique(actions: PlanAction[], action: PlanAction, seen: Set<string>): void {
  const key = actionKey(action)
  if (seen.has(key)) return
  seen.add(key)
  actions.push(action)
}

export interface EvidenceItem {
  kind: string
  label: string
  detail?: string
  severity?: string
  evidenceSnippet?: string
}

export interface ProximityEvidence {
  channel: "usb" | "wifi" | "ble"
  id: string
  title: string
  severity?: string
  detail?: string
}

export interface EngagementGraph {
  target: string
  objective: string
  persona: string
  confirmed: EvidenceItem[]
  candidates: EvidenceItem[]
  blockers: string[]
  otHosts: OtHostClassification[]
  pivotScores?: SubnetScore[]
  passiveHits?: Array<{ source: string; port?: number; service?: string; banner?: string }>
}

export function buildEngagementGraph(opts: {
  target: string
  graph: AttackSurfaceGraph
  credGraph: CredentialGraph
  otHosts?: OtHostClassification[]
  objective?: string
  live?: boolean
  extraBlockers?: string[]
  pivotScores?: SubnetScore[]
  proximityFindings?: ProximityEvidence[]
  personaOverride?: string
  passiveHits?: Array<{ source: string; port?: number; service?: string; banner?: string }>
}): EngagementGraph {
  const flow = buildFlowProfile(opts.target, undefined, opts.objective ?? opts.target)
  const objective = inferFlowObjective(flow, opts.objective)
  const policy = evaluateEngagementPolicy({
    profile: flow,
    objective,
    live: opts.live ?? resolveLiveMode(),
    credGraph: opts.credGraph,
  })

  const confirmed: EvidenceItem[] = []
  const candidates: EvidenceItem[] = []

  for (const [ip, asset] of Object.entries(opts.graph.toJSON().assets ?? {})) {
    const ad = asset as {
      services?: Record<string, { port?: number; service?: string; vulns?: VulnNode[] }>
      endpoints?: Array<{ path?: string; heuristic?: string }>
    }
    for (const [portStr, svc] of Object.entries(ad.services ?? {})) {
      for (const v of svc.vulns ?? []) {
        const item: EvidenceItem = {
          kind: "vuln",
          label: v.title ?? v.id ?? "finding",
          detail: `${ip}:${portStr}`,
          severity: v.severity,
          evidenceSnippet: v.evidence?.[0]?.rawOutput?.slice(0, 120),
        }
        if (v.state === "CONFIRMED") confirmed.push(item)
        else if (v.state !== "FALSE_POSITIVE") candidates.push(item)
      }
    }
    for (const ep of ad.endpoints ?? []) {
      if (ep.heuristic && ep.heuristic !== "other") {
        candidates.push({
          kind: "endpoint",
          label: ep.path ?? "/",
          detail: `${ip} [${ep.heuristic}]`,
        })
      }
    }
  }

  for (const cred of opts.credGraph.listCredentials()) {
    const item: EvidenceItem = {
      kind: "credential",
      label: `${cred.username ?? cred.type}@${cred.domain ?? cred.host ?? "?"}`,
      detail: cred.source,
    }
    if (cred.used || cred.role === "krbtgt" || cred.role === "dc_machine") confirmed.push(item)
    else candidates.push(item)
  }

  for (const pivot of opts.credGraph.toJSON().pivots ?? []) {
    if (pivot.success) {
      confirmed.push({ kind: "pivot", label: `${pivot.from}→${pivot.to}`, detail: pivot.method })
    }
  }

  for (const bh of opts.credGraph.getBloodHoundPaths().slice(0, 8)) {
    candidates.push({
      kind: "bloodhound_path",
      label: `${bh.start} → ${bh.end}`,
      detail: bh.targetHosts.join(", ") || bh.nodes.slice(-2).join("→"),
      severity: "high",
      evidenceSnippet: `BloodHound path via ${bh.nodes.length} node(s)`,
    })
  }

  for (const hit of opts.passiveHits ?? []) {
    candidates.push({
      kind: "passive_intel",
      label: hit.service ?? hit.source,
      detail: hit.port ? `port ${hit.port}` : hit.source,
      evidenceSnippet: hit.banner?.slice(0, 120),
    })
  }

  for (const ot of opts.otHosts ?? []) {
    const confirmedProbe = ot.probeSummary?.includes("read-property-ok")
      || ot.probeSummary?.includes("modbus-read-ok")
      || ot.probeSummary?.includes("dnp3-app-read-ok")
    const item: EvidenceItem = {
      kind: "ot_host",
      label: ot.host,
      detail: `${ot.protocols.join(",") || "probe"}${ot.probeSummary ? ` [${ot.probeSummary}]` : ""}`,
      severity: ot.otLikely ? "high" : "info",
      evidenceSnippet: ot.probeSummary,
    }
    if (ot.otLikely && (confirmedProbe || ot.openPorts.includes(502))) confirmed.push(item)
    else if (ot.otLikely || ot.openPorts.length) candidates.push(item)
  }

  const pivotScores = opts.pivotScores ?? scoreOtSubnets(
    flow.scope.filter((s) => s.includes("/") || /^\d+\.\d+\.\d+\.\d+$/.test(s)),
    opts.credGraph,
    [],
  )
  for (const ps of pivotScores.slice(0, 6)) {
    const item: EvidenceItem = {
      kind: "ot_pivot",
      label: ps.subnet,
      detail: `confidence=${ps.confidence}`,
      severity: ps.confidence >= 0.6 ? "high" : "medium",
      evidenceSnippet: ps.reason,
    }
    if (ps.confidence >= 0.6) candidates.push(item)
    else if (ps.confidence >= 0.35) candidates.push(item)
  }

  for (const pf of opts.proximityFindings ?? []) {
    const item: EvidenceItem = {
      kind: pf.channel === "usb" ? "usb_finding" : pf.channel === "wifi" ? "wifi_finding" : "ble_device",
      label: pf.title,
      detail: pf.detail,
      severity: pf.severity,
    }
    if (pf.severity === "high" || pf.severity === "critical") confirmed.push(item)
    else candidates.push(item)
  }

  const pivotBlockers: string[] = []
  if (objective === "hybrid_it_ot" && pivotScores.length === 0) {
    pivotBlockers.push("hybrid_it_ot: no OT subnets inferred — set OURMINE_OT_SUBNETS or pass plant_subnet")
  }
  if (objective === "hybrid_it_ot" && pivotScores[0] && pivotScores[0].confidence < 0.35) {
    pivotBlockers.push(`hybrid_it_ot: low pivot confidence (${pivotScores[0].confidence}) on ${pivotScores[0].subnet}`)
  }

  const blockers = [...policy.blockers, ...pivotBlockers, ...(opts.extraBlockers ?? [])].slice(0, 16)

  return {
    target: opts.target,
    objective,
    persona: opts.personaOverride ?? flow.persona,
    confirmed: confirmed.slice(0, 24),
    candidates: candidates.slice(0, 24),
    blockers,
    otHosts: opts.otHosts ?? [],
    pivotScores: pivotScores.slice(0, 8),
  }
}

export function graphHasOpenSmb(graph?: AttackSurfaceGraph): { host: string; port: number } | null {
  if (!graph) return null
  for (const [ip, asset] of Object.entries(graph.toJSON().assets ?? {})) {
    for (const [portStr, svc] of Object.entries(
      (asset as { services?: Record<string, { service?: string; state?: string }> }).services ?? {},
    )) {
      const port = parseInt(portStr, 10)
      const service = (svc.service ?? "").toLowerCase()
      if (port === 445 || service.includes("smb") || service.includes("microsoft-ds")) {
        if (svc.state !== "closed") return { host: ip, port: port || 445 }
      }
    }
  }
  return null
}

/** Deterministic next actions from graph state (not LLM). */
export function getNextActions(eg: EngagementGraph, opts: GetNextActionsOpts = {}): PlanAction[] {
  const flow = buildFlowProfile(eg.target, undefined, eg.objective)
  const objective = eg.objective as import("./target_flow.ts").FlowObjective
  const phases = phasesForObjective(objective)
  const completed = opts.completedPhases ?? []
  const lastPhase = opts.lastPhase ?? completed[completed.length - 1]
  const actions: PlanAction[] = []
  const seen = new Set<string>()
  let step = 1

  // 0b. BloodHound path replay when paths ingested
  const bhPaths = opts.credGraph?.getBloodHoundPaths() ?? []
  if (bhPaths.length && (eg.persona === "enterprise_ad" || objective === "identity_first")) {
    pushUnique(actions, {
      step: step++,
      label: "BloodHound pivot replay",
      tool: "ares_dispatch",
      args: { module: "pivot_replay", target: eg.target, domain: bhPaths[0]!.start },
      mitre: "T1068",
      phase: "post_ex",
      rationale: `${bhPaths.length} BloodHound path(s) — netexec replay on path hosts`,
    }, seen)
  }

  // 0c. Credential spray when creds + open SMB
  const smbTarget = graphHasOpenSmb(opts.attackGraph)
  const graphCreds = opts.credGraph?.listCredentials().filter((c) => !c.used) ?? []
  if (graphCreds.length && smbTarget) {
    pushUnique(actions, {
      step: step++,
      label: `Cred spray → SMB ${smbTarget.host}`,
      tool: "ares_dispatch",
      args: { module: "cred_spray", target: smbTarget.host, service: "smb", port: String(smbTarget.port) },
      mitre: "T1110.003",
      phase: "exploit",
      rationale: `${graphCreds.length} unused cred(s) + open SMB — password spray path`,
    }, seen)
  }

  // 0. Autonomous intel prefetch — KEV/ransom/PoC hints (no LLM turn)
  if (opts.intelPrefetch) {
    for (const ia of buildIntelNextActions(opts.intelPrefetch)) {
      pushUnique(actions, { ...ia, step: step++ }, seen)
    }
  }

  // 1. Continue engagement — primary multi-turn path (no re-plan)
  if (opts.engagementResumeToken) {
    pushUnique(actions, {
      step: step++,
      label: "Continue engagement",
      tool: "ares_engagement_continue",
      args: { resumeToken: opts.engagementResumeToken },
      phase: lastPhase ?? "recon",
      rationale: "Server picks next uncompleted phase from resumeToken — no re-plan",
    }, seen)
  }

  // 2. AD auto-chain when creds confirmed
  const creds = opts.credGraph?.listCredentials() ?? []
  const hasDomainCreds = creds.some((c) => c.used || c.role === "krbtgt" || c.role === "dc_machine")
    || eg.confirmed.some((c) => c.kind === "credential")
  if (hasDomainCreds && !skipAdAutoChain(flow, objective)) {
    pushUnique(actions, {
      step: step++,
      label: "Auto-chain AD kill path",
      tool: opts.engagementResumeToken ? "ares_engagement_continue" : "ares_engagement_slice",
      args: opts.engagementResumeToken
        ? { resumeToken: opts.engagementResumeToken, phase: "post_ex" }
        : { target: eg.target, objective: eg.objective, phase: "post_ex" },
      mitre: "T1003",
      phase: "post_ex",
      rationale: "Confirmed domain creds — DCSync→Kerberos→lateral via engagement_slice post_ex",
    }, seen)
  }

  // 3. Identity phase when AD target and recon done, identity pending
  if (
    flow.isAdLikely
    && completed.includes("recon")
    && !completed.includes("identity")
    && phases.includes("identity")
  ) {
    pushUnique(actions, {
      step: step++,
      label: "Identity / Kerberos phase",
      tool: opts.engagementResumeToken ? "ares_engagement_continue" : "ares_engagement_slice",
      args: opts.engagementResumeToken
        ? { resumeToken: opts.engagementResumeToken, phase: "identity" }
        : { target: eg.target, phase: "identity", objective: eg.objective },
      mitre: "T1558",
      phase: "identity",
      rationale: "AD target after recon — cred access and Kerberos paths",
    }, seen)
  }

  // 4. Validate suspected vulns
  const vulnCandidates = eg.candidates.filter((c) => c.kind === "vuln")
  if (vulnCandidates.length) {
    pushUnique(actions, {
      step: step++,
      label: "Validate suspected findings",
      tool: opts.engagementResumeToken ? "ares_engagement_continue" : "ares_engagement_slice",
      args: opts.engagementResumeToken
        ? { resumeToken: opts.engagementResumeToken, phase: "exploit" }
        : { target: eg.target, objective: eg.objective, phase: "exploit" },
      phase: "exploit",
      rationale: `${vulnCandidates.length} candidate vuln(s) pending validation`,
    }, seen)
    const webVulns = vulnCandidates.filter((c) => c.detail?.includes(":80") || c.detail?.includes(":443") || c.detail?.includes(":8080"))
    if (webVulns.length) {
      pushUnique(actions, {
        step: step++,
        label: "Nuclei template validation",
        tool: "ares_dispatch",
        args: { module: "nuclei_scan", target: eg.target },
        mitre: "T1595.002",
        phase: "exploit",
        rationale: `${webVulns.length} web vuln candidate(s) — nuclei re-scan for validation`,
      }, seen)
    }
  }

  // 5. OT subnet sweep for CIDR / OT hosts
  if (flow.kind === "cidr" || eg.otHosts.length > 0) {
    const resumeArg = opts.resumeToken ? { resumeToken: opts.resumeToken } : {}
    pushUnique(actions, {
      step: step++,
      label: "Continue OT subnet sweep",
      tool: "ares_dispatch",
      args: { module: "ot_batch_scan", target: eg.target, ...resumeArg },
      mitre: "T0846",
      phase: "recon",
      rationale: eg.otHosts.length
        ? `${eg.otHosts.length} OT host(s) found — continue sweep or exploit`
        : "CIDR target — paginated ot_batch_scan with resumeToken",
    }, seen)
  }

  // 6. Hybrid IT→OT pivot / ranked OT sweep
  const scored = eg.pivotScores ?? scoreOtSubnets(
    flow.scope.filter((s) => s.includes("/") || /^\d+\.\d+\.\d+\.\d+$/.test(s)),
    opts.credGraph,
    [],
  )
  if (scored.length && (objective === "hybrid_it_ot" || eg.persona === "hybrid_it_ot")) {
    pushUnique(actions, {
      step: step++,
      label: `Pivot to ${scored[0]!.subnet} (${scored[0]!.confidence})`,
      tool: "ares_dispatch",
      args: { module: "hybrid_pivot", target: eg.target, plant_subnet: scored[0]!.subnet },
      mitre: "T0886",
      phase: "exploit",
      rationale: scored[0]!.reason,
    }, seen)
  } else if (scored.length && objective === "ot_ics") {
    pushUnique(actions, {
      step: step++,
      label: `Ranked sweep ${scored[0]!.subnet}`,
      tool: "ares_dispatch",
      args: { module: "ot_batch_scan", target: scored[0]!.subnet, ranked: true },
      mitre: "T0846",
      phase: "recon",
      rationale: `pivot_scorer conf=${scored[0]!.confidence}: ${scored[0]!.reason}`,
    }, seen)
  }

  const bleCandidates = eg.candidates.filter((c) => c.kind === "ble_device")
  if (bleCandidates.length || eg.persona === "iot_device") {
    pushUnique(actions, {
      step: step++,
      label: "BLE discovery follow-up",
      tool: "ares_dispatch",
      args: { module: "ble_audit", target: eg.target, objective: eg.objective },
      mitre: "T1011",
      phase: "recon",
      rationale: `${bleCandidates.length || "hinted"} BLE path(s) — bluetoothctl/hcitool scan`,
    }, seen)
  }

  if (eg.candidates.some((c) => c.kind === "usb_finding") || eg.persona === "physical_usb") {
    pushUnique(actions, {
      step: step++,
      label: "BadUSB / HID implant",
      tool: "ares_dispatch",
      args: { module: "ares_hardware_implant", target: eg.target, type: "usb" },
      mitre: "T1091",
      phase: "exploit",
      rationale: "USB proximity — BadUSB payload via ares_hardware_implant",
    }, seen)
  }

  if (eg.candidates.some((c) => c.kind === "wifi_finding") || eg.persona === "wireless_perimeter") {
    pushUnique(actions, {
      step: step++,
      label: "WiFi perimeter recon",
      tool: "ares_dispatch",
      args: { module: "wifi_audit", target: eg.target, objective: eg.objective },
      mitre: "T1557",
      phase: "recon",
      rationale: "Wireless perimeter — iw/nmcli before network_exploit",
    }, seen)
  }

  const hasCreds = eg.confirmed.some((c) => c.kind === "credential")
    || eg.candidates.some((c) => c.kind === "credential")
  const hasPivot = eg.confirmed.some((c) => c.kind === "pivot")

  if ((eg.persona === "enterprise_ad" || objective === "identity_first") && hasCreds) {
    pushUnique(actions, {
      step: step++,
      label: "AD post-ex slice",
      tool: opts.engagementResumeToken ? "ares_engagement_continue" : "ares_engagement_slice",
      args: opts.engagementResumeToken
        ? { resumeToken: opts.engagementResumeToken, phase: "post_ex" }
        : { target: eg.target, objective: eg.objective, phase: "post_ex" },
      mitre: "T1078",
      phase: "post_ex",
      rationale: "Creds in graph — auto_chain via engagement_slice post_ex",
    }, seen)
  }

  if (hasPivot && (eg.persona === "enterprise_ad" || objective === "identity_first")) {
    pushUnique(actions, {
      step: step++,
      label: "Continue lateral slice",
      tool: "ares_engagement_continue",
      args: opts.engagementResumeToken
        ? { resumeToken: opts.engagementResumeToken, phase: "post_ex" }
        : { target: eg.target, objective: eg.objective, phase: "post_ex" },
      mitre: "T1021",
      phase: "post_ex",
      rationale: "Prior pivot success — resume slice for scope-envelope lateral",
    }, seen)
    if (hasCreds) {
      pushUnique(actions, {
        step: step++,
        label: "Multi-host campaign loop",
        tool: "ares_dispatch",
        args: { module: "campaign_loop", target: eg.target, objective: eg.objective },
        mitre: "T1021",
        phase: "post_ex",
        rationale: "Confirmed creds + pivot — cred→BloodHound→tunnel campaign_loop",
      }, seen)
    }
  }

  if (eg.persona === "enterprise_ad" && phases.includes("apt") && hasCreds && hasPivot) {
    pushUnique(actions, {
      step: step++,
      label: "Tier-1 depth slice",
      tool: opts.engagementResumeToken ? "ares_engagement_continue" : "ares_engagement_slice",
      args: opts.engagementResumeToken
        ? { resumeToken: opts.engagementResumeToken, phase: "apt" }
        : { target: eg.target, objective: eg.objective, phase: "apt" },
      phase: "apt",
      rationale: "AD creds + pivot — full tier-1 orchestrator via engagement_slice apt",
    }, seen)
  }

  if (objective === "supply_chain" || eg.persona === "supply_chain_repo") {
    pushUnique(actions, {
      step: step++,
      label: "Supply chain audit",
      tool: "ares_dispatch",
      args: { module: "supply_chain_exec", target: eg.target, objective: eg.objective },
      mitre: "T1195",
      phase: "exploit",
      rationale: "Supply chain objective — npm/CI/CD compromise path",
    }, seen)
    pushUnique(actions, {
      step: step++,
      label: "CI/CD implant chain",
      tool: "ares_dispatch",
      args: { module: "ares_supply_chain_implant", target: eg.target },
      mitre: "T1195.002",
      phase: "exploit",
      rationale: "Registry + workflow poison via ares_supply_chain_implant",
    }, seen)
  }

  if (
    eg.persona === "cloud_saas"
    || eg.persona === "container_k8s"
    || eg.persona === "esxi_hypervisor"
    || objective === "cloud_ransom"
  ) {
    pushUnique(actions, {
      step: step++,
      label: "Cloud-native attack surface",
      tool: "ares_dispatch",
      args: { module: "ares_cloud_native", target: eg.target, objective: eg.objective },
      mitre: "T1526",
      phase: "exploit",
      rationale: "Cloud persona — IMDS/IAM/K8s breakout via ares_cloud_native",
    }, seen)
    pushUnique(actions, {
      step: step++,
      label: "Multi-cloud ASM fuse",
      tool: "ares_dispatch",
      args: { module: "multi_cloud_asm", target: eg.target },
      mitre: "T1580",
      phase: "recon",
      rationale: "Fuse cloud assets into attack surface graph",
    }, seen)
  }

  if (eg.persona === "telecom_carrier" || objective === "telecom") {
    pushUnique(actions, {
      step: step++,
      label: "SS7 / MAP exploit",
      tool: "ares_dispatch",
      args: { module: "ares_ss7_exploit", target: eg.target },
      mitre: "T1565",
      phase: "exploit",
      rationale: "Telecom persona — SS7 MAP scaffold + live telecom audit",
    }, seen)
  }

  if (eg.persona === "web_app" || eg.persona === "ai_agent_surface" || objective === "ai_agent") {
    if (vulnCandidates.length) {
      pushUnique(actions, {
        step: step++,
        label: "Strix web fuzz",
        tool: "ares_dispatch",
        args: { module: "strix_web", target: eg.target, attack: "form_fuzz" },
        mitre: "T1190",
        phase: "exploit",
        rationale: `${vulnCandidates.length} web candidate(s) — StrixCoordinator fuzz`,
      }, seen)
      pushUnique(actions, {
        step: step++,
        label: "Exploit adapter ranking",
        tool: "ares_dispatch",
        args: { module: "exploit_adapter", target: eg.target, list: "true" },
        mitre: "T1210",
        phase: "exploit",
        rationale: "Rank MSF/exploit modules for confirmed services",
      }, seen)
    }
  }

  if (hasPivot && (objective === "hybrid_it_ot" || eg.persona === "hybrid_it_ot")) {
    pushUnique(actions, {
      step: step++,
      label: "Segment tunnel orchestration",
      tool: "ares_dispatch",
      args: { module: "segment_tunnel", target: eg.target },
      mitre: "T1021",
      phase: "post_ex",
      rationale: "IT→OT pivot success — segment tunnel for plant reach",
    }, seen)
    pushUnique(actions, {
      step: step++,
      label: "Autonomous pivot expand",
      tool: "ares_dispatch",
      args: { module: "autonomous_pivot", target: eg.target, objective: "recon_only" },
      mitre: "T1021",
      phase: "post_ex",
      rationale: "Expand scope envelope after hybrid pivot",
    }, seen)
  }

  if (eg.otHosts.length > 0 || objective === "ot_ics") {
    const otHost = eg.otHosts[0]?.host ?? eg.target
    pushUnique(actions, {
      step: step++,
      label: "Profinet L2 probe",
      tool: "ares_dispatch",
      args: { module: "profinet_l2", target: otHost, host: otHost },
      mitre: "T0846",
      phase: "recon",
      rationale: "OT host detected — Profinet DCP/S7 L2 discovery",
    }, seen)
  }

  if (hasCreds && (eg.persona === "enterprise_ad" || objective === "identity_first")) {
    pushUnique(actions, {
      step: step++,
      label: "Identity chain playbook",
      tool: "ares_dispatch",
      args: { module: "identity_chain", target: eg.target },
      mitre: "T1556",
      phase: "identity",
      rationale: "Domain creds — OAuth/SSO/PRT identity chain",
    }, seen)
  }

  // 7. Engagement report export when post-ex complete or findings confirmed
  if (completed.includes("post_ex") || (eg.confirmed.length >= 2 && completed.includes("exploit"))) {
    pushUnique(actions, {
      step: step++,
      label: "Export engagement report",
      tool: "ares_dispatch",
      args: { module: "engagement_report", target: eg.target, objective: eg.objective },
      mitre: "T1580",
      phase: "post_ex",
      rationale: `${eg.confirmed.length} confirmed finding(s) — markdown summary from graph`,
    }, seen)
  }

  // 8. Each remaining phase — deterministic order from phasesForObjective
  for (const phase of phases) {
    if (completed.includes(phase)) continue
    pushUnique(actions, {
      step: step++,
      label: `Phase: ${phase}`,
      tool: opts.engagementResumeToken ? "ares_engagement_continue" : "ares_engagement_slice",
      args: opts.engagementResumeToken
        ? { resumeToken: opts.engagementResumeToken, phase }
        : { target: eg.target, objective: eg.objective, phase },
      phase,
      rationale: "Graph-driven phase advance",
    }, seen)
  }

  return actions.slice(0, 6).map((a, i) => ({ ...a, step: i + 1 }))
}

/** Run ValidationEngine on graph candidates where validators exist. */
export async function validateGraphCandidates(
  graph: AttackSurfaceGraph,
  live: boolean,
): Promise<{ validated: number; promoted: number }> {
  if (!live) return { validated: 0, promoted: 0 }
  let validated = 0
  let promoted = 0

  for (const [ip, asset] of Object.entries(graph.toJSON().assets ?? {})) {
    const ad = asset as { services?: Record<string, { service?: string; vulns?: VulnNode[] }> }
    for (const [portStr, svc] of Object.entries(ad.services ?? {})) {
      const port = parseInt(portStr, 10)
      for (const vuln of svc.vulns ?? []) {
        if (vuln.state !== "SUSPECTED" && vuln.state !== "VALIDATION_PENDING") continue
        const assetNode = graph.upsertAsset(ip)
        const svcNode = assetNode.services.get(port)
        const liveVuln = svcNode?.vulns.find((v) => v.id === vuln.id)
        if (!liveVuln) continue
        const result = await ValidationEngine.validate({
          vuln: liveVuln,
          ip,
          port,
          service: svc.service ?? "unknown",
          graph,
        })
        validated++
        if (result.validated && liveVuln.state === "CONFIRMED") promoted++
      }
    }
  }

  graph.invalidatePaths()
  return { validated, promoted }
}

/** ICS impact proof for every Modbus host — semantic process state promotes CONFIRMED. */
export async function proveOtImpacts(
  graph: AttackSurfaceGraph,
  otHosts: OtHostClassification[],
  live: boolean,
): Promise<EvidenceItem[]> {
  const proofs: EvidenceItem[] = []
  if (!live) return proofs

  const modbusHosts = otHosts.filter((h) => h.otLikely && h.openPorts.includes(502))
  for (const ot of modbusHosts) {
    const vuln: VulnNode = {
      id: `ics-${ot.host}-502`,
      title: `Modbus exposure ${ot.host}:502`,
      severity: "high",
      confidence: "suspected",
      state: "SUSPECTED",
      capLevel: 3,
      evidence: [],
    }
    const { proof, ics } = await ImpactDemonstrationEngine.demonstrateIcsImpact(vuln, ot.host, {
      port: 502,
      live: true,
    })
    if (proof) {
      const asset = graph.upsertAsset(ot.host)
      let svc = asset.services.get(502)
      if (!svc) {
        svc = {
          port: 502,
          protocol: "tcp",
          state: "open",
          service: "modbus",
          version: "",
          evidence: [],
          vulns: [],
        }
        asset.services.set(502, svc)
      }
      vuln.state = "CONFIRMED"
      vuln.confidence = "confirmed"
      vuln.evidence.push({
        id: proof.safeProofMarker,
        tool: "ics_impact",
        command: `demonstrateIcsImpact ${ot.host}:502`,
        rawOutput: proof.evidenceSnippet,
        parsedAt: proof.timestamp,
        executionMs: 0,
      })
      svc.vulns.push(vuln)
      proofs.push({
        kind: "ics_impact",
        label: ot.host,
        detail: ics.semantic?.impactNarrative?.slice(0, 80) ?? proof.proofType,
        severity: "high",
        evidenceSnippet: proof.evidenceSnippet.slice(0, 120),
      })
    }
  }

  return proofs
}

export default { buildEngagementGraph, getNextActions, validateGraphCandidates, proveOtImpacts }
