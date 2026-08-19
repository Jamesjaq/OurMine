/**
 * @module mcp_efficiency
 * Token-efficient MCP: compact outputs, phase bundling, slim tool surface.
 */
export function isEfficientMode(): boolean {
  return process.env.OURMINE_MCP_EFFICIENT !== "0"
    && process.env.OURMINE_MCP_EFFICIENT !== "false"
}

/** Tools exposed when efficient mode is ON (curated surface vs full catalog). */
export const EFFICIENT_TOOL_ALLOWLIST = new Set([
  "bash",
  "ares_engagement_slice",
  "ares_engagement_continue",
  "ares_engagement_watch",
  "ares_autopilot",
  "ares_artifact_get",
  "ares_phase",
  "ares_pentest_plan",
  "ares_intel_feed",
  "ares_threat_intel",
  "ares_recon",
  "ares_bountyhunter",
  "ares_vuln_research",
  "ares_ad_exploit",
  "ares_strix_web",
  "ares_exfil",
  "ares_counter_intel",
  "ares_pentest_run",
  "ares_auto_chain",
  "ares_dispatch",
  "cred_access_auto",
  "ares_orchestrator",
  "ares_evasion_engine",
  "ares_opsec_throttle",
  "ares_iot_scada",
  "ares_innovation_engine",
  "ares_self_healing",
  "ares_self_improvement",
  "ares_specialized_impact",
  "ares_ghost_autonomy",
  "ares_lateral_movement",
])

/** Verbose standalone audits excluded from default efficient surface — use ares_dispatch / ares_tool_search. */
export const EFFICIENT_TOOL_DENYLIST = new Set([
  "ares_lolbins_audit",
  "ares_ebpf_audit",
  "ares_uefi_bootkit_audit",
  "ares_ai_agent_audit",
  "ares_edge_appliance_audit",
  "ares_cicd_k8s_audit",
  "ares_adcs_audit",
  "ares_esxi_audit",
  "ares_opsec_review",
  "ares_proof_export",
  "ares_intel_watch",
  "ares_vx_lookup",
  "ares_stix_ingest",
  "ares_auto_research",
  "ares_scanner_parse",
  "ares_firmware",
  "ares_malware_dev",
  "ares_yara_scan",
  "ares_caldera_ttp",
  "ares_atlas_ml",
  "ares_supply_chain",
  "ares_campaign",
  "ares_raas_campaign",
  "ares_pivot_replay",
  "ares_topcut_assess",
])

export type AresPhase = "recon" | "identity" | "exploit" | "post_ex" | "apt"

export const PHASE_MODULES: Record<AresPhase, string[]> = {
  recon: ["intel_feed", "recon", "bountyhunter", "vuln_research", "ot_scan", "telecom_audit", "usb_audit", "wifi_audit", "ble_audit", "proximity_audit"],
  identity: ["cred_access_auto", "kerberos_advanced", "lateral_scale"],
  exploit: ["strix_web", "ad_exploit", "evasion_engine", "network_exploit", "iot_scada", "ss7_exploit"],
  post_ex: ["auto_chain", "persistence_advanced", "exfil", "anti_forensics_advanced", "impact_assess", "raas_campaign", "ics_impact_proof"],
  apt: ["orchestrator", "firmware_implant", "airgap_bridge", "hardware_implant", "hybrid_pivot"],
}

const STATUS_KEYS = [
  "success", "dryRun", "summary", "objectiveMet", "executed", "built", "deployed",
  "probed", "succeeded", "total", "exitCode", "opsec_blocked", "tool", "phase",
  "target", "objective", "count", "hint", "query",
] as const

function extractFallbackSummary(p: Record<string, unknown>): string {
  if (typeof p.summary === "string" && p.summary) return p.summary.slice(0, 200)
  if (typeof p.message === "string") return p.message.slice(0, 200)
  if (p.error) return String(p.error).slice(0, 200)
  if (typeof p.stdout === "string" && p.stdout.trim()) return p.stdout.trim().slice(0, 200)
  if (typeof p.stderr === "string" && p.stderr.trim()) return p.stderr.trim().slice(0, 200)
  return "ok"
}

/** Strip verbose payloads before they hit the LLM context. */
export function compactToolOutput(payload: unknown, maxLen = 1200): string {
  if (payload == null) return "{}"
  const p = payload as Record<string, unknown>

  const compact: Record<string, unknown> = {}

  for (const key of STATUS_KEYS) {
    if (key in p) compact[key] = p[key]
  }

  if (typeof p.stdout === "string" && p.stdout.trim()) {
    compact.stdout = p.stdout.trim().slice(0, 500)
  }
  if (typeof p.stderr === "string" && p.stderr.trim()) {
    compact.stderr = p.stderr.trim().slice(0, 300)
  }
  if (p.dryRun === true && !compact.stderr && typeof p.stderr === "string") {
    compact.reason = p.stderr.slice(0, 200)
  }
  if (p.opsec_blocked === true) {
    compact.reason = String(p.stderr ?? compact.stderr ?? "OPSEC gate blocked execution").slice(0, 200)
  }

  if (Array.isArray(p.phases)) {
    const first = (p.phases as unknown[])[0] as Record<string, unknown> | undefined
    if (first && typeof first.name === "string") {
      compact.phases = (p.phases as Array<{ name?: string; nodes?: number; aresPhase?: string; mitre?: string[] }>).map((x) => ({
        name: x.name,
        nodes: x.nodes,
        aresPhase: x.aresPhase,
        mitre: x.mitre?.slice(0, 4),
      }))
    } else {
      compact.phases = (p.phases as Array<{ phase?: string; success?: boolean; detail?: string; summary?: string }>).map((x) => ({
        phase: x.phase,
        ok: x.success,
        detail: (x.detail ?? x.summary ?? "").slice(0, 120),
      }))
    }
  }

  if (p.ptt && typeof p.ptt === "object") compact.ptt = p.ptt
  if (Array.isArray(p.recommendedPhases)) compact.recommendedPhases = p.recommendedPhases
  if (typeof p.workflow === "string") compact.workflow = p.workflow.slice(0, 200)

  if (Array.isArray(p.modules)) {
    compact.modules = (p.modules as Array<{ name?: string; success?: boolean; summary?: string; skipped?: boolean }>).map((m) => ({
      name: m.name,
      ok: m.success,
      skip: m.skipped,
      summary: (m.summary ?? "").slice(0, 100),
    }))
  }

  if (Array.isArray(p.steps)) {
    const steps = p.steps as Array<{ module?: string; success?: boolean; summary?: string }>
    if (steps.length && typeof steps[0]?.module === "string") {
      compact.steps = steps.map((s) => ({
        module: s.module,
        ok: s.success,
        summary: (s.summary ?? "").slice(0, 80),
      }))
    } else {
      compact.steps = `${steps.filter((s) => (s as { success?: boolean }).success !== false).length}/${steps.length} ok`
    }
  }

  if (Array.isArray(p.nextActions)) {
    compact.nextActions = (p.nextActions as Array<{ step?: number; tool?: string; label?: string }>).slice(0, 4)
  }

  if (p.profile && typeof p.profile === "object") {
    compact.profile = p.profile
  }

  if (Array.isArray(p.artifacts)) compact.artifactCount = (p.artifacts as unknown[]).length
  if (Array.isArray(p.techniques)) compact.techniques = (p.techniques as string[]).slice(0, 12)
  if (Array.isArray(p.findings)) compact.findingCount = (p.findings as unknown[]).length
  if (Array.isArray(p.discoveredLOLBins)) {
    compact.lolbinCount = (p.discoveredLOLBins as unknown[]).length
    compact.lolbinSample = (p.discoveredLOLBins as Array<{ name?: string }>).slice(0, 5).map((b) => b.name)
  }
  if (Array.isArray(p.skills)) compact.skillCount = (p.skills as unknown[]).length

  if (p.context && typeof p.context === "object") {
    const c = p.context as Record<string, unknown>
    compact.context = {
      domain: c.domain,
      canKerberos: c.canKerberos,
      canLateral: c.canLateral,
      krbtgt: c.krbtgtHash ? "(present)" : undefined,
    }
  }

  if (Array.isArray(p.results)) {
    compact.results = (p.results as Array<{ name?: string; score?: number }>).slice(0, 6)
  }

  if (p.error) compact.error = String(p.error).slice(0, 200)

  if (!("summary" in compact)) {
    const fallback = extractFallbackSummary(p)
    if (fallback !== "ok" || Object.keys(compact).length === 0) {
      compact.summary = fallback
    }
  }

  const out = JSON.stringify(Object.keys(compact).length ? compact : { summary: extractFallbackSummary(p) })
  return out.length > maxLen ? out.slice(0, maxLen - 3) + "..." : out
}

/** Slim surface when efficient mode is OFF — search meta-tools instead of full catalog schemas. */
export const SEARCH_MODE_TOOL_ALLOWLIST = new Set([
  "bash",
  "ares_engagement_slice",
  "ares_engagement_continue",
  "ares_autopilot",
  "ares_artifact_get",
  "ares_phase",
  "ares_pentest_plan",
  "ares_intel_feed",
  "ares_threat_intel",
  "ares_pentest_run",
  "ares_auto_chain",
  "ares_dispatch",
  "ares_opsec_throttle",
  "ares_iot_scada",
  "ares_tool_search",
  "ares_tool_call",
])

export function filterToolsForEfficiency<T extends { name: string }>(tools: T[]): T[] {
  const deny = (t: T) => !EFFICIENT_TOOL_DENYLIST.has(t.name)
  if (isEfficientMode()) {
    return tools.filter((t) => EFFICIENT_TOOL_ALLOWLIST.has(t.name) && deny(t))
  }
  return tools.filter((t) => SEARCH_MODE_TOOL_ALLOWLIST.has(t.name) && deny(t))
}

export function searchModeMcpInstructions(toolCount: number, catalogSize: number): string {
  return `OurMine ARES search mode — ${toolCount} exposed tools (${catalogSize} searchable via ares_tool_search).

Workflow:
1. ares_tool_search(query) to find the right module
2. ares_tool_call(tool, arguments) to invoke it
3. ares_phase / ares_dispatch / ares_auto_chain for bundled work

Set OURMINE_MCP_EFFICIENT=1 for the default curated surface (${EFFICIENT_TOOL_ALLOWLIST.size} tools).`
}

export function efficientMcpInstructions(toolCount: number): string {
  return `OurMine ARES efficient mode — ${toolCount} curated tools (full suite: set OURMINE_MCP_EFFICIENT=0).

Workflow (minimal turns):
1. ares_engagement_slice(target) — plan + first phase + graph (~400B: rt, na, aid)
2. ares_engagement_continue(resumeToken) — next phase without re-plan; follow na[] exactly
3. ares_autopilot(target) — full tier-1 loop in ONE call when fully autonomous
4. ares_artifact_get(aid) — full confirmed/candidates/steps when compact response includes aid
5. ares_auto_chain / ares_dispatch per na[] when graph lists them

Never re-plan after slice: use rt and na[].t/na[].a. Details in .ourmine/ares/.`
}

export default {
  isEfficientMode,
  compactToolOutput,
  filterToolsForEfficiency,
  efficientMcpInstructions,
  searchModeMcpInstructions,
  EFFICIENT_TOOL_ALLOWLIST,
  EFFICIENT_TOOL_DENYLIST,
  SEARCH_MODE_TOOL_ALLOWLIST,
  PHASE_MODULES,
}
