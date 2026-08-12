/**
 * @module mcp_efficiency
 * Token-efficient MCP: compact outputs, phase bundling, slim tool surface.
 */
export function isEfficientMode(): boolean {
  return process.env.OURMINE_MCP_EFFICIENT !== "0"
    && process.env.OURMINE_MCP_EFFICIENT !== "false"
}

/** Tools exposed when efficient mode is ON (~16 vs 141). */
export const EFFICIENT_TOOL_ALLOWLIST = new Set([
  "bash",
  "ares_phase",
  "ares_pentest_plan",
  "ares_intel_feed",
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
])

export type AresPhase = "recon" | "identity" | "exploit" | "post_ex" | "apt"

export const PHASE_MODULES: Record<AresPhase, string[]> = {
  recon: ["intel_feed", "recon", "bountyhunter", "vuln_research"],
  identity: ["cred_access_auto", "kerberos_advanced", "lateral_scale"],
  exploit: ["strix_web", "ad_exploit", "evasion_engine", "network_exploit"],
  post_ex: ["auto_chain", "persistence_advanced", "exfil", "anti_forensics_advanced"],
  apt: ["orchestrator"],
}

/** Strip verbose payloads before they hit the LLM context. */
export function compactToolOutput(payload: unknown, maxLen = 1200): string {
  if (payload == null) return "{}"
  const p = payload as Record<string, unknown>

  const compact: Record<string, unknown> = {}

  for (const key of ["success", "dryRun", "summary", "objectiveMet", "executed", "built", "deployed", "probed", "succeeded", "total"]) {
    if (key in p) compact[key] = p[key]
  }

  if (typeof p.summary === "string") {
    compact.summary = p.summary
  }

  if (Array.isArray(p.phases)) {
    compact.phases = (p.phases as Array<{ phase?: string; success?: boolean; detail?: string; summary?: string }>).map((x) => ({
      phase: x.phase,
      ok: x.success,
      detail: (x.detail ?? x.summary ?? "").slice(0, 120),
    }))
  }

  if (Array.isArray(p.modules)) {
    compact.modules = (p.modules as Array<{ name?: string; success?: boolean; summary?: string; skipped?: boolean }>).map((m) => ({
      name: m.name,
      ok: m.success,
      skip: m.skipped,
      summary: (m.summary ?? "").slice(0, 100),
    }))
  }

  if (Array.isArray(p.steps)) {
    compact.steps = `${(p.steps as unknown[]).filter((s) => (s as { success?: boolean }).success !== false).length}/${(p.steps as unknown[]).length} ok`
  }

  if (Array.isArray(p.artifacts)) compact.artifactCount = (p.artifacts as unknown[]).length
  if (Array.isArray(p.techniques)) compact.techniques = (p.techniques as string[]).slice(0, 12)
  if (Array.isArray(p.findings)) compact.findingCount = (p.findings as unknown[]).length
  if (p.context && typeof p.context === "object") {
    const c = p.context as Record<string, unknown>
    compact.context = {
      domain: c.domain,
      canKerberos: c.canKerberos,
      canLateral: c.canLateral,
      krbtgt: c.krbtgtHash ? "(present)" : undefined,
    }
  }

  if (p.output && typeof p.output === "string") compact.output = (p.output as string).slice(0, 400)
  if (p.error) compact.error = String(p.error).slice(0, 200)

  const out = JSON.stringify(Object.keys(compact).length ? compact : { summary: String(p.summary ?? "ok").slice(0, 200) })
  return out.length > maxLen ? out.slice(0, maxLen - 3) + "..." : out
}

/** Slim surface when efficient mode is OFF — search meta-tools instead of 141 schemas. */
export const SEARCH_MODE_TOOL_ALLOWLIST = new Set([
  "bash",
  "ares_phase",
  "ares_pentest_plan",
  "ares_intel_feed",
  "ares_pentest_run",
  "ares_auto_chain",
  "ares_dispatch",
])

export function filterToolsForEfficiency<T extends { name: string }>(tools: T[]): T[] {
  if (isEfficientMode()) {
    return tools.filter((t) => EFFICIENT_TOOL_ALLOWLIST.has(t.name))
  }
  return tools.filter((t) => SEARCH_MODE_TOOL_ALLOWLIST.has(t.name))
}

export function searchModeMcpInstructions(toolCount: number, catalogSize: number): string {
  return `OurMine ARES search mode — ${toolCount} exposed tools (${catalogSize} searchable via ares_tool_search).

Workflow:
1. ares_tool_search(query) to find the right module
2. ares_tool_call(tool, arguments) to invoke it
3. ares_phase / ares_dispatch / ares_auto_chain for bundled work

Set OURMINE_MCP_EFFICIENT=1 for the default 16-tool curated surface.`
}

export function efficientMcpInstructions(toolCount: number): string {
  return `OurMine ARES efficient mode — ${toolCount} curated tools (full suite: set OURMINE_MCP_EFFICIENT=0).

Workflow (minimal turns):
1. ares_intel_feed + ares_pentest_plan(target)
2. ares_phase(phase,recon|identity|exploit|post_ex|apt) — runs full phase server-side in ONE call
3. ares_auto_chain when AD creds exist
4. ares_dispatch(module, params) for a single specific engine

Prefer ares_phase over calling many tools. Outputs are compact summaries — details live in .ourmine/ares/.`
}

export default {
  isEfficientMode,
  compactToolOutput,
  filterToolsForEfficiency,
  efficientMcpInstructions,
  searchModeMcpInstructions,
  EFFICIENT_TOOL_ALLOWLIST,
  SEARCH_MODE_TOOL_ALLOWLIST,
  PHASE_MODULES,
}
