/**
 * @module opencode_tool_policy
 * OpenCode-native tool globs + pentest agent allowlist (complements OURMINE_MCP_EFFICIENT).
 */
import { EFFICIENT_TOOL_ALLOWLIST } from "./mcp_efficiency.ts"

export const OPENCODE_ARES_SERVER = "ares"
export const OPENCODE_GH_GREP_SERVER = "gh_grep"
export const PENTEST_AGENT_NAME = "pentest"

/** Always available when efficient mode is OFF — search meta-tools + core routers. */
export const SEARCH_MODE_TOOL_ALLOWLIST = new Set([
  "bash",
  "ares_tool_search",
  "ares_tool_call",
  "ares_phase",
  "ares_dispatch",
  "ares_auto_chain",
  "ares_pentest_plan",
  "ares_intel_feed",
  "ares_threat_intel",
  "ares_pentest_run",
  "ares_opsec_throttle",
])

/** OpenCode names MCP tools as `{server}_{toolName}`. */
export function opencodeNamespacedTool(server: string, toolName: string): string {
  return `${server}_${toolName}`
}

/** Canonical engagement orchestration — default pentest agent path (not pentest_run). */
export const CANONICAL_PENTEST_TOOLS = [
  "ares_engagement_slice",
  "ares_engagement_continue",
  "ares_autopilot",
  "ares_artifact_get",
  "ares_threat_intel",
  "ares_pentest_plan",
  "bash",
] as const

/** Legacy LLM-steered path — requires OURMINE_PENTEST_RUN=1 on the agent. */
export const LEGACY_PENTEST_RUN_TOOL = "ares_pentest_run"

/** Pentest agent re-enables after global `ares_*: false`. */
export function buildPentestAgentToolAllowlist(opts: { ghGrep?: boolean; allowPentestRun?: boolean } = {}): Record<string, boolean> {
  const allow: Record<string, boolean> = {}
  const pentestRunEnabled =
    opts.allowPentestRun === true
    || process.env.OURMINE_PENTEST_RUN === "1"
    || process.env.OURMINE_PENTEST_RUN === "true"

  for (const tool of CANONICAL_PENTEST_TOOLS) {
    allow[opencodeNamespacedTool(OPENCODE_ARES_SERVER, tool)] = true
  }
  // Supplementary efficient tools (recon, dispatch) without pentest_run by default
  for (const tool of EFFICIENT_TOOL_ALLOWLIST) {
    if (tool === LEGACY_PENTEST_RUN_TOOL && !pentestRunEnabled) continue
    if (CANONICAL_PENTEST_TOOLS.includes(tool)) continue
    allow[opencodeNamespacedTool(OPENCODE_ARES_SERVER, tool)] = true
  }
  allow[opencodeNamespacedTool(OPENCODE_ARES_SERVER, "ares_tool_search")] = true
  allow[opencodeNamespacedTool(OPENCODE_ARES_SERVER, "ares_tool_call")] = true
  if (opts.ghGrep !== false) {
    allow[`${OPENCODE_GH_GREP_SERVER}*`] = true
  }
  return allow
}

/** Global OpenCode tools block — disable heavy MCP surfaces by default. */
export function buildGlobalToolDenylist(opts: { ghGrep?: boolean } = {}): Record<string, boolean> {
  const deny: Record<string, boolean> = {
    [`${OPENCODE_ARES_SERVER}_*`]: false,
  }
  if (opts.ghGrep !== false) {
    deny[`${OPENCODE_GH_GREP_SERVER}*`] = false
  }
  return deny
}

export function ghGrepEnabled(): boolean {
  return process.env.OURMINE_GH_GREP !== "0" && process.env.OURMINE_GH_GREP !== "false"
}

export function mergeOpenCodeToolPolicy(
  config: Record<string, unknown>,
  opts: { ghGrep?: boolean } = {},
): Record<string, unknown> {
  const gh = opts.ghGrep ?? ghGrepEnabled()
  const tools = { ...(config.tools as Record<string, boolean> | undefined), ...buildGlobalToolDenylist({ ghGrep: gh }) }
  const agent = { ...(config.agent as Record<string, unknown> | undefined) }
  const pentest = { ...(agent[PENTEST_AGENT_NAME] as Record<string, unknown> | undefined) }
  const pentestTools = {
    ...(pentest.tools as Record<string, boolean> | undefined),
    ...buildPentestAgentToolAllowlist({ ghGrep: gh }),
  }
  agent[PENTEST_AGENT_NAME] = { ...pentest, tools: pentestTools }
  return { ...config, tools, agent }
}

export function mergeGhGrepMcp(config: Record<string, unknown>, enabled = ghGrepEnabled()): Record<string, unknown> {
  if (!enabled) return config
  const mcp = { ...(config.mcp as Record<string, unknown> | undefined) }
  mcp[OPENCODE_GH_GREP_SERVER] = {
    type: "remote",
    url: "https://mcp.grep.app",
    enabled: true,
  }
  return { ...config, mcp }
}

export default {
  buildPentestAgentToolAllowlist,
  buildGlobalToolDenylist,
  mergeOpenCodeToolPolicy,
  mergeGhGrepMcp,
  opencodeNamespacedTool,
}
