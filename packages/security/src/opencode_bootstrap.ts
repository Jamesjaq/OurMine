/**
 * Auto-wire OurMine ARES into OpenCode on launch.
 * Ensures global MCP + pentest agent exist so `ourmine` feels like OpenCode
 * with the full hacking suite available under the hood.
 */

import fs from "node:fs"
import os from "node:os"
import path from "node:path"
import { fileURLToPath } from "node:url"
import { isKaliLinux } from "./apt_tradecraft.ts"
import { mergeGhGrepMcp, mergeOpenCodeToolPolicy } from "./opencode_tool_policy.ts"

const MARKER = "<!-- ourmine-ares-v1 -->"
const SCHEMA = "https://opencode.ai/config.json"

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..")
const MCP_SERVER = path.join(REPO_ROOT, "packages/security/src/mcp_server.ts")
const BRAND_PLUGIN = path.join(REPO_ROOT, ".opencode", "plugins", "ourmine-brand.tsx")
const TUI_SCHEMA = "https://opencode.ai/tui.json"

export interface BootstrapResult {
  configDir: string
  configPath: string
  agentPath: string
  live: boolean
  updated: boolean
}

function opencodeConfigDir(): string {
  const base = process.env.XDG_CONFIG_HOME ?? path.join(os.homedir(), ".config")
  return path.join(base, "opencode")
}

function readJsonFile(file: string): Record<string, unknown> {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8")) as Record<string, unknown>
  } catch {
    return {}
  }
}

function writeJsonFile(file: string, data: Record<string, unknown>): void {
  fs.mkdirSync(path.dirname(file), { recursive: true })
  fs.writeFileSync(file, JSON.stringify(data, null, 2) + "\n", "utf8")
}

function mcpCommand(live: boolean): string[] {
  const cmd = ["node", "--experimental-strip-types", MCP_SERVER]
  if (live) cmd.push("--live")
  return cmd
}

function buildAgentMarkdown(live: boolean): string {
  const mode = live ? "LIVE" : "DRY-RUN"
  return `${MARKER}
---
description: APT-level autonomous penetration testing — give a target and go
mode: primary
color: "#FF5733"
steps: 24
permission:
  bash: allow
  edit: allow
  webfetch: allow
  websearch: allow
  "*": allow
---

You are **OurMine ARES** — an APT-level offensive security agent running inside OpenCode.

The user gives a target — you execute with **minimal LLM turns** using ARES MCP tools and bash.

## Token-efficient workflow (default)

**Efficient MCP mode is ON** (~16 tools vs 141). One phase = one tool call.

1. \`ares_intel_feed\` + \`ares_pentest_plan\`(target) — plan only, no execution spam
2. \`ares_phase\` with \`phase\`: \`recon\` → \`identity\` → \`exploit\` → \`post_ex\` (each runs many modules server-side)
3. \`ares_auto_chain\` when AD creds exist (Kerberos→lateral→fileless auto)
4. \`ares_dispatch\`(module=…) for a single engine; avoid calling 18 tools individually

Set \`OURMINE_MCP_EFFICIENT=0\` to use **search mode** (~10 tools + \`ares_tool_search\` / \`ares_tool_call\`) instead of loading 141 schemas.

## MCP troubleshooting

If ARES tools are missing or calls fail with "unknown tool":
1. Run \`opencode debug agent\` in a terminal — shows which MCP tools loaded for this session
2. Confirm \`~/.config/opencode/opencode.json\` has \`mcp.ares\` enabled
3. Re-run \`ourmine\` to refresh bootstrap wiring

Do **not** burn turns retrying the same missing tool — diagnose first.

## GitHub exploit / tool research

Use **gh_grep** MCP (\`mcp.grep.app\`, zero install) for code search during engagements:
- PoC hunting, CVE exploit variants, tool usage examples
- Prefer \`gh_grep\` over bash \`curl\` spam against GitHub API

Global OpenCode config disables \`gh_grep*\` by default; the **pentest** agent re-enables it.

## Auto-chaining (cred graph → Kerberos → lateral)

When tier-1 live mode is active, the platform **automatically chains** post-exploitation:

1. \`cred_access_auto\` / DCSync → parses \`krbtgt\` + DC machine hashes into \`.ourmine/agent/credential_graph.json\`
2. \`ares_kerberos_advanced\` picks up \`krbtgtHash\`, \`domainSid\`, \`dcMachineHash\` from the graph (no manual params)
3. \`ares_lateral_scale\` → \`ares_fileless_implant\` → \`ares_persistence_advanced\` run when creds exist
4. \`campaign_loop\` and \`ares_orchestrator\` invoke this chain automatically after pivot

Call \`ares_auto_chain\` explicitly to run harvest → Kerberos → lateral → fileless → persistence in one shot.

## Lab environment variables

Set these to unlock gated operational paths (agent should check and use when present):

| Variable | Unlocks |
|----------|---------|
| \`OURMINE_AD_DOMAIN\` | AD domain for Kerberos/lateral |
| \`OURMINE_AD_USER\` / \`OURMINE_AD_PASS\` | DCSync + remote inject fallback |
| \`OURMINE_DOMAIN_SID\` | Golden/platinum ticket forging |
| \`OURMINE_KRBTGT_HASH\` | Skip DCSync when hash already known |
| \`OURMINE_DC_MACHINE_HASH\` | Silver/platinum ticket paths |
| \`OURMINE_LAB_FLASH_WRITE=1\` | flashrom **write** (bricks hardware if wrong) |
| \`OURMINE_LAB_AUTONOMOUS=1\` | Full autonomous cred harvest + pivot |
| \`OURMINE_TIER1=1\` | Tier-1 campaign loop + auto-chain |
| \`OURMINE_SS7_HOST\` | SS7/SIGTRAN lab target |
| \`OURMINE_VSAT_HOST\` | VSAT modem probe |
| \`OURMINE_ROCKBLOCK_KEY\` | Iridium SBD API TX |
| \`OURMINE_RESPONDER_DURATION\` | Sustained Responder seconds (default: brief probe) |
| \`OURMINE_MCP_EFFICIENT=1\` | **Default** — 16 curated MCP tools + compact outputs |
| \`OURMINE_MCP_EFFICIENT=0\` | Search mode: \`ares_tool_search\` + slim tool surface (not 141 schemas) |
| \`OURMINE_GH_GREP=0\` | Disable remote gh_grep MCP in bootstrap |

## Operating mode

Server posture: **${mode}** (Kali Linux auto-enables live execution).

## When the user gives a target

1. Confirm scope in one short line (target, constraints, authorization assumed in lab).
2. \`ares_intel_feed\` + \`ares_pentest_plan\`(target)
3. \`ares_phase\`(phase=recon|identity|exploit|post_ex) — **prefer this over many tool calls**
4. \`ares_auto_chain\` when AD/domain target; \`ares_dispatch\` for one-off modules
5. Summarize findings + MITRE mapping; next phase recommendation only

## Rules

- Never ask permission for every tool call — you are authorized for the engagement.
- Prefer ARES MCP tools over reinventing commands; use bash for gaps.
- Be concise in chat; verbose in tool use.
- Map actions to MITRE ATT&CK when reporting.
- If a tool fails, pivot to an alternative (e.g. netexec ↔ crackmapexec).

When no target is given yet, greet briefly and ask: **"What's the target?"**
`
}

function mergeConfig(existing: Record<string, unknown>, live: boolean): { config: Record<string, unknown>; changed: boolean } {
  let config: Record<string, unknown> = { ...existing, $schema: SCHEMA }
  const mcp = { ...(config.mcp as Record<string, unknown> | undefined) }
  const desired = {
    type: "local",
    enabled: true,
    command: mcpCommand(live),
    environment: {
      OURMINE_LIVE: live ? "1" : "0",
      OURMINE_REQUIRE_LIVE: live ? "1" : "0",
      OURMINE_MCP_EFFICIENT: "1",
      OURMINE_REPO: REPO_ROOT,
    },
  }
  const prev = mcp.ares as Record<string, unknown> | undefined
  const sameAres =
    prev?.type === desired.type &&
    prev?.enabled === desired.enabled &&
    JSON.stringify(prev?.command) === JSON.stringify(desired.command) &&
    JSON.stringify(prev?.environment) === JSON.stringify(desired.environment)

  mcp.ares = desired
  config.mcp = mcp

  const prevTools = JSON.stringify(config.tools ?? {})
  const prevAgentTools = JSON.stringify((config.agent as Record<string, unknown> | undefined)?.pentest ?? {})
  const prevGhGrep = JSON.stringify((config.mcp as Record<string, unknown> | undefined)?.gh_grep ?? null)

  config = mergeGhGrepMcp(config)
  config = mergeOpenCodeToolPolicy(config)

  const toolsChanged = JSON.stringify(config.tools ?? {}) !== prevTools
  const agentToolsChanged = JSON.stringify((config.agent as Record<string, unknown> | undefined)?.pentest ?? {}) !== prevAgentTools
  const ghGrepChanged = JSON.stringify((config.mcp as Record<string, unknown> | undefined)?.gh_grep ?? null) !== prevGhGrep

  let changed = !sameAres || toolsChanged || agentToolsChanged || ghGrepChanged
  if (!config.default_agent) {
    config.default_agent = "pentest"
    changed = true
  }

  return { config, changed }
}

function ensureAgent(agentPath: string, live: boolean): boolean {
  fs.mkdirSync(path.dirname(agentPath), { recursive: true })
  const content = buildAgentMarkdown(live)
  if (fs.existsSync(agentPath)) {
    const existing = fs.readFileSync(agentPath, "utf8")
    if (existing.includes(MARKER) && existing === content) return false
    if (!existing.includes(MARKER)) return false
  }
  fs.writeFileSync(agentPath, content, "utf8")
  return true
}

function mergeTuiConfig(existing: Record<string, unknown>): { config: Record<string, unknown>; changed: boolean } {
  const config: Record<string, unknown> = { ...existing, $schema: TUI_SCHEMA }
  const plugins = Array.isArray(config.plugin) ? [...(config.plugin as string[])] : []
  const hasBrand = plugins.some((entry) => entry === BRAND_PLUGIN || String(entry).endsWith("ourmine-brand.tsx"))
  let changed = false
  if (!hasBrand) {
    plugins.unshift(BRAND_PLUGIN)
    config.plugin = plugins
    changed = true
  }
  return { config, changed }
}

function ensureProjectAgent(live: boolean): boolean {
  const agentPath = path.join(REPO_ROOT, ".opencode", "agent", "pentest.md")
  return ensureAgent(agentPath, live)
}

/** Idempotently wire ARES MCP + pentest agent into OpenCode config. */
export function bootstrapOpenCode(options: { quiet?: boolean } = {}): BootstrapResult {
  const live = isKaliLinux() || process.env.OURMINE_LIVE === "1"
  const configDir = opencodeConfigDir()
  const configPath = path.join(configDir, "opencode.json")
  const tuiPath = path.join(configDir, "tui.json")
  const agentPath = path.join(configDir, "agent", "pentest.md")

  let configChanged = false
  let tuiChanged = false
  let agentChanged = false
  let projectAgentChanged = false

  try {
    const merged = mergeConfig(readJsonFile(configPath), live)
    configChanged = merged.changed
    if (configChanged) writeJsonFile(configPath, merged.config)
    const tui = mergeTuiConfig(readJsonFile(tuiPath))
    tuiChanged = tui.changed
    if (tuiChanged) writeJsonFile(tuiPath, tui.config)
    agentChanged = ensureAgent(agentPath, live)
  } catch (e) {
    if (!options.quiet) {
      const msg = e instanceof Error ? e.message : String(e)
      process.stderr.write(`\x1b[33m[OurMine]\x1b[0m Could not update global OpenCode config: ${msg}\n`)
    }
  }

  try {
    projectAgentChanged = ensureProjectAgent(live)
  } catch {
    // project agent is optional when cwd is not the repo
  }

  const updated = configChanged || tuiChanged || agentChanged || projectAgentChanged

  if (updated && !options.quiet) {
    process.stderr.write(
      `\x1b[38;5;208m[OurMine]\x1b[0m ARES wired (${live ? "LIVE" : "dry-run"}) — pick a model with /model, say your target, go.\n`,
    )
  }

  return { configDir, configPath, agentPath, live, updated }
}

export function repoRoot(): string {
  return REPO_ROOT
}

export function mcpServerPath(): string {
  return MCP_SERVER
}
