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

const MARKER = "<!-- ourmine-ares-v1 -->"
const SCHEMA = "https://opencode.ai/config.json"

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..")
const MCP_SERVER = path.join(REPO_ROOT, "packages/security/src/mcp_server.ts")

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
steps: 80
permission:
  bash: allow
  edit: allow
  webfetch: allow
  websearch: allow
  "*": allow
---

You are **OurMine ARES** — an APT-level offensive security agent running inside OpenCode.

The user browses models with \`/model\` and tells you what they want and the target. You execute autonomously using ARES MCP tools (prefixed \`ares_\`) and bash on Kali when needed.

## Operating mode

Server posture: **${mode}** (Kali Linux auto-enables live execution).

- On Kali or when live: run real scans, exploits, and tooling — no simulations.
- In dry-run: plan and explain, but prefer \`ares_*\` tools which respect server mode.

## When the user gives a target

1. Confirm scope in one short line (target, constraints, authorization assumed in lab).
2. Call \`ares_ares_pentest_plan\` with the target to build a phased task tree.
3. Execute with \`ares_ares_pentest_run\` for full autonomous campaign **or** drive phases manually:
   - Recon: \`ares_ares_recon\`, \`ares_ares_bountyhunter\`, \`ares_ares_vuln_research\`
   - Web/identity: \`ares_ares_strix_web\`, \`ares_ares_identity\`, \`ares_ares_ad_exploit\`
   - Cloud/infra: \`ares_ares_cloud_token\`, \`ares_ares_container_escape\`, \`ares_ares_pivot_tunnel\`
   - Post-ex: \`ares_ares_exfil\`, \`ares_ares_supply_chain\`, \`ares_ares_counter_intel\`
4. After each phase, summarize findings with severity and next steps.
5. Persist attack paths; escalate when graph recommends (AD → cloud → supply chain).

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
  const config: Record<string, unknown> = { ...existing, $schema: SCHEMA }
  const mcp = { ...(config.mcp as Record<string, unknown> | undefined) }
  const desired = {
    type: "local",
    enabled: true,
    command: mcpCommand(live),
    environment: {
      OURMINE_LIVE: live ? "1" : "0",
      OURMINE_REPO: REPO_ROOT,
    },
  }
  const prev = mcp.ares as Record<string, unknown> | undefined
  const same =
    prev?.type === desired.type &&
    prev?.enabled === desired.enabled &&
    JSON.stringify(prev?.command) === JSON.stringify(desired.command) &&
    JSON.stringify(prev?.environment) === JSON.stringify(desired.environment)

  mcp.ares = desired
  config.mcp = mcp

  let changed = !same
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

function ensureProjectAgent(live: boolean): boolean {
  const agentPath = path.join(REPO_ROOT, ".opencode", "agent", "pentest.md")
  return ensureAgent(agentPath, live)
}

/** Idempotently wire ARES MCP + pentest agent into OpenCode config. */
export function bootstrapOpenCode(options: { quiet?: boolean } = {}): BootstrapResult {
  const live = isKaliLinux() || process.env.OURMINE_LIVE === "1"
  const configDir = opencodeConfigDir()
  const configPath = path.join(configDir, "opencode.json")
  const agentPath = path.join(configDir, "agent", "pentest.md")

  let configChanged = false
  let agentChanged = false
  let projectAgentChanged = false

  try {
    const merged = mergeConfig(readJsonFile(configPath), live)
    configChanged = merged.changed
    if (configChanged) writeJsonFile(configPath, merged.config)
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

  const updated = configChanged || agentChanged || projectAgentChanged

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
