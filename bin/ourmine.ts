#!/usr/bin/env node
/**
 * OurMine ⛏️ — OpenCode + ARES Security Platform
 *
 * Architecture:
 *   - ALL original OpenCode commands are passed DIRECTLY to the real `opencode` binary
 *   - Security commands (recon, audit, pentest, etc.) run through the ARES engine
 *   - Running bare `ourmine` or `ourmine tui` launches the real OpenCode TUI
 *   - Running `ourmine --help` shows this combined help page
 *
 * This means /model, /new, /sessions, /fork, /compact, /diff, /share, /warp, /stash,
 * /agents, /mcps, /plugins, /skills, /themes, /variants, /connect, /org, /editor,
 * /settings, /debug, /status — all work natively through the real OpenCode engine.
 */

import { spawn, spawnSync } from "node:child_process"
import { execShell, ExecutionDisplay, runSubagent } from "../packages/security/src/runtime_exec.ts"
import { PentestAgent } from "../packages/security/src/pentestgpt_agent.ts"
import { bootstrapOpenCode } from "../packages/security/src/opencode_bootstrap.ts"
import * as security from "../packages/security/src/index.ts"

const OURMINE_VERSION = "1.0.0"

const C = {
  reset:   "\x1b[0m",  bold:    "\x1b[1m",
  dim:     "\x1b[2m",  green:   "\x1b[32m",
  yellow:  "\x1b[33m", red:     "\x1b[31m",
  cyan:    "\x1b[36m", orange:  "\x1b[38;5;208m",
  grey:    "\x1b[90m", blue:    "\x1b[34m",
  magenta: "\x1b[35m", white:   "\x1b[97m",
}

// ─── Set of OurMine-specific security commands (everything else → opencode) ──

const SECURITY_COMMANDS = new Set([
  "recon", "audit", "pentest", "yara", "c2", "modules",
  "security", "sec", "serve", "agent", "toolcheck", "watch", "retest", "topcut", "depth",
  "tier1", "tier1bench",
])

// ─── Security-only help addendum ──────────────────────────────────────────────

function securityHelp() {
  console.log(`
${C.bold}${C.orange}OurMine Security Commands (ARES Suite):${C.reset}
  ourmine recon <target>       AI-driven recon: OSINT, subdomains, email enum
  ourmine audit <target>       Container + cloud vulnerability audit
  ourmine pentest <target>     Full autonomous PentestGPT attack plan
  ourmine yara <path>          YARA rulepack scan on a file/path
  ourmine c2 [status]          C2 channel & beacon management
  ourmine serve                Start ARES MCP server on stdio (for LLM agents)
  ourmine agent <target>       Interactive LLM-driven pentest agent
  ourmine toolcheck            Check which security tools are installed
  ourmine watch <target> [min]     Continuous engagement snapshots (default 60 min)
  ourmine watch <target> --daemon    Run scheduled watch daemon (interval from [min] or 60)
  ourmine retest <target> <id> Retest a finding for remediation status
  ourmine topcut                 Score readiness vs enterprise BAS platforms
  ourmine depth                  Operational depth score (tier-1 capability)
  ourmine tier1 [target]         Run tier-1 orchestrator + depth metrics (set OURMINE_TIER1=1)
  ourmine tier1bench             Lab benchmark for tier-1 capabilities
  ourmine security list        Same as 'modules'

${C.bold}Security Flags:${C.reset}
  ${C.grey}--live${C.reset}                       Enable real network/exec mode
  ${C.grey}--dry-run${C.reset}                    Force simulation (overrides Kali auto-live)
  ${C.grey}--require-live${C.reset}               Fail if tools unavailable (no fallbacks)

${C.grey}All other commands (tui, run, models, session, mcp, providers, stats,
export, import, session, github, pr, db, web, acp, attach, upgrade)
are passed directly to the real OpenCode binary.${C.reset}
`)
}

// ─── OpenCode launch (bootstrap ARES MCP + pentest agent, then delegate) ───

function launchOpenCode(args: string[]): void {
  delegateToOpenCode(args)
}

function delegateToOpenCode(args: string[]): void {
  const child = spawn("opencode", args, {
    stdio: "inherit",
    env: { ...process.env, OURMINE: "1", OURMINE_BRAND: "1" },
  })

  const sigs: NodeJS.Signals[] = ["SIGINT", "SIGTERM", "SIGHUP"]
  const fwd: Partial<Record<NodeJS.Signals, () => void>> = {}
  for (const s of sigs) {
    fwd[s] = () => { try { child.kill(s) } catch {} }
    process.on(s, fwd[s]!)
  }

  child.on("error", (e) => { console.error(e.message); process.exit(1) })
  child.on("exit", (code, signal) => {
    for (const s of sigs) process.removeListener(s, fwd[s]!)
    if (signal) { process.kill(process.pid, signal); return }
    process.exit(typeof code === "number" ? code : 0)
  })
}

// ─── Security command handlers ────────────────────────────────────────────────

async function cmdRecon(target: string, display: ExecutionDisplay, isLive: boolean) {
  display.emit({ type: "agent_start", label: `Recon → ${target}` })

  display.emit({ type: "tool_start", label: "ai_recon.runRecon", detail: target })
  const r = await security.ai_recon.runRecon({ domain: target }, { live: isLive })
  display.emit({ type: "tool_done",  label: "ai_recon.runRecon",
    detail: `${r.employees?.length ?? 0} employees, ${r.emailPatterns?.length ?? 0} email patterns` })

  display.emit({ type: "tool_start", label: "bountyhunter.recon", detail: target })
  const b = await security.bountyhunter.recon({ target, endpoints: [] }, { live: isLive })
  display.emit({ type: "tool_done",  label: "bountyhunter.recon",
    detail: `${b.subdomains?.length ?? 0} subdomains` })

  display.emit({ type: "subagent_spawn", label: "[osint] Passive OSINT Worker" })
  display.emit({ type: "subagent_msg",   label: "osint", detail: "crt.sh, Shodan, HaveIBeenPwned, LinkedIn..." })
  await new Promise(r => setTimeout(r, 80))
  display.emit({ type: "subagent_done",  label: "[osint] Passive OSINT Worker" })

  if (r.employees?.length) {
    r.employees.forEach(e =>
      display.emit({ type: "finding", label: `Employee: ${e.fullName}`, severity: "info", detail: e.email }))
  }
  if (b.subdomains?.length) {
    b.subdomains.slice(0, 5).forEach(sd =>
      display.emit({ type: "finding", label: `Subdomain: ${sd}`, severity: "info" }))
  }

  display.emit({ type: "agent_done", label: `Recon → ${target}` })
}

async function cmdAudit(target: string, display: ExecutionDisplay, isLive: boolean) {
  display.emit({ type: "agent_start", label: `Audit → ${target}` })

  display.emit({ type: "tool_start", label: "container.auditContainer" })
  const c = security.container.auditContainer({ live: isLive })
  display.emit({ type: "tool_done",  label: "container.auditContainer",
    detail: `docker=${c.dockerSocketMounted} cgroup=${c.cgroupEscapePossible}` })
  if (c.dockerSocketMounted)
    display.emit({ type: "finding", label: "Docker socket mounted", severity: "high", detail: "/var/run/docker.sock exposed" })

  display.emit({ type: "tool_start", label: "cloud_token.fetchAWSMetadata" })
  const aws = await security.cloud_token.fetchAWSMetadata({ live: isLive })
  display.emit({ type: "tool_done",  label: "cloud_token.fetchAWSMetadata",
    detail: aws ? `KeyId=${aws.accessKeyId}` : "No IMDS" })
  if (aws)
    display.emit({ type: "finding", label: "AWS credentials from IMDS", severity: "critical", detail: aws.accessKeyId })

  display.emit({ type: "tool_start", label: "counter_intel.auditDefenses" })
  const ci = security.counter_intel.auditDefenses({ live: isLive })
  display.emit({ type: "tool_done",  label: "counter_intel.auditDefenses",
    detail: `honeypot=${ci.honeypotDetected}` })

  display.emit({ type: "agent_done", label: `Audit → ${target}` })
}

async function cmdPentest(target: string, display: ExecutionDisplay, isLive: boolean) {
  display.emit({ type: "agent_start", label: `Autonomous Pentest → ${target}` })

  display.emit({ type: "tool_start", label: "pentestgpt_ptt.buildDefaultTree", detail: target })
  const tree = security.pentestgpt_ptt.buildDefaultTree(target)
  const summary = security.pentestgpt_ptt.treeSummary(tree)
  display.emit({ type: "tool_done",  label: "pentestgpt_ptt.buildDefaultTree",
    detail: `${summary.total} nodes across ${Object.keys(summary.byPhase ?? {}).length} phases` })

  const subagents = [
    { id: "sa-recon", role: "Recon Subagent",      task: `Enumerate ${target}`, modules: ["ai_recon","bountyhunter","scanner_parsers"] },
    { id: "sa-ad",    role: "AD Attack Subagent",   task: `Kerberoast ${target}`, modules: ["identity","ad_exploit"] },
    { id: "sa-web",   role: "Web Exploit Subagent", task: `Exploit web surface`, modules: ["strix_engine","oauth_chain"] },
    { id: "sa-infra", role: "Infra Subagent",       task: `Cloud & container escape`, modules: ["cloud_token","container","pivot_tunnel"] },
  ]

  for (const sa of subagents) {
    const res = await runSubagent(sa, display, { live: isLive })
    res.findings.forEach(f => display.emit({ type: "finding", label: f, severity: "info" }))
  }

  display.emit({ type: "tool_start", label: "PentestAgent.runAutonomous", detail: target })
  const agent = new PentestAgent({ target, scope: [target], live: isLive, requireLive: false })
  const result = await agent.runAutonomous()
  display.emit({ type: "tool_done",  label: "PentestAgent.runAutonomous",
    detail: `${result.summary["completed"]}/${result.summary["totalTasks"]} tasks` })
  result.findings.forEach(f =>
    display.emit({ type: "finding", label: f.title, severity: f.severity, detail: f.recommendation }))

  display.emit({ type: "agent_done", label: `Autonomous Pentest → ${target}` })
}

async function cmdModules() {
  const { toolSummary, checkTools } = await import("../packages/security/src/tool_detection.ts")
  const mods = Object.keys(security).filter((k) => !k.startsWith("_")).sort()
  console.log(`\n${C.bold}ARES Security Modules (${mods.length} namespaces):${C.reset}\n`)
  mods.forEach((mod, i) => {
    const num = String(i + 1).padStart(3, " ")
    console.log(`  ${C.orange}${num}.${C.reset} ${C.cyan}${mod.padEnd(28)}${C.reset}`)
  })
  console.log(`\n${C.bold}Tool availability (sample):${C.reset}`)
  const sample = checkTools("nmap", "gobuster", "curl", "nuclei", "kubectl")
  for (const t of sample) {
    const mark = t.available ? `${C.green}✓${C.reset}` : `${C.red}✗${C.reset}`
    console.log(`  ${mark} ${t.name}${t.version ? ` v${t.version}` : ""}`)
  }
  console.log(`\n${C.grey}Run 'ourmine toolcheck' for full tool report.${C.reset}\n`)
}

async function cmdServe() {
  console.log(`${C.bold}${C.orange}OurMine ARES MCP Server${C.reset}`)
  console.log(`${C.grey}Starting MCP server on stdio...${C.reset}`)
  console.log(`${C.grey}Connect an LLM agent to this process for tool access.${C.reset}\n`)

  const { startMcpServer } = await import("../packages/security/src/mcp_server.ts")
  startMcpServer()
}

async function cmdAgent(target: string, isLive: boolean, requireLive: boolean) {
  console.log(`\n${C.bold}${C.orange}OurMine LLM-Driven Pentest Agent${C.reset}`)
  console.log(`${C.grey}Target: ${target} | Mode: ${isLive ? "LIVE" : "DRY-RUN"}${requireLive ? " | REQUIRE-LIVE" : ""}${C.reset}\n`)

  const { hasLLMKey, listProviders } = await import("../packages/security/src/llm_client.ts")
  if (!hasLLMKey()) {
    console.log(`${C.yellow}No LLM API key found. Running in deterministic mode.${C.reset}`)
    console.log(`${C.grey}Set ANTHROPIC_API_KEY, OPENAI_API_KEY, or GOOGLE_API_KEY for AI-driven analysis.${C.reset}\n`)
  } else {
    const providers = listProviders()
    console.log(`${C.green}LLM providers available: ${providers.join(", ")}${C.reset}\n`)
  }

  const { PentestAgent } = await import("../packages/security/src/pentestgpt_agent.ts")
  const agent = new PentestAgent({
    target,
    scope: [target],
    live: isLive,
    requireLive,
    maxSteps: 30,
  })

  console.log(`${C.cyan}Starting autonomous pentest...${C.reset}\n`)
  const result = await agent.runAutonomous()

  console.log(`\n${C.bold}${C.green}═══ PENTEST COMPLETE ═══${C.reset}\n`)
  console.log(`${C.bold}Summary:${C.reset}`)
  console.log(`  Target: ${result.summary["target"]}`)
  console.log(`  Tasks completed: ${result.summary["completed"]}/${result.summary["totalTasks"]}`)

  const findings = result.summary["findings"] as Record<string, number> | undefined
  if (findings) {
    console.log(`  Findings: ${findings["critical"] ?? 0} critical, ${findings["high"] ?? 0} high, ${findings["medium"] ?? 0} medium, ${findings["low"] ?? 0} low`)
  }

  if (result.findings.length > 0) {
    console.log(`\n${C.bold}Findings:${C.reset}`)
    for (const f of result.findings) {
      const color = f.severity === "critical" ? C.red : f.severity === "high" ? C.orange : f.severity === "medium" ? C.yellow : C.grey
      console.log(`  ${color}[${f.severity.toUpperCase()}]${C.reset} ${f.title}`)
      console.log(`    ${C.grey}${f.recommendation}${C.reset}`)
    }
  }
  console.log()
}

async function cmdToolCheck() {
  const { toolSummary } = await import("../packages/security/src/tool_detection.ts")
  console.log(`\n${C.bold}${C.orange}ARES Tool Detection${C.reset}\n`)
  console.log(toolSummary())
  console.log()
}

async function cmdWatch(target: string, intervalMinutes: number, isLive: boolean, daemon: boolean) {
  const { runWatchCycle, computeDelta, startWatch } = await import("../packages/security/src/engagement_watch.ts")
  console.log(`\n${C.bold}${C.orange}Engagement Watch${C.reset}`)
  console.log(`${C.grey}Target: ${target} | Interval: ${intervalMinutes}m | Mode: ${isLive ? "LIVE" : "DRY-RUN"}${daemon ? " | DAEMON" : ""}${C.reset}\n`)

  const printResult = (result: { snapshot: { findingIds: string[]; merkleRoot?: string }; delta: { since: string; newFindings: string[]; removedFindings: string[] } | null }) => {
    const ts = new Date().toISOString()
    console.log(`${C.grey}[${ts}]${C.reset} ${C.green}Snapshot${C.reset} — ${result.snapshot.findingIds.length} findings`)
    if (result.snapshot.merkleRoot) {
      console.log(`${C.grey}  Merkle: ${result.snapshot.merkleRoot.slice(0, 16)}…${C.reset}`)
    }
    if (result.delta) {
      console.log(`  ${C.bold}Delta:${C.reset} +${result.delta.newFindings.length} / -${result.delta.removedFindings.length}`)
      result.delta.newFindings.slice(0, 5).forEach((id) => console.log(`    ${C.red}+ ${id}${C.reset}`))
      result.delta.removedFindings.slice(0, 5).forEach((id) => console.log(`    ${C.green}- ${id}${C.reset}`))
    }
  }

  if (daemon) {
    console.log(`${C.cyan}Watch daemon running. Press Ctrl+C to stop.${C.reset}\n`)
    const stop = startWatch({ target, intervalMinutes, live: isLive }, printResult)
    const shutdown = () => { stop(); console.log(`\n${C.yellow}Watch daemon stopped.${C.reset}`); process.exit(0) }
    process.on("SIGINT", shutdown)
    process.on("SIGTERM", shutdown)
    await new Promise(() => {})
    return
  }

  const result = await runWatchCycle({ target, intervalMinutes, live: isLive })
  printResult(result)
  if (!result.delta) {
    console.log(`${C.grey}No prior snapshot for delta comparison.${C.reset}`)
  }
  console.log()
}

async function cmdTopCut() {
  const { assessTopCut, formatTopCutReport } = await import("../packages/security/src/top_cut_score.ts")
  const report = await assessTopCut()
  console.log(formatTopCutReport(report))
  console.log()
  if (!report.meetsTopCut) process.exitCode = 1
}

async function cmdDepth() {
  const { assessOperationalDepth, formatDepthReport } = await import("../packages/security/src/operational_depth_score.ts")
  const report = await assessOperationalDepth()
  console.log(formatDepthReport(report))
  console.log()
}

async function cmdTier1(target: string, isLive: boolean) {
  process.env.OURMINE_TIER1 = "1"
  const { enableTier1Mode } = await import("../packages/security/src/tier1_config.ts")
  enableTier1Mode()
  const { AttackSurfaceGraph } = await import("../packages/security/src/attack_surface.ts")
  const { runTier1Orchestrator } = await import("../packages/security/src/tier1_orchestrator.ts")
  const { assessOperationalDepth, formatDepthReport } = await import("../packages/security/src/operational_depth_score.ts")
  const graph = new AttackSurfaceGraph(target)
  console.log(`\n${C.bold}${C.orange}Tier-1 APT Orchestrator${C.reset}`)
  console.log(`${C.grey}Target: ${target} | Mode: ${isLive ? "LIVE" : "DRY-RUN"} | OURMINE_TIER1=1${C.reset}\n`)
  const result = await runTier1Orchestrator({ target, graph, live: isLive })
  console.log(result.summary)
  console.log()
  const depth = await assessOperationalDepth()
  console.log(formatDepthReport(depth))
  console.log()
}

async function cmdRetest(target: string, findingId: string, isLive: boolean) {
  const { retestFinding } = await import("../packages/security/src/engagement_watch.ts")
  console.log(`\n${C.bold}${C.orange}Finding Retest${C.reset}`)
  console.log(`${C.grey}Target: ${target} | Finding: ${findingId} | Mode: ${isLive ? "LIVE" : "DRY-RUN"}${C.reset}\n`)

  const result = await retestFinding(target, findingId, { live: isLive })
  const color = result.remediated ? C.green : result.newState === "RETEST_PENDING" ? C.yellow : C.orange
  console.log(`  ${color}${result.previousState} → ${result.newState}${C.reset}`)
  console.log(`  Remediated: ${result.remediated ? "yes" : "no"}`)
  console.log(`  ${C.grey}${result.output}${C.reset}\n`)
}

// ─── Main ─────────────────────────────────────────────────────────────────────

async function main() {
  const args    = process.argv.slice(2)

  // Wire ARES MCP into OpenCode config on every OurMine invocation (instant MCP on startup)
  try {
    bootstrapOpenCode({ quiet: args.length > 0 })
  } catch {
    // never block on bootstrap
  }

  const dryRun  = args.includes("--dry-run")
  const requireLive = args.includes("--require-live")
  const daemon = args.includes("--daemon")
  const passArgs = args.filter(a => !["--live", "--dry-run", "--require-live", "--daemon"].includes(a))

  const { isKaliLinux } = await import("../packages/security/src/apt_tradecraft.ts")
  const isLive  = !dryRun && (args.includes("--live") || isKaliLinux())

  // No args → launch real opencode TUI (ARES auto-wired)
  if (args.length === 0) {
    launchOpenCode([])
    return
  }

  const sub = passArgs[0]
  const rest = passArgs.slice(1)
  const target = rest[0] ?? "target.local"

  // Show combined help
  if (sub === "--help" || sub === "-h" || sub === "help") {
    // First show real opencode help
    const ocHelp = spawnSync("opencode", ["--help"], { encoding: "utf8" })
    process.stdout.write(ocHelp.stdout ?? "")
    // Then append OurMine security additions
    securityHelp()
    return
  }

  // Show version
  if (sub === "--version" || sub === "-v") {
    const ocVer = spawnSync("opencode", ["--version"], { encoding: "utf8" })
    console.log(`opencode ${(ocVer.stdout ?? "").trim()}  +  ourmine v${OURMINE_VERSION}`)
    return
  }

  // Security-specific commands handled by OurMine
  if (SECURITY_COMMANDS.has(sub)) {
    const display = new ExecutionDisplay()

    switch (sub) {
      case "recon":
        await cmdRecon(target, display, isLive)
        break
      case "audit":
        await cmdAudit(target, display, isLive)
        break
      case "pentest":
        await cmdPentest(target, display, isLive)
        break
      case "yara": {
        display.emit({ type: "tool_start", label: "yara.scan", detail: target })
        try {
          const fs = await import("node:fs")
          const text = fs.readFileSync(target, "utf8")
          const matches = security.yara.scanText(text)
          display.emit({ type: "tool_done", label: "yara.scan", detail: `${matches.length} matches` })
          matches.forEach(m => display.emit({ type: "finding", label: m.rule ?? "match", severity: "high", detail: m.description }))
        } catch (e: any) {
          display.emit({ type: "tool_done", label: "yara.scan", detail: `Error: ${e?.message}` })
        }
        break
      }
      case "c2": {
        const c2sub = rest[0] ?? "status"
        display.emit({ type: "tool_start", label: `c2.${c2sub}` })
        console.log(`  ${C.orange}C2${C.reset}  ${C.grey}[DRY-RUN] No active beacons. Use --live to activate.${C.reset}`)
        display.emit({ type: "tool_done", label: `c2.${c2sub}`, detail: "0 beacons" })
        break
      }
      case "security":
      case "sec":
      case "modules":
        await cmdModules()
        break
      case "serve":
        await cmdServe()
        break
      case "agent":
        await cmdAgent(target, isLive, requireLive)
        break
      case "toolcheck":
        await cmdToolCheck()
        break
      case "watch": {
        const intervalArg = rest.find((a) => /^\d+$/.test(a))
        const interval = parseInt(intervalArg ?? "60", 10) || 60
        await cmdWatch(target, interval, isLive, daemon)
        break
      }
      case "topcut":
        await cmdTopCut()
        break
      case "depth":
        await cmdDepth()
        break
      case "tier1":
        await cmdTier1(target, isLive)
        break
      case "tier1bench":
        console.error("tier1bench is validation-only and must be run by the isolated VM validation worker")
        process.exitCode = 2
        break
      case "retest": {
        const findingId = rest[1]
        if (!findingId) {
          console.error(`${C.red}Usage: ourmine retest <target> <finding-id>${C.reset}`)
          process.exit(1)
        }
        await cmdRetest(target, findingId, isLive)
        break
      }
    }
    return
  }

  // ── Everything else → real opencode binary, full stdio passthrough ─────────
  launchOpenCode(passArgs)
}

main().catch(e => {
  console.error(`\x1b[31m[OurMine Error]\x1b[0m ${e?.message ?? e}`)
  process.exit(1)
})
