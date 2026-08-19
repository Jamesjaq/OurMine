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
${C.bold}${C.orange}OurMine Syndicate Prime (v3.4.0):${C.reset}
  ourmine recon <target>       Syndicate-driven recon: Dynamic cell synthesis
  ourmine audit <target>       High-fidelity infrastructure & sector audit
  ourmine pentest <target>     Full autonomous Syndicate Prime engagement
  ourmine yara <path>          YARA rulepack scan on a file/path
  ourmine c2 [status]          Covert mesh C2 & ghost autonomy management
  ourmine serve                Start ARES MCP server (Syndicate Prime backend)
  ourmine agent <target>       Autonomous Syndicate operative (LLM-driven)
  ourmine toolcheck            Check arsenal availability and tradecraft
  ourmine watch <target> [min]     Continuous engagement snapshots (default 60 min)
  ourmine watch <target> --daemon    Run scheduled watch daemon (interval from [min] or 60)
  ourmine retest <target> <id> Retest a finding for remediation status
  ourmine topcut                 Score readiness vs enterprise BAS platforms
  ourmine depth                  Operational depth score (Syndicate capability)
  ourmine tier1 [target]         Run tier-1 orchestrator + depth metrics
  ourmine tier1bench             Lab benchmark for tier-1 capabilities
  ourmine security list        List all 200+ ARES security modules

${C.bold}Syndicate Directives:${C.reset}
  ${C.grey}--live${C.reset}                       Enable ABSOLUTE LIVE execution (no mocks)
  ${C.grey}--dry-run${C.reset}                    Simulation is FORBIDDEN in v3.4.0 (throws error)
  ${C.grey}--require-live${C.reset}               Strict dependency enforcement

${C.grey}All other commands are passed directly to the real OpenCode binary.${C.reset}
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

async function cmdRecon(target: string, display: ExecutionDisplay, isLive: boolean, objective?: string) {
  display.emit({ type: "agent_start", label: `Syndicate Reconnaissance → ${target}` })
  const { runSyndicateSpawn } = await import("../packages/security/src/ares/syndicate_spawn.ts")

  const spawnPlan = runSyndicateSpawn({ target, objective: objective ?? `Reconnaissance and surface profiling on ${target}` }, { live: isLive })
  display.emit({ type: "tool_start", label: "Syndicate Assembler", detail: `${spawnPlan.structure.totalDepartments} departments, ${spawnPlan.structure.totalOperatives} operatives` })

  const { runAresOrchestrator } = await import("../packages/security/src/ares/orchestrator.ts")
  const res = await runAresOrchestrator({
    target,
    objective: objective ?? "Autonomous reconnaissance and asset profiling",
    display,
  }, { live: isLive })

  display.emit({ type: "finding", label: "Recon Summary", severity: "high", detail: res.summary })
  display.emit({ type: "agent_done", label: `Syndicate Reconnaissance → ${target}` })
}

async function cmdAudit(target: string, display: ExecutionDisplay, isLive: boolean, objective?: string) {
  display.emit({ type: "agent_start", label: `Syndicate Audit → ${target}` })
  const { runAresOrchestrator } = await import("../packages/security/src/ares/orchestrator.ts")

  const res = await runAresOrchestrator({
    target,
    objective: objective ?? "Comprehensive infrastructure security audit",
    display,
  }, { live: isLive })

  display.emit({ type: "finding", label: "Syndicate Audit Results", severity: "high", detail: res.summary })
  display.emit({ type: "agent_done", label: `Syndicate Audit → ${target}` })
}

async function cmdPentest(target: string, display: ExecutionDisplay, isLive: boolean, objective?: string) {
  display.emit({ type: "agent_start", label: `Syndicate Prime Engagement → ${target}` })
  const { runAresOrchestrator } = await import("../packages/security/src/ares/orchestrator.ts")

  const res = await runAresOrchestrator({
    target,
    objective: objective ?? "Full-scale autonomous adversarial operation",
    display,
  }, { live: isLive })

  display.emit({ type: "finding", label: "Engagement Summary", severity: "critical", detail: res.summary })
  display.emit({ type: "agent_done", label: `Syndicate Prime Engagement → ${target}` })
}

async function cmdModules() {
  const { toolSummary, checkTools } = await import("../packages/security/src/tool_detection.ts")
  const mods = Object.keys(security).filter((k) => !k.startsWith("_")).sort()
  console.log(`\n${C.bold}${C.orange}OurMine Security Modules (${mods.length} namespaces):${C.reset}\n`)
  for (const m of mods) {
    const val = (security as Record<string, any>)[m]
    const fnCount = typeof val === "object" && val !== null ? Object.keys(val).length : 1
    console.log(`  ${C.cyan}• ${m.padEnd(28)}${C.reset} ${C.grey}(${fnCount} exported symbols)${C.reset}`)
  }
  const status = checkTools()
  console.log(`\n${C.bold}Tool Availability:${C.reset} ${status.availableCount}/${status.totalCount} binaries found\n`)
}

async function cmdServe() {
  const { startMcpServer } = await import("../packages/security/src/mcp_server.ts")
  await startMcpServer()
}

async function cmdAgent(target: string, isLive: boolean) {
  const display = new ExecutionDisplay()
  display.emit({ type: "agent_start", label: `Pentest Agent → ${target}` })
  const agent = new PentestAgent({ target, live: isLive })
  const result = await agent.run()
  display.emit({ type: "finding", label: "Agent Result", severity: "high", detail: result })
  display.emit({ type: "agent_done", label: `Pentest Agent → ${target}` })
}

async function cmdWatch(target: string, intervalMinutes: number, daemon: boolean, isLive: boolean) {
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
  
  let objective: string | undefined
  const objIdx = args.indexOf("--objective")
  if (objIdx !== -1 && args[objIdx + 1]) {
    objective = args[objIdx + 1]
  }

  const passArgs = args.filter((a, i) => {
    if (["--live", "--dry-run", "--require-live", "--daemon"].includes(a)) return false
    if (a === "--objective") return false
    if (i > 0 && args[i - 1] === "--objective") return false
    return true
  })

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
        await cmdRecon(target, display, isLive, objective)
        break
      case "audit":
        await cmdAudit(target, display, isLive, objective)
        break
      case "pentest":
        await cmdPentest(target, display, isLive, objective)
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
        await cmdAgent(target, isLive)
        break
      case "watch": {
        const interval = parseInt(rest[1] ?? "60", 10) || 60
        await cmdWatch(target, interval, daemon, isLive)
        break
      }
      case "retest": {
        const findingId = rest[1]
        if (!findingId) {
          console.error(`${C.red}Error: missing finding ID for retest${C.reset}`)
          process.exit(1)
        }
        await cmdRetest(target, findingId, isLive)
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
      case "tier1bench": {
        const { runTier1LabBenchmark } = await import("../packages/security/src/tier1_orchestrator.ts")
        await runTier1LabBenchmark()
        break
      }
    }
    return
  }

  // Fallback: delegate everything else to opencode binary
  delegateToOpenCode(args)
}

main().catch((e) => {
  console.error(e)
  process.exit(1)
})
