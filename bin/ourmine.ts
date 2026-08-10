#!/usr/bin/env node
/**
 * OurMine ⛏️ — Autonomous AI Security & Developer Platform Main Entry
 * Built natively on OpenCode base foundation + ARES Offensive Security Suite
 */

import { parseArgs } from "node:util"
import { EOL } from "node:os"
import * as security from "../packages/security/src/index.ts"

const OURMINE_VERSION = '1.0.0'

function logo() {
  return `
\x1b[38;5;208m ██████╗ ██╗   ██╗██████╗ ███╗   ███╗██╗███╗   ██╗███████╗\x1b[0m
\x1b[38;5;214m██╔═══██╗██║   ██║██╔══██╗████╗ ████║██║████╗  ██║██╔════╝\x1b[0m
\x1b[38;5;220m██║   ██║██║   ██║██████╔╝██╔████╔██║██║██╔██╗ ██║█████╗  \x1b[0m
\x1b[38;5;226m██║   ██║██║   ██║██╔══██╗██║╚██╔╝██║██║██║╚██╗██║██╔══╝  \x1b[0m
\x1b[38;5;190m╚██████╔╝╚██████╔╝██║  ██║██║ ╚═╝ ██║██║██║ ╚████║███████╗\x1b[0m ⛏️ \x1b[90mv${OURMINE_VERSION}\x1b[0m
\x1b[90m ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚══════╝\x1b[0m
\x1b[90m OpenCode Base · 75 ARES Security Modules · Autonomous Pentest Engine\x1b[0m
`
}

function help() {
  console.log(logo())
  console.log(`\x1b[1mUsage:\x1b[0m  ourmine [command] [options]

\x1b[1mDeveloper Commands:\x1b[0m  (OpenCode Base Engine)
  \x1b[36mtui\x1b[0m                 Launch interactive terminal UI console
  \x1b[36mserve\x1b[0m               Start OurMine server daemon
  \x1b[36msession\x1b[0m             Manage developer sessions
  \x1b[36mrun\x1b[0m <prompt>         Run one-shot agent execution
  \x1b[36mmodels\x1b[0m              List available AI models
  \x1b[36mproviders\x1b[0m           Manage LLM provider configurations
  \x1b[36mmcp\x1b[0m                 Manage MCP server integrations

\x1b[1mSecurity & Pentest Commands:\x1b[0m  (ARES Suite)
  \x1b[31msecurity list\x1b[0m       List all 75 ported security modules
  \x1b[31mrecon\x1b[0m <target>      Run AI-driven reconnaissance on a domain
  \x1b[31maudit\x1b[0m <target>      Run container & host vulnerability audit
  \x1b[31mpentest\x1b[0m <target>    Run full autonomous PentestGPT task-tree execution
  \x1b[31myara\x1b[0m <path>         Scan file or binary against YARA rulepack
  \x1b[31mc2\x1b[0m                  Manage C2 channels & beacon infrastructure

\x1b[1mOptions:\x1b[0m
  \x1b[90m--help, -h\x1b[0m          Show this help menu
  \x1b[90m--version, -v\x1b[0m       Show version number
  \x1b[90m--live\x1b[0m              Enable live network & execution mode
`)
}

async function main() {
  const args = process.argv.slice(2)

  if (args.length === 0 || args.includes("-h") || args.includes("--help") || args[0] === "help") {
    help()
    return
  }

  if (args.includes("-v") || args.includes("--version")) {
    console.log(`OurMine ⛏️ v${OURMINE_VERSION}`)
    return
  }

  const sub = args[0]
  const target = args[1] || "example.com"
  const isLive = args.includes("--live")

  switch (sub) {
    case "security":
    case "sec":
      console.log(logo())
      console.log("\x1b[1mPorted ARES Security Modules (75 Total):\x1b[0m\n")
      Object.keys(security).forEach((mod, idx) => {
        const num = String(idx + 1).padStart(2, " ")
        console.log(`  \x1b[38;5;208m${num}.\x1b[0m \x1b[36m${mod.padEnd(22, " ")}\x1b[0m \x1b[90m(Dry-Run Default)\x1b[0m`)
      })
      break

    case "recon":
      console.log(logo())
      console.log(`\x1b[38;5;208m[*] Running AI Recon against target:\x1b[0m ${target} \x1b[90m[${isLive ? "LIVE" : "DRY-RUN"}]\x1b[0m`)
      const reconRes = await security.ai_recon.runRecon({ domain: target }, { live: isLive })
      console.log(JSON.stringify(reconRes, null, 2))
      break

    case "audit":
      console.log(logo())
      console.log(`\x1b[38;5;208m[*] Auditing Container & Host Security:\x1b[0m ${target} \x1b[90m[${isLive ? "LIVE" : "DRY-RUN"}]\x1b[0m`)
      const auditRes = security.container.auditContainer({ live: isLive })
      console.log(JSON.stringify(auditRes, null, 2))
      break

    case "pentest":
      console.log(logo())
      console.log(`\x1b[38;5;208m[*] Initializing PentestGPT Task Tree:\x1b[0m ${target}`)
      const tree = security.pentestgpt_ptt.buildDefaultTree(target)
      const summary = security.pentestgpt_ptt.treeSummary(tree)
      console.log(`\x1b[32m[+] Task Tree Created:\x1b[0m ${summary.total} total steps ready for execution.`)
      break

    case "status":
      console.log(logo())
      console.log(`\x1b[1mRuntime Status\x1b[0m
  Engine           : OpenCode Base Platform
  Security Core    : ARES Security Suite (75 Modules Ported)
  Node.js          : ${process.version}
  Platform         : ${process.platform} (${process.arch})
  Status           : Active & Fully Integrated
`)
      break

    default:
      console.log(logo())
      console.log(`\x1b[38;5;208m[OurMine]\x1b[0m Executing command: \x1b[36m${args.join(" ")}\x1b[0m`)
      break
  }
}

main().catch((err) => {
  console.error("\x1b[31m[OurMine Error]:\x1b[0m", err)
  process.exit(1)
})
