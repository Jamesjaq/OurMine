#!/usr/bin/env node
/**
 * OurMine ⛏️ — Autonomous AI Security & Developer Platform Main Entry
 * Built natively on OpenCode base foundation + ARES Offensive Security Suite
 */

const OURMINE_VERSION = '1.0.0';

function banner() {
  return `
\x1b[38;5;208m ██████╗ ██╗   ██╗██████╗ ███╗   ███╗██╗███╗   ██╗███████╗\x1b[0m
\x1b[38;5;214m██╔═══██╗██║   ██║██╔══██╗████╗ ████║██║████╗  ██║██╔════╝\x1b[0m
\x1b[38;5;220m██║   ██║██║   ██║██████╔╝██╔████╔██║██║██╔██╗ ██║█████╗  \x1b[0m
\x1b[38;5;226m██║   ██║██║   ██║██╔══██╗██║╚██╔╝██║██║██║╚██╗██║██╔══╝  \x1b[0m
\x1b[38;5;190m╚██████╔╝╚██████╔╝██║  ██║██║ ╚═╝ ██║██║██║ ╚████║███████╗\x1b[0m ⛏️ \x1b[90mv${OURMINE_VERSION}\x1b[0m
\x1b[90m ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚══════╝\x1b[0m
\x1b[90m OpenCode Autonomous Agent Base · ARES Security Suite · HITL Gates\x1b[0m
`;
}

function help() {
  console.log(banner());
  console.log(`\x1b[1mUsage:\x1b[0m  ourmine [command] [options]

\x1b[1mDeveloper Commands:\x1b[0m  (OpenCode Engine)
  \x1b[36m(default)\x1b[0m           Launch the interactive Terminal UI
  \x1b[36mserve\x1b[0m               Start the OurMine server daemon
  \x1b[36msession\x1b[0m             Manage sessions (list, create, delete)
  \x1b[36mrun\x1b[0m <prompt>         Run a one-shot agent prompt
  \x1b[36mmodels\x1b[0m              List available AI models
  \x1b[36mproviders\x1b[0m           Manage LLM providers
  \x1b[36mmcp\x1b[0m                 Manage MCP servers
  \x1b[36mplugin\x1b[0m              Manage plugins
  \x1b[36mweb\x1b[0m                 Open the web console

\x1b[1mSecurity & Pentest Commands:\x1b[0m  (ARES Suite)
  \x1b[31mrecon\x1b[0m <target>      Run automated network/web reconnaissance
  \x1b[31maudit\x1b[0m <target>      Run vulnerability audit & ATT&CK analysis
  \x1b[31mpentest\x1b[0m <target>    Run autonomous adversary emulation run
  \x1b[31myara\x1b[0m <path>         Scan file/binary against YARA rulepack
  \x1b[31mc2\x1b[0m                  Manage C2 channels & listener infrastructure
  \x1b[31mopsec\x1b[0m               Validate OPSEC policies & evasion checks
  \x1b[31mstatus\x1b[0m              OurMine runtime status

\x1b[1mOptions:\x1b[0m
  \x1b[90m--help, -h\x1b[0m          Show this help
  \x1b[90m--version, -v\x1b[0m       Show version
`);
}

function status() {
  console.log(banner());
  console.log(`\x1b[1mRuntime Status\x1b[0m
  Engine           : OpenCode Autonomous Agent Base
  Security Core    : ARES ATT&CK Engine (75+ Modules)
  Database         : ares2.db (MITRE TTPs & YARA Rules Seeded)
  Node.js          : ${process.version}
  Platform         : ${process.platform} (${process.arch})
  OURMINE_ROOT     : ${process.env.OURMINE_ROOT || process.cwd()}
`);
}

const [,, cmd, ...rest] = process.argv;

switch (cmd) {
  case 'status': status(); break;
  case '--help': case '-h': case 'help': help(); break;
  case '--version': case '-v': console.log(`OurMine ⛏️ v${OURMINE_VERSION}`); break;
  default:
    if (!cmd || cmd === 'tui') {
      console.log(banner());
      console.log(`\x1b[38;5;208m[OurMine TUI]\x1b[0m Autonomous AI Security & Developer Agent ready.`);
      console.log(`\x1b[90mType prompts or run commands (/recon, /audit, /pentest, /session, /help)\x1b[0m\n`);
    } else {
      console.log(`\x1b[38;5;208m[OurMine]\x1b[0m Executing command: ${cmd} ${rest.join(' ')}`);
    }
}
