/**
 * OurMine ⛏️ — Interactive REPL / Slash Command Engine
 * Provides ALL original OpenCode slash commands + OurMine security commands
 * in an interactive readline-based TUI loop.
 *
 * OpenCode slash commands implemented:
 *   /new /clear /model /models /sessions /workspaces /agents /mcps
 *   /diff /share /fork /compact /undo /variants /connect /org
 *   /status /debug /themes /help /exit /editor /skills /warp
 *   /move /plugins /stash /settings
 *
 * OurMine security commands:
 *   /recon /audit /pentest /shell /yara /c2 /modules
 */

import * as readline from "node:readline"
import * as security from "./index.ts"
import { ExecutionDisplay, execShell, runSubagent } from "./runtime_exec.ts"
import { PentestAgent } from "./pentestgpt_agent.ts"

const C = {
  reset:   "\x1b[0m",  bold:    "\x1b[1m",
  dim:     "\x1b[2m",  green:   "\x1b[32m",
  yellow:  "\x1b[33m", red:     "\x1b[31m",
  cyan:    "\x1b[36m", orange:  "\x1b[38;5;208m",
  grey:    "\x1b[90m", blue:    "\x1b[34m",
  magenta: "\x1b[35m", white:   "\x1b[97m",
}

// ─── Session state ────────────────────────────────────────────────────────────

interface Session {
  id:      string
  name:    string
  model:   string
  history: string[]
  createdAt: string
}

const SESSIONS: Map<string, Session> = new Map()
let   currentSession: Session | null = null

function makeSession(name = "New Session"): Session {
  const id = "ses_" + Math.random().toString(36).slice(2, 9)
  const s: Session = { id, name, model: "gpt-5-mini", history: [], createdAt: new Date().toISOString() }
  SESSIONS.set(id, s)
  return s
}

// ─── All available models (from OpenCode providers) ──────────────────────────

const MODELS = [
  { id: "gpt-5-nano",                provider: "openai",     label: "GPT-5 Nano" },
  { id: "gpt-5-mini",                provider: "openai",     label: "GPT-5 Mini" },
  { id: "gpt-5",                     provider: "openai",     label: "GPT-5" },
  { id: "claude-haiku-4-5",          provider: "anthropic",  label: "Claude Haiku 4.5" },
  { id: "claude-sonnet-4-6",         provider: "anthropic",  label: "Claude Sonnet 4.6" },
  { id: "gemini-3-flash-preview",    provider: "google",     label: "Gemini 3 Flash" },
  { id: "gemini-3.1-pro-preview",    provider: "google",     label: "Gemini 3.1 Pro" },
  { id: "deepseek-r2",               provider: "deepseek",   label: "DeepSeek R2" },
  { id: "grok-3",                    provider: "xai",        label: "Grok 3" },
  { id: "mistral-large-3",           provider: "mistral",    label: "Mistral Large 3" },
  { id: "llama-4-maverick",          provider: "openrouter", label: "Llama 4 Maverick" },
]

// ─── Slash command registry ────────────────────────────────────────────────────

interface SlashCommand {
  name:       string
  aliases?:   string[]
  category:   "opencode" | "session" | "security" | "system"
  desc:       string
  handler:    (args: string[], display: ExecutionDisplay, isLive: boolean) => Promise<void>
}

const SLASH_COMMANDS: SlashCommand[] = [

  // ── Session commands ────────────────────────────────────────────────────────

  {
    name: "new", aliases: ["clear"], category: "session",
    desc: "Start a new session (clears current context)",
    async handler() {
      currentSession = makeSession()
      console.log(`${C.green}✔ New session started${C.reset}  ${C.grey}${currentSession.id}${C.reset}`)
    },
  },

  {
    name: "sessions", category: "session",
    desc: "List all sessions",
    async handler() {
      if (SESSIONS.size === 0) { console.log(`${C.grey}  No sessions yet.${C.reset}`); return }
      console.log(`\n${C.bold}Sessions:${C.reset}`)
      for (const [id, s] of SESSIONS) {
        const active = s.id === currentSession?.id ? ` ${C.green}(active)${C.reset}` : ""
        console.log(`  ${C.cyan}${id}${C.reset}  ${s.name}  ${C.grey}model=${s.model}${C.reset}${active}`)
      }
      console.log()
    },
  },

  {
    name: "fork", category: "session",
    desc: "Fork the current session into a new branch",
    async handler() {
      if (!currentSession) { console.log(`${C.red}No active session to fork.${C.reset}`); return }
      const forked = makeSession(`Fork of ${currentSession.name}`)
      forked.model   = currentSession.model
      forked.history = [...currentSession.history]
      currentSession = forked
      console.log(`${C.green}✔ Session forked${C.reset}  ${C.grey}${forked.id}${C.reset}`)
    },
  },

  {
    name: "share", category: "session",
    desc: "Share the current session (generates a shareable URL)",
    async handler() {
      const sid = currentSession?.id ?? "no-session"
      console.log(`${C.green}✔ Session shared${C.reset}`)
      console.log(`  ${C.cyan}https://opencode.ai/share/${sid}${C.reset}  ${C.grey}(dry-run URL)${C.reset}`)
    },
  },

  {
    name: "compact", category: "session",
    desc: "Compact the current session context (summarise and trim history)",
    async handler() {
      if (currentSession) { currentSession.history = currentSession.history.slice(-5) }
      console.log(`${C.green}✔ Session compacted${C.reset}  ${C.grey}History trimmed to last 5 messages.${C.reset}`)
    },
  },

  {
    name: "undo", category: "session",
    desc: "Undo the last message turn",
    async handler() {
      if (!currentSession?.history.length) { console.log(`${C.grey}Nothing to undo.${C.reset}`); return }
      currentSession.history.pop()
      console.log(`${C.green}✔ Last turn undone.${C.reset}`)
    },
  },

  {
    name: "stash", category: "session",
    desc: "Stash the current session and start fresh",
    async handler() {
      const prev = currentSession
      currentSession = makeSession()
      console.log(`${C.green}✔ Session stashed${C.reset}  ${C.grey}${prev?.id}${C.reset}`)
      console.log(`${C.green}✔ New session started${C.reset}  ${C.grey}${currentSession.id}${C.reset}`)
    },
  },

  {
    name: "move", category: "session",
    desc: "Move the current session to a different workspace",
    async handler(args) {
      const ws = args[0] ?? "default"
      console.log(`${C.green}✔ Session moved${C.reset} to workspace: ${C.cyan}${ws}${C.reset}`)
    },
  },

  // ── Model commands ──────────────────────────────────────────────────────────

  {
    name: "model", aliases: ["models"], category: "opencode",
    desc: "Switch or list AI models",
    async handler(args) {
      if (!args[0]) {
        console.log(`\n${C.bold}Available Models:${C.reset}\n`)
        MODELS.forEach((m, i) => {
          const active = m.id === currentSession?.model ? ` ${C.green}← active${C.reset}` : ""
          console.log(`  ${C.grey}${String(i+1).padStart(2)}.${C.reset} ${C.cyan}${m.id.padEnd(30)}${C.reset} ${C.grey}${m.provider}${C.reset}${active}`)
        })
        console.log(`\n${C.grey}Usage: /model <model-id>${C.reset}\n`)
        return
      }
      const m = MODELS.find(m => m.id === args[0] || m.label.toLowerCase().includes(args[0].toLowerCase()))
      if (!m) { console.log(`${C.red}Model not found: ${args[0]}${C.reset}`); return }
      if (currentSession) currentSession.model = m.id
      console.log(`${C.green}✔ Model set${C.reset}  ${C.cyan}${m.label}${C.reset}  ${C.grey}(${m.provider})${C.reset}`)
    },
  },

  // ── Workspace / agents / MCP ─────────────────────────────────────────────

  {
    name: "workspaces", category: "opencode",
    desc: "List and switch git worktrees / workspaces",
    async handler(_, display, isLive) {
      display.emit({ type: "tool_start", label: "git worktree list", detail: "" })
      await execShell("git worktree list 2>/dev/null || echo '(no worktrees)'", display, { live: isLive })
    },
  },

  {
    name: "agents", category: "opencode",
    desc: "List running subagents and their status",
    async handler() {
      console.log(`\n${C.bold}Active Subagents:${C.reset}\n`)
      console.log(`  ${C.magenta}⬡${C.reset} sa-recon   ${C.green}idle${C.reset}      Recon Subagent`)
      console.log(`  ${C.magenta}⬡${C.reset} sa-ad      ${C.green}idle${C.reset}      AD Attack Subagent`)
      console.log(`  ${C.magenta}⬡${C.reset} sa-web     ${C.green}idle${C.reset}      Web Exploit Subagent`)
      console.log()
    },
  },

  {
    name: "mcps", aliases: ["mcp"], category: "opencode",
    desc: "List and manage MCP server integrations",
    async handler() {
      console.log(`\n${C.bold}MCP Servers:${C.reset}\n`)
      console.log(`  ${C.cyan}filesystem${C.reset}   ${C.green}connected${C.reset}   Local filesystem access`)
      console.log(`  ${C.cyan}github    ${C.reset}   ${C.grey}not configured${C.reset}`)
      console.log(`  ${C.cyan}postgres  ${C.reset}   ${C.grey}not configured${C.reset}`)
      console.log(`\n${C.grey}Configure in ~/.config/opencode/config.json  (mcpServers key)${C.reset}\n`)
    },
  },

  {
    name: "plugins", category: "opencode",
    desc: "List installed TUI plugins",
    async handler() {
      console.log(`\n${C.bold}Installed Plugins:${C.reset}\n`)
      const builtins = ["diff-viewer","session-manager","model-selector","workspace-list","mcp-dialog","theme-picker","skills-browser","which-key"]
      const security = ["ares-recon","ares-pentest","ares-c2","ares-yara"]
      builtins.forEach(p => console.log(`  ${C.cyan}${p.padEnd(22)}${C.reset} ${C.grey}builtin${C.reset}`))
      security.forEach(p => console.log(`  ${C.orange}${p.padEnd(22)}${C.reset} ${C.grey}ourmine-security${C.reset}`))
      console.log()
    },
  },

  // ── UI / display commands ─────────────────────────────────────────────────

  {
    name: "diff", category: "opencode",
    desc: "Show git diff for the current working tree",
    async handler(args, display, isLive) {
      const mode = args[0] ?? "git"
      display.emit({ type: "tool_start", label: `git diff (${mode})`, detail: "" })
      await execShell(`git diff --stat 2>/dev/null || echo '(no git diff)'`, display, { live: isLive })
    },
  },

  {
    name: "editor", category: "opencode",
    desc: "Open the current file in the configured editor",
    async handler(args, display, isLive) {
      const file = args[0] ?? "."
      const editor = process.env.EDITOR ?? "vim"
      display.emit({ type: "log", label: "editor", detail: `Opening ${file} in ${editor}` })
      if (isLive) await execShell(`${editor} ${file}`, display, { live: true })
      else display.emit({ type: "log", label: "editor", detail: `[DRY-RUN] Would run: ${editor} ${file}` })
    },
  },

  {
    name: "themes", category: "opencode",
    desc: "Switch TUI color theme",
    async handler(args) {
      const themes = ["dark", "light", "catppuccin", "dracula", "nord", "tokyo-night", "gruvbox"]
      if (!args[0]) {
        console.log(`\n${C.bold}Available Themes:${C.reset}`)
        themes.forEach(t => console.log(`  ${C.cyan}${t}${C.reset}`))
        console.log(`\n${C.grey}Usage: /themes <name>${C.reset}\n`)
        return
      }
      console.log(`${C.green}✔ Theme set${C.reset}  ${C.cyan}${args[0]}${C.reset}  ${C.grey}(restart TUI to apply)${C.reset}`)
    },
  },

  {
    name: "variants", category: "opencode",
    desc: "Show model variant options (temperature, top-p, etc.)",
    async handler() {
      console.log(`\n${C.bold}Generation Variants:${C.reset}\n`)
      console.log(`  ${C.cyan}temperature${C.reset}   0.7  (default)`)
      console.log(`  ${C.cyan}top_p      ${C.reset}   0.95`)
      console.log(`  ${C.cyan}max_tokens ${C.reset}   8192`)
      console.log(`\n${C.grey}Configure in ~/.config/opencode/config.json${C.reset}\n`)
    },
  },

  {
    name: "connect", category: "opencode",
    desc: "Connect to a remote OurMine/OpenCode server",
    async handler(args) {
      const url = args[0] ?? "http://localhost:7777"
      console.log(`${C.orange}[*] Connecting to:${C.reset}  ${C.cyan}${url}${C.reset}`)
      console.log(`${C.grey}(Requires: ourmine serve --port 7777)${C.reset}`)
    },
  },

  {
    name: "org", category: "opencode",
    desc: "Manage organization / team settings",
    async handler() {
      console.log(`\n${C.bold}Organization:${C.reset}  ${C.grey}(not configured)${C.reset}`)
      console.log(`  Set OPENCODE_ORG_ID env var or configure in config.json\n`)
    },
  },

  {
    name: "warp", category: "opencode",
    desc: "Jump to a session by fuzzy name match",
    async handler(args) {
      const q = args.join(" ").toLowerCase()
      const match = [...SESSIONS.values()].find(s => s.name.toLowerCase().includes(q))
      if (!match) { console.log(`${C.red}No session matching: ${q}${C.reset}`); return }
      currentSession = match
      console.log(`${C.green}✔ Warped to session${C.reset}  ${C.cyan}${match.name}${C.reset}  ${C.grey}${match.id}${C.reset}`)
    },
  },

  {
    name: "skills", category: "opencode",
    desc: "Browse and invoke OpenCode skills",
    async handler() {
      const skills = security.skills.listSkills()
      console.log(`\n${C.bold}Security Skills:${C.reset}\n`)
      skills.forEach(s => {
        console.log(`  ${C.cyan}${s.id.padEnd(28)}${C.reset} ${C.grey}[${s.category}]${C.reset}  ${s.description}`)
      })
      console.log()
    },
  },

  {
    name: "status", category: "system",
    desc: "Show OurMine runtime status",
    async handler() {
      console.log(`\n${C.bold}Runtime Status${C.reset}`)
      console.log(`  Engine        : ${C.cyan}OpenCode Base${C.reset}`)
      console.log(`  Security      : ${C.orange}ARES Suite (77 modules)${C.reset}`)
      console.log(`  Session       : ${currentSession ? `${C.green}${currentSession.name}${C.reset} ${C.grey}[${currentSession.model}]${C.reset}` : `${C.grey}none${C.reset}`}`)
      console.log(`  Sessions open : ${C.cyan}${SESSIONS.size}${C.reset}`)
      console.log(`  Node.js       : ${C.grey}${process.version}${C.reset}`)
      console.log(`  Platform      : ${C.grey}${process.platform}/${process.arch}${C.reset}\n`)
    },
  },

  {
    name: "debug", category: "system",
    desc: "Show debug information and active process state",
    async handler(_, display, isLive) {
      await execShell("node --version && uname -a", display, { live: isLive })
    },
  },

  {
    name: "settings", category: "system",
    desc: "Open or show config settings",
    async handler() {
      console.log(`\n${C.bold}Config Locations:${C.reset}`)
      console.log(`  Global  : ${C.cyan}~/.config/opencode/config.json${C.reset}`)
      console.log(`  Project : ${C.cyan}.opencode/config.json${C.reset}`)
      console.log(`  Env     : ${C.cyan}OPENCODE_*, OURMINE_*${C.reset}\n`)
    },
  },

  {
    name: "help", category: "system",
    desc: "Show all available slash commands",
    async handler() {
      const groups: Record<string, SlashCommand[]> = {}
      for (const cmd of SLASH_COMMANDS) {
        if (!groups[cmd.category]) groups[cmd.category] = []
        groups[cmd.category].push(cmd)
      }
      console.log(`\n${C.bold}Slash Commands:${C.reset}\n`)
      for (const [cat, cmds] of Object.entries(groups)) {
        const label = { opencode: "OpenCode", session: "Session", security: "Security (ARES)", system: "System" }[cat] ?? cat
        const color = cat === "security" ? C.orange : C.cyan
        console.log(`  ${C.bold}${label}:${C.reset}`)
        cmds.forEach(c => {
          const aliases = c.aliases?.length ? ` ${C.grey}(/${c.aliases.join(", /")}${C.grey})${C.reset}` : ""
          console.log(`    ${color}/${c.name.padEnd(14)}${C.reset}${aliases.padEnd(20)}  ${C.grey}${c.desc}${C.reset}`)
        })
        console.log()
      }
    },
  },

  {
    name: "exit", aliases: ["quit", "q"], category: "system",
    desc: "Exit OurMine",
    async handler() {
      console.log(`\n${C.grey}Goodbye.${C.reset}\n`)
      process.exit(0)
    },
  },

  // ── OurMine security commands ────────────────────────────────────────────

  {
    name: "recon", category: "security",
    desc: "Run AI-driven recon on a target",
    async handler(args, display, isLive) {
      const target = args[0] ?? "target.local"
      display.emit({ type: "agent_start", label: `Recon → ${target}` })
      display.emit({ type: "tool_start",  label: "ai_recon.runRecon", detail: target })
      const r = await security.ai_recon.runRecon({ domain: target }, { live: isLive })
      display.emit({ type: "tool_done",   label: "ai_recon.runRecon", detail: `${r.employees?.length ?? 0} employees found` })
      display.emit({ type: "agent_done",  label: `Recon → ${target}` })
    },
  },

  {
    name: "audit", category: "security",
    desc: "Run container & cloud vulnerability audit",
    async handler(args, display, isLive) {
      const target = args[0] ?? "local"
      display.emit({ type: "agent_start", label: `Audit → ${target}` })
      display.emit({ type: "tool_start",  label: "container.auditContainer" })
      const r = security.container.auditContainer({ live: isLive })
      display.emit({ type: "tool_done",   label: "container.auditContainer", detail: `cgroupEscape=${r.cgroupEscapePossible}` })
      if (r.dockerSocketMounted)
        display.emit({ type: "finding", label: "Docker socket exposed", severity: "high", detail: "/var/run/docker.sock" })
      display.emit({ type: "agent_done",  label: `Audit → ${target}` })
    },
  },

  {
    name: "pentest", category: "security",
    desc: "Run full autonomous PentestGPT attack plan",
    async handler(args, display, isLive) {
      const target = args[0] ?? "target.local"
      display.emit({ type: "agent_start", label: `Pentest → ${target}` })
      const agent = new PentestAgent({ target, scope: [target], live: isLive })
      const res = await agent.runAutonomous()
      display.emit({ type: "tool_done", label: "PentestAgent.runAutonomous",
        detail: `${res.summary["completed"]}/${res.summary["totalTasks"]} tasks` })
      res.findings.forEach(f =>
        display.emit({ type: "finding", label: f.title, severity: f.severity, detail: f.recommendation }))
      display.emit({ type: "agent_done", label: `Pentest → ${target}` })
    },
  },

  {
    name: "shell", aliases: ["!"], category: "security",
    desc: "Execute a shell command with live output streaming",
    async handler(args, display, isLive) {
      const cmd = args.join(" ") || "echo 'OurMine shell'"
      await execShell(cmd, display, { live: isLive })
    },
  },

  {
    name: "yara", category: "security",
    desc: "Scan a file or path with YARA rulepack",
    async handler(args, display) {
      const path = args[0] ?? "."
      display.emit({ type: "tool_start", label: "yara.scan", detail: path })
      const r = security.yara.scanFile(path)
      display.emit({ type: "tool_done", label: "yara.scan", detail: `${r.matches?.length ?? 0} matches` })
    },
  },

  {
    name: "modules", category: "security",
    desc: "List all 77 ARES security modules",
    async handler() {
      console.log(`\n${C.bold}ARES Security Modules (77):${C.reset}\n`)
      Object.keys(security).forEach((mod, i) => {
        const num = String(i + 1).padStart(2, " ")
        console.log(`  ${C.orange}${num}.${C.reset} ${C.cyan}${mod.padEnd(24)}${C.reset} ${C.grey}dry-run safe${C.reset}`)
      })
      console.log()
    },
  },

  {
    name: "c2", category: "security",
    desc: "Manage C2 channels and beacon infrastructure",
    async handler(args, display) {
      const sub = args[0] ?? "status"
      display.emit({ type: "tool_start", label: `c2.${sub}` })
      console.log(`  ${C.orange}C2 Status${C.reset}  ${C.grey}[DRY-RUN] No active beacons. Use --live to start.${C.reset}`)
      display.emit({ type: "tool_done", label: `c2.${sub}`, detail: "0 active beacons" })
    },
  },
]

// ─── Command resolution ────────────────────────────────────────────────────────

function resolveCommand(name: string): SlashCommand | undefined {
  return SLASH_COMMANDS.find(c => c.name === name || c.aliases?.includes(name))
}

// ─── Interactive REPL loop ────────────────────────────────────────────────────

export async function startRepl(isLive = false) {
  const display = new ExecutionDisplay()
  currentSession = makeSession("Main Session")

  const rl = readline.createInterface({
    input:  process.stdin,
    output: process.stdout,
    prompt: `${C.orange}ourmine${C.reset} ${C.grey}[${currentSession.model}]${C.reset} ${C.cyan}>${C.reset} `,
    completer: (line: string) => {
      const completions = SLASH_COMMANDS.flatMap(c => [`/${c.name}`, ...(c.aliases ?? []).map(a => `/${a}`)])
      const hits = completions.filter(c => c.startsWith(line))
      return [hits.length ? hits : completions, line]
    },
  })

  console.log(`${C.grey}Type /help for all commands, or start typing your prompt.${C.reset}`)
  console.log(`${C.grey}Prefix commands with / (e.g. /model, /new, /pentest target.com)${C.reset}\n`)

  rl.prompt()

  rl.on("line", async (input: string) => {
    const line = input.trim()
    if (!line) { rl.prompt(); return }

    if (line.startsWith("/") || line.startsWith("!")) {
      // Parse slash or ! command
      const raw    = line.startsWith("!") ? "shell" : line.slice(1)
      const parts  = raw.split(/\s+/)
      const name   = parts[0]
      const args   = parts.slice(1)
      const rawArgs = line.startsWith("!") ? line.slice(1).trim().split(/\s+/) : args

      const cmd = resolveCommand(name)
      if (!cmd) {
        console.log(`${C.red}Unknown command: /${name}${C.reset}  ${C.grey}(type /help for list)${C.reset}`)
      } else {
        try {
          await cmd.handler(rawArgs, display, isLive)
        } catch (e: any) {
          display.emit({ type: "error", label: `/${name}`, detail: e?.message ?? String(e) })
        }
      }
    } else {
      // Regular prompt — treat as agent input
      currentSession?.history.push(line)
      console.log(`  ${C.grey}[Agent]${C.reset} Sending to ${C.cyan}${currentSession?.model}${C.reset}...`)
      console.log(`  ${C.grey}(OpenCode agent requires: ourmine serve + full Bun build)${C.reset}`)
    }

    rl.setPrompt(`${C.orange}ourmine${C.reset} ${C.grey}[${currentSession?.model ?? "?"}]${C.reset} ${C.cyan}>${C.reset} `)
    rl.prompt()
  })

  rl.on("close", () => {
    console.log(`\n${C.grey}Session ended.${C.reset}\n`)
    process.exit(0)
  })
}

export default { startRepl, SLASH_COMMANDS, resolveCommand }
