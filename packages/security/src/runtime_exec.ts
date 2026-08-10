/**
 * @module runtime/exec
 * OurMine Terminal Execution Engine — streams real subprocess output to the
 * TUI with OpenCode-style display: spinners, agent event log, tool-call banners,
 * PTY passthrough, and subagent tracking.
 */

import { spawn, spawnSync } from "node:child_process"
import * as readline from "node:readline"

// ─── ANSI helpers ─────────────────────────────────────────────────────────────

const C = {
  reset:   "\x1b[0m",
  bold:    "\x1b[1m",
  dim:     "\x1b[2m",
  green:   "\x1b[32m",
  yellow:  "\x1b[33m",
  red:     "\x1b[31m",
  cyan:    "\x1b[36m",
  orange:  "\x1b[38;5;208m",
  grey:    "\x1b[90m",
  blue:    "\x1b[34m",
  magenta: "\x1b[35m",
  white:   "\x1b[97m",
}

const SPINNER_FRAMES = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]

// ─── Types ────────────────────────────────────────────────────────────────────

export interface ExecEvent {
  type:
    | "agent_start"     | "agent_done"
    | "tool_start"      | "tool_done"
    | "shell_start"     | "shell_stdout" | "shell_stderr" | "shell_done"
    | "subagent_spawn"  | "subagent_msg" | "subagent_done"
    | "finding"         | "log"          | "error"
  label:    string
  detail?:  string
  exitCode?: number
  severity?: "critical" | "high" | "medium" | "low" | "info"
}

export type EventHandler = (ev: ExecEvent) => void

// ─── Spinner (for interactive terminals) ─────────────────────────────────────

export class Spinner {
  private frame  = 0
  private timer?: ReturnType<typeof setInterval>
  private label  = ""

  start(label: string) {
    this.label = label
    if (!process.stdout.isTTY) {
      process.stdout.write(`${C.grey}…${C.reset} ${label}\n`)
      return
    }
    this.timer = setInterval(() => {
      process.stdout.write(`\r${C.cyan}${SPINNER_FRAMES[this.frame % SPINNER_FRAMES.length]}${C.reset} ${this.label}   `)
      this.frame++
    }, 80)
  }

  update(label: string) { this.label = label }

  stop(result: "ok" | "err" | "skip" = "ok") {
    if (this.timer) clearInterval(this.timer)
    const icon = result === "ok" ? `${C.green}✔${C.reset}` : result === "err" ? `${C.red}✖${C.reset}` : `${C.grey}–${C.reset}`
    if (process.stdout.isTTY) process.stdout.write("\r\x1b[2K")
    process.stdout.write(`  ${icon} ${this.label}\n`)
  }
}

// ─── Live execution display ────────────────────────────────────────────────────

export class ExecutionDisplay {
  private handlers: EventHandler[] = []

  onEvent(handler: EventHandler) { this.handlers.push(handler) }

  emit(ev: ExecEvent) {
    this.handlers.forEach(h => h(ev))
    this._print(ev)
  }

  private _print(ev: ExecEvent) {
    switch (ev.type) {
      case "agent_start":
        console.log(`\n${C.bold}${C.orange}◈ Agent Start${C.reset}  ${ev.label}`)
        console.log(`${C.grey}${"─".repeat(60)}${C.reset}`)
        break
      case "agent_done":
        console.log(`${C.grey}${"─".repeat(60)}${C.reset}`)
        console.log(`${C.green}◉ Agent Complete${C.reset}  ${ev.label}\n`)
        break
      case "tool_start":
        console.log(`  ${C.cyan}⟫ Tool${C.reset}  ${C.bold}${ev.label}${C.reset}  ${C.grey}${ev.detail ?? ""}${C.reset}`)
        break
      case "tool_done":
        console.log(`  ${C.green}✔ Done${C.reset}  ${C.bold}${ev.label}${C.reset}  ${C.grey}${ev.detail ?? ""}${C.reset}`)
        break
      case "shell_start":
        console.log(`\n  ${C.orange}▸ Shell${C.reset}  ${C.bold}${ev.label}${C.reset}`)
        break
      case "shell_stdout":
        process.stdout.write(`${C.grey}  │${C.reset} ${ev.detail}\n`)
        break
      case "shell_stderr":
        process.stdout.write(`${C.yellow}  │${C.reset} ${ev.detail}\n`)
        break
      case "shell_done":
        console.log(`  ${ev.exitCode === 0 ? C.green + "✔" : C.red + "✖"}${C.reset} exit ${ev.exitCode ?? 0}`)
        break
      case "subagent_spawn":
        console.log(`\n  ${C.magenta}⬡ Subagent${C.reset}  ${C.bold}${ev.label}${C.reset}  ${C.grey}spawned${C.reset}`)
        break
      case "subagent_msg":
        console.log(`  ${C.magenta}│${C.reset} ${ev.detail}`)
        break
      case "subagent_done":
        console.log(`  ${C.green}⬡ Subagent${C.reset}  ${C.bold}${ev.label}${C.reset}  ${C.grey}done${C.reset}`)
        break
      case "finding": {
        const sev = ev.severity ?? "info"
        const sevColor = sev === "critical" ? C.red : sev === "high" ? C.orange : sev === "medium" ? C.yellow : C.grey
        console.log(`  ${sevColor}◆ Finding${C.reset}  [${sev.toUpperCase()}]  ${C.bold}${ev.label}${C.reset}`)
        if (ev.detail) console.log(`    ${C.grey}${ev.detail}${C.reset}`)
        break
      }
      case "log":
        console.log(`  ${C.grey}·${C.reset} ${ev.detail ?? ev.label}`)
        break
      case "error":
        console.log(`  ${C.red}✖ Error${C.reset}  ${ev.label}  ${C.grey}${ev.detail ?? ""}${C.reset}`)
        break
    }
  }
}

// ─── Shell executor — streams stdout/stderr in real-time ──────────────────────

export interface ShellOptions {
  env?:     Record<string, string>
  cwd?:     string
  timeout?: number
  live?:    boolean
}

export function execShell(
  cmd: string,
  display: ExecutionDisplay,
  opts: ShellOptions = {}
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  return new Promise((resolve) => {
    if (!opts.live) {
      display.emit({ type: "shell_start",  label: cmd })
      display.emit({ type: "shell_stdout", label: cmd, detail: `[DRY-RUN] ${cmd}` })
      display.emit({ type: "shell_done",   label: cmd, exitCode: 0 })
      resolve({ stdout: `[DRY-RUN] ${cmd}`, stderr: "", exitCode: 0 })
      return
    }

    display.emit({ type: "shell_start", label: cmd })

    const proc = spawn("bash", ["-c", cmd], {
      env:   { ...process.env, ...(opts.env ?? {}) },
      cwd:   opts.cwd ?? process.cwd(),
      stdio: ["ignore", "pipe", "pipe"],
    })

    let stdout = ""
    let stderr = ""

    proc.stdout.setEncoding("utf8")
    proc.stderr.setEncoding("utf8")

    proc.stdout.on("data", (chunk: string) => {
      stdout += chunk
      chunk.trimEnd().split("\n").forEach(line =>
        display.emit({ type: "shell_stdout", label: cmd, detail: line }))
    })

    proc.stderr.on("data", (chunk: string) => {
      stderr += chunk
      chunk.trimEnd().split("\n").forEach(line =>
        display.emit({ type: "shell_stderr", label: cmd, detail: line }))
    })

    if (opts.timeout) {
      setTimeout(() => proc.kill("SIGTERM"), opts.timeout)
    }

    proc.on("close", (code) => {
      const exitCode = code ?? 1
      display.emit({ type: "shell_done", label: cmd, exitCode })
      resolve({ stdout, stderr, exitCode })
    })
  })
}

// ─── Subagent simulation display ─────────────────────────────────────────────

export interface SubagentConfig {
  id:       string
  role:     string
  task:     string
  modules?: string[]
}

export async function runSubagent(
  cfg: SubagentConfig,
  display: ExecutionDisplay,
  opts: { live?: boolean } = {}
): Promise<{ id: string; status: "done" | "error"; findings: string[] }> {
  display.emit({ type: "subagent_spawn", label: `[${cfg.id}] ${cfg.role}` })
  display.emit({ type: "subagent_msg",   label: cfg.id, detail: `Task: ${cfg.task}` })

  const findings: string[] = []

  for (const mod of (cfg.modules ?? [])) {
    display.emit({ type: "tool_start", label: mod, detail: cfg.task })
    await new Promise(r => setTimeout(r, 40)) // simulate async work
    const finding = `[${cfg.role}] Module '${mod}' executed — dry-run result`
    findings.push(finding)
    display.emit({ type: "tool_done", label: mod, detail: "completed" })
  }

  display.emit({ type: "subagent_done", label: `[${cfg.id}] ${cfg.role}` })
  return { id: cfg.id, status: "done", findings }
}

export default { ExecutionDisplay, Spinner, execShell, runSubagent }
