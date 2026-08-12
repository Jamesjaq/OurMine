/**
 * @module domain_probe
 * Shared DNS/WHOIS/HTTP probes for live social-engineering and OAuth assessments.
 */
import { execFile } from "node:child_process"
import { promisify } from "node:util"
import { resolveMx, resolveTxt } from "node:dns/promises"

const execFileP = promisify(execFile)

export interface HttpProbeResult {
  url: string
  status: number
  ok: boolean
  bodyPreview: string
}

export async function httpProbe(url: string, timeoutMs = 5000): Promise<HttpProbeResult> {
  try {
    const resp = await fetch(url, {
      method: "GET",
      signal: AbortSignal.timeout(timeoutMs),
      redirect: "manual",
      headers: {
        Accept: "application/json, text/html, */*",
        "User-Agent": "OurMine/1.0 (authorized-assessment)",
      },
    })
    const body = await resp.text().catch(() => "")
    const ok = resp.ok || resp.status === 301 || resp.status === 302
    return { url, status: resp.status, ok, bodyPreview: body.slice(0, 800) }
  } catch {
    return { url, status: 0, ok: false, bodyPreview: "" }
  }
}

export interface EmailSecurityProbe {
  mx: string[]
  spf: string | null
  dmarc: string | null
  dmarcPolicy: string | null
}

export async function probeEmailSecurity(domain: string): Promise<EmailSecurityProbe> {
  const mx: string[] = []
  let spf: string | null = null
  let dmarc: string | null = null
  let dmarcPolicy: string | null = null

  try {
    const mxRecs = await resolveMx(domain)
    mx.push(...mxRecs.map((r) => r.exchange.replace(/\.$/, "")))
  } catch { /* no MX */ }

  try {
    const txt = await resolveTxt(domain)
    for (const rec of txt) {
      const joined = rec.join("")
      if (joined.toLowerCase().startsWith("v=spf1")) spf = joined
    }
  } catch { /* no TXT */ }

  try {
    const dmarcTxt = await resolveTxt(`_dmarc.${domain}`)
    for (const rec of dmarcTxt) {
      const joined = rec.join("")
      if (joined.toLowerCase().startsWith("v=dmarc1")) {
        dmarc = joined
        dmarcPolicy = joined.match(/;\s*p=([^;\s]+)/i)?.[1] ?? null
      }
    }
  } catch { /* no DMARC */ }

  return { mx, spf, dmarc, dmarcPolicy }
}

export async function probeWhois(domain: string): Promise<{ registrar: string | null; org: string | null; raw: string }> {
  try {
    const { stdout } = await execFileP("whois", [domain], { timeout: 10000 })
    const raw = stdout.slice(0, 1500)
    return {
      registrar: raw.match(/Registrar:\s*([^\n]+)/i)?.[1]?.trim() ?? null,
      org: raw.match(/Registrant Organization:\s*([^\n]+)/i)?.[1]?.trim() ?? null,
      raw,
    }
  } catch {
    return { registrar: null, org: null, raw: "" }
  }
}
