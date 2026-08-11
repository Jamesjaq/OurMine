/**
 * Live Reconnaissance Engine
 * Real OSINT, DNS enumeration, certificate transparency, and WHOIS lookup.
 * Uses: gobuster, dig, whois, curl (via execFile & HTTP)
 */

import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import * as https from 'node:https'
import * as http from 'node:http'

const execFileP = promisify(execFile)

export interface ReconFinding {
  type: 'subdomain' | 'cert' | 'whois' | 'dns_zone_transfer' | 'dork'
  domain: string
  detail: string
  severity: 'info' | 'low' | 'medium' | 'high'
  data: string
}

export class LiveReconEngine {
  async enumerateSubdomains(domain: string, wordlist?: string): Promise<string[]> {
    const subdomains = new Set<string>()
    const wl = wordlist || '/usr/share/wordlists/dirb/common.txt'
    try {
      const result = await execFileP('gobuster', ['dns', '-d', domain, '-w', wl, '-t', '20'], { timeout: 60000 }).catch((e: unknown) => ({ stdout: (e as {stdout?: string}).stdout || '' }))
      const lines = result.stdout.split('\n')
      for (const line of lines) {
        const m = line.match(/Found:\s*(\S+)/i)
        if (m && m[1]) subdomains.add(m[1].toLowerCase())
      }
    } catch { /* ignore */ }
    // Also try crt.sh query
    try {
      const crtSubs = await this.queryCrtSh(domain)
      for (const sub of crtSubs) subdomains.add(sub)
    } catch { /* ignore */ }
    return [...subdomains]
  }

  async queryCrtSh(domain: string): Promise<string[]> {
    const subdomains = new Set<string>()
    return new Promise((resolve) => {
      const url = `https://crt.sh/?q=%.${domain}&output=json`
      https.get(url, { timeout: 10000 }, (res) => {
        let data = ''
        res.on('data', d => { data += d })
        res.on('end', () => {
          try {
            const parsed = JSON.parse(data) as Array<{ name_value: string }>
            for (const item of parsed) {
              const names = item.name_value.split('\n')
              for (const name of names) {
                const cleaned = name.trim().toLowerCase().replace(/^\*\./, '')
                if (cleaned.endsWith(domain)) subdomains.add(cleaned)
              }
            }
          } catch { /* ignore JSON parse error */ }
          resolve([...subdomains])
        })
      }).on('error', () => resolve([])).on('timeout', () => resolve([]))
    })
  }

  async checkDnsZoneTransfer(domain: string): Promise<ReconFinding[]> {
    const findings: ReconFinding[] = []
    try {
      // Find nameservers first
      const nsResult = await execFileP('dig', ['NS', domain, '+short'], { timeout: 10000 }).catch(() => ({ stdout: '' }))
      const nsList = nsResult.stdout.split('\n').map(s => s.trim()).filter(Boolean)
      for (const ns of nsList) {
        try {
          const axfrResult = await execFileP('dig', ['AXFR', `@${ns}`, domain], { timeout: 15000 }).catch(() => ({ stdout: '' }))
          if (axfrResult.stdout.includes('IN\tA') || axfrResult.stdout.includes('IN A')) {
            findings.push({
              type: 'dns_zone_transfer',
              domain,
              detail: `DNS Zone Transfer SUCCEEDED on nameserver ${ns}`,
              severity: 'high',
              data: axfrResult.stdout.slice(0, 2000),
            })
          }
        } catch { /* ignore */ }
      }
    } catch { /* ignore */ }
    return findings
  }

  async lookupWhois(domain: string): Promise<ReconFinding[]> {
    const findings: ReconFinding[] = []
    try {
      const result = await execFileP('whois', [domain], { timeout: 10000 })
      const out = result.stdout
      const registrar = out.match(/Registrar:\s*([^\n]+)/i)?.[1]
      const created = out.match(/Creation Date:\s*([^\n]+)/i)?.[1]
      const org = out.match(/Registrant Organization:\s*([^\n]+)/i)?.[1]
      findings.push({
        type: 'whois',
        domain,
        detail: `WHOIS: Org=${org || 'N/A'}, Registrar=${registrar || 'N/A'}, Created=${created || 'N/A'}`,
        severity: 'info',
        data: out.slice(0, 1500),
      })
    } catch { /* ignore */ }
    return findings
  }

  async fullRecon(domain: string): Promise<{ findings: ReconFinding[]; subdomains: string[] }> {
    const [subdomains, zoneTransfers, whois] = await Promise.all([
      this.enumerateSubdomains(domain).catch(() => [] as string[]),
      this.checkDnsZoneTransfer(domain).catch(() => [] as ReconFinding[]),
      this.lookupWhois(domain).catch(() => [] as ReconFinding[]),
    ])
    const findings: ReconFinding[] = [
      ...zoneTransfers,
      ...whois,
      ...subdomains.map(s => ({
        type: 'subdomain' as const,
        domain: s,
        detail: `Discovered subdomain: ${s}`,
        severity: 'info' as const,
        data: s,
      })),
    ]
    return { findings, subdomains }
  }
}
