/**
 * @module extortion_mode
 * Extortion-only ransomware simulation — catalog/leak without encrypt.
 */
import { loadRansomwareGroups } from "./intel_feeds.ts"

export interface ExtortionModeConfig {
  enabled: boolean
  skipEncrypt: boolean
  catalogOnly: boolean
  publishSimulation: boolean
}

const DESTRUCTIVE_RAAS = new Set([
  "raas_vss_wipe",
  "raas_esxi_encrypt",
  "raas_smb_spread",
  "raas_gpo_spread",
  "raas_gpo_deploy",
  "esxi_lab_encrypt",
])

const CATALOG_MODULES = new Set([
  "raas_leak_catalog",
  "raas_exfil_upload",
  "raas_tor_portal",
  "collection_engine",
])

export function extortionModeFromEnv(): ExtortionModeConfig {
  const v = process.env.OURMINE_EXTORTION_ONLY?.trim().toLowerCase()
  const enabled = v === "1" || v === "true" || v === "yes"
  return {
    enabled,
    skipEncrypt: enabled,
    catalogOnly: enabled,
    publishSimulation: enabled,
  }
}

export function extortionModeForGroup(groupId?: string): ExtortionModeConfig {
  if (!groupId) return extortionModeFromEnv()
  const groups = loadRansomwareGroups()
  const hit = groups.find((g) => String(g.id) === groupId || String(g.name).toLowerCase() === groupId.toLowerCase())
  if (hit?.extortionOnly === true) {
    return { enabled: true, skipEncrypt: true, catalogOnly: true, publishSimulation: true }
  }
  return extortionModeFromEnv()
}

export function applyExtortionMode(modules: string[], config: ExtortionModeConfig): string[] {
  if (!config.enabled) return modules
  return modules.filter((m) => {
    if (DESTRUCTIVE_RAAS.has(m)) return false
    if (config.catalogOnly && m === "raas_campaign") return false
    return true
  }).concat(
    config.catalogOnly && !modules.some((m) => CATALOG_MODULES.has(m))
      ? ["raas_leak_catalog"]
      : [],
  ).filter((m, i, arr) => arr.indexOf(m) === i)
}

export function shouldSkipDestructiveRaas(config: ExtortionModeConfig): boolean {
  return config.enabled && config.skipEncrypt
}

export default {
  extortionModeFromEnv,
  extortionModeForGroup,
  applyExtortionMode,
  shouldSkipDestructiveRaas,
}
