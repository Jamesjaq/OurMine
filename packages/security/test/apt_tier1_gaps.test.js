/**
 * Tier-1 APT gap coverage tests — 2024-2026 TTPs vs OurMine modules
 */
import { describe, test } from "node:test"
import assert from "node:assert/strict"
import { applyPolicyToModules, evaluateEngagementPolicy } from "../src/engagement_policy.ts"
import { buildFlowProfile } from "../src/target_flow.ts"
import { resolveAptProfile, loadAptPlaybookMappings, getThreatIntel } from "../src/apt_intel_feed.ts"

const GAP_MATRIX = [
  { technique: "RMM abuse (T1219)", module: "rmm_audit", actors: ["scattered_spider", "alphv_blackcat", "fin7", "lockbit5"] },
  { technique: "Citrix Bleed / edge (T1556.006)", module: "citrix_audit", actors: ["lockbit5", "alphv_blackcat", "apt41", "cl0p"] },
  { technique: "Helpdesk vishing (T1566.002)", module: "helpdesk_social_auto", actors: ["scattered_spider", "alphv_blackcat", "fin7"] },
  { technique: "OAuth consent phishing (T1550.001)", module: "oauth_consent_audit", actors: ["apt29", "shinyhunters", "scattered_spider"] },
  { technique: "MFA fatigue (T1621)", module: "identity_playbooks", actors: ["scattered_spider"] },
  { technique: "LOTL (T1059)", module: "lolbins_audit", actors: ["volt_typhoon", "salt_typhoon", "apt29"] },
  { technique: "VPN/edge audit", module: "edge_audit", actors: ["volt_typhoon", "salt_typhoon", "akira", "lockbit5"] },
  { technique: "Supply chain npm/pypi (T1195.002)", module: "supply_chain_audit", actors: ["lazarus", "apt38", "team_pcp"] },
  { technique: "SaaS IdP abuse", module: "idp_audit", actors: ["apt29", "shinyhunters", "storm_0501"] },
  { technique: "AiTM/OAuth (T1557)", module: "evilginx_lab", actors: ["scattered_spider", "alphv_blackcat"] },
]

describe("apt_tier1_gap_matrix", () => {
  for (const row of GAP_MATRIX) {
    test(`${row.technique} → module ${row.module} in playbook for ${row.actors[0]}`, () => {
      const mappings = loadAptPlaybookMappings()
      const hit = row.actors.some((a) => mappings[a]?.modules.includes(row.module))
      assert.ok(hit, `${row.module} missing from playbooks for ${row.actors.join(", ")}`)
    })
  }

  test("new actor profiles resolve: APT29, FIN7, ALPHV", () => {
    assert.equal(resolveAptProfile("APT29")?.id, "apt29")
    assert.equal(resolveAptProfile("Midnight Blizzard")?.id, "apt29")
    assert.equal(resolveAptProfile("FIN7")?.id, "fin7")
    assert.equal(resolveAptProfile("BlackCat")?.id, "alphv_blackcat")
  })

  test("aptHint wires Scattered Spider modules into engagement policy", () => {
    const profile = buildFlowProfile("corp.example.com", undefined, "identity_first")
    const mods = applyPolicyToModules("identity", profile, "identity_first", undefined, false, "Scattered Spider")
    assert.ok(mods.includes("helpdesk_social_auto"), `got: ${mods.slice(0, 8).join(", ")}`)
    assert.ok(mods.includes("rmm_audit"))
    assert.ok(mods.includes("oauth_consent_audit"))
  })

  test("aptHint wires LockBit modules into ransomware policy", () => {
    const profile = buildFlowProfile("10.0.0.1", undefined, "ransomware_impact")
    const policy = evaluateEngagementPolicy({
      profile,
      objective: "ransomware_impact",
      live: false,
      aptHint: "LockBit",
    })
    assert.ok(policy.prioritizeModules.includes("citrix_audit"))
    assert.ok(policy.prioritizeModules.includes("rmm_audit"))
  })

  test("getThreatIntel returns APT29 oauth_consent_audit module", async () => {
    const r = await getThreatIntel({
      target: "contoso.onmicrosoft.com",
      actor: "APT29",
      live: false,
      refresh: true,
    })
    assert.ok(r)
    assert.equal(r.profileId, "apt29")
    assert.ok(r.modules.includes("oauth_consent_audit"))
  })
})

describe("new_tier1_modules", () => {
  test("rmm_audit dry-run returns T1219 findings", async () => {
    const { auditRmmAbuse, RMM_ABUSE_CATALOG } = await import("../src/rmm_audit.ts")
    assert.ok(RMM_ABUSE_CATALOG.length >= 5)
    const r = await auditRmmAbuse("corp.example.com", { dryRun: true })
    assert.equal(r.dryRun, true)
    assert.ok(r.findings.some((f) => f.mitre === "T1219"))
  })

  test("citrix_audit dry-run flags Citrix Bleed", async () => {
    const { auditCitrixEdge, CITRIX_BLEED_CVE } = await import("../src/citrix_audit.ts")
    assert.equal(CITRIX_BLEED_CVE, "CVE-2023-4966")
    const r = await auditCitrixEdge("vpn.corp.example.com", { dryRun: true })
    assert.ok(r.citrixBleedSusceptible)
    assert.ok(r.findings.some((f) => f.cve === "CVE-2023-4966"))
  })

  test("helpdesk_social_auto generates Scattered Spider scenarios", async () => {
    const { auditHelpdeskSocial, generateVishingBundle } = await import("../src/helpdesk_social_auto.ts")
    const r = await auditHelpdeskSocial("corp.example.com", { dryRun: true, actor: "Scattered Spider" })
    assert.ok(r.scenarios.length >= 2)
    assert.ok(r.scenarios.every((s) => s.channel === "vishing" || s.channel === "smishing"))
    const bundle = generateVishingBundle("corp.example.com")
    assert.ok(bundle.checklist.length >= 3)
  })

  test("oauth_consent_audit covers APT29 ConsentFix patterns", async () => {
    const { auditOAuthConsent, CONSENT_ATTACK_PATTERNS } = await import("../src/oauth_consent_audit.ts")
    assert.ok(CONSENT_ATTACK_PATTERNS.some((p) => p.id === "consentfix-v3"))
    const r = await auditOAuthConsent("contoso.onmicrosoft.com", { dryRun: true })
    assert.equal(r.consentPhishingRisk, "critical")
    assert.ok(r.findings.some((f) => f.actor === "APT29"))
  })
})
