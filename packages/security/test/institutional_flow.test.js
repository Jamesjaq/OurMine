/**
 * Institutional sector hint routes — banking, corporate, government, university,
 * k12, healthcare, insurance, legal, telecom, NGO, critical infra, SaaS
 */
import { describe, test, before } from "node:test"
import assert from "node:assert/strict"
import {
  buildFlowProfile,
  inferFlowObjective,
  modulesForPhase,
} from "../src/target_flow.ts"
import { applyPolicyToModules } from "../src/engagement_policy.ts"
import {
  detectInstitutionalSector,
  reconInstitutionalSector,
  sectorPortHeuristics,
  allInstitutionalSectors,
  objectiveForSector,
  personaForSector,
} from "../src/institutional_hints.ts"
import { auditNetworkDevice } from "../src/net_device.ts"
import { auditWifi } from "../src/wifi_audit.ts"
import { reconIdpOAuthPaths } from "../src/ares/cloud_native.ts"
import { OT_PORTS } from "../src/ot_batch_scan.ts"
import { getThreatIntel } from "../src/apt_intel_feed.ts"

describe("institutional_hints", () => {
  before(() => {
    process.env.OURMINE_ALLOW_DRY_RUN = "1"
    process.env.OURMINE_LIVE = "0"
  })

  test("taxonomy includes all twelve institutional sectors", () => {
    const sectors = allInstitutionalSectors()
    for (const id of [
      "banking", "corporate_office", "government", "university", "k12_school",
      "healthcare", "insurance", "legal", "telecom_office", "ngo",
      "critical_infra", "saas",
    ]) {
      assert.ok(sectors.includes(id), `missing sector ${id}`)
    }
    assert.equal(sectors.length, 12)
  })

  test("detectInstitutionalSector maps all primary sectors", () => {
    assert.equal(detectInstitutionalSector("dicom pacs hl7 epic"), "healthcare")
    assert.equal(detectInstitutionalSector("swift iso8583 sacco credit union"), "banking")
    assert.equal(detectInstitutionalSector("eduroam campus wifi university.edu"), "university")
    assert.equal(detectInstitutionalSector("k-12 school district chromebook student info"), "k12_school")
    assert.equal(detectInstitutionalSector("citrix pulse f5 zta agency.gov"), "government")
    assert.equal(detectInstitutionalSector("m365 branch office voip printer"), "corporate_office")
    assert.equal(detectInstitutionalSector("insurance claims guidewire legacy app"), "insurance")
    assert.equal(detectInstitutionalSector("law firm imanage dms document mgmt"), "legal")
    assert.equal(detectInstitutionalSector("telecom office noc oss bss ss7"), "telecom_office")
    assert.equal(detectInstitutionalSector("ngo nonprofit donor portal charity"), "ngo")
    assert.equal(detectInstitutionalSector("iec61850 substation mms"), "critical_infra")
    assert.equal(detectInstitutionalSector("okta entra google workspace oauth"), "saas")
  })

  test("k12 takes priority over university when both hints present", () => {
    assert.equal(
      detectInstitutionalSector("school district eduroam campus"),
      "k12_school",
    )
  })

  test("healthcare hint routes to iot_device with institutional_recon", () => {
    const flow = buildFlowProfile("pacs.hospital.local", undefined, "dicom pacs hl7 medical iot")
    assert.equal(flow.institutionalSector, "healthcare")
    assert.equal(flow.persona, "iot_device")
    assert.equal(inferFlowObjective(flow, "dicom pacs"), "ot_ics")
    const recon = modulesForPhase("recon", flow, "ot_ics")
    assert.ok(recon.includes("institutional_recon"))
    const policy = applyPolicyToModules("recon", flow, "ot_ics", undefined, false)
    assert.ok(policy.includes("institutional_recon"))
    const exploit = applyPolicyToModules("exploit", flow, "ot_ics", undefined, false)
    assert.ok(exploit.includes("iot_scada"))
  })

  test("banking hint routes identity_first with institutional modules", () => {
    const flow = buildFlowProfile("bank.example.com", undefined, "swift iso8583 core banking sacco")
    assert.equal(flow.institutionalSector, "banking")
    assert.equal(inferFlowObjective(flow), "identity_first")
    assert.equal(personaForSector("banking"), "enterprise_ad")
    const policy = applyPolicyToModules("recon", flow, "identity_first", undefined, false)
    assert.ok(policy.includes("institutional_recon"))
    assert.ok(policy.includes("net_device_audit"))
  })

  test("university eduroam routes wireless_perimeter + wifi_audit", async () => {
    const flow = buildFlowProfile("university.edu", undefined, "eduroam campus wifi ldap")
    assert.equal(flow.institutionalSector, "university")
    assert.equal(flow.persona, "wireless_perimeter")
    assert.equal(inferFlowObjective(flow), "proximity_physical")
    assert.equal(objectiveForSector("university"), "proximity_physical")
    const policy = applyPolicyToModules("recon", flow, "proximity_physical", undefined, false)
    assert.ok(policy.includes("wifi_audit"))
    assert.ok(policy.includes("institutional_recon"))

    const wifi = await auditWifi("campus-wlan", { live: false, hint: "eduroam campus" })
    assert.equal(wifi.dryRun, true)
    assert.ok(wifi.findings.some((f) => f.id === "wifi-eduroam-hint"))
    assert.ok(wifi.enterpriseHints.some((n) => n.ssid === "eduroam"))
  })

  test("k12 school district routes wifi_audit + institutional_recon", () => {
    const flow = buildFlowProfile("district.k12.us", undefined, "k-12 school district chromebook student info ferpa")
    assert.equal(flow.institutionalSector, "k12_school")
    assert.equal(flow.persona, "wireless_perimeter")
    assert.equal(inferFlowObjective(flow), "proximity_physical")
    const policy = applyPolicyToModules("recon", flow, "proximity_physical", undefined, false)
    assert.ok(policy.includes("wifi_audit"))
    assert.ok(policy.includes("institutional_recon"))
  })

  test("government VPN hint fingerprints F5/Citrix/Pulse + citrix_audit", () => {
    const flow = buildFlowProfile("vpn.agency.gov", undefined, "citrix pulse f5 zta bypass")
    assert.equal(flow.institutionalSector, "government")
    const audit = auditNetworkDevice("vpn.agency.gov", { live: false, hint: "citrix pulse f5 zta" })
    assert.equal(audit.dryRun, true)
    assert.ok(audit.vulnerabilities.some((v) => v.id.includes("NETDEV-VPN")))
    const policy = applyPolicyToModules("recon", flow, "identity_first", undefined, false)
    assert.ok(policy.includes("net_device_audit"))
    assert.ok(policy.includes("institutional_recon"))
    assert.ok(policy.includes("citrix_audit"))
  })

  test("corporate office M365 routes enterprise_ad + app_security", () => {
    const flow = buildFlowProfile("hq.corp.example.com", undefined, "m365 branch office voip printer")
    assert.equal(flow.institutionalSector, "corporate_office")
    assert.equal(inferFlowObjective(flow), "identity_first")
    const policy = applyPolicyToModules("recon", flow, "identity_first", undefined, false)
    assert.ok(policy.includes("net_device_audit"))
    assert.ok(policy.includes("app_security_engine"))
  })

  test("insurance legacy app routes institutional_recon", () => {
    const flow = buildFlowProfile("claims.insurer.com", undefined, "insurance guidewire legacy app")
    assert.equal(flow.institutionalSector, "insurance")
    assert.equal(inferFlowObjective(flow), "identity_first")
    const policy = applyPolicyToModules("recon", flow, "identity_first", undefined, false)
    assert.ok(policy.includes("institutional_recon"))
  })

  test("legal DMS routes web_app + app_security_engine", () => {
    const flow = buildFlowProfile("dms.lawfirm.com", undefined, "law firm imanage dms document mgmt")
    assert.equal(flow.institutionalSector, "legal")
    assert.equal(flow.persona, "web_app")
    assert.equal(inferFlowObjective(flow), "standard")
    const recon = modulesForPhase("recon", flow, "standard")
    assert.ok(recon.includes("institutional_recon"))
    assert.ok(recon.includes("app_security_engine"))
    const policy = applyPolicyToModules("recon", flow, "standard", undefined, false)
    assert.ok(policy.includes("app_security_engine"))
  })

  test("telecom office routes telecom_carrier objective", () => {
    const flow = buildFlowProfile("noc.carrier.local", undefined, "telecom office noc oss bss sigtran")
    assert.equal(flow.institutionalSector, "telecom_office")
    assert.equal(flow.persona, "telecom_carrier")
    assert.equal(inferFlowObjective(flow), "telecom")
    const policy = applyPolicyToModules("recon", flow, "telecom", undefined, false)
    assert.ok(policy.includes("telecom_audit"))
    assert.ok(policy.includes("institutional_recon"))
  })

  test("NGO donor portal routes cloud_saas identity_first", () => {
    const flow = buildFlowProfile("donor.ngo.org", undefined, "ngo nonprofit donor portal charity")
    assert.equal(flow.institutionalSector, "ngo")
    assert.equal(inferFlowObjective(flow), "identity_first")
    const policy = applyPolicyToModules("recon", flow, "identity_first", undefined, false)
    assert.ok(policy.includes("institutional_recon"))
    assert.ok(policy.includes("ares_cloud_native"))
  })

  test("critical infra IEC 61850 routes ot_scada_plant + port 102", () => {
    const flow = buildFlowProfile("10.50.0.0/24", undefined, "iec61850 substation water scada")
    assert.equal(flow.institutionalSector, "critical_infra")
    assert.equal(flow.persona, "ot_scada_plant")
    assert.equal(inferFlowObjective(flow), "ot_ics")
    const iecPort = OT_PORTS.find((p) => p.port === 102)
    assert.ok(iecPort)
    assert.equal(iecPort.protocol, "iec61850")
    const policy = applyPolicyToModules("recon", flow, "ot_ics", undefined, false)
    assert.ok(policy.includes("ot_batch_scan"))
    assert.ok(policy.includes("institutional_recon"))
  })

  test("SaaS OAuth hint routes cloud_saas + IdP abuse paths", async () => {
    const flow = buildFlowProfile("tenant.okta.com", undefined, "okta entra google workspace oauth")
    assert.equal(flow.institutionalSector, "saas")
    assert.equal(flow.persona, "cloud_saas")
    assert.equal(inferFlowObjective(flow), "identity_first")
    const idp = await reconIdpOAuthPaths({ hint: "okta entra google workspace", live: false })
    assert.equal(idp.dryRun, true)
    assert.ok(idp.abusePaths.length >= 3)
    assert.ok(idp.providers.includes("okta"))
    const policy = applyPolicyToModules("recon", flow, "identity_first", undefined, false)
    assert.ok(policy.includes("ares_cloud_native"))
    assert.ok(policy.includes("institutional_recon"))
  })

  test("reconInstitutionalSector dry-run returns port heuristics + artifact", async () => {
    const r = await reconInstitutionalSector("healthcare", "pacs.local", { live: false })
    assert.equal(r.dryRun, true)
    assert.ok(r.portHints.some((p) => p.port === 104))
    assert.ok(r.findings.some((f) => f.id === "inst-healthcare-dicom"))
    assert.ok(r.artifactId?.startsWith("institutional_"))
    assert.ok(sectorPortHeuristics("banking").some((p) => p.port === 8087))
    assert.ok(sectorPortHeuristics("banking").some((p) => p.port === 5000))
  })

  test("intel snippets resolve for healthcare and banking sectors", async () => {
    const hc = await getThreatIntel({
      target: "pacs.hospital.local",
      aptHint: "dicom pacs hl7",
      live: false,
      refresh: true,
    })
    assert.ok(hc)
    assert.equal(hc.profileId, "healthcare_tradecraft")
    assert.ok(hc.intelSnippet.length <= 200)
    assert.ok(/HL7|DICOM|healthcare/i.test(hc.intelSnippet))

    const bank = await getThreatIntel({
      target: "core.bank.example.com",
      aptHint: "swift iso8583 sacco",
      live: false,
      refresh: true,
    })
    assert.ok(bank)
    assert.equal(bank.profileId, "finance_tradecraft")
    assert.ok(/SWIFT|ISO|banking/i.test(bank.intelSnippet))
  })

  test("intel snippet for k12 and legal sectors", async () => {
    const k12 = await getThreatIntel({
      target: "district.k12.us",
      aptHint: "k-12 school district chromebook",
      live: false,
      refresh: true,
    })
    assert.ok(k12)
    assert.equal(k12.profileId, "k12_campus")
    assert.ok(/Chromebook|district|FERPA|WiFi/i.test(k12.intelSnippet))

    const legal = await getThreatIntel({
      target: "dms.lawfirm.com",
      aptHint: "law firm imanage dms",
      live: false,
      refresh: true,
    })
    assert.ok(legal)
    assert.equal(legal.profileId, "legal_dms")
    assert.ok(/DMS|matter|legal/i.test(legal.intelSnippet))
  })
})
