/**
 * USB / WiFi / BLE proximity flow — dry-run only
 */
import { describe, test, before } from "node:test"
import assert from "node:assert/strict"
import { auditUsb, usbTemplatePaths } from "../src/usb_audit.ts"
import { auditWifi, wifiOffensiveAllowed } from "../src/wifi_audit.ts"
import { auditBle } from "../src/ble_audit.ts"
import { auditProximity, detectProximityChannels } from "../src/proximity_audit.ts"
import { buildFlowProfile, inferFlowObjective, modulesForPhase } from "../src/target_flow.ts"
import { applyPolicyToModules } from "../src/engagement_policy.ts"
import { buildActionablePlan } from "../src/pentest_plan_builder.ts"
import { runEngagementSlice } from "../src/engagement_slice.ts"
import { getNextActions, buildEngagementGraph } from "../src/engagement_graph.ts"
import { AttackSurfaceGraph } from "../src/attack_surface.ts"
import { CredentialGraph } from "../src/credential_graph.ts"

describe("proximity_flow", () => {
  before(() => {
    process.env.OURMINE_ALLOW_DRY_RUN = "1"
    process.env.OURMINE_LIVE = "0"
  })

  test("usb dry-run returns template paths only", async () => {
    const r = await auditUsb("corp-lobby", { live: false, dryRun: true })
    assert.equal(r.dryRun, true)
    assert.equal(r.findings.length, 0)
    assert.ok(r.templatePaths.length >= 3)
    assert.ok(r.summary.includes("template"))
  })

  test("wifi dry-run skips offensive unless env set", async () => {
    const prev = process.env.OURMINE_WIFI_OFFENSIVE
    delete process.env.OURMINE_WIFI_OFFENSIVE
    const r = await auditWifi("corp-wlan", { live: false, dryRun: true })
    assert.equal(r.dryRun, true)
    assert.equal(r.networks.length, 0)
    assert.equal(wifiOffensiveAllowed(), false)
    if (prev) process.env.OURMINE_WIFI_OFFENSIVE = prev
  })

  test("ble dry-run returns empty devices", async () => {
    const r = await auditBle("smart-building", { live: false, dryRun: true })
    assert.equal(r.dryRun, true)
    assert.equal(r.devices.length, 0)
    assert.equal(r.findings.length, 0)
  })

  test("detectProximityChannels routes usb wifi ble", () => {
    assert.deepEqual(detectProximityChannels("corporate lobby usb badusb drop"), ["usb"])
    assert.deepEqual(detectProximityChannels("wifi perimeter ssid"), ["wifi"])
    assert.deepEqual(detectProximityChannels("ble smart lock building"), ["ble"])
  })

  test("physical_usb persona and policy modules", () => {
    const flow = buildFlowProfile("corp.local", undefined, "corporate lobby usb badusb physical")
    assert.equal(flow.persona, "physical_usb")
    assert.equal(inferFlowObjective(flow), "proximity_physical")
    const mods = applyPolicyToModules("recon", flow, "proximity_physical", undefined, false)
    assert.ok(mods.includes("usb_audit"))
  })

  test("wireless_perimeter routes wifi before network exploit", () => {
    const flow = buildFlowProfile("guest-wifi.corp.com", undefined, "wifi wireless perimeter")
    assert.equal(flow.persona, "wireless_perimeter")
    const exploit = modulesForPhase("exploit", flow, "proximity_physical")
    assert.ok(exploit.indexOf("wifi_audit") < exploit.indexOf("ares_network_exploit"))
  })

  test("plan builder adds proximity dispatch for USB hint", () => {
    const plan = buildActionablePlan("corp.local", { objective: "corporate lobby usb badusb drop" })
    assert.equal(plan.objective, "proximity_physical")
    assert.ok(plan.nextActions.some((a) => a.tool === "ares_dispatch" && a.args.module === "proximity_audit"))
    assert.ok(plan.gaps?.some((g) => g.includes("OURMINE_LIVE")))
  })

  test("engagement slice dry-run for BLE smart building", async () => {
    const r = await runEngagementSlice({
      target: "building-42.local",
      live: false,
      objective: "ble smart lock smart building",
    })
    assert.equal(r.persona, "iot_device")
    assert.equal(r.dryRun, true)
    assert.ok(r.graphNextActions.some((a) =>
      a.tool === "ares_dispatch" && (a.args.module === "ble_audit" || a.args.module === "wifi_audit")))
  })

  test("graphNextActions includes hardware implant for physical_usb", () => {
    const eg = buildEngagementGraph({
      target: "lobby-pc.corp.com",
      graph: new AttackSurfaceGraph("lobby-pc.corp.com"),
      credGraph: CredentialGraph.load(),
      objective: "corporate lobby usb badusb",
      live: false,
      proximityFindings: [{ channel: "usb", id: "t1", title: "BadUSB staged", severity: "high" }],
    })
    assert.equal(eg.persona, "physical_usb")
    const actions = getNextActions(eg, {})
    assert.ok(actions.some((a) => a.args.module === "ares_hardware_implant" || a.args.module === "usb_audit"))
  })
})
