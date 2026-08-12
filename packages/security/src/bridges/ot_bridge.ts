import type { AgentToolContext, ToolRunResult } from "../agent_tools.ts"
import { hostFromTarget } from "../agent_tools.ts"
import { result, agentToolBridge } from "./_shared.ts"

export const ot_bridge = {
  iot_scada: async (ctx, params) => {
    const { executeScadaAction } = await import("../iot_scada.ts")
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
    const { auditTelecom } = await import("../telecom_audit.ts")
    const host = String(params.host ?? hostFromTarget(ctx.target))
    const r = await auditTelecom(host, { live: ctx.live, snmpCommunity: String(params.community ?? "public") })
    return result("telecom_audit", "auditTelecom", ctx, r)
  },
  usb_audit: async (ctx, params) => {
    const { auditUsb } = await import("../usb_audit.ts")
    const r = await auditUsb(String(params.target ?? ctx.target), {
      live: ctx.live,
      duckyScript: params.duckyScript as string | undefined,
      scenario: params.scenario as string | undefined,
    })
    return result("usb_audit", "auditUsb", ctx, r, r.templatePaths.length > 0 || r.findings.length > 0)
  },
  wifi_audit: async (ctx, params) => {
    const { auditWifi } = await import("../wifi_audit.ts")
    const hint = String(params.hint ?? params.objective ?? ctx.target)
    const r = await auditWifi(String(params.target ?? ctx.target), { live: ctx.live, iface: params.iface as string | undefined, hint })
    return result("wifi_audit", "auditWifi", ctx, r, r.networks.length > 0 || r.dryRun)
  },
  ble_audit: async (ctx, params) => {
    const { auditBle } = await import("../ble_audit.ts")
    const r = await auditBle(String(params.target ?? ctx.target), { live: ctx.live, scanSeconds: params.scanSeconds as number | undefined })
    return result("ble_audit", "auditBle", ctx, r, r.devices.length > 0 || r.dryRun)
  },
  proximity_audit: async (ctx, params) => {
    const { auditProximity } = await import("../proximity_audit.ts")
    const r = await auditProximity(String(params.target ?? ctx.target), {
      live: ctx.live,
      hint: String(params.hint ?? params.objective ?? ctx.target),
    })
    return result("proximity_audit", "auditProximity", ctx, r, r.findings.length > 0 || r.dryRun)
  },
  ot_scan: async (ctx, params) => {
    const { executeScadaAction } = await import("../iot_scada.ts")
    const { auditTelecom } = await import("../telecom_audit.ts")
    const host = String(params.host ?? hostFromTarget(ctx.target))
    const modbus = await executeScadaAction({ host, protocol: "modbus", action: "read" }, { live: ctx.live })
    const dnp3 = await executeScadaAction({ host, protocol: "dnp3", action: "probe" }, { live: ctx.live })
    const mqtt = await executeScadaAction({ host, protocol: "mqtt", action: "connect" }, { live: ctx.live })
    const bacnet = await executeScadaAction({ host, protocol: "bacnet", action: "whois" }, { live: ctx.live })
    const coap = await executeScadaAction({ host, protocol: "coap", action: "discover" }, { live: ctx.live })
    const profinet = await executeScadaAction({ host, protocol: "profinet", action: "identify" }, { live: ctx.live })
    const s7 = await executeScadaAction({ host, protocol: "s7", action: "probe" }, { live: ctx.live })
    const telecom = await auditTelecom(host, { live: ctx.live })
    return result("ot_scan", "ot_it_telecom_scan", ctx, { modbus, dnp3, mqtt, bacnet, coap, profinet, s7, telecom })
  },
  ot_batch_scan: async (ctx, params) => {
    const cidr = String(params.cidr ?? params.target ?? ctx.target)
    if (params.ranked === true || params.ranked === "true" || params.subnets) {
      const { scanRankedOtSubnets } = await import("../ot_batch_scan.ts")
      const subnets = params.subnets
        ? String(params.subnets).split(",").map((s) => s.trim()).filter(Boolean)
        : [cidr]
      const r = await scanRankedOtSubnets(subnets, {
        live: ctx.live,
        maxHosts: params.max_hosts != null ? Number(params.max_hosts) : undefined,
        resumeToken: params.resumeToken ? String(params.resumeToken) : undefined,
        credGraph: ctx.credGraph,
      })
      return result("ot_batch_scan", "scanRankedOtSubnets", ctx, r, r.scanned > 0)
    }
    const { scanOtSubnet } = await import("../ot_batch_scan.ts")
    const r = await scanOtSubnet(cidr, {
      live: ctx.live,
      maxHosts: params.max_hosts != null ? Number(params.max_hosts) : undefined,
      offset: params.offset != null ? Number(params.offset) : undefined,
      resumeToken: params.resumeToken ? String(params.resumeToken) : undefined,
    })
    return result("ot_batch_scan", "scanOtSubnet", ctx, r, r.scanned > 0)
  },
  hybrid_pivot: async (ctx, params) => {
    const { runHybridItOtPivot } = await import("../hybrid_pivot.ts")
    const r = await runHybridItOtPivot({
      target: String(params.target ?? ctx.target),
      live: ctx.live,
      domain: params.domain as string | undefined,
      plantSubnet: params.plant_subnet as string | undefined,
      skipItRecon: params.skip_it_recon === true || params.skip_it_recon === "true",
      hint: String(params.hint ?? params.objective ?? ctx.target),
      credGraph: ctx.credGraph,
    })
    return result("hybrid_pivot", "runHybridItOtPivot", ctx, r, r.otHosts.some((h) => h.otLikely))
  },
  ics_impact_proof: async (ctx, params) => {
    const { proveIcsImpact, assessOtRansomReadiness } = await import("../ics_impact_proof.ts")
    const host = String(params.host ?? params.target ?? ctx.target)
    if (params.ransom_assess === true || params.ransom_assess === "true") {
      const r = await assessOtRansomReadiness(host, ctx.live)
      return result("ics_impact_proof", "assessOtRansomReadiness", ctx, r, r.hmiLikely)
    }
    const r = await proveIcsImpact({
      host,
      live: ctx.live,
      port: params.port ? Number(params.port) : undefined,
      allowWrite: params.allow_write === true || params.allow_write === "true",
    })
    return result("ics_impact_proof", "proveIcsImpact", ctx, r, r.success)
  },
  firmware_audit: async (ctx, params) => {
    const { executeFirmwareAction } = await import("../firmware.ts")
    const filePath = String(params.path ?? params.firmware_path ?? "")
    const action = String(params.action ?? "extract")
    if (!filePath) return result("firmware_audit", "executeFirmwareAction", ctx, { error: "path required" }, false)
    const payload = executeFirmwareAction(filePath, action, { live: ctx.live })
    const ok = !payload.error
    return result("firmware_audit", "executeFirmwareAction", ctx, payload, ok)
  },
  profinet_l2: async (ctx, params) => {
    const { probeProfinetFull } = await import("../profinet_l2.ts")
    const host = String(params.host ?? params.target ?? hostFromTarget(ctx.target))
    const r = await probeProfinetFull(host, ctx.live)
    return result("profinet_l2", "probeProfinetFull", ctx, r, r.udp34964 || r.s7Port102 || !ctx.live)
  },
  ot_segment_infer: async (ctx, params) => {
    const { inferPlantSubnets } = await import("../ot_segment_infer.ts")
    const subnets = inferPlantSubnets({
      target: String(params.target ?? ctx.target),
      credGraph: ctx.credGraph,
    })
    return result("ot_segment_infer", "inferPlantSubnets", ctx, { subnets }, subnets.length > 0)
  },
} as const
