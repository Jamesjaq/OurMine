/**
 * @module mcp_bridged_tools
 * Auto-register all module_bridge tools as MCP tools for instant discovery at startup.
 */
import { bridgedToolNames } from "./module_bridge.ts"
import type { McpTool } from "./mcp_tool_types.ts"

const BRIDGED_DESCRIPTIONS: Record<string, string> = {
  ares_zero_day_fuzzer: "Coverage-guided fuzzer + crash triage + exploit synthesis (APT parity)",
  ares_fileless_implant: "Memory-only implant: reflective loader, syscalls, ETW/AMSI unhooking",
  ares_firmware_implant: "UEFI/BIOS implant builder + SMM hook + flashrom/chipsec deploy",
  ares_hypervisor_rootkit: "VBS/HVCI bypass + ESXi audit + lab hypervisor encrypt/recovery",
  ares_airgap_bridge: "Air-gap jumping: USB ducky, stego, DNS exfil, RF/acoustic channels",
  ares_rat_builder: "Modular RAT with NativeImplantGenerator + CovertC2 + polymorphic build",
  ares_supply_chain_implant: "Full supply-chain kill chain: CI/CD poison, npm audit, registry analysis",
  ares_evasion_engine: "Advanced EDR bypass: syscalls, ETW patch, unhooking, EDR feedback loop",
  ares_satellite_c2: "Satellite/VSAT covert C2 + domain fronting + stego beacon",
  ares_ss7_exploit: "SS7/telecom MAP operations + live telecom perimeter audit",
  ares_hardware_implant: "USB/RF/SDR hardware implant framework + BadUSB + RFID clone",
  ares_kerberos_advanced: "Platinum/Diamond/Skeleton Key + kerberoast + DCSync + PtH",
  ares_persistence_advanced: "COM/WMI/GPO/BITS/cert persistence via PersistenceEngine live install",
  ares_lateral_scale: "RDP hijack, DCOM, WMI, impacket/netexec lateral at scale",
  ares_anti_forensics_advanced: "Selective log suppression, timestomp, MFT/USN anti-forensics",
  ares_network_exploit: "BGP/DNS poison, LLMNR, WPAD, DHCPv6, network device audit",
  ares_cloud_native: "Azure/AWS/GCP IMDS, IAM privesc, K8s breakout, multi-cloud ASM",
  ares_ai_ml_attacks: "AI payload mutation, exploit synthesis, fuzz+AI, adaptive EDR evasion",
  ares_orchestrator: "Run all 18 ARES APT-parity engines in one live orchestrated pass",
  tier1_orchestrator: "Full tier-1 APT orchestrator (all depth engines)",
  tier1_validation: "L3/L4 suite: IDOR/BOLA, privesc proof, exploit replay",
  tier1_depth: "Operational depth metrics (L3/L4 rate, workflow %)",
  campaign_loop: "Multi-host cred→BloodHound→pivot→tunnel campaign loop",
  autonomous_pivot: "Scope-envelope autonomous lateral pivot loop",
  http_state_fuzz: "HTTP API state machine fuzzer (L3-L4 validation)",
  exploit_synthesis: "Polyglot WAF payloads, deser scaffold, adaptive MSF rank",
  cred_access_auto: "Autonomous LSASS/DCSync/secretsdump (scope-gated)",
  edr_feedback_loop: "EDR detection → C2 channel rotation closed loop",
  supply_chain_exec: "Supply chain compromise execution path",
  engagement_memory: "Long-engagement memory + blue-team modeling",
}

export function buildBridgedMcpTools(
  existingNames: Set<string>,
  mcpLive: () => boolean,
): McpTool[] {
  return bridgedToolNames()
    .filter((name) => !existingNames.has(name))
    .map((name) => ({
      name,
      description: BRIDGED_DESCRIPTIONS[name] ?? `OurMine live module: ${name.replace(/_/g, " ")}`,
      inputSchema: {
        type: "object" as const,
        properties: {
          target: { type: "string", description: "Target host, URL, or scope anchor" },
          domain: { type: "string", description: "AD domain (when applicable)" },
          live: { type: "boolean", description: "Force live execution (default: server live mode)" },
          params: { type: "string", description: "JSON object of module-specific parameters" },
        },
      },
      async handler(args: Record<string, unknown>) {
        const { runBridgedModule } = await import("./module_bridge.ts")
        const { AttackSurfaceGraph } = await import("./attack_surface.ts")
        const target = String(args.target ?? "127.0.0.1")
        const live = typeof args.live === "boolean" ? args.live : mcpLive()
        let params: Record<string, unknown> = {}
        if (args.domain) params.domain = args.domain
        if (args.params) {
          try {
            params = {
              ...params,
              ...(typeof args.params === "string"
                ? JSON.parse(args.params)
                : (args.params as Record<string, unknown>)),
            }
          } catch {
            params.params_raw = args.params
          }
        }
        for (const [k, v] of Object.entries(args)) {
          if (!["target", "domain", "live", "params"].includes(k)) params[k] = v
        }
        const ctx = {
          target,
          live,
          graph: new AttackSurfaceGraph(target),
        }
        const result = await runBridgedModule(ctx, name, params)
        if (!result) return { error: `bridged module not found: ${name}` }
        return {
          tool: result.tool,
          success: result.success,
          dryRun: result.dryRun,
          output: result.output,
        }
      },
    }))
}

export default { buildBridgedMcpTools }
