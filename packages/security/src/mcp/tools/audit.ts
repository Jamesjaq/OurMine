import * as fs from "node:fs"
import * as security from "../../index.ts"
import * as dispatch from "../../mcp_dispatch.ts"
import { PentestAgent } from "../../pentestgpt_agent.ts"
import { ContextGuard } from "../../context_guard.ts"
import { gateExecution } from "../../opsec_gate.ts"
import type { McpTool } from "../../mcp_tool_types.ts"
import { buildActionablePlan } from "../../pentest_plan_builder.ts"
import { runEngagementSlice } from "../../engagement_slice.ts"
import { runEngagementAutopilot } from "../../engagement_autopilot.ts"
import { readArtifact } from "../../mcp_artifacts.ts"
import { mcpContext } from "../context.ts"

export function buildAuditTools(): McpTool[] {
  const { mcpLive, toolBroker, globalThrottleEngine } = mcpContext
  return [
    {
        name: "ares_counter_intel",
        description: "Counter-intelligence: detect blue team monitoring tools (EDR, SIEM agents, honeypots, canary tokens), identify analyst VMs, evade detection.",
        inputSchema: {
          type: "object",
          properties: {
            check: { type: "string", description: "What to detect", enum: ["edr","siem_agent","honeypot","canary_token","sandbox","analyst_vm","all"] },
          },
          required: ["check"],
        },
        async handler({ check }) {
          const live = mcpLive()
          return security.counter_intel.detect({ check: String(check ?? "all") as any, live })
        },
      },

    {
        name: "ares_adcs_audit",
        description: "Audit Active Directory Certificate Services (AD CS) for ESC1-ESC13 misconfigurations, Shadow Credentials, PKINIT support, and PetitPotam NTLM relay web enrollment endpoints.",
        inputSchema: {
          type: "object",
          properties: {
            domain: { type: "string", description: "Target Active Directory domain" },
            dc_ip:  { type: "string", description: "Domain Controller IP (optional)" },
          },
          required: ["domain"],
        },
        async handler({ domain, dc_ip }) {
          const live = mcpLive()
          return security.adcs_audit.auditADCS({ domain: String(domain), dcIp: String(dc_ip ?? "") }, { live })
        },
      },

    {
        name: "ares_esxi_audit",
        description: "Audit VMware ESXi & Hypervisor security: inspect vim-cmd & esxcli access, raw .vmdk datastore exposure, and snapshot integrity.",
        inputSchema: {
          type: "object",
          properties: {
            host: { type: "string", description: "Target ESXi host IP or hostname" },
          },
          required: ["host"],
        },
        async handler({ host }) {
          const live = mcpLive()
          return security.esxi_audit.auditESXi({ host: String(host) }, { live })
        },
      },

    {
        name: "ares_lolbins_audit",
        description: "Discover system binaries useful for execution bypass and privilege escalation (LOLBas on Windows, GTFOBins on Linux/macOS).",
        inputSchema: {
          type: "object",
          properties: {},
        },
        async handler() {
          const live = mcpLive()
          return security.lolbins_audit.auditLOLBins({ live })
        },
      },

    {
        name: "ares_ebpf_audit",
        description: "Audit stealth kernel persistence and rootkits: inspect eBPF socket filters/tracepoints and user-land LD_PRELOAD hooks (/etc/ld.so.preload).",
        inputSchema: {
          type: "object",
          properties: {},
        },
        async handler() {
          const live = mcpLive()
          return security.ebpf_audit.auditEBPFAndPersistence({ live })
        },
      },

    {
        name: "ares_ai_agent_audit",
        description: "Audit AI agent guardrails, RAG context pipelines, indirect prompt injection vulnerabilities, data poisoning risks, and tool parameter hijacking.",
        inputSchema: {
          type: "object",
          properties: {
            agent_url:    { type: "string", description: "Target AI Agent HTTP endpoint or RAG URL" },
            fuzz_depth:   { type: "string", description: "Fuzzing depth", enum: ["quick","full","deep"] },
          },
        },
        async handler({ agent_url, fuzz_depth }) {
          const live = mcpLive()
          return security.ai_agent_audit.auditAIAgentGuardrails({ targetAgentUrl: String(agent_url ?? ""), fuzzDepth: String(fuzz_depth ?? "quick") as any }, { live })
        },
      },

    {
        name: "ares_edge_appliance_audit",
        description: "Audit edge appliances (firewalls, VPNs) for firmware integrity hash mismatches, unencrypted TLS session tickets, and VPN memory leaks.",
        inputSchema: {
          type: "object",
          properties: {
            target: { type: "string", description: "Edge appliance IP or hostname" },
          },
          required: ["target"],
        },
        async handler({ target }) {
          const live = mcpLive()
          return security.edge_appliance_audit.auditEdgeAppliance({ target: String(target) }, { live })
        },
      },

    {
        name: "ares_uefi_bootkit_audit",
        description: "Audit UEFI firmware, Secure Boot DBX revoked hash database updates, NVRAM configuration, and vulnerable signed driver (BYOVD) loading.",
        inputSchema: {
          type: "object",
          properties: {},
        },
        async handler() {
          const live = mcpLive()
          return security.uefi_bootkit_audit.auditUEFIAndBootkit({ live })
        },
      },

    {
        name: "ares_cicd_k8s_audit",
        description: "Audit CI/CD pipeline workflows (GitHub Actions triggers/secrets) and Kubernetes ServiceAccount RBAC permissions for over-privileged wildcards.",
        inputSchema: {
          type: "object",
          properties: {
            target: { type: "string", description: "Repository path or cluster name" },
          },
        },
        async handler({ target }) {
          const live = mcpLive()
          return security.cicd_k8s_audit.auditCICDAndK8s({ repositoryOrCluster: String(target ?? "local") }, { live })
        },
      },

    {
        name: "ares_opsec_throttle",
        description: "Configure traffic control, execution pacing, and delay jitter to control test traffic density.",
        inputSchema: {
          type: "object",
          properties: {
            requests_per_minute: { type: "number", description: "Max requests per minute" },
            jitter_ms:           { type: "number", description: "Max random delay jitter in milliseconds" },
          },
        },
        async handler({ requests_per_minute, jitter_ms }) {
          const engine = new security.opsec_throttle.OpsecThrottleEngine({
            maxRequestsPerMinute: Number(requests_per_minute ?? 60),
            jitterMs: Number(jitter_ms ?? 200),
          })
          await engine.paceExecution()
          return { status: "PACED", config: engine.getConfig() }
        },
      },

    {
        name: "ares_agent_resilience",
        description: "Validate and repair AI agent tool-call parameter hallucinations, or checkpoint session state.",
        inputSchema: {
          type: "object",
          properties: {
            action:    { type: "string", description: "Resilience action", enum: ["repair_params", "checkpoint"] },
            tool_name: { type: "string", description: "Tool name to validate/repair" },
            session_id:{ type: "string", description: "Session ID for checkpointing" },
          },
          required: ["action"],
        },
        async handler({ action, tool_name, session_id }) {
          const engine = security.agent_resilience.resilienceEngine
          if (action === "repair_params") {
            return engine.validateAndRepairToolCall(String(tool_name ?? "unknown"), {})
          }
          return engine.saveCheckpoint(String(session_id ?? "default"), 1, "Manual Checkpoint", [])
        },
      },

    {
        name: "ares_opsec_review",
        description: "OPSEC gate review for a command before execution.",
        inputSchema: {
          type: "object",
          properties: {
            tool: { type: "string" },
            command: { type: "string" },
            force: { type: "boolean" },
          },
          required: ["tool", "command"],
        },
        async handler({ tool, command, force }) {
          return gateExecution({ tool: String(tool), command: String(command), live: mcpLive(), force: Boolean(force) })
        },
      }
  ]
}
