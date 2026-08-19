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

export function buildIdentityTools(): McpTool[] {
  const { mcpLive, toolBroker, globalThrottleEngine } = mcpContext
  return [
    {
        name: "ares_identity",
        description: "Identity attacks: Kerberoasting, AS-REP roasting, MFA bypass, credential abuse, NTLM relay detection.",
        inputSchema: {
          type: "object",
          properties: {
            domain:   { type: "string", description: "Active Directory domain (e.g. corp.local)" },
            attack:   { type: "string", description: "Attack type", enum: ["kerberoast","asrep_roast","mfa_bypass","ntlm_relay","credential_spray"] },
            dc:       { type: "string", description: "Domain controller IP (optional)" },
          },
          required: ["domain", "attack"],
        },
        async handler({ domain, attack, dc }) {
          const live = mcpLive()
          return security.identity.execute({ domain: String(domain), attack: String(attack) as any, dc: String(dc ?? "") }, { live })
        },
      },

    {
        name: "ares_ad_exploit",
        description: "Active Directory exploitation: DCSync, Pass-the-Hash, Golden Ticket, Silver Ticket, BloodHound path traversal.",
        inputSchema: {
          type: "object",
          properties: {
            domain:   { type: "string", description: "Target AD domain" },
            technique:{ type: "string", description: "Exploitation technique", enum: ["dcsync","pass_the_hash","golden_ticket","silver_ticket","acl_abuse"] },
            target:   { type: "string", description: "Target user or computer" },
          },
          required: ["domain", "technique"],
        },
        async handler({ domain, technique, target }) {
          const live = mcpLive()
          return dispatch.adExploitExecute({ domain: String(domain), technique: String(technique), target: String(target ?? "") }, { live })
        },
      },

    {
        name: "ares_hybrid_ad_entra",
        description: "Hybrid AD/Entra ID attacks: SSSO token abuse, PTA agent bypass, cloud Kerberos trust attacks, DCSync via Azure.",
        inputSchema: {
          type: "object",
          properties: {
            domain:    { type: "string", description: "On-prem AD domain" },
            tenant_id: { type: "string", description: "Azure/Entra tenant ID" },
            technique: { type: "string", description: "Attack vector", enum: ["ssso_token","pta_bypass","cloud_kerberos","dcsync_cloud"] },
          },
          required: ["domain"],
        },
        async handler({ domain, tenant_id, technique }) {
          const live = mcpLive()
          return dispatch.hybridAdEntraExecute({ domain: String(domain), tenantId: String(tenant_id ?? ""), technique: String(technique ?? "ssso_token") }, { live })
        },
      },

    {
        name: "ares_oauth_chain",
        description: "OAuth 2.0 attack chains: authorization code interception, PKCE downgrade, device code phishing, token theft, redirect_uri bypass.",
        inputSchema: {
          type: "object",
          properties: {
            target:     { type: "string", description: "OAuth provider or target app URL" },
            technique:  { type: "string", description: "OAuth attack vector", enum: ["code_intercept","pkce_bypass","device_code_phish","token_theft","redirect_bypass","implicit_flow"] },
            client_id:  { type: "string", description: "OAuth client_id (optional)" },
          },
          required: ["target", "technique"],
        },
        async handler({ target, technique, client_id }) {
          const live = mcpLive()
          return dispatch.oauthChainExecute({ target: String(target), technique: String(technique), clientId: String(client_id ?? "") }, { live })
        },
      },

    {
        name: "ares_webmail_exploit",
        description: "Webmail exploitation: OWA password spray, Gmail OAuth phishing, Microsoft 365 MFA fatigue, Exchange ProxyShell/LogonShell.",
        inputSchema: {
          type: "object",
          properties: {
            target:    { type: "string", description: "Target webmail URL or tenant" },
            technique: { type: "string", description: "Attack type", enum: ["owa_spray","gmail_oauth","m365_mfa_fatigue","proxyshell","evilginx"] },
          },
          required: ["target", "technique"],
        },
        async handler({ target, technique }) {
          const live = mcpLive()
          return dispatch.webmailExploitExecute({ target: String(target), technique: String(technique) }, { live })
        },
      },

    {
        name: "ares_idp_oauth_audit",
        description: "Audit Identity Providers (IdP) & OAuth apps for overprivileged multi-tenant consent permissions, FIDO2 fallback, and token bindings.",
        inputSchema: {
          type: "object",
          properties: {
            domain: { type: "string", description: "Target IdP domain or tenant" },
          },
          required: ["domain"],
        },
        async handler({ domain }) {
          const live = mcpLive()
          return security.idp_oauth_audit.auditIdPAndOAuth({ domain: String(domain) }, { live })
        },
      },
    {
        name: "ares_device_code_audit",
        description: "Audit target for OAuth Device Code Flow (RFC 8628) support and initiate phishing/interception assessment.",
        inputSchema: {
          type: "object",
          properties: {
            domain: { type: "string", description: "Target domain or identity provider" },
          },
          required: ["domain"],
        },
        async handler({ domain }) {
          const live = mcpLive()
          return dispatch.deviceCodeAuditExecute({ domain: String(domain) }, { live })
        },
      }
  ]
}
