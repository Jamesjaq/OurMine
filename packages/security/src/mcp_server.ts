#!/usr/bin/env node
/**
 * OurMine ARES MCP Server
 *
 * Exposes all ARES security modules + bridged tools + bash executor as MCP tools.
 * The OpenCode agent discovers and calls these natively — the LLM can
 * autonomously invoke recon, pentest, C2, malware analysis, YARA, etc.
 *
 * Protocol: MCP (Model Context Protocol) over stdio
 * Transport: JSON-RPC 2.0 line-by-line on stdin/stdout
 *
 * Start: node --experimental-strip-types mcp_server.ts
 */

import { execFile, spawn } from "node:child_process"
import { promisify } from "node:util"
import * as path from "node:path"
import { fileURLToPath } from "node:url"
import * as security from "./index.ts"
import * as dispatch from "./mcp_dispatch.ts"
import { PentestAgent } from "./pentestgpt_agent.ts"

const execFileAsync = promisify(execFile)

// ─── MCP JSON-RPC helpers ─────────────────────────────────────────────────────

function send(obj: unknown) {
  process.stdout.write(JSON.stringify(obj) + "\n")
}

function ok(id: unknown, result: unknown) {
  send({ jsonrpc: "2.0", id, result })
}

function err(id: unknown, code: number, message: string) {
  send({ jsonrpc: "2.0", id, error: { code, message } })
}

import { ToolBroker } from "./tool_broker.ts"
import { ContextGuard } from "./context_guard.ts"
import { OpsecThrottleEngine } from "./opsec_throttle.ts"
import { resolveLiveMode } from "./exec_options.ts"
import { gateExecution } from "./opsec_gate.ts"
import type { McpTool } from "./mcp_tool_types.ts"
import { buildBridgedMcpTools } from "./mcp_bridged_tools.ts"
import {
  compactToolOutput,
  efficientMcpInstructions,
  filterToolsForEfficiency,
  isEfficientMode,
  searchModeMcpInstructions,
} from "./mcp_efficiency.ts"
import { buildToolSearchTools } from "./mcp_tool_search.ts"
const toolBroker = new ToolBroker()
const globalThrottleEngine = new OpsecThrottleEngine()

function mcpLive(): boolean {
  return resolveLiveMode()
}

const LIVE_DEFAULT = resolveLiveMode()

const tools: McpTool[] = [

  // ── Shell / terminal ────────────────────────────────────────────────────────

  {
    name: "bash",
    description: "Execute a validated command from the allowed security tool registry (nmap, apt, wallet CLIs, etc.). For pipes/scripts/complex shell, use OpenCode native bash instead.",
    inputSchema: {
      type: "object",
      properties: {
        command:  { type: "string",  description: "Security tool command to execute (e.g. nmap -sV target.com)" },
        cwd:      { type: "string",  description: "Working directory" },
      },
      required: ["command"],
    },
    async handler({ command, cwd }) {
      const live = mcpLive()
      if (!live) {
        return { stdout: "", stderr: "dry-run: pass --live or run on Kali", exitCode: 0, dryRun: true }
      }
      const gate = await gateExecution({ tool: "bash", command: String(command), live: true })
      if (!gate.allowed) {
        return { stdout: "", stderr: gate.review.mitigations.join("; "), exitCode: 1, opsec_blocked: true }
      }
      const cmd = gate.mitigatedCommand ?? String(command)

      try {
        const result = await toolBroker.executeSafe(cmd, cwd ? String(cwd) : process.cwd())
        return {
          stdout: ContextGuard.wrapUntrustedData("bash_stdout", result.stdout),
          stderr: ContextGuard.wrapUntrustedData("bash_stderr", result.stderr),
          exitCode: result.exitCode,
        }
      } catch (err: any) {
        return {
          stdout: "",
          stderr: ContextGuard.wrapUntrustedData("bash_error", err?.message ?? String(err)),
          exitCode: 1,
        }
      }
    },
  },

  // ── Recon ──────────────────────────────────────────────────────────────────

  {
    name: "ares_recon",
    description: "AI-driven target reconnaissance: OSINT, employee enumeration, email pattern discovery, LinkedIn scraping, subdomain enumeration via crt.sh/HaveIBeenPwned/Shodan.",
    inputSchema: {
      type: "object",
      properties: {
        domain:    { type: "string", description: "Target domain or organization name" },
        deep:      { type: "string", description: "deep=true for full OSINT sweep", enum: ["true","false"] },
      },
      required: ["domain"],
    },
    async handler({ domain, deep }) {
      const live = mcpLive()
      return security.ai_recon.runRecon({ domain: String(domain), deep: deep === "true" }, { live })
    },
  },

  {
    name: "ares_bountyhunter",
    description: "Bug bounty recon: subdomain enumeration, endpoint discovery, JS secret scanning, vulnerability surface mapping.",
    inputSchema: {
      type: "object",
      properties: {
        target:    { type: "string", description: "Target domain or IP" },
        endpoints: { type: "string", description: "Comma-separated known endpoints (optional)" },
      },
      required: ["target"],
    },
    async handler({ target, endpoints }) {
      const live = mcpLive()
      const eps = String(endpoints ?? "").split(",").filter(Boolean)
      return security.bountyhunter.recon({ target: String(target), endpoints: eps }, { live })
    },
  },

  {
    name: "ares_scanner_parse",
    description: "Parse scanner output files: nmap XML, masscan JSON, nuclei JSON, nessus .nessus. Returns structured finding objects.",
    inputSchema: {
      type: "object",
      properties: {
        format:  { type: "string", description: "Scanner format", enum: ["nmap","masscan","nuclei","nessus"] },
        content: { type: "string", description: "Raw scanner output content to parse" },
      },
      required: ["format", "content"],
    },
    async handler({ format, content }) {
      return security.scanner_parsers.parse(String(format) as any, String(content))
    },
  },

  // ── Vulnerability & CVE research ───────────────────────────────────────────

  {
    name: "ares_vuln_research",
    description: "Research vulnerabilities: query NVD API for CVEs, search exploit-db, correlate CVE IDs with known PoC exploits.",
    inputSchema: {
      type: "object",
      properties: {
        query:  { type: "string", description: "CVE ID (e.g. CVE-2024-1234), product name, or keyword" },
        limit:  { type: "number", description: "Max results (default 10)" },
      },
      required: ["query"],
    },
    async handler({ query, limit }) {
      const live = mcpLive()
      return dispatch.vulnResearch({ query: String(query), limit: Number(limit ?? 10) }, { live })
    },
  },

  {
    name: "ares_auto_research",
    description: "Automated vulnerability research pipeline: CVE correlation, patch diff analysis, automated PoC generation candidates.",
    inputSchema: {
      type: "object",
      properties: {
        target:   { type: "string", description: "Target software, version, or CVE ID" },
        strategy: { type: "string", description: "Research strategy", enum: ["cve","patch_diff","exploit_chain"] },
      },
      required: ["target"],
    },
    async handler({ target, strategy }) {
      const live = mcpLive()
      return dispatch.autoResearch({ target: String(target), strategy: String(strategy ?? "cve") }, { live })
    },
  },

  // ── Identity & Active Directory ────────────────────────────────────────────

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

  // ── Web & API exploitation ─────────────────────────────────────────────────

  {
    name: "ares_strix_web",
    description: "Offensive browser engine (Strix): Chrome DevTools Protocol automation for XSS exploitation, CSRF, session hijacking, DOM-based attacks, Caido proxy GraphQL interface.",
    inputSchema: {
      type: "object",
      properties: {
        url:     { type: "string", description: "Target URL" },
        attack:  { type: "string", description: "Attack type", enum: ["xss_probe","csrf","session_hijack","dom_clobbering","prototype_pollution","ssti"] },
        payload: { type: "string", description: "Custom payload (optional)" },
      },
      required: ["url", "attack"],
    },
    async handler({ url, attack, payload }) {
      const live = mcpLive()
      return dispatch.strixExecute({ url: String(url), attack: String(attack), payload: String(payload ?? "") }, { live })
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

  // ── Cloud & Container ──────────────────────────────────────────────────────

  {
    name: "ares_cloud_token",
    description: "Cloud credential theft: AWS IMDSv1/v2 metadata, GCP metadata service, Azure IMDS, ECS task role theft, Lambda env var extraction.",
    inputSchema: {
      type: "object",
      properties: {
        provider: { type: "string", description: "Cloud provider", enum: ["aws","gcp","azure","ecs","lambda"] },
      },
      required: ["provider"],
    },
    async handler({ provider }) {
      const live = mcpLive()
      if (String(provider) === "aws") return security.cloud_token.fetchAWSMetadata({ live })
      return security.cloud_token.fetchCloudCredentials({ provider: String(provider) as any, live })
    },
  },

  {
    name: "ares_container_escape",
    description: "Container escape techniques: privileged container abuse, cgroup v1 release_agent, Docker socket exploitation, namespace pivoting, runc CVEs.",
    inputSchema: {
      type: "object",
      properties: {
        technique: { type: "string", description: "Escape vector", enum: ["docker_socket","cgroup_escape","privileged","namespace_pivot","runc_cve"] },
      },
    },
    async handler({ technique }) {
      const live = mcpLive()
      return security.container.escape({ technique: String(technique ?? "docker_socket") as any, live })
    },
  },

  {
    name: "ares_audit_host",
    description: "Host/container security audit: enumerate misconfigurations, check for docker socket, over-privileged capabilities, SUID binaries, world-writable paths.",
    inputSchema: {
      type: "object",
      properties: {
        depth: { type: "string", description: "Audit depth", enum: ["quick","full"] },
      },
    },
    async handler({ depth }) {
      const live = mcpLive()
      return security.container.auditContainer({ live, depth: String(depth ?? "quick") as any })
    },
  },

  // ── Exfiltration ───────────────────────────────────────────────────────────

  {
    name: "ares_exfil",
    description: "Data exfiltration channels: DNS chunked tunnel, ICMP covert channel, HTTP covert channel with steganography, Slack webhook exfil, S3 upload, Pastebin.",
    inputSchema: {
      type: "object",
      properties: {
        data:     { type: "string", description: "Data or file path to exfiltrate" },
        channel:  { type: "string", description: "Exfil channel", enum: ["dns","icmp","http","s3","slack","pastebin","gdrive"] },
        endpoint: { type: "string", description: "C2 endpoint or destination URL" },
      },
      required: ["data", "channel"],
    },
    async handler({ data, channel, endpoint }) {
      const live = mcpLive()
      return dispatch.exfiltrate({ data: String(data), channel: String(channel), endpoint: String(endpoint ?? "") }, { live })
    },
  },

  // ── Pivoting & C2 ─────────────────────────────────────────────────────────

  {
    name: "ares_pivot_tunnel",
    description: "Pivoting and tunneling: SOCKS5 proxy via SSH, Chisel-style tunneling, reverse SSH, port forwarding, ligolo-ng style proxy.",
    inputSchema: {
      type: "object",
      properties: {
        method:  { type: "string", description: "Tunnel method", enum: ["socks5_ssh","chisel","reverse_ssh","port_forward","ligolo"] },
        lhost:   { type: "string", description: "Local/attacker host" },
        lport:   { type: "number", description: "Local port" },
        rhost:   { type: "string", description: "Remote/pivot host" },
        rport:   { type: "number", description: "Remote port" },
      },
      required: ["method"],
    },
    async handler({ method, lhost, lport, rhost, rport }) {
      const live = mcpLive()
      return dispatch.pivotTunnelExecute({ method: String(method), lhost: String(lhost ?? "127.0.0.1"), lport: Number(lport ?? 1080), rhost: String(rhost ?? ""), rport: Number(rport ?? 0) }, { live })
    },
  },

  {
    name: "ares_c2",
    description: "C2 (Command & Control) framework: manage operator sessions, agent beacons, proxy rotation, Telegram/Discord/Graph API C2 channels, dead drop mechanisms.",
    inputSchema: {
      type: "object",
      properties: {
        action:  { type: "string", description: "C2 action", enum: ["status","list_beacons","send_task","rotate_proxy","setup_channel"] },
        channel: { type: "string", description: "C2 channel type", enum: ["http","https","dns","telegram","discord","graph"] },
        payload: { type: "string", description: "Task payload or command for beacon" },
      },
      required: ["action"],
    },
    async handler({ action, channel, payload }) {
      const live = mcpLive()
      return dispatch.c2Execute({ action: String(action), channel: String(channel ?? "https"), payload: String(payload ?? "") }, { live })
    },
  },

  // ── Social Engineering ─────────────────────────────────────────────────────

  {
    name: "ares_social_eng",
    description: "Social engineering: AI-personalized spear-phishing email generation, pretexting scripts, vishing call scripts, lure document generation.",
    inputSchema: {
      type: "object",
      properties: {
        target_name:    { type: "string", description: "Target's full name" },
        target_email:   { type: "string", description: "Target's email address" },
        target_company: { type: "string", description: "Target's company/org" },
        lure:           { type: "string", description: "Phishing lure topic", enum: ["password_reset","invoice","it_support","hr_policy","ceo_fraud","package_delivery"] },
        method:         { type: "string", description: "Delivery method", enum: ["email","sms","phone","linkedin"] },
      },
      required: ["target_name", "lure"],
    },
    async handler({ target_name, target_email, target_company, lure, method }) {
      const live = mcpLive()
      return dispatch.socialEngGenerate({ targetName: String(target_name), targetEmail: String(target_email ?? ""), targetCompany: String(target_company ?? ""), lure: String(lure), method: String(method ?? "email") }, { live })
    },
  },

  // ── Payload & Malware ──────────────────────────────────────────────────────

  {
    name: "ares_payload_gen",
    description: "Offensive payload generation: shellcode stagers, reverse shells in multiple languages (Python, PowerShell, Bash, C#, Go, Rust), dropper logic, obfuscation.",
    inputSchema: {
      type: "object",
      properties: {
        type:     { type: "string", description: "Payload type", enum: ["reverse_shell","bind_shell","shellcode","dropper","stager","dll_injection"] },
        language: { type: "string", description: "Output language", enum: ["python","powershell","bash","csharp","go","rust","c","vba","hta"] },
        lhost:    { type: "string", description: "Attacker/listener host" },
        lport:    { type: "number", description: "Listener port" },
        encode:   { type: "string", description: "Encoding/obfuscation", enum: ["none","base64","xor","aes","caesar"] },
      },
      required: ["type", "language"],
    },
    async handler({ type, language, lhost, lport, encode }) {
      const live = mcpLive()
      return dispatch.toolkitGeneratePayload({ type: String(type), language: String(language), lhost: String(lhost ?? "127.0.0.1"), lport: Number(lport ?? 4444), encode: String(encode ?? "none") }, { live })
    },
  },

  {
    name: "ares_malware_dev",
    description: "Malware development primitives: process injection, AMSI bypass, ETW patching, sandbox evasion, anti-analysis techniques, persistence mechanisms.",
    inputSchema: {
      type: "object",
      properties: {
        technique: { type: "string", description: "Malware technique", enum: ["process_injection","amsi_bypass","etw_patch","sandbox_evasion","registry_persist","wmi_persist","scheduled_task"] },
        target_process: { type: "string", description: "Target process name for injection (e.g. explorer.exe)" },
      },
      required: ["technique"],
    },
    async handler({ technique, target_process }) {
      const live = mcpLive()
      return dispatch.malwareDevExecute({ technique: String(technique), targetProcess: String(target_process ?? "explorer.exe") }, { live })
    },
  },

  // ── YARA & detection ───────────────────────────────────────────────────────

  {
    name: "ares_yara_scan",
    description: "YARA rulepack scan: detect malware, ransomware, C2 beacons, webshells, cryptominers in files or memory dumps. Returns matching rule names and offsets.",
    inputSchema: {
      type: "object",
      properties: {
        path:      { type: "string", description: "File or directory path to scan" },
        ruleset:   { type: "string", description: "YARA ruleset to apply", enum: ["malware","ransomware","c2","webshell","cryptominer","all"] },
      },
      required: ["path"],
    },
    async handler({ path: filePath }) {
      try {
        const text = await fs.promises.readFile(String(filePath), "utf8")
        const matches = security.yara.scanText(text)
        return { matches, count: matches.length, engine: "fallback" }
      } catch (e: any) {
        return { matches: [], count: 0, error: e?.message }
      }
    },
  },

  // ── IoT, Mobile, Firmware ──────────────────────────────────────────────────

  {
    name: "ares_iot_scada",
    description: "IoT/SCADA exploitation: Modbus register read/write, DNP3 spoofing, MQTT broker abuse, BACnet enumeration, industrial protocol fuzzing.",
    inputSchema: {
      type: "object",
      properties: {
        host:     { type: "string", description: "Target host or IP" },
        protocol: { type: "string", description: "Industrial protocol", enum: ["modbus","dnp3","mqtt","bacnet","profinet","coap"] },
        action:   { type: "string", description: "Action", enum: ["enumerate","read","write","fuzz","exploit"] },
      },
      required: ["host", "protocol"],
    },
    async handler({ host, protocol, action }) {
      const live = mcpLive()
      return dispatch.iotScadaExecute({ host: String(host), protocol: String(protocol), action: String(action ?? "enumerate") }, { live })
    },
  },

  {
    name: "ares_mobile",
    description: "Mobile exploitation: ADB command execution, APK static analysis and decompilation, QR code decoding and phishing, Android intent fuzzing.",
    inputSchema: {
      type: "object",
      properties: {
        action: { type: "string", description: "Mobile action", enum: ["adb_exec","apk_analyze","qr_decode","intent_fuzz","frida_hook"] },
        target: { type: "string", description: "APK path, device serial, QR content, or package name" },
      },
      required: ["action"],
    },
    async handler({ action, target }) {
      const live = mcpLive()
      return dispatch.mobileExecute({ action: String(action), target: String(target ?? "") }, { live })
    },
  },

  {
    name: "ares_firmware",
    description: "Firmware analysis: binwalk-style extraction, entropy analysis, UART pinout detection, hardcoded credential search, binary patching.",
    inputSchema: {
      type: "object",
      properties: {
        path:   { type: "string", description: "Firmware file path" },
        action: { type: "string", description: "Analysis action", enum: ["extract","entropy","strings","credentials","patch","uart_detect"] },
      },
      required: ["path", "action"],
    },
    async handler({ path, action }) {
      const live = mcpLive()
      return dispatch.firmwareAnalyze({ path: String(path), action: String(action) }, { live })
    },
  },

  // ── Counter-intel & Detection ──────────────────────────────────────────────

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

  // ── Pentest orchestration ──────────────────────────────────────────────────

  {
    name: "ares_pentest_plan",
    description: "Build a full structured pentest task tree (PentestGPT-style). Returns a phased plan: recon → initial access → lateral movement → privilege escalation → exfiltration.",
    inputSchema: {
      type: "object",
      properties: {
        target: { type: "string", description: "Target host, domain, or CIDR range" },
        scope:  { type: "string", description: "Comma-separated in-scope assets" },
        phase:  { type: "string", description: "Filter to a specific phase", enum: ["all","recon","initial_access","lateral_movement","priv_esc","persistence","exfiltration"] },
      },
      required: ["target"],
    },
    async handler({ target, scope, phase }) {
      const tree = security.pentestgpt_ptt.buildDefaultTree(String(target))
      const summary = security.pentestgpt_ptt.treeSummary(tree)
      return { tree, summary, target, phase: phase ?? "all" }
    },
  },

  {
    name: "ares_pentest_run",
    description: "Run the full autonomous PentestGPT agent: spawns parallel subagents for recon, AD attack, web exploit, and infrastructure escape, then synthesizes findings.",
    inputSchema: {
      type: "object",
      properties: {
        target: { type: "string", description: "Primary target (domain or IP)" },
        scope:  { type: "string", description: "Comma-separated in-scope assets" },
      },
      required: ["target"],
    },
    async handler({ target, scope }) {
      const live = mcpLive()
      const scopes = String(scope ?? target).split(",").map(s => s.trim())
      const agent = new PentestAgent({ target: String(target), scope: scopes, live })
      return agent.runAutonomous()
    },
  },

  // ── MITRE ─────────────────────────────────────────────────────────────────

  {
    name: "ares_caldera_ttp",
    description: "MITRE Caldera TTP executor: load and execute ATT&CK technique profiles (YAML-based), run atomic tests, map findings to MITRE ATT&CK framework.",
    inputSchema: {
      type: "object",
      properties: {
        technique_id: { type: "string", description: "MITRE ATT&CK technique ID (e.g. T1059.001)" },
        profile:      { type: "string", description: "Caldera profile name (optional)" },
      },
      required: ["technique_id"],
    },
    async handler({ technique_id, profile }) {
      const live = mcpLive()
      return dispatch.calderaTtpExecute({ techniqueId: String(technique_id), profile: String(profile ?? "") }, { live })
    },
  },

  {
    name: "ares_atlas_ml",
    description: "MITRE ATLAS ML attack framework: model theft, adversarial input crafting, training data poisoning, model inversion, membership inference.",
    inputSchema: {
      type: "object",
      properties: {
        attack:      { type: "string", description: "ML attack type", enum: ["model_theft","adversarial_input","data_poisoning","model_inversion","membership_inference"] },
        model_url:   { type: "string", description: "Target model API URL (optional)" },
      },
      required: ["attack"],
    },
    async handler({ attack, model_url }) {
      const live = mcpLive()
      return dispatch.atlasArsenalExecute({ attack: String(attack), modelUrl: String(model_url ?? "") }, { live })
    },
  },

  // ── Developer targeting ────────────────────────────────────────────────────

  {
    name: "ares_dev_target",
    description: "Developer-focused attacks: GitHub token scraping from public repos, CI/CD secret extraction, npm/PyPI supply chain poisoning detection, Slack workspace exfil.",
    inputSchema: {
      type: "object",
      properties: {
        target:    { type: "string", description: "GitHub org/repo, CI system URL, or npm package name" },
        technique: { type: "string", description: "Attack technique", enum: ["github_token_scrape","cicd_secrets","npm_typosquat","slack_exfil","dockerfile_leak"] },
      },
      required: ["target", "technique"],
    },
    async handler({ target, technique }) {
      const live = mcpLive()
      return dispatch.devTargetExecute({ target: String(target), technique: String(technique) }, { live })
    },
  },

  {
    name: "ares_supply_chain",
    description: "Supply chain attack detection and simulation: package typosquatting, dependency confusion, malicious package injection, GitHub Actions poisoning.",
    inputSchema: {
      type: "object",
      properties: {
        package:   { type: "string", description: "Package name to analyze" },
        ecosystem: { type: "string", description: "Package ecosystem", enum: ["npm","pip","gem","cargo","nuget","maven"] },
        mode:      { type: "string", description: "Analysis mode", enum: ["detect","simulate","generate"] },
      },
      required: ["package", "ecosystem"],
    },
    async handler({ package: pkg, ecosystem, mode }) {
      const live = mcpLive()
      return security.supply_chain.analyze({ package: String(pkg), ecosystem: String(ecosystem) as any, mode: String(mode ?? "detect") as any }, { live })
    },
  },

  // ── Campaign & skills ──────────────────────────────────────────────────────

  {
    name: "ares_campaign",
    description: "Red team campaign orchestration: build multi-phase attack campaigns with objectives, assign modules to phases, track progress.",
    inputSchema: {
      type: "object",
      properties: {
        target:    { type: "string", description: "Campaign target organization" },
        objective: { type: "string", description: "Campaign objective", enum: ["espionage","ransomware","destructive","supply_chain","agentic","data_exfil","persistence"] },
        execute:   { type: "boolean", description: "Execute campaign (runCampaign) vs plan-only" },
        profileId: { type: "string", description: "APT profile id from intel feeds" },
        phases:    { type: "string", description: "Comma-separated phases to include" },
      },
      required: ["target"],
    },
    async handler({ target, objective, execute, profileId, phases }) {
      const live = mcpLive()
      if (execute && live) {
        return dispatch.campaignExecute({
          target: String(target),
          objective: String(objective ?? "espionage"),
          profileId: profileId ? String(profileId) : undefined,
          phases: String(phases ?? "all").split(","),
        }, { live })
      }
      return dispatch.campaignPlan({ target: String(target), objective: String(objective ?? "espionage"), profileId: profileId ? String(profileId) : undefined, phases: String(phases ?? "all").split(",") }, { live })
    },
  },

  {
    name: "ares_skills_list",
    description: "List all available ARES pentest skills: pre-built attack recipes organized by category (recon, exploit, post-exploit, report).",
    inputSchema: {
      type: "object",
      properties: {
        category: { type: "string", description: "Filter by category", enum: ["all","recon","exploit","post_exploit","evasion","report"] },
      },
    },
    async handler({ category }) {
      const skills = security.skills.listSkills()
      const filtered = String(category ?? "all") === "all" ? skills : skills.filter((s: any) => s.category === category)
      return { skills: filtered, total: filtered.length }
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
];

// ─── Threat Intel MCP tools ───────────────────────────────────────────────────

tools.push(
  {
    name: "ares_intel_feed",
    description: "Query threat intel feeds by actor, CVE, family, or target. Returns enrichTarget/pollFeeds metadata (no malware binaries).",
    inputSchema: {
      type: "object",
      properties: {
        target: { type: "string", description: "Target host/domain/IP" },
        actor: { type: "string", description: "APT profile id filter" },
        cve: { type: "string", description: "CVE id filter" },
        family: { type: "string", description: "vx malware family name" },
        poll: { type: "boolean", description: "Poll live KEV/Ransomwatch feeds" },
      },
    },
    async handler({ target, actor, cve, family, poll }) {
      const live = mcpLive()
      if (poll) {
        const records = await security.intel_feeds.pollFeeds({ live })
        return { records, count: records.length }
      }
      if (family) {
        return { family: security.intel_feeds.lookupVxFamily(String(family)) }
      }
      if (target) {
        const brief = await security.intel_feeds.enrichTarget(String(target), { live })
        if (actor) {
          brief.activeProfiles = brief.activeProfiles.filter((p) => p.id === String(actor))
        }
        if (cve) {
          brief.priorityCves = brief.priorityCves.filter((c) => c.cve === String(cve))
        }
        return brief
      }
      return {
        cves: security.intel_feeds.loadCvePriority(),
        vxFamilies: security.intel_feeds.loadVxFamilyIndex().slice(0, 20),
      }
    },
  },
  {
    name: "ares_intel_watch",
    description: "Watch org/domain against ransomwatch + cached intel feeds for stealer-log / victim matches.",
    inputSchema: {
      type: "object",
      properties: {
        org: { type: "string", description: "Organization name" },
        domains: { type: "array", items: { type: "string" }, description: "Domains to watch" },
      },
      required: ["org"],
    },
    async handler({ org, domains }) {
      const live = mcpLive()
      const domainList = Array.isArray(domains) ? domains.map(String) : []
      const watch = security.intel_feeds.watchOrg(String(org), domainList)
      const ransom = await security.intel_feeds.fetchRansomwatch(live)
      const matches = ransom.filter((r) =>
        String(r.ioc ?? "").toLowerCase().includes(String(org).toLowerCase()) ||
        domainList.some((d) => String(r.ioc ?? "").includes(d)),
      )
      return { ...watch, ransomMatches: matches }
    },
  },
  {
    name: "ares_vx_lookup",
    description: "Hash or vx-underground family metadata lookup (metadata only — never downloads samples).",
    inputSchema: {
      type: "object",
      properties: {
        hash: { type: "string", description: "SHA256 hash" },
        family: { type: "string", description: "Malware family name" },
      },
    },
    async handler({ hash, family }) {
      if (hash) return security.intel_feeds.lookupHash(String(hash))
      if (family) return { entry: security.intel_feeds.lookupVxFamily(String(family)) }
      return { vxFamilies: security.intel_feeds.loadVxFamilyIndex().slice(0, 50) }
    },
  },
  {
    name: "ares_ai_surface",
    description: "Scan for exposed AI/ML stack (Langflow, Nacos, n8n, MinIO). Live-only probes.",
    inputSchema: {
      type: "object",
      properties: {
        target: { type: "string", description: "Target host or URL" },
      },
      required: ["target"],
    },
    async handler({ target }) {
      const live = mcpLive()
      return security.intel_feeds.scanAiSurface(String(target), live)
    },
  },
  {
    name: "ares_stix_ingest",
    description: "Ingest STIX/TAXII threat intel collection into target graph. Enable feeds in data/intel/taxii_feeds.json.",
    inputSchema: {
      type: "object",
      properties: {
        target: { type: "string", description: "Target host/domain for IOC matching" },
        baseUrl: { type: "string", description: "TAXII 2.1 server base URL" },
        collectionId: { type: "string", description: "TAXII collection ID" },
        pollAll: { type: "boolean", description: "Poll all enabled feeds from taxii_feeds.json" },
      },
      required: ["target"],
    },
    async handler({ target, baseUrl, collectionId, pollAll }) {
      const live = mcpLive()
      const { AttackSurfaceGraph } = await import("./attack_surface.ts")
      const graph = new AttackSurfaceGraph(String(target))
      graph.upsertAsset(String(target).replace(/^https?:\/\//, "").split("/")[0]!)
      if (pollAll) {
        const records = await security.intel_feeds.pollStixFeeds(graph, { live })
        return { records, count: records.length, hits: records.length }
      }
      if (baseUrl && collectionId) {
        return security.intel_feeds.ingestStixTaxii(String(baseUrl), String(collectionId), graph, {})
      }
      const feeds = security.intel_feeds.loadTaxiiFeeds().filter((f) => f.enabled)
      return { feeds, note: "Enable feeds in taxii_feeds.json or pass baseUrl+collectionId" }
    },
  },
  {
    name: "ares_proof_export",
    description: "Build tamper-evident proof pack (JSON + HTML + PDF) from target engagement graph.",
    inputSchema: {
      type: "object",
      properties: {
        target: { type: "string", description: "Engagement target" },
      },
      required: ["target"],
    },
    async handler({ target }) {
      const { AttackSurfaceGraph } = await import("./attack_surface.ts")
      const { buildProofPack, writeProofPack } = await import("./proof_pack.ts")
      const graph = new AttackSurfaceGraph(String(target))
      graph.upsertAsset(String(target).replace(/^https?:\/\//, "").split("/")[0]!)
      const pack = buildProofPack(graph)
      const path = writeProofPack(pack)
      return { path, merkleRoot: pack.merkleRoot, findings: pack.findings.length }
    },
  },
  {
    name: "ares_engagement_watch",
    description: "Run engagement watch cycle: snapshot, delta findings, persist graph.",
    inputSchema: {
      type: "object",
      properties: {
        target: { type: "string" },
        live: { type: "boolean" },
      },
      required: ["target"],
    },
    async handler({ target, live: liveArg }) {
      const live = liveArg ?? mcpLive()
      const { runWatchCycle } = await import("./engagement_watch.ts")
      return runWatchCycle({ target: String(target), intervalMinutes: 60, live })
    },
  },
  {
    name: "ares_retest_finding",
    description: "Retest a finding against watch history for remediation status.",
    inputSchema: {
      type: "object",
      properties: {
        target: { type: "string" },
        findingId: { type: "string" },
        live: { type: "boolean" },
      },
      required: ["target", "findingId"],
    },
    async handler({ target, findingId, live: liveArg }) {
      const live = liveArg ?? mcpLive()
      const { retestFinding } = await import("./engagement_watch.ts")
      return retestFinding(String(target), String(findingId), { live })
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
  },
  {
    name: "ares_pivot_replay",
    description: "BloodHound + netexec credential replay pivot chain.",
    inputSchema: {
      type: "object",
      properties: {
        target: { type: "string" },
        domain: { type: "string" },
      },
      required: ["target"],
    },
    async handler({ target, domain }) {
      const live = mcpLive()
      const { executeAgentTool } = await import("./agent_tools.ts")
      const { ToolBroker } = await import("./tool_broker.ts")
      const { AttackSurfaceGraph } = await import("./attack_surface.ts")
      const graph = new AttackSurfaceGraph(String(target))
      const ctx = { target: String(target), graph, broker: new ToolBroker(), live }
      return executeAgentTool(ctx, "pivot_replay", { domain: domain ? String(domain) : undefined })
    },
  },
  {
    name: "ares_raas_campaign",
    description: "RaaS stack: VSS wipe, double-extortion catalog, RSA payment bundle, ESXi encrypt, SMB/GPO spread. Destructive ops require live + forceLive.",
    inputSchema: {
      type: "object",
      properties: {
        targetDir: { type: "string", description: "Directory to catalog/encrypt" },
        esxiHost: { type: "string" },
        smbTargets: { type: "array", items: { type: "string" } },
        domain: { type: "string" },
        forceLive: { type: "boolean" },
        family: { type: "string" },
        live: { type: "boolean" },
      },
      required: ["targetDir"],
    },
    async handler({ targetDir, esxiHost, smbTargets, domain, forceLive, family, live: liveArg }) {
      const live = liveArg ?? mcpLive()
      return dispatch.raasCampaignExecute(
        {
          targetDir: String(targetDir),
          esxiHost: esxiHost ? String(esxiHost) : undefined,
          smbTargets: Array.isArray(smbTargets) ? smbTargets.map(String) : undefined,
          domain: domain ? String(domain) : undefined,
          forceLive: Boolean(forceLive),
          family: family ? String(family) : undefined,
        },
        { live },
      )
    },
  },
  {
    name: "ares_topcut_assess",
    description: "Score OurMine readiness vs enterprise BAS top-cut bar.",
    inputSchema: { type: "object", properties: {} },
    async handler() {
      const { assessTopCut, formatTopCutReport } = await import("./top_cut_score.ts")
      const report = await assessTopCut()
      return { ...report, formatted: formatTopCutReport(report) }
    },
  },
)

const existingToolNames = new Set(tools.map((t) => t.name))
tools.push(...buildBridgedMcpTools(existingToolNames, mcpLive))

const allTools = tools
const baseExposed = filterToolsForEfficiency(allTools)
const fullToolMap = new Map(allTools.map((t) => [t.name, t]))
const searchTools = isEfficientMode() ? [] : buildToolSearchTools(fullToolMap)
const toolsExposed = isEfficientMode() ? baseExposed : [...baseExposed, ...searchTools]

// ─── MCP server main loop ─────────────────────────────────────────────────────

const toolMap = new Map(toolsExposed.map((t) => [t.name, t]))

async function handleRequest(req: any) {
  const { id, method, params } = req

  switch (method) {

    case "initialize":
      ok(id, {
        protocolVersion: "2024-11-05",
        serverInfo: { name: "ourmine-ares", version: "1.0.0" },
        capabilities: { tools: {} },
        instructions: isEfficientMode()
          ? efficientMcpInstructions(toolsExposed.length)
          : searchModeMcpInstructions(toolsExposed.length, allTools.length),
      })
      break

    case "notifications/initialized":
      // no-op
      break

    case "tools/list":
      ok(id, {
        tools: toolsExposed.map((t) => ({
          name:        t.name,
          description: t.description,
          inputSchema: t.inputSchema,
        })),
      })
      break

    case "tools/call": {
      await globalThrottleEngine.paceExecution()

      const toolName = params?.name
      const toolArgs = params?.arguments ?? {}
      const tool = toolMap.get(toolName)

      if (!tool) {
        err(id, -32601, `Unknown tool: ${toolName}`)
        break
      }

      try {
        const result = await tool.handler(toolArgs)
        const text = isEfficientMode()
          ? compactToolOutput(result, 1500)
          : JSON.stringify(result, null, 2)
        ok(id, {
          content: [{
            type: "text",
            text,
          }],
        })
      } catch (e: any) {
        ok(id, {
          content: [{
            type: "text",
            text: `Error: ${e?.message ?? String(e)}`,
          }],
          isError: true,
        })
      }
      break
    }

    case "ping":
      ok(id, {})
      break

    default:
      err(id, -32601, `Method not found: ${method}`)
  }
}

/** Start the MCP JSON-RPC server on stdin/stdout. Safe to call from `ourmine serve`. */
export function startMcpServer(): void {
  let buffer = ""
  process.stdin.setEncoding("utf8")
  process.stdin.on("data", async (chunk: string) => {
    buffer += chunk
    const lines = buffer.split("\n")
    buffer = lines.pop() ?? ""
    for (const line of lines) {
      const trimmed = line.trim()
      if (!trimmed) continue
      try {
        const req = JSON.parse(trimmed)
        await handleRequest(req)
      } catch {
        // malformed JSON — ignore
      }
    }
  })

  process.stdin.on("end", () => process.exit(0))
  process.stderr.write(`[ourmine-ares MCP] started — ${toolsExposed.length} tools (${allTools.length} total, efficient=${isEfficientMode()})\n`)
}

const isMain =
  typeof process.argv[1] === "string" &&
  fileURLToPath(import.meta.url) === path.resolve(process.argv[1])

if (isMain) {
  startMcpServer()
}
