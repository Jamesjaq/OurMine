#!/usr/bin/env node
/**
 * OurMine ARES MCP Server
 *
 * Exposes all 77 ARES security modules + a bash executor as MCP tools.
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
import * as security from "./index.ts"
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

// ─── Tool definitions ─────────────────────────────────────────────────────────

interface McpTool {
  name:        string
  description: string
  inputSchema: {
    type:       "object"
    properties: Record<string, { type: string; description: string; enum?: string[] }>
    required?:  string[]
  }
  handler: (args: Record<string, unknown>) => Promise<unknown>
}

const LIVE_DEFAULT = false  // always dry-run unless --live flag in args

const tools: McpTool[] = [

  // ── Shell / terminal ────────────────────────────────────────────────────────

  {
    name: "bash",
    description: "Execute a bash shell command. Returns stdout, stderr, and exit code. Use for any terminal operation: running tools like nmap, gobuster, sqlmap, hydra, netcat, curl, git, python scripts, etc.",
    inputSchema: {
      type: "object",
      properties: {
        command:  { type: "string",  description: "Bash command to execute" },
        timeout:  { type: "number",  description: "Timeout in milliseconds (default 30000)" },
        cwd:      { type: "string",  description: "Working directory (default: project root)" },
      },
      required: ["command"],
    },
    async handler({ command, timeout = 30000, cwd }) {
      const live = process.argv.includes("--live")
      if (!live) {
        return { stdout: `[DRY-RUN] ${command}`, stderr: "", exitCode: 0, note: "Pass --live to execute real commands" }
      }
      return new Promise(resolve => {
        const proc = spawn("bash", ["-c", String(command)], {
          cwd: String(cwd ?? process.cwd()),
          env: process.env,
          stdio: ["ignore", "pipe", "pipe"],
        })
        let stdout = "", stderr = ""
        proc.stdout.on("data", (d: Buffer) => { stdout += d.toString() })
        proc.stderr.on("data", (d: Buffer) => { stderr += d.toString() })
        const timer = setTimeout(() => { proc.kill("SIGTERM") }, Number(timeout))
        proc.on("close", (code) => {
          clearTimeout(timer)
          resolve({ stdout: stdout.slice(0, 50000), stderr: stderr.slice(0, 10000), exitCode: code ?? 1 })
        })
      })
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
      const live = process.argv.includes("--live")
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
      const live = process.argv.includes("--live")
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
      const live = process.argv.includes("--live")
      return security.vuln_research.research({ query: String(query), limit: Number(limit ?? 10) }, { live })
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
      const live = process.argv.includes("--live")
      return security.auto_research.research({ target: String(target), strategy: String(strategy ?? "cve") as any }, { live })
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
      const live = process.argv.includes("--live")
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
      const live = process.argv.includes("--live")
      return security.ad_exploit.execute({ domain: String(domain), technique: String(technique) as any, target: String(target ?? "") }, { live })
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
      const live = process.argv.includes("--live")
      return security.hybrid_ad_entra.execute({ domain: String(domain), tenantId: String(tenant_id ?? ""), technique: String(technique ?? "ssso_token") as any }, { live })
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
      const live = process.argv.includes("--live")
      return security.strix_engine.execute({ url: String(url), attack: String(attack) as any, payload: String(payload ?? "") }, { live })
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
      const live = process.argv.includes("--live")
      return security.oauth_chain.execute({ target: String(target), technique: String(technique) as any, clientId: String(client_id ?? "") }, { live })
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
      const live = process.argv.includes("--live")
      return security.webmail_exploit.execute({ target: String(target), technique: String(technique) as any }, { live })
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
      const live = process.argv.includes("--live")
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
      const live = process.argv.includes("--live")
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
      const live = process.argv.includes("--live")
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
      const live = process.argv.includes("--live")
      return security.exfil.exfiltrate({ data: String(data), channel: String(channel) as any, endpoint: String(endpoint ?? "") }, { live })
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
      const live = process.argv.includes("--live")
      return security.pivot_tunnel.execute({ method: String(method) as any, lhost: String(lhost ?? "127.0.0.1"), lport: Number(lport ?? 1080), rhost: String(rhost ?? ""), rport: Number(rport ?? 0) }, { live })
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
      const live = process.argv.includes("--live")
      return security.c2.execute({ action: String(action) as any, channel: String(channel ?? "https") as any, payload: String(payload ?? "") }, { live })
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
      const live = process.argv.includes("--live")
      return security.social_eng.generate({ targetName: String(target_name), targetEmail: String(target_email ?? ""), targetCompany: String(target_company ?? ""), lure: String(lure) as any, method: String(method ?? "email") as any }, { live })
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
      const live = process.argv.includes("--live")
      return security.toolkit.generatePayload({ type: String(type) as any, language: String(language) as any, lhost: String(lhost ?? "127.0.0.1"), lport: Number(lport ?? 4444), encode: String(encode ?? "none") as any }, { live })
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
      const live = process.argv.includes("--live")
      return security.malware_dev.execute({ technique: String(technique) as any, targetProcess: String(target_process ?? "explorer.exe") }, { live })
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
    async handler({ path, ruleset }) {
      return security.yara.scanFile(String(path), String(ruleset ?? "all") as any)
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
      const live = process.argv.includes("--live")
      return security.iot_scada.execute({ host: String(host), protocol: String(protocol) as any, action: String(action ?? "enumerate") as any }, { live })
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
      const live = process.argv.includes("--live")
      return security.mobile.execute({ action: String(action) as any, target: String(target ?? "") }, { live })
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
      const live = process.argv.includes("--live")
      return security.firmware.analyze({ path: String(path), action: String(action) as any }, { live })
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
      const live = process.argv.includes("--live")
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
      const live = process.argv.includes("--live")
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
      const live = process.argv.includes("--live")
      return security.caldera_ttp.execute({ techniqueId: String(technique_id), profile: String(profile ?? "") }, { live })
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
      const live = process.argv.includes("--live")
      return security.atlas_arsenal.execute({ attack: String(attack) as any, modelUrl: String(model_url ?? "") }, { live })
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
      const live = process.argv.includes("--live")
      return security.dev_target.execute({ target: String(target), technique: String(technique) as any }, { live })
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
      const live = process.argv.includes("--live")
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
        objective: { type: "string", description: "Campaign objective", enum: ["data_exfil","ransomware","persistence","destructive","espionage"] },
        phases:    { type: "string", description: "Comma-separated phases to include" },
      },
      required: ["target", "objective"],
    },
    async handler({ target, objective, phases }) {
      const live = process.argv.includes("--live")
      return security.campaign.plan({ target: String(target), objective: String(objective) as any, phases: String(phases ?? "all").split(",") }, { live })
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

]

// ─── MCP server main loop ─────────────────────────────────────────────────────

const toolMap = new Map(tools.map(t => [t.name, t]))

async function handleRequest(req: any) {
  const { id, method, params } = req

  switch (method) {

    case "initialize":
      ok(id, {
        protocolVersion: "2024-11-05",
        serverInfo: { name: "ourmine-ares", version: "1.0.0" },
        capabilities: { tools: {} },
        instructions: `You are equipped with OurMine ARES — a full offensive security suite with ${tools.length} hacking tools and a bash executor.

You can autonomously:
- Run reconnaissance (recon, OSINT, subdomain enum)
- Exploit vulnerabilities (web, AD, cloud, IoT, mobile)
- Execute shell commands and real terminal tools (nmap, sqlmap, etc.) via the 'bash' tool
- Generate payloads and C2 infrastructure
- Run full autonomous pentest campaigns

Security posture: DRY-RUN by default. Server started with --live flag enables real execution.

Always think step-by-step. Use ares_pentest_plan first to build a task tree, then execute phases.`,
      })
      break

    case "notifications/initialized":
      // no-op
      break

    case "tools/list":
      ok(id, {
        tools: tools.map(t => ({
          name:        t.name,
          description: t.description,
          inputSchema: t.inputSchema,
        })),
      })
      break

    case "tools/call": {
      const toolName = params?.name
      const toolArgs = params?.arguments ?? {}
      const tool = toolMap.get(toolName)

      if (!tool) {
        err(id, -32601, `Unknown tool: ${toolName}`)
        break
      }

      try {
        const result = await tool.handler(toolArgs)
        ok(id, {
          content: [{
            type: "text",
            text: JSON.stringify(result, null, 2),
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

// Read JSON-RPC messages line by line from stdin
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
    } catch (e) {
      // malformed JSON — ignore
    }
  }
})

process.stdin.on("end", () => process.exit(0))
process.stderr.write(`[ourmine-ares MCP] started — ${tools.length} tools available\n`)
