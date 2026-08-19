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

export function buildOffensiveTools(): McpTool[] {
  const { mcpLive, toolBroker, globalThrottleEngine } = mcpContext
  return [
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
          const p = String(provider)
          if (p === "aws") return security.cloud_token.fetchAWSMetadata({ live })
          if (p === "gcp") return security.cloud_token.fetchGCPMetadata({ live })
          if (p === "azure") return security.cloud_token.fetchAzureMetadata({ live })
          return { provider: p, dryRun: !live, credentials: null, note: "ecs/lambda assessment stub" }
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
        name: "ares_syndicate_mission",
        description: "Syndicate Prime Mission Control: Execute a fully autonomous, self-organizing adversarial engagement. Synthesizes bespoke departments and operatives based on your mission objective.",
        inputSchema: {
          type: "object",
          properties: {
            target:    { type: "string", description: "Target IP, domain, or range" },
            objective: { type: "string", description: "Detailed mission objective (e.g. 'Infiltrate energy grid and deploy voice lures')" },
          },
          required: ["target", "objective"],
        },
        async handler({ target, objective }) {
          const live = mcpLive()
          return security.ares.runAresOrchestrator({ target: String(target), objective: String(objective), live })
        },
      },

    {
        name: "ares_malware_factory",
        description: "Weapon Synthesis & Refactoring: Raid vx-underground for samples, refactor code for mission demands, apply polymorphic obfuscation, and stage payloads.",
        inputSchema: {
          type: "object",
          properties: {
            family:    { type: "string", description: "Malware family to source (e.g. LockBit)" },
            objective: { type: "string", description: "Mission-specific refactoring objective" },
          },
          required: ["objective"],
        },
        async handler({ family, objective }) {
          const live = mcpLive()
          return security.ares.runMalwareFactory({ family: String(family ?? ""), objective: String(objective) }, { live })
        },
      },

    {
        name: "ares_multi_platform_arsenal",
        description: "Multi-Platform Exploitation: Tailor exploits and payloads for macOS (TCC/EndpointSecurity), Mobile (SS7/Android), and ATM (XFS) hardware.",
        inputSchema: {
          type: "object",
          properties: {
            platform: { type: "string", description: "Target platform", enum: ["macos","mobile_ios","mobile_android","atm_xfs","linux_kernel","windows_kernel"] },
            action:   { type: "string", description: "Exploitation action" },
          },
          required: ["platform", "action"],
        },
        async handler({ platform, action }) {
          const live = mcpLive()
          return security.ares.runMultiPlatformArsenal({ platform: String(platform), action: String(action) }, { live })
        },
      },

    {
        name: "ares_kali_bridge",
        description: "Kali Linux Tool Orchestration: Execute native Kali Linux tools (Nmap, Metasploit, Sqlmap, Hydra) for automated exploitation.",
        inputSchema: {
          type: "object",
          properties: {
            tool:    { type: "string", description: "Kali tool to run", enum: ["nmap","metasploit","sqlmap","hydra","gobuster"] },
            command: { type: "string", description: "Full command arguments" },
          },
          required: ["tool", "command"],
        },
        async handler({ tool, command }) {
          const live = mcpLive()
          return security.ares.runKaliBridge({ tool: String(tool), command: String(command) }, { live })
        },
      },

    {
        name: "ares_c2_resilience",
        description: "C2 Resilience & Credential Rotation: Autonomous failover and credential rotation across multiple cloud channels (Slack, Notion, GitHub).",
        inputSchema: {
          type: "object",
          properties: {
            action: { type: "string", description: "Resilience action", enum: ["rotate_credentials","failover_check","self_heal"] },
          },
          required: ["action"],
        },
        async handler({ action }) {
          const live = mcpLive()
          return security.ares.runC2Resilience({ action: String(action) }, { live })
        },
      },

    {
        name: "ares_financial_warfare",
        description: "Financial Warfare: Infiltrate SWIFT gateways, manipulate ISO 20022 messages, and disrupt clearing networks.",
        inputSchema: {
          type: "object",
          properties: {
            vector: { type: "string", description: "Financial attack vector", enum: ["swift_gateway","ledger_manipulation","iso20022_injection"] },
          },
          required: ["vector"],
        },
        async handler({ vector }) {
          const live = mcpLive()
          return security.ares.runFinancialWarfare({ vector: String(vector), live })
        },
      },

    {
        name: "ares_cognitive_ops",
        description: "Cognitive Warfare: Generate AI-personalized vishing scripts, deepfake voice clones, and authority lures for MFA bypass.",
        inputSchema: {
          type: "object",
          properties: {
            executive: { type: "string", description: "Target executive role/name" },
            channel:   { type: "string", description: "Manipulation channel", enum: ["voice_vishing","video_deepfake","synthetic_persona","mfa_bypass"] },
          },
          required: ["executive"],
        },
        async handler({ executive, channel }) {
          const live = mcpLive()
          return security.ares.runCognitiveOps({ targetExecutive: String(executive), channel: String(channel ?? "voice_vishing"), live })
        },
      },

    {
        name: "ares_anti_forensics",
        description: "Anti-Forensics & Sanitization: Clean operational traces, timestomp files, and neutralize forensic artifacts after an engagement.",
        inputSchema: {
          type: "object",
          properties: {
            action: { type: "string", description: "Cleanup action", enum: ["artifact_clean","log_sanitize","timestomp"] },
          },
          required: ["action"],
        },
        async handler({ action }) {
          const live = mcpLive()
          return security.ares.runAntiForensics({ action: String(action), live })
        },
      },

    {
        name: "ares_deception_noise",
        description: "Deception & Attribution Masking: Inject false-flag indicators of compromise, flood SOC telemetry, and mask operational attribution.",
        inputSchema: {
          type: "object",
          properties: {
            group: { type: "string", description: "APT group to mimic", enum: ["Lazarus Group","APT28 (Fancy Bear)","Scattered Spider"] },
          },
          required: ["group"],
        },
        async handler({ group }) {
          const live = mcpLive()
          return security.ares.runDeceptionNoise({ attributedGroup: String(group), live })
        },
      },

    {
        name: "ares_raas_advanced",
        description: "Double-Extortion Ransomware: Exfiltrate sensitive data, encrypt local targets, and provision Tor-based recovery portals.",
        inputSchema: {
          type: "object",
          properties: {
            target:   { type: "string", description: "Target host to encrypt" },
            manifest: { type: "string", description: "JSON exfiltration manifest path" },
          },
          required: ["target", "manifest"],
        },
        async handler({ target, manifest }) {
          const live = mcpLive()
          return security.ares.runRaasAdvanced(String(target), String(manifest), { live })
        },
      },

    {
        name: "ares_satellite_c2",
        description: "Satellite Covert C2: Establish covert satellite channels (VSAT/Iridium) and steganographic beaconing.",
        inputSchema: {
          type: "object",
          properties: {
            vsat_host: { type: "string", description: "VSAT modem host/gateway" },
          },
        },
        async handler({ vsat_host }) {
          const live = mcpLive()
          return security.ares.deploySatelliteC2({ vsatHost: String(vsat_host ?? ""), live })
        },
      },

    {
        name: "ares_innovation_engine",
        description: "Proactive Research & Zero-Day Synthesis: Hunt for latest exploits, analyze NVD/CISA feeds, and synthesize mission-specific tradecraft.",
        inputSchema: {
          type: "object",
          properties: {
            focus: { type: "string", description: "Research focus (e.g. 'cPanel zero-day')" },
          },
        },
        async handler({ focus }) {
          const live = mcpLive()
          return security.ares.runInnovationEngine({ focus: String(focus ?? "") }, { live })
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
        name: "ares_topcut_assess",
        description: "Score OurMine readiness vs enterprise BAS top-cut bar.",
        inputSchema: { type: "object", properties: {} },
        async handler() {
          const { assessTopCut, formatTopCutReport } = await import("./top_cut_score.ts")
          const report = await assessTopCut()
          return { ...report, formatted: formatTopCutReport(report) }
        },
      }
  ]
}
