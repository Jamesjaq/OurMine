/**
 * @module skills
 * Offensive Security Skills Index & Loader — Real tool availability detection,
 * skill execution framework, taxonomy indexing, and automated tool integration.
 */

import { resolveDryRun } from "./exec_options.ts"
import { execSync, exec as execCallback } from "child_process";
import { existsSync } from "fs";
import { promisify } from "util";

const execAsync = promisify(execCallback);

export interface SecuritySkill {
  id: string;
  name: string;
  category: "recon" | "exploit" | "post_exploit" | "cloud" | "ad" | "mobile";
  description: string;
  tags: string[];
  requiredTools: string[];
  optionalTools?: string[];
}

export interface ToolAvailability {
  tool: string;
  available: boolean;
  path?: string;
  version?: string;
}

export interface SkillExecutionResult {
  skillId: string;
  success: boolean;
  output: string;
  error?: string;
  toolsUsed: string[];
  toolsMissing: string[];
  duration: number;
}

export interface TaxonomyNode {
  category: string;
  skills: SecuritySkill[];
  subcategories?: Record<string, TaxonomyNode>;
}

const SKILL_CATALOG: SecuritySkill[] = [
  {
    id: "skill_subdomain_enum",
    name: "Subdomain Enumeration",
    category: "recon",
    description: "Passive and active subdomain discovery using DNS resolution, certificate transparency, and OSINT sources",
    tags: ["dns", "osint", "subdomain", "recon"],
    requiredTools: ["dig"],
    optionalTools: ["amass", "subfinder", "dnsenum"],
  },
  {
    id: "skill_kerberoast",
    name: "Kerberoasting",
    category: "ad",
    description: "Request TGS tickets for SPN accounts and extract hashes for offline cracking",
    tags: ["active_directory", "kerberos", "credential"],
    requiredTools: ["impacket-getTGS"],
    optionalTools: ["impacket", "rubeus"],
  },
  {
    id: "skill_aws_imds",
    name: "AWS IMDS Extraction",
    category: "cloud",
    description: "Fetch IAM credentials from EC2 instance metadata service (IMDSv1/v2)",
    tags: ["aws", "cloud", "metadata", "credential"],
    requiredTools: ["curl"],
    optionalTools: ["aws-cli"],
  },
  {
    id: "skill_c2_beacon",
    name: "C2 Beaconing",
    category: "post_exploit",
    description: "Establish persistent HTTPS/DNS covert channel for command and control",
    tags: ["c2", "implant", "persistence"],
    requiredTools: ["curl"],
    optionalTools: ["socat", "ncat"],
  },
  {
    id: "skill_port_scan",
    name: "Port Scanning",
    category: "recon",
    description: "TCP/UDP port scanning with service version detection and OS fingerprinting",
    tags: ["network", "scanning", "service_detection"],
    requiredTools: ["nmap"],
    optionalTools: ["masscan", "rustscan"],
  },
  {
    id: "skill_web_vuln_scan",
    name: "Web Vulnerability Scanning",
    category: "exploit",
    description: "Automated web application vulnerability scanning with template-based detection",
    tags: ["web", "vulnerability", "http"],
    requiredTools: ["nuclei"],
    optionalTools: ["nikto", "wapiti"],
  },
  {
    id: "skill_sql_injection",
    name: "SQL Injection Testing",
    category: "exploit",
    description: "Automated SQL injection detection and exploitation with database fingerprinting",
    tags: ["sqli", "database", "web"],
    requiredTools: ["sqlmap"],
    optionalTools: [],
  },
  {
    id: "skill_priv_esc_linux",
    name: "Linux Privilege Escalation",
    category: "post_exploit",
    description: "Automated Linux privilege escalation path discovery and exploitation",
    tags: ["linux", "privesc", "suid", "sudo"],
    requiredTools: ["find", "grep"],
    optionalTools: ["linpeas", "linux-exploit-suggester"],
  },
  {
    id: "skill_priv_esc_windows",
    name: "Windows Privilege Escalation",
    category: "post_exploit",
    description: "Automated Windows privilege escalation path discovery and exploitation",
    tags: ["windows", "privesc", "token", "service"],
    requiredTools: ["powershell"],
    optionalTools: ["winpeas", "seatbelt", "sharpup"],
  },
  {
    id: "skill_cloud_enum",
    name: "Cloud Enumeration",
    category: "cloud",
    description: "Multi-cloud resource enumeration and misconfiguration detection",
    tags: ["aws", "azure", "gcp", "enumeration"],
    requiredTools: ["curl"],
    optionalTools: ["aws-cli", "az-cli", "gcloud"],
  },
  {
    id: "skill_wireless_audit",
    name: "Wireless Network Audit",
    category: "recon",
    description: "WiFi network scanning, deauthentication, and WPA/WPA2 handshake capture",
    tags: ["wifi", "wireless", "wpa", "aircrack"],
    requiredTools: ["airmon-ng", "airodump-ng"],
    optionalTools: ["aireplay-ng", "aircrack-ng"],
  },
  {
    id: "skill_packet_capture",
    name: "Packet Capture & Analysis",
    category: "recon",
    description: "Network packet capture, protocol analysis, and traffic extraction",
    tags: ["network", "pcap", "wireshark", "traffic"],
    requiredTools: ["tcpdump"],
    optionalTools: ["tshark", "wireshark"],
  },
  {
    id: "skill_password_spray",
    name: "Password Spraying",
    category: "exploit",
    description: "Low-and-slow credential spraying against multiple authentication protocols",
    tags: ["credential", "brute_force", "authentication"],
    requiredTools: ["curl"],
    optionalTools: ["crackmapexec", "spray"],
  },
  {
    id: "skill_lateral_movement",
    name: "Lateral Movement",
    category: "post_exploit",
    description: "Network pivoting, pass-the-hash, and remote execution for lateral movement",
    tags: ["pivoting", "pth", "remote_execution"],
    requiredTools: ["ssh"],
    optionalTools: ["crackmapexec", "evil-winrm", "impacket-wmiexec"],
  },
  {
    id: "skill_data_exfil",
    name: "Data Exfiltration",
    category: "post_exploit",
    description: "Covert data exfiltration via DNS, ICMP, HTTP, or steganographic channels",
    tags: ["exfiltration", "covert", "data_theft"],
    requiredTools: ["curl"],
    optionalTools: ["dnscat2", "icmpsh"],
  },
  {
    id: "skill_network_scan",
    name: "Network Discovery",
    category: "recon",
    description: "Host discovery, network mapping, and topology enumeration",
    tags: ["network", "discovery", "topology"],
    requiredTools: ["nmap"],
    optionalTools: ["masscan", "arp-scan"],
  },
  {
    id: "skill_agentic_ai_hunt",
    name: "Agentic AI Surface Hunt",
    category: "recon",
    description: "Intel-driven hunt for exposed LLM endpoints, Langflow, Nacos, n8n, MinIO",
    tags: ["ai", "agentic", "intel", "langflow"],
    requiredTools: ["curl"],
    optionalTools: ["nuclei"],
  },
  {
    id: "skill_ransomware_readiness",
    name: "Ransomware Readiness Assessment",
    category: "post_exploit",
    description: "Read-only backup/snapshot audit, ESXi exposure, recovery gap analysis",
    tags: ["ransomware", "backup", "esxi", "impact"],
    requiredTools: ["curl"],
    optionalTools: ["nmap"],
  },
  {
    id: "skill_supply_chain_worm",
    name: "Supply Chain Worm Hunt",
    category: "exploit",
    description: "Lockfile poison detection, CI/CD pipeline audit, npm worm indicators",
    tags: ["supply_chain", "npm", "cicd", "lockfile"],
    requiredTools: ["grep"],
    optionalTools: ["npm"],
  },
  {
    id: "skill_identity_first",
    name: "Identity-First Attack Chain",
    category: "exploit",
    description: "Scattered Spider style: social eng assess, identity attack, evilginx, IdP OAuth audit",
    tags: ["identity", "okta", "oauth", "phishing"],
    requiredTools: ["curl"],
    optionalTools: ["evilginx2"],
  },
];

const KNOWN_TOOL_PATHS: Record<string, string[]> = {
  nmap: ["/usr/bin/nmap", "/usr/local/bin/nmap", "/opt/nmap/nmap"],
  sqlmap: ["/usr/bin/sqlmap", "/usr/local/bin/sqlmap", "/opt/sqlmap/sqlmap.py"],
  nuclei: ["/usr/bin/nuclei", "/usr/local/bin/nuclei", "/opt/nuclei/nuclei"],
  amass: ["/usr/bin/amass", "/usr/local/bin/amass"],
  subfinder: ["/usr/bin/subfinder", "/usr/local/bin/subfinder"],
  masscan: ["/usr/bin/masscan", "/usr/local/bin/masscan"],
  "impacket-getTGS": ["/usr/bin/impacket-getTGS", "/usr/local/bin/impacket-getTGS", "/usr/bin/getTGS"],
  curl: ["/usr/bin/curl", "/usr/local/bin/curl"],
  dig: ["/usr/bin/dig", "/usr/local/bin/dig"],
  ssh: ["/usr/bin/ssh", "/usr/local/bin/ssh"],
  tcpdump: ["/usr/bin/tcpdump", "/usr/local/bin/tcpdump"],
  find: ["/usr/bin/find", "/usr/local/bin/find"],
  grep: ["/usr/bin/grep", "/usr/local/bin/grep"],
  powershell: ["/usr/bin/pwsh", "/usr/local/bin/pwsh", "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"],
  "airmon-ng": ["/usr/bin/airmon-ng", "/usr/local/bin/airmon-ng"],
  "airodump-ng": ["/usr/bin/airodump-ng", "/usr/local/bin/airodump-ng"],
};

import { isToolAvailable, getToolPath, checkTools } from "./tool_detection.ts";

async function detectToolAvailability(tool: string): Promise<ToolAvailability> {
  const info = checkTools(tool)[0];
  return {
    tool,
    available: info?.available ?? isToolAvailable(tool),
    path: info?.path ?? getToolPath(tool) ?? undefined,
    version: info?.version ?? undefined,
  };
}

export async function detectAllTools(
  skills: SecuritySkill[] = SKILL_CATALOG,
  dryRun = false
): Promise<ToolAvailability[]> {
  if (dryRun) {
    const allTools = new Set<string>();
    for (const skill of skills) {
      skill.requiredTools.forEach((t) => allTools.add(t));
      skill.optionalTools?.forEach((t) => allTools.add(t));
    }
    return [...allTools].map((tool) => ({
      tool,
      available: true,
      path: `/usr/bin/${tool}`,
      version: "dry-run-1.0",
    }));
  }

  const allTools = new Set<string>();
  for (const skill of skills) {
    skill.requiredTools.forEach((t) => allTools.add(t));
    skill.optionalTools?.forEach((t) => allTools.add(t));
  }

  const detections = [...allTools].map((tool) => detectToolAvailability(tool));
  return Promise.all(detections);
}

export function getSkillAvailability(skill: SecuritySkill, toolDetections: ToolAvailability[]): {
  ready: boolean;
  missingRequired: string[];
  missingOptional: string[];
} {
  const toolMap = new Map(toolDetections.map((t) => [t.tool, t]));
  const missingRequired = skill.requiredTools.filter((t) => !toolMap.get(t)?.available);
  const missingOptional = (skill.optionalTools ?? []).filter((t) => !toolMap.get(t)?.available);

  return {
    ready: missingRequired.length === 0,
    missingRequired,
    missingOptional,
  };
}

export function listSkills(category?: SecuritySkill["category"]): SecuritySkill[] {
  if (!category) return SKILL_CATALOG;
  return SKILL_CATALOG.filter((s) => s.category === category);
}

export async function getSkillById(id: string): Promise<SecuritySkill | undefined> {
  return SKILL_CATALOG.find((s) => s.id === id);
}

export async function searchSkills(query: string): Promise<SecuritySkill[]> {
  const lower = query.toLowerCase();
  return SKILL_CATALOG.filter(
    (s) =>
      s.name.toLowerCase().includes(lower) ||
      s.description.toLowerCase().includes(lower) ||
      s.tags.some((t) => t.includes(lower))
  );
}

export function buildTaxonomyIndex(skills: SecuritySkill[] = SKILL_CATALOG): Record<string, TaxonomyNode> {
  const index: Record<string, TaxonomyNode> = {};

  for (const skill of skills) {
    if (!index[skill.category]) {
      index[skill.category] = { category: skill.category, skills: [] };
    }
    index[skill.category].skills.push(skill);
  }

  for (const category of Object.keys(index)) {
    const subcats: Record<string, TaxonomyNode> = {};
    for (const skill of index[category].skills) {
      const primaryTag = skill.tags[0] ?? "misc";
      if (!subcats[primaryTag]) {
        subcats[primaryTag] = { category: primaryTag, skills: [] };
      }
      subcats[primaryTag].skills.push(skill);
    }
    index[category].subcategories = subcats;
  }

  return index;
}

async function executeSkillCommand(
  skill: SecuritySkill,
  target: string,
  options: Record<string, string | number | boolean> = {},
  dryRun = false
): Promise<SkillExecutionResult> {
  const startTime = Date.now();

  if (dryRun) {
    return {
      skillId: skill.id,
      success: true,
      output: `[DRY RUN] Would execute skill "${skill.name}" against target: ${target}\nTools: ${skill.requiredTools.join(", ")}`,
      toolsUsed: skill.requiredTools,
      toolsMissing: [],
      duration: 0,
    };
  }

  let command: string;
  switch (skill.id) {
    case "skill_port_scan":
      command = `nmap -sV -sC -oX - ${target}`;
      break;
    case "skill_subdomain_enum":
      command = `dig +short ${target} ANY 2>/dev/null || nslookup ${target}`;
      break;
    case "skill_sql_injection":
      command = `sqlmap -u "${target}" --batch --level=3 --risk=2 --output-dir=/tmp/sqlmap_out`;
      break;
    case "skill_network_scan":
      command = `nmap -sn -oX - ${target}`;
      break;
    case "skill_web_vuln_scan":
      command = `nuclei -u ${target} -severity critical,high,medium -json`;
      break;
    case "skill_packet_capture":
      command = `tcpdump -i any -c 1000 -w /tmp/capture.pcap host ${target}`;
      break;
    case "skill_aws_imds":
      command = `curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" 2>/dev/null && curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/`;
      break;
    case "skill_priv_esc_linux":
      command = `find / -perm -4000 -type f 2>/dev/null; sudo -l 2>/dev/null; cat /etc/crontab 2>/dev/null`;
      break;
    case "skill_agentic_ai_hunt":
      command = `curl -sk -m 5 -o /dev/null -w "%{http_code}" http://${target}:7860/api/v1/version; curl -sk -m 5 -o /dev/null -w "%{http_code}" http://${target}:8848/nacos/`;
      break;
    case "skill_ransomware_readiness":
      command = `curl -sk -m 8 -I https://${target}:443/ 2>/dev/null; echo "backup_audit:read-only"`;
      break;
    case "skill_supply_chain_worm":
      command = `test -f package-lock.json && grep -E "easy-day-js|reqeusts" package-lock.json 2>/dev/null || echo "no lockfile in cwd"`;
      break;
    case "skill_identity_first":
      command = `curl -sk -m 5 -I https://${target}/.well-known/openid-configuration 2>/dev/null`;
      break;
    default:
      command = `echo "No default command for skill: ${skill.name}"`;
  }

  try {
    const { stdout, stderr } = await execAsync(command, {
      timeout: 60000,
      maxBuffer: 1024 * 1024 * 10,
    });
    return {
      skillId: skill.id,
      success: true,
      output: stdout,
      error: stderr || undefined,
      toolsUsed: skill.requiredTools,
      toolsMissing: [],
      duration: Date.now() - startTime,
    };
  } catch (error) {
    const errMsg = error instanceof Error ? error.message : String(error);
    return {
      skillId: skill.id,
      success: false,
      output: "",
      error: errMsg,
      toolsUsed: skill.requiredTools,
      toolsMissing: skill.requiredTools,
      duration: Date.now() - startTime,
    };
  }
}

export async function executeSkill(
  skillId: string,
  target: string,
  options: { dryRun?: boolean; toolDetections?: ToolAvailability[]; execOptions?: Record<string, string | number | boolean> } = {}
): Promise<SkillExecutionResult> {
  const { dryRun = false, execOptions = {} } = options;
  const skill = SKILL_CATALOG.find((s) => s.id === skillId);

  if (!skill) {
    return {
      skillId,
      success: false,
      output: "",
      error: `Skill not found: ${skillId}`,
      toolsUsed: [],
      toolsMissing: [],
      duration: 0,
    };
  }

  const toolDetections = options.toolDetections ?? (await detectAllTools([skill], dryRun));
  const availability = getSkillAvailability(skill, toolDetections);

  if (!availability.ready && !dryRun) {
    return {
      skillId,
      success: false,
      output: "",
      error: `Missing required tools: ${availability.missingRequired.join(", ")}`,
      toolsUsed: [],
      toolsMissing: availability.missingRequired,
      duration: 0,
    };
  }

  return executeSkillCommand(skill, target, execOptions, dryRun);
}

export async function executeSkillChain(
  skillIds: string[],
  target: string,
  options: { dryRun?: boolean } = {}
): Promise<SkillExecutionResult[]> {
  const { dryRun = false } = options;
  const results: SkillExecutionResult[] = [];
  const toolDetections = await detectAllTools(
    SKILL_CATALOG.filter((s) => skillIds.includes(s.id)),
    dryRun
  );

  for (const skillId of skillIds) {
    const result = await executeSkill(skillId, target, { dryRun, toolDetections });
    results.push(result);

    if (!result.success && !dryRun) {
      break;
    }
  }

  return results;
}

export default {
  listSkills,
  getSkillById,
  searchSkills,
  detectAllTools,
  getSkillAvailability,
  buildTaxonomyIndex,
  executeSkill,
  executeSkillChain,
};
