/**
 * @module counter_intel
 * Counter-Intelligence & Blue Team Evasion — Honeypot & Canary Token Detector,
 * Security Analyst Process Monitoring, EDR Sensor Sandbox Detection, and Deception Technology Mapping.
 */

import { resolveDryRun } from "./exec_options.ts"
import * as fs from "node:fs";
import { execFileSync } from "node:child_process";
import { isToolAvailable } from "./tool_detection.ts";

export interface CounterIntelResult {
  honeypotDetected: boolean;
  canaryTokensFound: string[];
  blueTeamMonitoring: boolean;
  edrDetected: string[];
  sandboxIndicators: string[];
  networkMonitoring: string[];
  processAlerts: string[];
  dryRun: boolean;
  error?: string;
}

interface Finding {
  type: "canary" | "honeypot" | "edr" | "sandbox" | "network" | "process";
  name: string;
  detail: string;
}

function safeExec(command: string, args: string[] = [], timeout = 5000): string {
  try {
    return execFileSync(command, args, { timeout, encoding: "utf-8", stdio: ["pipe", "pipe", "pipe"] }).trim();
  } catch {
    return "";
  }
}

function checkRunningProcesses(): Finding[] {
  const findings: Finding[] = [];
  const edrPatterns = [
    { name: "CrowdStrike Falcon", pattern: /falcon|csfalconservice|falconagent/i },
    { name: "Carbon Black", pattern: /cbdefense|carbonblack|cb-agent|RepMgr|RepWAV|RepUtils/i },
    { name: "Symantec Endpoint Protection", pattern: /sep|ccSvcHst|SmcService|smc\.exe/i },
    { name: "McAfee ENS", pattern: /mcafee|mfetp|masvc|macmnsvc/i },
    { name: "SentinelOne", pattern: /sentinel|SentinelAgent|SentinelServiceHost/i },
    { name: "Cylance", pattern: /cylance|CylanceSvc/i },
    { name: "Sysmon", pattern: /sysmon|Sysmon\.exe|Sysmon64\.exe/i },
    { name: "osquery", pattern: /osquery/i },
    { name: "Wazuh", pattern: /wazuh|ossec|wazuh-agentd/i },
    { name: "OSSEC", pattern: /ossec/i },
    { name: "Tanium", pattern: /tanium|TaniumClient|TaniumDetect/i },
    { name: "Trellix (FireEye)", pattern: /trellix|fireeye|xagt|HXAgent/i },
    { name: "Rapid7 Insight Agent", pattern: /ir_agent|insight.agent/i },
    { name: "Qualys Cloud Agent", pattern: /qualys|qagent/i },
    { name: "Deep Security", pattern: /ds_agent|trend|dcagent/i },
    { name: "Sophos", pattern: /sophos|sophosagent|sophosfile/i },
  ];

  const psOutput = safeExec("ps", ["aux"]);
  if (!psOutput) {
    const tasklist = safeExec("tasklist", []);
    for (const ep of edrPatterns) {
      if (ep.pattern.test(tasklist)) {
        findings.push({ type: "edr", name: ep.name, detail: "Detected via tasklist" });
      }
    }
    return findings;
  }

  const lines = psOutput.split("\n").filter(Boolean);
  for (const line of lines) {
    for (const ep of edrPatterns) {
      if (ep.pattern.test(line)) {
        const alreadyFound = findings.some((f) => f.name === ep.name);
        if (!alreadyFound) {
          findings.push({ type: "edr", name: ep.name, detail: `Process: ${line.split(/\s+/)[10] || "unknown"}` });
        }
      }
    }
  }
  return findings;
}

function checkSystemdServices(): Finding[] {
  const findings: Finding[] = [];
  if (!isToolAvailable("systemctl")) return findings;

  const servicePatterns = [
    { name: "Sysmon", pattern: /sysmon/i },
    { name: "osquery", pattern: /osquery/i },
    { name: "Wazuh", pattern: /wazuh/i },
    { name: "OSSEC", pattern: /ossec/i },
    { name: "CrowdStrike", pattern: /falcon/i },
    { name: "Qualys", pattern: /qualys/i },
    { name: "Rapid7", pattern: /ir_agent/i },
  ];

  const output = safeExec("systemctl", ["list-units", "--type=service", "--all", "--no-pager"]);
  for (const sp of servicePatterns) {
    if (sp.pattern.test(output)) {
      findings.push({ type: "edr", name: sp.name, detail: "Systemd service detected" });
    }
  }
  return findings;
}

function checkHoneypots(): Finding[] {
  const findings: Finding[] = [];

  const honeypotProcesses = [
    { name: "Cowrie", pattern: /cowrie/i },
    { name: "Dionaea", pattern: /dionaea/i },
    { name: "Kippo", pattern: /kippo/i },
    { name: "Conpot", pattern: /conpot/i },
    { name: "HoneyPy", pattern: /honey.py|honey.py/i },
    { name: "Telpot", pattern: /telpot/i },
    { name: "Honeyd", pattern: /honeyd/i },
    { name: "T-Pot", pattern: /tpot/i },
    { name: "Artillery", pattern: /artillery/i },
  ];

  const psOutput = safeExec("ps", ["aux"]);
  for (const hp of honeypotProcesses) {
    if (hp.pattern.test(psOutput)) {
      findings.push({ type: "honeypot", name: hp.name, detail: "Running process detected" });
    }
  }

  const honeypotPorts = [
    { port: "2222", name: "Cowrie/Kippo SSH Honeypot" },
    { port: "2323", name: "Telnet Honeypot" },
    { port: "8080", name: "HTTP Honeypot (check)" },
    { port: "5900", name: "VNC Honeypot" },
    { port: "1433", name: "MSSQL Honeypot" },
    { port: "3306", name: "MySQL Honeypot" },
    { port: "6379", name: "Redis Honeypot" },
  ];

  const ssOutput = safeExec("ss", ["-tlnp"]);
  const netstatOutput = ssOutput || safeExec("netstat", ["-tlnp"]);
  for (const hp of honeypotPorts) {
    if (netstatOutput.includes(`:${hp.port}`)) {
      findings.push({ type: "honeypot", name: hp.name, detail: `Port ${hp.port} listening` });
    }
  }

  const honeypotFiles = [
    "/opt/cowrie",
    "/opt/dionaea",
    "/opt/kippo",
    "/opt/conpot",
    "/opt/honssh",
    "/opt/honeyd",
    "/opt/tpot",
    "/var/lib/cowrie",
  ];

  for (const hf of honeypotFiles) {
    if (fs.existsSync(hf)) {
      findings.push({ type: "honeypot", name: `Honeypot installation: ${hf}`, detail: "Directory exists" });
    }
  }

  return findings;
}

function checkCanaryTokens(): Finding[] {
  const findings: Finding[] = [];

  const canaryPaths = [
    "/tmp/canary.token",
    "/tmp/.canary",
    "/var/tmp/canary.token",
    "/dev/shm/canary",
    "/tmp/systemd-private-*.tmp",
    "C:\\canary.txt",
    "C:\\Users\\Public\\canary.txt",
    "C:\\Windows\\Temp\\canary.token",
    "%USERPROFILE%\\Documents\\report.docx",
    "%USERPROFILE%\\Downloads\\invoice.xlsx",
  ];

  for (const cp of canaryPaths) {
    try {
      if (fs.existsSync(cp)) {
        findings.push({ type: "canary", name: "File Canary Token", detail: `Found: ${cp}` });
      }
    } catch {
      // Path resolution may fail for glob patterns — ignore
    }
  }

  const envCanaryKeys = [
    "CANARYTOKEN",
    "CANARY_TOKEN",
    "HONEYTOKEN",
    "DECEPTION_TOKEN",
  ];

  for (const key of envCanaryKeys) {
    if (process.env[key]) {
      findings.push({ type: "canary", name: "Environment Canary Token", detail: `${key} is set` });
    }
  }

  return findings;
}

function checkSandboxIndicators(): Finding[] {
  const findings: Finding[] = [];

  const vmIndicators = [
    { name: "VMware Tools", file: "/usr/bin/vmtoolsd" },
    { name: "VMware Tools", file: "/usr/bin/vmware-user-suid-wrapper" },
    { name: "VirtualBox Guest Additions", file: "/usr/bin/VBoxService" },
    { name: "VirtualBox Guest Additions", file: "/usr/bin/VBoxClient" },
    { name: "QEMU Guest Agent", file: "/usr/bin/qemu-ga" },
    { name: "Hyper-V Guest", file: "/usr/bin/hv_kvp_daemon" },
    { name: "Hyper-V Guest", file: "/usr/bin/hv_vss_daemon" },
    { name: "Parallels Tools", file: "/usr/bin/prltoolsd" },
    { name: "Xen Guest", file: "/usr/sbin/xenstored" },
  ];

  for (const vi of vmIndicators) {
    try {
      if (fs.existsSync(vi.file)) {
        findings.push({ type: "sandbox", name: vi.name, detail: `Binary: ${vi.file}` });
      }
    } catch {
      // ignore
    }
  }

  const dmiPath = "/sys/class/dmi/id/sys_vendor";
  try {
    if (fs.existsSync(dmiPath)) {
      const vendor = fs.readFileSync(dmiPath, "utf-8").trim().toLowerCase();
      const vmVendors: Record<string, string> = {
        vmware: "VMware Virtual Platform",
        innotek: "VirtualBox",
        microsoft: "Microsoft Corporation (Hyper-V)",
        google: "Google Compute Engine",
        amazon: "Amazon EC2",
        xen: "Xen",
        qemu: "QEMU",
        parallels: "Parallels Software",
        oracle: "Oracle Corporation (VirtualBox)",
      };
      for (const [key, value] of Object.entries(vmVendors)) {
        if (vendor.includes(key)) {
          findings.push({ type: "sandbox", name: `VM Hypervisor`, detail: `DMI vendor: ${value}` });
        }
      }
    }
  } catch {
    // DMI not accessible
  }

  const cpuFlags = safeExec("lscpu");
  if (/Virtualization|Hypervisor|vmware|kvm|xen|hypervisor/i.test(cpuFlags)) {
    findings.push({ type: "sandbox", name: "Virtual CPU", detail: "CPU flags indicate virtualization" });
  }

  try {
    const cpuinfo = fs.readFileSync("/proc/cpuinfo", "utf-8");
    if (/vmware|virtualbox|qemu|kvm|xen|hypervisor/i.test(cpuinfo)) {
      findings.push({ type: "sandbox", name: "Virtual CPU", detail: "/proc/cpuinfo indicates virtualization" });
    }
  } catch {
    // /proc/cpuinfo not available (Windows, etc.)
  }

  const macPrefixes = [
    { prefix: "00:50:56", name: "VMware" },
    { prefix: "00:0c:29", name: "VMware" },
    { prefix: "00:1c:14", name: "VMware" },
    { prefix: "08:00:27", name: "VirtualBox" },
    { prefix: "52:54:00", name: "QEMU/KVM" },
    { prefix: "00:16:3e", name: "Xen" },
  ];

  try {
    const netOutput = safeExec("ip", ["link", "show"]);
    if (netOutput) {
      const macRegex = /link\/ether\s+([0-9a-fA-F:]{17})/g;
      let match;
      while ((match = macRegex.exec(netOutput)) !== null) {
        const mac = match[1].toLowerCase();
        for (const mp of macPrefixes) {
          if (mac.startsWith(mp.prefix)) {
            findings.push({ type: "sandbox", name: `VM MAC Address`, detail: `${mp.name} MAC: ${mac}` });
          }
        }
      }
    }
  } catch {
    // ip command not available
  }

  return findings;
}

function checkNetworkMonitoring(): Finding[] {
  const findings: Finding[] = [];

  const tcpdumpAvail = isToolAvailable("tcpdump");
  if (tcpdumpAvail) {
    const promiscCheck = safeExec("tcpdump", ["-D"]);
    if (promiscCheck) {
      const interfaces = promiscCheck.split("\n").filter(Boolean);
      for (const iface of interfaces) {
        if (/promisc/i.test(iface)) {
          findings.push({ type: "network", name: "Promiscuous Mode", detail: `Interface: ${iface.trim()}` });
        }
      }
    }
  }

  const arpOutput = safeExec("ip", ["neigh"]) || safeExec("arp", ["-a"]);
  if (arpOutput) {
    const suspiciousGateways = arpOutput.split("\n").filter((line) => {
      return /gateway|router|gw/i.test(line) && /\d+\.\d+\.\d+\.\d+/.test(line);
    });
    if (suspiciousGateways.length > 1) {
      findings.push({ type: "network", name: "Multiple Gateways", detail: `${suspiciousGateways.length} gateway entries in ARP table` });
    }
  }

  const iptablesRules = safeExec("iptables", ["-L", "-n"]);
  const hasLogging = /LOG|LOGGING|NFLOG|nflog/i.test(iptablesRules);
  const hasMirroring = /TEE|REDIRECT|PORT|RNETNS/i.test(iptablesRules);
  if (hasLogging) {
    findings.push({ type: "network", name: "Traffic Logging", detail: "iptables LOG rules detected" });
  }
  if (hasMirroring) {
    findings.push({ type: "network", name: "Traffic Mirroring", detail: "iptables TEE/REDIRECT rules detected" });
  }

  const nftablesOutput = safeExec("nft", ["list", "ruleset"]);
  if (/log|meter|limit/i.test(nftablesOutput)) {
    findings.push({ type: "network", name: "nftables Monitoring", detail: "Logging or metering rules detected" });
  }

  const tcpWrapperFiles = ["/etc/hosts.deny", "/etc/hosts.allow"];
  for (const tw of tcpWrapperFiles) {
    try {
      if (fs.existsSync(tw)) {
        const content = fs.readFileSync(tw, "utf-8");
        if (/ALL|PARANOID|SPAWN|twist/i.test(content)) {
          findings.push({ type: "network", name: "TCP Wrappers", detail: `Active restrictions in ${tw}` });
        }
      }
    } catch {
      // ignore
    }
  }

  return findings;
}


export function auditDefenses(opts: { live?: boolean; dryRun?: boolean; check?: string } = {}): CounterIntelResult {
  const dryRun = resolveDryRun(opts);

  try {
    const findings: Finding[] = [];

    // Local checks always run (real process/service enumeration)
    findings.push(...checkRunningProcesses());
    findings.push(...checkSystemdServices());
    findings.push(...checkSandboxIndicators());

    if (!dryRun) {
      findings.push(...checkHoneypots());
      findings.push(...checkCanaryTokens());
      findings.push(...checkNetworkMonitoring());
    }

    const edrDetected = findings.filter((f) => f.type === "edr").map((f) => f.name);
    const canaryTokensFound = findings.filter((f) => f.type === "canary").map((f) => f.detail);
    const honeypotsFound = findings.filter((f) => f.type === "honeypot").map((f) => f.name);
    const sandboxIndicators = findings.filter((f) => f.type === "sandbox").map((f) => f.detail);
    const networkMonitoring = findings.filter((f) => f.type === "network").map((f) => f.detail);
    const processAlerts = findings.map((f) => `[${f.type.toUpperCase()}] ${f.name}: ${f.detail}`);

    return {
      honeypotDetected: honeypotsFound.length > 0,
      canaryTokensFound,
      blueTeamMonitoring: edrDetected.length > 0,
      edrDetected: [...new Set(edrDetected)],
      sandboxIndicators,
      networkMonitoring,
      processAlerts,
      dryRun,
    };
  } catch (err) {
    return {
      honeypotDetected: false,
      canaryTokensFound: [],
      blueTeamMonitoring: false,
      edrDetected: [],
      sandboxIndicators: [],
      networkMonitoring: [],
      processAlerts: [],
      dryRun,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

/** MCP/CLI alias for auditDefenses */
export const detect = auditDefenses;

export default { auditDefenses, detect };
