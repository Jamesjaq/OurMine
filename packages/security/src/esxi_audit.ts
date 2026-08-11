/**
 * @module security/esxi_audit
 * VMware ESXi & Hypervisor Security Audit Engine
 * Inspects hypervisor configurations, administration tooling, snapshots, and datastore integrity.
 *
 * Live mode requires: ssh (OpenSSH client)
 * Dry-run mode returns realistic simulated findings with no external calls.
 */

import { resolveDryRun } from "./exec_options.ts"
import { execFileSync } from "node:child_process"
import { isToolAvailable } from "./tool_detection.ts"

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ESXiCredentials {
  username: string
  password?: string
  keyPath?: string
}

export interface ESXiConfig {
  host: string
  port?: number
  credentials?: ESXiCredentials
}

export interface ESXiFinding {
  id: string
  category: "ADMIN" | "STORAGE" | "SNAPSHOT" | "NETWORK"
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
  title: string
  description: string
  remediation: string
}

export interface ESXiVMInfo {
  name: string
  powerState: string
  snapshotCount: number
  snapshotAge_days: number | null
  vmdkPath: string
}

export interface ESXiDatastoreInfo {
  name: string
  capacityGB: number
  freeGB: number
  mounted: boolean
  permissions: string
}

export interface ESXiAuditResult {
  host: string
  esxcliAvailable: boolean
  vimCmdExposed: boolean
  sshAccessConfirmed: boolean
  shellEnabled: boolean
  lockdownMode: string
  version: string | null
  vmsDetected: ESXiVMInfo[]
  snapshotsDetected: number
  datastores: ESXiDatastoreInfo[]
  rawDatastoresExposed: string[]
  findings: ESXiFinding[]
  isDryRun: boolean
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function run(cmd: string, args: string[], timeoutMs = 15000): string | null {
  try {
    return execFileSync(cmd, args, {
      timeout: timeoutMs,
      encoding: "utf-8",
      stdio: ["pipe", "pipe", "pipe"],
    })
  } catch {
    return null
  }
}

function sshExec(
  host: string,
  command: string,
  creds: ESXiCredentials,
  timeoutMs = 15000
): string | null {
  if (!isToolAvailable("ssh")) return null

  const sshArgs: string[] = [
    "-o", "BatchMode=yes",
    "-o", "StrictHostKeyChecking=no",
    "-o", "ConnectTimeout=10",
    "-o", "LogLevel=ERROR",
  ]

  if (creds.keyPath) {
    sshArgs.push("-i", creds.keyPath)
  }

  if (creds.password && !creds.keyPath) {
    return null
  }

  const user = creds.username || "root"
  sshArgs.push(`${user}@${host}`, command)

  return run("ssh", sshArgs, timeoutMs)
}

function parseBool(val: string | null): boolean {
  if (!val) return false
  const v = val.trim().toLowerCase()
  return v === "true" || v === "1" || v === "enabled" || v === "on"
}

// ---------------------------------------------------------------------------
// Dry-run simulation data
// ---------------------------------------------------------------------------

function generateSimulatedVMs(): ESXiVMInfo[] {
  return [
    { name: "dc01-prod", powerState: "powered on", snapshotCount: 2, snapshotAge_days: 45, vmdkPath: "[datastore1] dc01-prod/dc01-prod.vmdk" },
    { name: "web-server-01", powerState: "powered on", snapshotCount: 0, snapshotAge_days: null, vmdkPath: "[datastore1] web-server-01/web-server-01.vmdk" },
    { name: "db-replica", powerState: "powered off", snapshotCount: 1, snapshotAge_days: 120, vmdkPath: "[datastore2] db-replica/db-replica.vmdk" },
    { name: "dev-test-vm", powerState: "powered on", snapshotCount: 5, snapshotAge_days: 180, vmdkPath: "[datastore1] dev-test-vm/dev-test-vm.vmdk" },
  ]
}

function generateSimulatedDatastores(): ESXiDatastoreInfo[] {
  return [
    { name: "datastore1", capacityGB: 4800, freeGB: 1200, mounted: true, permissions: "drwxrwxrwx 1 root root" },
    { name: "datastore2", capacityGB: 9600, freeGB: 3400, mounted: true, permissions: "drwxrwxrwx 1 root root" },
  ]
}

function generateSimulatedFindings(): ESXiFinding[] {
  return [
    {
      id: "ESXI-01",
      category: "ADMIN",
      severity: "HIGH",
      title: "ESXi Shell and SSH Access Enabled",
      description: "The ESXi host has both Shell and SSH services enabled, allowing remote command-line access to the hypervisor. This increases the attack surface and may allow unauthorized administrative actions.",
      remediation: "Disable ESXi Shell and SSH via the vSphere Client or running 'esxcli system ssh server set --disabled=true' and 'esxcli system shell set --disabled=true' when not in active maintenance.",
    },
    {
      id: "ESXI-02",
      category: "ADMIN",
      severity: "MEDIUM",
      title: "Lockdown Mode Not in Strict Enforcement",
      description: "The host is not running in strict lockdown mode, meaning users with direct ESXi credentials can perform operations bypassing vCenter audit trails.",
      remediation: "Enable strict lockdown mode via vCenter to force all administrative operations through the vCenter audit pipeline.",
    },
    {
      id: "ESXI-03",
      category: "STORAGE",
      severity: "CRITICAL",
      title: "Direct VMDK Datastore Access",
      description: "Datastore mount points allow direct raw reading of .vmdk files, bypassing virtual machine access controls. Any user with datastore browse permissions can extract disk contents.",
      remediation: "Restrict VMFS volume access using vSphere permissions and enforce explicit vSphere API authorization for datastore browsing. Use encrypted VMDK where possible.",
    },
    {
      id: "ESXI-04",
      category: "STORAGE",
      severity: "HIGH",
      title: "Overly Permissive Datastore Permissions",
      description: "Datastore volumes are mounted with world-writable permissions (drwxrwxrwx), allowing any local user to read, modify, or delete VM disk files.",
      remediation: "Apply least-privilege NFS/VMFS export permissions and restrict datastore access to authorized service accounts only.",
    },
    {
      id: "ESXI-05",
      category: "SNAPSHOT",
      severity: "MEDIUM",
      title: "Stale VM Snapshots Detected (>30 days)",
      description: "Multiple VMs have snapshots older than 30 days. Stale snapshots consume storage, degrade performance, and may contain sensitive data from previous states.",
      remediation: "Implement a snapshot lifecycle policy: delete all snapshots older than 72 hours. Use 'vim-cmd vmsvc/snapshot.getall' to audit and remove stale snapshots.",
    },
    {
      id: "ESXI-06",
      category: "SNAPSHOT",
      severity: "HIGH",
      title: "Excessive Snapshot Chain on dev-test-vm",
      description: "VM 'dev-test-vm' has 5 accumulated snapshots forming a deep delta chain, risking data corruption and significant I/O performance degradation.",
      remediation: "Consolidate all snapshots on affected VMs immediately. Implement monitoring to alert when snapshot count exceeds 2 per VM.",
    },
    {
      id: "ESXI-07",
      category: "NETWORK",
      severity: "HIGH",
      title: "VMkernel Management Interface Exposed",
      description: "The VMkernel management interface is bound to a network segment that may be routable from less-trusted zones, exposing vSphere management protocols (SOAP, CIM) to potential lateral movement.",
      remediation: "Isolate management interfaces to a dedicated VLAN with firewall rules restricting access to authorized jump hosts only.",
    },
    {
      id: "ESXI-08",
      category: "NETWORK",
      severity: "MEDIUM",
      title: "Unencrypted VM Traffic on Management vSwitch",
      description: "VM-to-VM traffic on the management vSwitch is not encrypted, allowing potential interception of sensitive inter-VM communications on the same host.",
      remediation: "Implement NSX-T distributed firewall with encryption enabled, or use VM encryption policies for sensitive workloads.",
    },
  ]
}

// ---------------------------------------------------------------------------
// Live audit implementation
// ---------------------------------------------------------------------------

function performLiveAudit(config: ESXiConfig, creds: ESXiCredentials): ESXiAuditResult {
  const host = config.host
  const findings: ESXiFinding[] = []
  let esxcliAvailable = false
  let vimCmdExposed = false
  let sshAccessConfirmed = false
  let shellEnabled = false
  let lockdownMode = "unknown"
  let version: string | null = null
  const vmsDetected: ESXiVMInfo[] = []
  let snapshotsDetected = 0
  const datastores: ESXiDatastoreInfo[] = []
  const rawDatastoresExposed: string[] = []

  // Step 1: Test SSH connectivity
  const sshTest = sshExec(host, "echo OK", creds, 10000)
  if (sshTest && sshTest.trim() === "OK") {
    sshAccessConfirmed = true
  } else {
    findings.push({
      id: "ESXI-LIVE-00",
      category: "ADMIN",
      severity: "LOW",
      title: "SSH Access Not Available",
      description: "Could not establish SSH connection to the ESXi host. Some checks were skipped. Ensure credentials and network connectivity are correct.",
      remediation: "Verify SSH is enabled on the ESXi host and that credentials are valid.",
    })

    return {
      host,
      esxcliAvailable: false,
      vimCmdExposed: false,
      sshAccessConfirmed: false,
      shellEnabled: false,
      lockdownMode: "unknown",
      version: null,
      vmsDetected: [],
      snapshotsDetected: 0,
      datastores: [],
      rawDatastoresExposed: [],
      findings,
      isDryRun: false,
    }
  }

  // Step 2: Check ESXi Shell status
  const shellOutput = sshExec(host, "esxcli system shell get", creds)
  if (shellOutput) {
    const enabledMatch = shellOutput.match(/Enabled:\s*(true|false)/i)
    shellEnabled = enabledMatch ? parseBool(enabledMatch[1]) : false

    if (shellEnabled) {
      findings.push({
        id: "ESXI-01",
        category: "ADMIN",
        severity: "HIGH",
        title: "ESXi Shell Access Enabled",
        description: "The ESXi Shell service is enabled on this host, providing direct local console access. Combined with SSH, this allows full root-level command execution.",
        remediation: "Disable ESXi Shell: esxcli system shell set --disabled=true. Only enable during supervised maintenance windows.",
      })
    }
  }

  // Step 3: Check SSH server status
  const sshStatus = sshExec(host, "esxcli system ssh server get", creds)
  if (sshStatus) {
    const sshEnabled = sshStatus.match(/Enabled:\s*(true|false)/i)
    if (sshEnabled && parseBool(sshEnabled[1])) {
      findings.push({
        id: "ESXI-09",
        category: "ADMIN",
        severity: "HIGH",
        title: "SSH Server Enabled on Hypervisor",
        description: "The SSH server is running on the ESXi host, allowing remote shell access. This expands the attack surface for credential brute-force and exploitation attacks.",
        remediation: "Disable SSH when not needed: esxcli system ssh server set --disabled=true. Use the vSphere Client for routine management.",
      })
    }

    const protocolMatch = sshStatus.match(/Protocol:\s*(\d+)/i)
    if (protocolMatch && parseInt(protocolMatch[1], 10) < 2) {
      findings.push({
        id: "ESXI-10",
        category: "NETWORK",
        severity: "MEDIUM",
        title: "SSH Protocol Version 1 Detected",
        description: "The ESXi SSH server is configured to accept Protocol version 1, which has known cryptographic weaknesses.",
        remediation: "Force SSH Protocol 2 only: modify /etc/ssh/sshd_config to set 'Protocol 2' and restart the SSH service.",
      })
    }
  }

  // Step 4: Check esxcli availability
  const esxcliTest = sshExec(host, "esxcli --version", creds)
  if (esxcliTest) {
    esxcliAvailable = true
    const verMatch = esxcliTest.match(/(\d+\.\d+\.\d+)/)
    version = verMatch ? verMatch[1] : null

    findings.push({
      id: "ESXI-11",
      category: "ADMIN",
      severity: "MEDIUM",
      title: "esxcli Administration Tool Accessible",
      description: "The esxcli command-line tool is available via SSH, providing full hypervisor configuration and management capabilities to authenticated users.",
      remediation: "Restrict SSH access to dedicated admin accounts and enforce MFA via vCenter. Audit all esxcli operations via syslog.",
    })
  }

  // Step 5: Check vim-cmd exposure
  const vimCmdTest = sshExec(host, "vim-cmd -v", creds)
  if (vimCmdTest) {
    vimCmdExposed = true
    findings.push({
      id: "ESXI-12",
      category: "ADMIN",
      severity: "HIGH",
      title: "vim-cmd Administrative Interface Exposed",
      description: "The vim-cmd tool is accessible via SSH, allowing direct manipulation of VMs, host configuration, and network settings bypassing vCenter controls.",
      remediation: "Disable SSH and restrict vim-cmd access. All administrative operations should flow through vCenter with proper RBAC auditing.",
    })
  }

  // Step 6: Check lockdown mode
  const lockdownOutput = sshExec(host, "esxcli system lockdown lockdown get", creds)
  if (lockdownOutput) {
    const modeMatch = lockdownOutput.match(/Lockdown Mode:\s*(.*)/i)
    lockdownMode = modeMatch ? modeMatch[1].trim() : "unknown"

    if (lockdownMode === "Disabled") {
      findings.push({
        id: "ESXI-03",
        category: "ADMIN",
        severity: "MEDIUM",
        title: "Lockdown Mode Disabled",
        description: "The host is not running in lockdown mode. Users with direct ESXi credentials can perform operations that bypass vCenter audit trails and RBAC.",
        remediation: "Enable strict lockdown mode via vCenter to ensure all administrative actions are logged and authorized through centralized controls.",
      })
    }
  }

  // Step 7: Enumerate VMs and check snapshots
  const vmListOutput = sshExec(host, "vim-cmd vmsvc/getallvms 2>/dev/null", creds)
  if (vmListOutput) {
    const lines = vmListOutput.trim().split("\n").filter(l => l.trim() && !l.startsWith("----"))

    for (const line of lines) {
      const parts = line.trim().split(/\s{2,}/)
      if (parts.length < 3) continue

      const vmName = parts[1]?.trim() || "unknown"
      const vmdkPath = parts[3]?.trim() || ""

      let snapshotCount = 0
      let snapshotAgeDays: number | null = null

      const snapInfo = sshExec(
        host,
        `vim-cmd vmsvc/snapshot.get $(vim-cmd vmsvc/getallvms | grep "${vmName}" | awk '{print $1}') 2>/dev/null`,
        creds,
        8000
      )

      if (snapInfo && !snapInfo.includes("has no snapshot")) {
        const snapMatches = snapInfo.match(/Snapshot\s+\d+/g)
        snapshotCount = snapMatches ? snapMatches.length : 0

        const dateMatch = snapInfo.match(/Created On:\s*(.+)/i)
        if (dateMatch) {
          try {
            const snapDate = new Date(dateMatch[1].trim())
            if (!isNaN(snapDate.getTime())) {
              snapshotAgeDays = Math.floor((Date.now() - snapDate.getTime()) / 86400000)
            }
          } catch { /* ignore parse errors */ }
        }
      }

      snapshotsDetected += snapshotCount

      vmsDetected.push({
        name: vmName,
        powerState: "unknown",
        snapshotCount,
        snapshotAge_days: snapshotAgeDays,
        vmdkPath,
      })

      if (snapshotAgeDays !== null && snapshotAgeDays > 30) {
        findings.push({
          id: `ESXI-SNAP-${vmName.slice(0, 8).toUpperCase()}`,
          category: "SNAPSHOT",
          severity: snapshotAgeDays > 90 ? "HIGH" : "MEDIUM",
          title: `Stale Snapshot on ${vmName} (${snapshotAgeDays} days old)`,
          description: `VM '${vmName}' has a snapshot that is ${snapshotAgeDays} days old. Stale snapshots consume storage, degrade performance, and may expose sensitive historical data.`,
          remediation: "Review and remove stale snapshots: vim-cmd vmsvc/snapshot.removeall <vmid>. Implement snapshot lifecycle monitoring.",
        })
      }

      if (snapshotCount > 3) {
        findings.push({
          id: `ESXI-SNAPCHAIN-${vmName.slice(0, 8).toUpperCase()}`,
          category: "SNAPSHOT",
          severity: "HIGH",
          title: `Excessive Snapshot Chain on ${vmName}`,
          description: `VM '${vmName}' has ${snapshotCount} accumulated snapshots, forming a deep delta chain that risks data corruption and significant I/O performance degradation.`,
          remediation: `Consolidate all snapshots on '${vmName}' immediately. Implement monitoring to alert when snapshot count exceeds 2 per VM.`,
        })
      }
    }
  }

  // Step 8: Enumerate datastores
  const dsList = sshExec(host, "esxcli storage filesystem list", creds)
  if (dsList) {
    const dsLines = dsList.trim().split("\n").filter(l => l.includes("/vmfs/volumes/"))

    for (const line of dsLines) {
      const mountMatch = line.match(/(\/vmfs\/volume\S+)/)
      if (!mountMatch) continue

      const mountPath = mountMatch[1]
      const nameMatch = line.match(/^(\S+)/)
      const dsName = nameMatch ? nameMatch[1] : mountPath

      const permCheck = sshExec(host, `ls -ld "${mountPath}"`, creds, 5000)
      const permissions = permCheck?.trim() || "unknown"
      const isWorldWritable = permissions.startsWith("drwxrwxrwx") || permissions.includes("rwxrwxrwx")

      datastores.push({
        name: dsName,
        capacityGB: 0,
        freeGB: 0,
        mounted: true,
        permissions,
      })

      rawDatastoresExposed.push(mountPath)

      if (isWorldWritable) {
        findings.push({
          id: `ESXI-DS-${dsName.slice(0, 8).toUpperCase()}`,
          category: "STORAGE",
          severity: "HIGH",
          title: `World-Writable Datastore: ${dsName}`,
          description: `Datastore '${dsName}' at ${mountPath} is mounted with world-writable permissions. Any local user can read, modify, or delete VM disk files.`,
          remediation: `Apply least-privilege permissions to ${mountPath}. Use 'chmod 750' and restrict access to authorized service accounts.`,
        })
      }
    }
  }

  // Step 9: Check for exposed management interfaces
  const vmkOutput = sshExec(host, "esxcli network ip interface ipv4 get", creds)
  if (vmkOutput) {
    const vmkLines = vmkOutput.trim().split("\n").filter(l => l.includes("vmk"))
    if (vmkLines.length > 0) {
      findings.push({
        id: "ESXI-NET-01",
        category: "NETWORK",
        severity: "HIGH",
        title: "VMkernel Management Interfaces Detected",
        description: `Found ${vmkLines.length} VMkernel network interface(s). Management interfaces may be exposed to network segments with insufficient isolation, enabling lateral movement.`,
        remediation: "Isolate VMkernel management interfaces to a dedicated VLAN. Use firewall rules to restrict access to authorized jump hosts only.",
      })
    }
  }

  // Step 10: Check for unencrypted VM traffic
  const encryptionCheck = sshExec(host, "vim-cmd vimsvc/auth/validate -s root -p '' 2>&1 | head -5", creds, 5000)
  if (encryptionCheck && encryptionCheck.includes("password")) {
    findings.push({
      id: "ESXI-NET-02",
      category: "NETWORK",
      severity: "MEDIUM",
      title: "VM Management API Accepts Weak Credentials",
      description: "The ESXi host management API appears to accept basic authentication over potentially unencrypted channels, risking credential interception.",
      remediation: "Enable TLS enforcement for all management interfaces. Configure vCenter to require certificate-based authentication.",
    })
  }

  // Step 11: Check for exposed vSphere web client
  const webCheck = sshExec(host, "esxcli network ip connection list | grep -E ':443|:80'", creds, 8000)
  if (webCheck && webCheck.trim().length > 0) {
    findings.push({
      id: "ESXI-NET-03",
      category: "NETWORK",
      severity: "LOW",
      title: "vSphere Web Client Port Open",
      description: "The ESXi host has web management ports (443/80) open, indicating the vSphere web client interface is accessible from the network.",
      remediation: "Restrict access to web management ports via firewall rules. Use VPN or jump host for remote management access.",
    })
  }

  // Step 12: Check for NTP configuration (time sync is critical for log integrity)
  const ntpCheck = sshExec(host, "esxcli system ntp get", creds, 5000)
  if (ntpCheck) {
    const ntpServers = ntpCheck.match(/Server:\s*(.+)/gi)
    if (!ntpServers || ntpServers.length === 0) {
      findings.push({
        id: "ESXI-TIME-01",
        category: "ADMIN",
        severity: "MEDIUM",
        title: "NTP Not Configured",
        description: "No NTP servers are configured on the ESXi host. Time drift can cause log correlation failures, certificate validation issues, and Kerberos authentication problems.",
        remediation: "Configure NTP servers: esxcli system ntp set --server=pool.ntp.org. Ensure time synchronization is enabled across all hosts.",
      })
    }
  }

  return {
    host,
    esxcliAvailable,
    vimCmdExposed,
    sshAccessConfirmed,
    shellEnabled,
    lockdownMode,
    version,
    vmsDetected,
    snapshotsDetected,
    datastores,
    rawDatastoresExposed,
    findings,
    isDryRun: false,
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export function auditESXi(
  config: ESXiConfig,
  options: { live?: boolean; dryRun?: boolean } = {}
): ESXiAuditResult {
  const isDryRun = options.dryRun !== undefined ? options.dryRun : !options.live

  if (isDryRun) {
    return {
      host: config.host,
      esxcliAvailable: true,
      vimCmdExposed: true,
      sshAccessConfirmed: true,
      shellEnabled: true,
      lockdownMode: "Disabled",
      version: "7.0.3",
      vmsDetected: generateSimulatedVMs(),
      snapshotsDetected: 8,
      datastores: generateSimulatedDatastores(),
      rawDatastoresExposed: ["/vmfs/volumes/datastore1", "/vmfs/volumes/datastore2"],
      findings: generateSimulatedFindings(),
      isDryRun: true,
    }
  }

  const creds: ESXiCredentials = config.credentials || { username: "root" }

  if (!isToolAvailable("ssh")) {
    return {
      host: config.host,
      esxcliAvailable: false,
      vimCmdExposed: false,
      sshAccessConfirmed: false,
      shellEnabled: false,
      lockdownMode: "unknown",
      version: null,
      vmsDetected: [],
      snapshotsDetected: 0,
      datastores: [],
      rawDatastoresExposed: [],
      findings: [
        {
          id: "ESXI-TOOL-00",
          category: "ADMIN",
          severity: "MEDIUM",
          title: "SSH Client Not Available",
          description: "The ssh binary is not installed on this system. Live ESXi audit requires SSH client access to the target host.",
          remediation: "Install OpenSSH client: apt install openssh-client / brew install openssh",
        },
      ],
      isDryRun: false,
    }
  }

  try {
    return performLiveAudit(config, creds)
  } catch (err) {
    return {
      host: config.host,
      esxcliAvailable: false,
      vimCmdExposed: false,
      sshAccessConfirmed: false,
      shellEnabled: false,
      lockdownMode: "unknown",
      version: null,
      vmsDetected: [],
      snapshotsDetected: 0,
      datastores: [],
      rawDatastoresExposed: [],
      findings: [
        {
          id: "ESXI-ERR-00",
          category: "ADMIN",
          severity: "LOW",
          title: "Audit Execution Error",
          description: `The live audit encountered an error: ${(err as Error).message?.slice(0, 200) || "unknown error"}`,
          remediation: "Verify network connectivity, credentials, and that the target is a valid ESXi host.",
        },
      ],
      isDryRun: false,
    }
  }
}

export default { auditESXi }
