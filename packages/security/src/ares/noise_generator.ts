/**
 * @module noise_generator
 * Synthetic Environmental Noise & Adaptive Mimicry Generator for ARES v5.0.
 * Injects realistic synthetic log entries into pristine or low-activity target systems
 * to ensure behavioral mimicry engines never default to static temporal signatures.
 */

import * as fs from "node:fs"
import { executeLiveCommand } from "../module_helpers.ts"

export interface NoiseInjectionResult {
  injected: boolean
  entriesCount: number
  targetLogPath: string
}

export function injectSyntheticNoise(targetLogPath: string = "/var/log/auth.log"): NoiseInjectionResult {
  const syntheticEntries = [
    `CRON[${Math.floor(Math.random() * 5000) + 1000}]: (root) CMD (apt-get update --quiet)`,
    `sshd[${Math.floor(Math.random() * 5000) + 1000}]: Accepted publickey for root from 10.0.2.2 port ${Math.floor(Math.random() * 40000) + 1024} ssh2`,
    `systemd[1]: Starting Daily Cleanup of Temporary Directories...`,
    `sudo:   ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/systemctl status`
  ]

  try {
    if (!fs.existsSync(targetLogPath)) {
      // Fallback to local artifact log if system log is not writable
      const fallbackPath = "/home/ubuntu/AuditOurMine/.ourmine/artifacts/synthetic_auth.log"
      fs.mkdirSync("/home/ubuntu/AuditOurMine/.ourmine/artifacts", { recursive: true })
      const noise = syntheticEntries.join("\n") + "\n"
      fs.writeFileSync(fallbackPath, noise, "utf8")
      return { injected: true, entriesCount: syntheticEntries.length, targetLogPath: fallbackPath }
    }

    const noise = "\n" + syntheticEntries.join("\n") + "\n"
    fs.appendFileSync(targetLogPath, noise, "utf8")
    return { injected: true, entriesCount: syntheticEntries.length, targetLogPath }
  } catch (e) {
    return { injected: false, entriesCount: 0, targetLogPath }
  }
}
