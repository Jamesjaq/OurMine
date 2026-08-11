/**
 * Cross-platform PATH resolver for security tooling.
 * Uses platform-specific lookup without requiring @opencode-ai/core.
 */

import { execFileSync } from "node:child_process"
import * as fs from "node:fs"
import * as path from "node:path"

function tryPath(name: string): string | null {
  const envPath = process.env.PATH ?? process.env.Path ?? ""
  const pathExt = process.env.PATHEXT ?? process.env.PathExt ?? (process.platform === "win32" ? ".EXE;.CMD;.BAT;.COM" : "")
  const extensions = process.platform === "win32"
    ? pathExt.split(";").map((e) => e.toLowerCase())
    : [""]

  for (const dir of envPath.split(path.delimiter)) {
    if (!dir) continue
    for (const ext of extensions) {
      const candidate = path.join(dir, name + ext)
      try {
        fs.accessSync(candidate, fs.constants.X_OK)
        return candidate
      } catch {
        // continue
      }
    }
  }
  return null
}

export function which(name: string): string {
  if (process.platform === "win32") {
    try {
      const result = execFileSync("where", [name], { timeout: 5000, encoding: "utf-8", stdio: ["pipe", "pipe", "pipe"] })
      const first = result.trim().split(/\r?\n/)[0]
      if (first) return first
    } catch {
      // fall through
    }
    const found = tryPath(name)
    if (found) return found
    throw new Error(`${name} not found on PATH`)
  }

  try {
    const result = execFileSync("command", ["-v", name], {
      timeout: 5000,
      encoding: "utf-8",
      shell: "/bin/sh",
      stdio: ["pipe", "pipe", "pipe"],
    })
    const resolved = result.trim()
    if (resolved) return resolved
  } catch {
    // fall through
  }

  try {
    const result = execFileSync("which", [name], { timeout: 5000, encoding: "utf-8", stdio: ["pipe", "pipe", "pipe"] })
    const resolved = result.trim()
    if (resolved && !resolved.includes("not found")) return resolved
  } catch {
    // fall through
  }

  const found = tryPath(name)
  if (found) return found
  throw new Error(`${name} not found on PATH`)
}

export function whichOrNull(name: string): string | null {
  try {
    return which(name)
  } catch {
    return null
  }
}
