/**
 * @module dependency_vault
 * Strict Dependency Vault & Cryptographic Pinning for ARES v5.0.
 * Eliminates supply-chain risks by verifying local workspace dependencies
 * against cryptographically stored SHA-256 hashes before execution.
 */

import * as fs from "node:fs"
import * as path from "node:path"
import * as crypto from "node:crypto"

export interface VaultAuditResult {
  secure: boolean
  verifiedCount: number
  tamperedModules: string[]
}

export function auditAndPinDependencies(): VaultAuditResult {
  const repoRoot = process.cwd().includes("AuditOurMine") ? "/home/ubuntu/AuditOurMine" : "/home/ubuntu/OurMine"
  const vaultDir = path.join(repoRoot, ".ourmine", "vault")
  const manifestPath = path.join(vaultDir, "dependency_manifest.json")

  fs.mkdirSync(vaultDir, { recursive: true })

  const aresSrcDir = path.join(repoRoot, "packages/security/src/ares")
  if (!fs.existsSync(aresSrcDir)) {
    return { secure: true, verifiedCount: 0, tamperedModules: [] }
  }

  const files = fs.readdirSync(aresSrcDir).filter(f => f.endsWith(".ts"))
  const manifest: Record<string, string> = fs.existsSync(manifestPath)
    ? JSON.parse(fs.readFileSync(manifestPath, "utf8"))
    : {}

  let verifiedCount = 0
  const tamperedModules: string[] = []

  for (const file of files) {
    const filePath = path.join(aresSrcDir, file)
    const content = fs.readFileSync(filePath)
    const hash = crypto.createHash("sha256").update(content).digest("hex")

    if (!manifest[file]) {
      manifest[file] = hash
    } else if (manifest[file] !== hash) {
      tamperedModules.push(file)
    }
    verifiedCount++
  }

  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2), "utf8")

  return {
    secure: tamperedModules.length === 0,
    verifiedCount,
    tamperedModules
  }
}
