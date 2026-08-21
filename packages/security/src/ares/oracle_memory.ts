/**
 * @module ares/oracle_memory
 * ARES v5.0 'Singularity Protocol' — Encrypted Ephemeral Memory Sharding.
 * Provides a forensic-resistant strategic memory layer using AES-256-GCM 
 * and distributed sharding in /dev/shm (RAM disk).
 */
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import { liveRequired } from "./_base.ts";

const MEMORY_ROOT = "/dev/shm/.ares_oracle_cache";
const SHARD_COUNT = 8;
const ALGORITHM = "aes-256-gcm";

export interface OracleState {
  missionId: string;
  heuristics: Record<string, any>;
  tacticalPatterns: string[];
  lastUpdate: number;
}

export class OracleMemory {
  private masterKey: Buffer;

  constructor() {
    // ARES v5.0: Use a persistent but hidden key for Singularity Protocol memory recovery
    const keyPath = path.join(process.cwd(), ".ourmine", ".vault_key");
    if (fs.existsSync(keyPath)) {
      this.masterKey = fs.readFileSync(keyPath);
    } else {
      this.masterKey = crypto.randomBytes(32);
      fs.mkdirSync(path.dirname(keyPath), { recursive: true });
      fs.writeFileSync(keyPath, this.masterKey, { mode: 0o600 });
    }
    this.initializeStorage();
  }

  private initializeStorage() {
    if (!fs.existsSync(MEMORY_ROOT)) {
      fs.mkdirSync(MEMORY_ROOT, { recursive: true, mode: 0o700 });
    }
  }

  /**
   * Shards and encrypts the state, then writes to ephemeral storage.
   */
  async commit(state: OracleState): Promise<void> {
    const data = Buffer.from(JSON.stringify(state));
    const shardSize = Math.ceil(data.length / SHARD_COUNT);

    for (let i = 0; i < SHARD_COUNT; i++) {
      const shardData = data.subarray(i * shardSize, (i + 1) * shardSize);
      if (shardData.length === 0) break;

      const iv = crypto.randomBytes(12);
      const cipher = crypto.createCipheriv(ALGORITHM, this.masterKey, iv);
      const encrypted = Buffer.concat([cipher.update(shardData), cipher.final()]);
      const tag = cipher.getAuthTag();

      const payload = Buffer.concat([iv, tag, encrypted]);
      fs.writeFileSync(path.join(MEMORY_ROOT, `shard_${i}.bin`), payload);
    }
  }

  /**
   * Reconstructs the state from encrypted shards.
   */
  async recall(): Promise<OracleState | null> {
    try {
      let fullData = Buffer.alloc(0);

      for (let i = 0; i < SHARD_COUNT; i++) {
        const shardPath = path.join(MEMORY_ROOT, `shard_${i}.bin`);
        if (!fs.existsSync(shardPath)) break;

        const payload = fs.readFileSync(shardPath);
        const iv = payload.subarray(0, 12);
        const tag = payload.subarray(12, 28);
        const encrypted = payload.subarray(28);

        const decipher = crypto.createDecipheriv(ALGORITHM, this.masterKey, iv);
        decipher.setAuthTag(tag);
        const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
        fullData = Buffer.concat([fullData, decrypted]);
      }

      return JSON.parse(fullData.toString());
    } catch (error) {
      return null;
    }
  }

  /**
   * Post-Operation Liquidation Protocol (POLP) - Zero-trace cleanup.
   */
  purge() {
    if (fs.existsSync(MEMORY_ROOT)) {
      const files = fs.readdirSync(MEMORY_ROOT);
      for (const file of files) {
        const filePath = path.join(MEMORY_ROOT, file);
        // Overwrite with random data before deletion for forensic resistance
        const size = fs.statSync(filePath).size;
        fs.writeFileSync(filePath, crypto.randomBytes(size));
        fs.unlinkSync(filePath);
      }
      fs.rmdirSync(MEMORY_ROOT);
    }
    this.masterKey.fill(0); // Wipe key from process memory
  }
}

export async function runOracleMemory(opts: { action: "commit" | "recall" | "purge", state?: OracleState }, env: { live: boolean }) {
  liveRequired("ares_oracle_memory", env);
  const oracle = new OracleMemory();

  if (opts.action === "commit" && opts.state) {
    await oracle.commit(opts.state);
    return { status: "COMMITTED", shards: SHARD_COUNT };
  } else if (opts.action === "recall") {
    const state = await oracle.recall();
    return { status: "RECALLED", state };
  } else if (opts.action === "purge") {
    oracle.purge();
    return { status: "PURGED" };
  }
  
  return { status: "NO_ACTION" };
}
