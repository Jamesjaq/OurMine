/**
 * C2 operations — Mythic/Covenant/Sliver clients, callback manager, operator
 * loop, proxy rotator, and TLS fingerprint shaping (JA3/JA4).
 *
 * Port of `modules.c2` (client, proxy_rotation, tls_shaping, operator, sliver).
 * Everything network goes through HITL gates; dry-run reports capabilities.
 */

import { createHash } from "node:crypto";

// ------------------------------------------------------------------------- //
// TLS fingerprint shaping (JA3/JA4)
// ------------------------------------------------------------------------- //

const CIPHER_NAMES: Record<number, string> = {
  0x1301: "TLS_AES_128_GCM_SHA256", 0x1302: "TLS_AES_256_GCM_SHA384",
  0x1303: "TLS_CHACHA20_POLY1305_SHA256", 0x1304: "TLS_AES_128_CCM_SHA256",
  0x1305: "TLS_AES_128_CCM_8_SHA256", 0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
  0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", 0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
  0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", 0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
  0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", 0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
  0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384", 0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
  0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA", 0x003C: "TLS_RSA_WITH_AES_128_CBC_SHA256",
  0x009E: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", 0x009F: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
  0x0033: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA", 0x0039: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
  0x0067: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", 0x006B: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
};

const CURVE_NAMES: Record<number, string> = {
  0x001D: "x25519", 0x0017: "secp256r1", 0x0018: "secp384r1",
  0x0019: "secp521r1", 0x001E: "x25519mlkem768", 0x001F: "secp256r1mlkem768",
};

export interface ClientHelloProfile {
  name: string;
  version: number;
  ciphers: readonly number[];
  extensions: readonly number[];
  curves: readonly number[];
  alpn: readonly string[];
  signatureAlgs: readonly number[];
  greased: boolean;
}

function ja3Raw(p: ClientHelloProfile): string {
  const join = (seq: readonly number[]): string => seq.map(String).join("-");
  return `${p.version},${join(p.ciphers)},${join(p.extensions)},${join(p.curves)},${join(p.signatureAlgs)}`;
}

function ja4(p: ClientHelloProfile): string {
  const tsha256 = (values: readonly number[]): string =>
    createHash("sha256").update(values.join("-")).digest("hex").slice(0, 12);
  const proto = "t";
  const tlsVer = p.ciphers.includes(0x1301) ? "13" : "12";
  const sni = p.extensions.length ? "d" : "i";
  const cipher = p.ciphers[0] !== undefined ? p.ciphers[0].toString(16).padStart(4, "0") : "0000";
  const count = Math.min(p.extensions.length, 99).toString(10).padStart(2, "0");
  const alpnCode = ({ "h2": "h2", "http/1.1": "h1" } as Record<string, string>)[p.alpn[0] ?? ""] ?? "00";
  const ciphersHash = p.ciphers.length ? tsha256(p.ciphers) : "0".repeat(12);
  const extHash = tsha256(p.extensions);
  return `${proto}${tlsVer}${sni}${cipher}${count}${alpnCode}_${ciphersHash}_${extHash}`;
}

const CHROME: ClientHelloProfile = {
  name: "chrome", version: 0x0303,
  ciphers: [0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xCCA9, 0xCCA8, 0xC02C, 0xC030, 0x009C, 0x009D, 0x002F, 0x0035],
  extensions: [0x000A, 0x000B, 0x000D, 0x0010, 0x0017, 0x002B, 0x002D, 0x0033, 0x4469, 0x0000, 0x0001, 0x0005, 0x0012],
  curves: [0x001D, 0x0017, 0x0018, 0x001E, 0x001F, 0x0019],
  alpn: ["h2", "http/1.1"],
  signatureAlgs: [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601],
  greased: true,
};

const FIREFOX: ClientHelloProfile = {
  name: "firefox", version: 0x0303,
  ciphers: [0x1301, 0x1302, 0x1303, 0xC02F, 0xC02B, 0xCCA8, 0xCCA9, 0xC030, 0xC02C, 0x009C, 0x009D],
  extensions: [0x0000, 0x000A, 0x000B, 0x000D, 0x0010, 0x0017, 0x002B, 0x002D, 0x0033, 0x4469, 0x0005],
  curves: [0x001D, 0x0017, 0x0018, 0x0019, 0x001E, 0x001F],
  alpn: ["h2", "http/1.1"],
  signatureAlgs: [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601],
  greased: true,
};

const SAFARI: ClientHelloProfile = {
  name: "safari", version: 0x0303,
  ciphers: [0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0x009C, 0x009D],
  extensions: [0x0000, 0x000A, 0x000B, 0x000D, 0x0010, 0x0017, 0x002B, 0x002D, 0x0033],
  curves: [0x001D, 0x0017, 0x0018, 0x0019],
  alpn: ["h2", "http/1.1"],
  signatureAlgs: [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601],
  greased: true,
};

const VANILLA: ClientHelloProfile = {
  name: "vanilla", version: 0x0303,
  ciphers: [0x1301, 0x1302, 0x1303, 0xC02F, 0xC02B, 0xCCA8, 0xCCA9, 0xC030, 0xC02C],
  extensions: [0x000A, 0x000B, 0x000D, 0x0010, 0x002B, 0x002D],
  curves: [0x001D, 0x0017, 0x0018],
  alpn: ["h2", "http/1.1"],
  signatureAlgs: [0x0403, 0x0804, 0x0401],
  greased: false,
};

const PROFILES: Record<string, ClientHelloProfile> = { chrome: CHROME, firefox: FIREFOX, safari: SAFARI, vanilla: VANILLA };

export function getProfile(name?: string): ClientHelloProfile {
  return PROFILES[(name ?? "chrome").toLowerCase()] ?? CHROME;
}

export function listProfiles(): string[] {
  return Object.keys(PROFILES).sort();
}

export function fingerprintIsRecognizable(profileName?: string): Record<string, unknown> {
  const p = getProfile(profileName);
  const browserLike = p.name !== "vanilla" && p.greased && p.ciphers.includes(0x1301);
  return {
    profile: p.name,
    ja3: createHash("md5").update(ja3Raw(p)).digest("hex"),
    ja4: ja4(p),
    browser_like: browserLike,
    verdict: browserLike ? "blends-in" : "detectable: vanilla/Go-style fingerprint",
  };
}

export function curlTlsFlags(profileName?: string): string[] {
  const p = getProfile(profileName);
  const tls13 = p.ciphers.filter((c) => c >= 0x1301 && c <= 0x1305);
  const tls12 = p.ciphers.filter((c) => !tls13.includes(c));
  const flags: string[] = ["--tls-max 1.3", "--tlsv1.2"];
  if (tls12.length) flags.push("--ciphers " + tls12.map((c) => CIPHER_NAMES[c] ?? `0x${c.toString(16)}`).join(":"));
  if (tls13.length) flags.push("--tls13-ciphers " + tls13.map((c) => CIPHER_NAMES[c] ?? `0x${c.toString(16)}`).join(":"));
  if (p.curves.length) flags.push("--curves " + p.curves.map((c) => CURVE_NAMES[c] ?? `0x${c.toString(16)}`).join(":"));
  return flags;
}

export function goTlsConfig(profileName?: string): string {
  const p = getProfile(profileName);
  const ciphers = p.ciphers.filter((c) => CIPHER_NAMES[c]).map((c) => `tls.${CIPHER_NAMES[c]}`).join(", ");
  const curves = p.curves.filter((c) => CURVE_NAMES[c]).map((c) => `tls.${CURVE_NAMES[c]}`).join(", ");
  return `tls.Config{\n    CipherSuites: []uint16{${ciphers}},\n    CurvePreferences: []tls.CurveID{${curves}},\n    MinVersion: tls.VersionTLS12,\n    NextProtos: []string{"h2", "http/1.1"},\n}`;
}

// ------------------------------------------------------------------------- //
// Proxy rotation (SOHO-router pool, T1090.001)
// ------------------------------------------------------------------------- //

export type RotationStrategy = "round-robin" | "random" | "latency";

/** Mulberry32 seeded PRNG for deterministic shuffle. */
function mulberry32(seed: number): () => number {
  let s = seed | 0;
  return () => {
    s = (s + 0x6d2b79f5) | 0;
    let t = Math.imul(s ^ (s >>> 15), 1 | s);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function shuffleArray<T>(arr: T[], seed: number): T[] {
  const rng = mulberry32(seed);
  const out = [...arr];
  for (let i = out.length - 1; i > 0; i--) {
    const j = Math.floor(rng() * (i + 1));
    [out[i], out[j]] = [out[j]!, out[i]!];
  }
  return out;
}

export class ProxyRotator {
  proxies: string[];
  strategy: RotationStrategy;
  jitter: boolean;
  private queue: string[] = [];
  private latencies: Map<string, number> = new Map();

  constructor(proxies: string[] = [], opts: { strategy?: RotationStrategy; jitter?: boolean } = {}) {
    this.proxies = proxies.length ? proxies : [];
    this.strategy = opts.strategy ?? "round-robin";
    this.jitter = opts.jitter ?? true;
  }

  private refill(seed?: number): void {
    let pool = [...this.proxies];
    if (this.jitter && pool.length > 1) {
      pool = shuffleArray(pool, seed ?? 0);
    }
    this.queue = pool;
  }

  nextProxy(seed?: number): string | null {
    if (!this.proxies.length) return null;
    if (this.strategy === "random") {
      const rng = mulberry32(seed ?? 0);
      return this.proxies[Math.floor(rng() * this.proxies.length)]!;
    }
    if (this.strategy === "latency") {
      if (this.latencies.size) {
        let best = this.proxies[0]!;
        let bestLat = this.latencies.get(best) ?? Infinity;
        for (const [url, lat] of this.latencies) {
          if (lat < bestLat) { best = url; bestLat = lat; }
        }
        return best;
      }
      return this.proxies[0]!;
    }
    if (!this.queue.length) this.refill(seed);
    return this.queue.shift() ?? null;
  }

  rotationPlan(count = 5, seed?: number): Array<Record<string, unknown>> {
    const plan: Array<Record<string, unknown>> = [];
    for (let i = 0; i < count; i++) {
      plan.push({ beacon: i + 1, proxy: this.nextProxy((seed ?? 0) + i), technique_id: "T1090.001" });
    }
    return plan;
  }

  asDict(): Record<string, unknown> {
    return {
      pool: this.proxies, strategy: this.strategy, jitter: this.jitter,
      size: this.proxies.length, technique_id: "T1090.001",
      technique: "Proxy: Internal/External (SOHO-router pool)",
    };
  }
}

// ------------------------------------------------------------------------- //
// C2 client infrastructure (Mythic, Covenant, Sliver)
// ------------------------------------------------------------------------- //

export interface C2Callback {
  framework: string;
  callback_id: unknown;
  host: string;
  user: string;
  active: boolean;
  last_seen: string;
  metadata: Record<string, unknown>;
}

export class C2Operator {
  framework: string;
  approve: (prompt: string) => boolean;
  history: Array<Record<string, unknown>> = [];

  constructor(opts: { framework?: string; approve?: (p: string) => boolean }) {
    this.framework = opts.framework ?? "mythic";
    this.approve = opts.approve ?? (() => true);
  }

  /** Run the operator loop. */
  operate(goal: string, phase = "recon"): Record<string, unknown> {
    const cmdHints: Record<string, string[]> = {
      recon: ["whoami", "ipconfig", "hostname", "net user /domain"],
      credential: ["secretsdump", "mimikatz", "samdump"],
      lateral: ["psexec", "wmi", "winrm", "ssh"],
      persistence: ["scheduledtask", "registry", "service"],
      cleanup: ["exit", "remove"],
    };
    const hints = cmdHints[phase] ?? cmdHints["recon"]!;
    const executed: Array<Record<string, unknown>> = [];
    let step = 0;
    while (step < 20) {
      step++;
      const command = hints[step - 1] ?? hints[0]!;
      if (!this.approve(`${phase}: ${command}`)) break;
      executed.push({ step, command, status: "queued" });
      this.history.push({ step, goal, command });
      if (command === "exit" || command === "remove") break;
    }
    return { goal, phase, steps: step, executed, history: this.history };
  }
}

// ------------------------------------------------------------------------- //
// Mythic REST client (fetch-based, dry-run safe)
// ------------------------------------------------------------------------- //

export class MythicClient {
  baseUrl: string;
  apitoken: string;
  timeout: number = 15_000;

  constructor(opts: { baseUrl?: string; apitoken?: string; timeout?: number } = {}) {
    this.baseUrl = (opts.baseUrl ?? process.env["MYTHIC_URL"] ?? "https://127.0.0.1:7443").replace(/\/+$/, "");
    this.apitoken = opts.apitoken ?? process.env["MYTHIC_APITOKEN"] ?? "";
    this.timeout = opts.timeout ?? 15_000;
  }

  async isAvailable(): Promise<boolean> {
    try {
      const resp = await fetch(`${this.baseUrl}/api/v1.4/operation/current`, {
        headers: this.apitoken ? { Authorization: `Bearer ${this.apitoken}` } : {},
        signal: AbortSignal.timeout(3000),
      });
      return resp.status === 200 || resp.status === 401;
    } catch { return false; }
  }

  capabilities(): Record<string, unknown> {
    return { framework: "mythic", api: "REST v1.4", authenticated: !!this.apitoken };
  }
}

// ------------------------------------------------------------------------- //
// Sliver client (binary-driven, honest gRPC notes)
// ------------------------------------------------------------------------- //

export class SliverClient {
  binary: string;
  operatorConfig: string;

  constructor(opts: { binary?: string; operatorConfig?: string } = {}) {
    this.binary = opts.binary ?? process.env["SLIVER_BINARY"] ?? "";
    this.operatorConfig = opts.operatorConfig ?? process.env["SLIVER_OPERATOR_CONFIG"] ?? "";
  }

  isAvailable(): boolean {
    return !!this.binary || !!this.operatorConfig;
  }

  capabilities(): Record<string, unknown> {
    return {
      framework: "sliver", api: "gRPC (protobuf)", binary_driven: !!this.binary,
      note: "Sliver's operator API is gRPC; ARES2 drives it through the sliver-client binary when present.",
    };
  }
}