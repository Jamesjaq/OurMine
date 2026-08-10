/**
 * Per-action OPSEC review — the forensic-footprint layer.
 *
 * For every planned action the graph considers, `reviewAction` produces an
 * `OpsecReview` answering the questions an APT operator asks before running
 * anything: footprint (disk/memory/network/registry), signature risk (does
 * the exact command trip known YARA detection shapes?), noise, cleanup, and
 * mitigations.
 *
 * Also includes C2 beacon timing (jittered intervals — fixed-interval
 * beaconing is one of the easiest SOC fingerprints).
 */

import { scanText, type YaraMatch } from "./yara.ts";

const DISK_TOOLS = new Set(["certutil", "bitsadmin", "curl", "tar", "wmic", "reg", "7z"]);
const MEMORY_TOOLS = new Set(["powershell", "mshta", "rundll32", "regsvr32", "wmic"]);

const HIGH_SIGNAL: Record<string, string> = {
  "-enc": "encoded PowerShell (-enc) — heavily signatured",
  "-encodedcommand": "encoded PowerShell (-EncodedCommand)",
  "DownloadString": "PS download cradle (IEX/DownloadString)",
  "amsiInitFailed": "AMSI reflection bypass — universally signatured",
  "certutil -urlcache": "certutil downloader (T1105)",
  "scrobj.dll": "regsvr32 squiblydoo (T1218.010)",
  "MiniDump": "LSASS dump via comsvcs (T1003.001)",
  "ntdsutil": "NTDS.dit dump (T1003.003)",
  "wevtutil cl": "event log clearing (T1070.004)",
};

export interface OpsecReview {
  action_id: string;
  tool: string;
  command: string;
  footprint: string[];
  signature_risk: "none" | "low" | "medium" | "high";
  yara_matches: YaraMatch[];
  noise: "low" | "medium" | "high";
  cleanup_required: string[];
  mitigations: string[];
  safe_to_run: boolean;
}

export function opsecReviewAsDict(r: OpsecReview): Record<string, unknown> {
  return {
    action_id: r.action_id,
    tool: r.tool,
    footprint: r.footprint,
    signature_risk: r.signature_risk,
    yara_matches: r.yara_matches.map((m) => ({ rule: m.rule, attack_id: m.attackId, engine: m.engine })),
    noise: r.noise,
    cleanup_required: r.cleanup_required,
    mitigations: r.mitigations,
    safe_to_run: r.safe_to_run,
  };
}

function footprintFor(tool: string, command: string): string[] {
  const touch: string[] = [];
  const lower = command.toLowerCase();
  const t = tool.toLowerCase();
  if (
    [...DISK_TOOLS].some((x) => t.includes(x)) ||
    /(?:-o |outfile|%temp%|\\temp\\)/.test(lower)
  ) {
    touch.push("disk: may drop a file (staging/payload)");
  }
  if (
    [...MEMORY_TOOLS].some((x) => t.includes(x)) ||
    /iex|invoke-expression|downloadstring/.test(lower)
  ) {
    touch.push("memory: in-memory script execution");
  }
  if (/https?:\/\/|curl|wget|bitsadmin \/transfer/.test(lower)) {
    touch.push("network: outbound fetch from a remote URL");
  }
  if (lower.includes("reg add") || lower.includes("registry")) {
    touch.push("registry: persistence/configuration change");
  }
  if (!touch.length) touch.push("minimal: no obvious persistent artifact");
  return touch;
}

function signatureFor(command: string, matches: YaraMatch[]): [string, string[]] {
  const reasons: string[] = [];
  for (const m of matches) {
    if (m.attackId) reasons.push(`YARA ${m.rule} (${m.attackId})`);
  }
  const lower = command.toLowerCase();
  for (const [frag, why] of Object.entries(HIGH_SIGNAL)) {
    if (lower.includes(frag)) reasons.push(why);
  }
  if (!reasons.length) return ["none", reasons];
  const count = reasons.length;
  if (
    count >= 3 ||
    reasons.some((r) => r.includes("AMS") || r.includes("universally") || r.includes("heavily"))
  ) {
    return ["high", reasons];
  }
  if (count >= 2) return ["medium", reasons];
  return ["low", reasons];
}

function noiseFor(tool: string, command: string): "low" | "medium" | "high" {
  const lower = command.toLowerCase();
  const t = tool.toLowerCase();
  if (
    ["powershell", "mshta", "rundll32", "regsvr32"].some((x) => t.includes(x)) ||
    lower.includes("-enc")
  ) {
    return "high";
  }
  if (/https?:\/\/|curl|wget/.test(lower)) return "medium";
  return "low";
}

function cleanupFor(_tool: string, command: string): string[] {
  const cleanup: string[] = [];
  const lower = command.toLowerCase();
  if (/(%temp%|\\temp\\)/.test(lower) || lower.includes("outfile") || lower.includes(" -o ")) {
    cleanup.push("delete staged files from %TEMP% after use");
  }
  if (lower.includes("wevtutil")) {
    cleanup.push("note: log clearing itself is a detection signal — weigh carefully");
  }
  if (lower.includes("reg add")) cleanup.push("remove added registry keys on exit");
  if (lower.includes("amsi") || lower.includes("etw") || lower.includes("patch")) {
    cleanup.push("bypasses are in-process only — no persistent cleanup needed");
  }
  return cleanup;
}

function mitigationsFor(review: OpsecReview, command: string): string[] {
  const mitigations: string[] = [];
  if (review.signature_risk === "high" || review.signature_risk === "medium") {
    mitigations.push("refactor payload to avoid signatured strings (split/encode/rename variables)");
  }
  if (command.includes("-enc")) {
    mitigations.push("prefer script blocks with -NoProfile over -enc (still monitored — weigh both)");
  }
  if (command.includes("certutil")) {
    mitigations.push("pair certutil downloads with immediate deletion + use -urlcache after first fetch");
  }
  if (command.includes("DownloadString")) {
    mitigations.push("use encrypted C2 (HTTPS) and short-lived staging URLs; avoid known malware C2 patterns");
  }
  if (review.yara_matches.some((m) => m.attackId)) {
    mitigations.push("payload tripped YARA rules — iterate before deployment (see vanta opsec)");
  }
  if (!mitigations.length) {
    mitigations.push("low-risk action — maintain standard hygiene (unique C2, encrypted transport)");
  }
  return mitigations;
}

export function reviewAction(action: {
  action_id?: string;
  tool?: string;
  command?: string;
}): OpsecReview {
  const command = String(action.command ?? "");
  const tool = String(action.tool ?? "");
  const matches = scanText(command);
  const [sig] = signatureFor(command, matches);
  const review: OpsecReview = {
    action_id: String(action.action_id ?? ""),
    tool,
    command,
    footprint: footprintFor(tool, command),
    signature_risk: sig as OpsecReview["signature_risk"],
    yara_matches: matches,
    noise: noiseFor(tool, command),
    cleanup_required: cleanupFor(tool, command),
    mitigations: [],
    safe_to_run: true,
  };
  review.mitigations = mitigationsFor(review, command);
  review.safe_to_run = review.signature_risk !== "high" && review.signature_risk !== "medium" && review.noise !== "high";
  return review;
}

export function evaluatePayload(payload: string, context = ""): Record<string, unknown> {
  const matches = scanText(payload);
  const [sig] = signatureFor(payload, matches);
  const review: OpsecReview = {
    action_id: "payload-check",
    tool: context || "payload",
    command: payload,
    footprint: footprintFor(context, payload),
    signature_risk: sig as OpsecReview["signature_risk"],
    yara_matches: matches,
    noise: noiseFor(context, payload),
    cleanup_required: cleanupFor(context, payload),
    mitigations: [],
    safe_to_run: true,
  };
  review.mitigations = mitigationsFor(review, payload);
  review.safe_to_run = review.signature_risk !== "high" && review.signature_risk !== "medium" && review.noise !== "high";
  return opsecReviewAsDict(review);
}

// ------------------------------------------------------------------------- //
// C2 beacon timing (modules/opsec/timing.py)
// ------------------------------------------------------------------------- //

export interface BeaconTimingProfile {
  name: string;
  intervalSeconds: number;
  jitterFraction: number;
}

export const BEACON_PROFILES: Record<string, BeaconTimingProfile> = {
  standard: { name: "standard", intervalSeconds: 60, jitterFraction: 0.2 },
  stealth: { name: "stealth", intervalSeconds: 300, jitterFraction: 0.4 },
  aggressive: { name: "aggressive", intervalSeconds: 15, jitterFraction: 0.1 },
  "full-jitter": { name: "full-jitter", intervalSeconds: 60, jitterFraction: 1.0 },
};

export const DEFAULT_BEACON_PROFILE = "standard";

export function jitterDelta(interval: number, jitterFraction: number, seed?: number): number {
  // Deterministic PRNG (mulberry32) so tests are reproducible.
  const rng = mulberry32(seed ?? Date.now() & 0xffffffff);
  const maxDelta = interval * jitterFraction;
  return rng() * (maxDelta * 2) - maxDelta;
}

export function nextBeaconInterval(opts: {
  intervalSeconds?: number;
  jitterFraction?: number;
  profile?: string;
  seed?: number;
} = {}): number {
  const { intervalSeconds, jitterFraction, profile, seed } = opts;
  let base: number;
  let jitter: number;
  if (profile != null) {
    const chosen = BEACON_PROFILES[profile];
    if (!chosen) {
      throw new Error(`unknown beacon profile '${profile}'; available: ${Object.keys(BEACON_PROFILES).sort().join(", ")}`);
    }
    base = chosen.intervalSeconds;
    jitter = chosen.jitterFraction;
  } else {
    base = intervalSeconds ?? BEACON_PROFILES[DEFAULT_BEACON_PROFILE]!.intervalSeconds;
    jitter = jitterFraction ?? 0.2;
  }
  if (base <= 0) throw new Error("beacon interval must be > 0");
  if (jitter < 0 || jitter > 1) throw new Error("jitterFraction must be in [0, 1]");
  const delay = base + jitterDelta(base, jitter, seed);
  return Math.max(delay, 0.5);
}

export function describeProfile(profile: string): Record<string, unknown> {
  const p = BEACON_PROFILES[profile];
  if (!p) throw new Error(`unknown beacon profile '${profile}'`);
  return {
    name: p.name,
    interval_seconds: p.intervalSeconds,
    jitter_fraction: p.jitterFraction,
    range_seconds: [
      p.intervalSeconds * (1 - p.jitterFraction),
      p.intervalSeconds * (1 + p.jitterFraction),
    ],
  };
}

function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
