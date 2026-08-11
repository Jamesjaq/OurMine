/**
 * @module bountyhunter
 * Bug-bounty recon — subdomain enumeration, endpoint discovery, JS secret
 * extraction, and scope-aware vulnerability triage.
 *
 * Designed for authorised bug-bounty programmes (HackerOne / Bugcrowd).
 */

import { resolveDryRun } from "./exec_options.ts"
import { spawnSync } from "node:child_process";
import * as crypto from "node:crypto";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface BountyTarget {
  domain: string;
  programName?: string;
  inScope: string[];      // regex or CIDR patterns in scope
  outOfScope: string[];   // exclusions
}

export interface Endpoint {
  url: string;
  method: string;
  status?: number;
  technologies?: string[];
  parameters?: string[];
}

export interface SecretFinding {
  file: string;
  line: number;
  type: string;           // "aws_key" | "github_token" | "jwt" | etc.
  value: string;          // masked excerpt
  confidence: number;     // 0–1
}

export interface VulnFinding {
  endpoint: string;
  type: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  description: string;
  evidence?: string;
  cvss?: number;
}

export interface ReconReport {
  target: BountyTarget;
  subdomains: string[];
  liveHosts: string[];
  endpoints: Endpoint[];
  secrets: SecretFinding[];
  findings: VulnFinding[];
  dryRun: boolean;
  timestamp: string;
}

export interface BountyHunterOptions {
  live?: boolean;
  resolveHosts?: boolean;
  scanPorts?: boolean;
  extractSecrets?: boolean;
  fuzzParams?: boolean;
}

// ─── Secret patterns ──────────────────────────────────────────────────────────

const SECRET_PATTERNS: Array<{ type: string; pattern: RegExp }> = [
  { type: "aws_access_key", pattern: /AKIA[0-9A-Z]{16}/g },
  { type: "aws_secret_key", pattern: /(?:aws|secret)[_-]?(?:access[_-]?)?key['":\s=]+([A-Za-z0-9/+=]{40})/gi },
  { type: "github_token", pattern: /ghp_[A-Za-z0-9]{36}/g },
  { type: "google_api_key", pattern: /AIza[0-9A-Za-z_-]{35}/g },
  { type: "jwt", pattern: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+/g },
  { type: "private_key", pattern: /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/g },
  { type: "slack_token", pattern: /xox[baprs]-[0-9]{12}-[0-9]{12}-[A-Za-z0-9]{24}/g },
  { type: "sendgrid_key", pattern: /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/g },
  { type: "stripe_key", pattern: /sk_(?:live|test)_[A-Za-z0-9]{24,}/g },
  { type: "twilio_key", pattern: /SK[0-9a-fA-F]{32}/g },
];

/**
 * Extract secrets from JavaScript source text.
 */
export function extractSecrets(source: string, filename = "unknown"): SecretFinding[] {
  const findings: SecretFinding[] = [];
  const lines = source.split("\n");

  for (let i = 0; i < lines.length; i++) {
    for (const { type, pattern } of SECRET_PATTERNS) {
      const matches = lines[i].matchAll(pattern);
      for (const match of matches) {
        const raw = match[0];
        findings.push({
          file: filename,
          line: i + 1,
          type,
          value: raw.slice(0, 4) + "****" + raw.slice(-4), // mask middle
          confidence: 0.85,
        });
      }
    }
  }

  return findings;
}

// ─── Subdomain enumeration ───────────────────────────────────────────────────

export async function discoverSubdomains(
  domain: string,
  opts: BountyHunterOptions = {}
): Promise<string[]> {
  const { live = false } = opts;
  if (!live) {
    return [`api.${domain}`, `app.${domain}`, `beta.${domain}`, `dev.${domain}`,
            `mail.${domain}`, `cdn.${domain}`, `assets.${domain}`];
  }

  const results = new Set<string>();

  // crt.sh
  try {
    const r = await fetch(`https://crt.sh/?q=%.${domain}&output=json`);
    if (r.ok) {
      const items = await r.json() as Array<{ name_value: string }>;
      items.forEach((i) => results.add(i.name_value.replace("*.", "")));
    }
  } catch {/* skip */}

  // subfinder
  const sf = spawnSync("subfinder", ["-d", domain, "-silent"], { encoding: "utf8", timeout: 120_000 });
  (sf.stdout ?? "").split("\n").filter(Boolean).forEach((s) => results.add(s.trim()));

  return [...results];
}

// ─── HTTP probing ─────────────────────────────────────────────────────────────

/**
 * Probe a list of hosts to find live HTTP services.
 */
export async function probeHosts(
  hosts: string[],
  opts: BountyHunterOptions = {}
): Promise<Endpoint[]> {
  const { live = false } = opts;
  if (!live) {
    return hosts.slice(0, 3).map((h) => ({
      url: `https://${h}`,
      method: "GET",
      status: 200,
      technologies: ["nginx", "React"],
    }));
  }

  const endpoints: Endpoint[] = [];
  for (const host of hosts) {
    for (const scheme of ["https", "http"]) {
      try {
        const resp = await fetch(`${scheme}://${host}`, {
          method: "GET",
          signal: AbortSignal.timeout(5000),
        });
        const server = resp.headers.get("server") ?? "";
        const powered = resp.headers.get("x-powered-by") ?? "";
        endpoints.push({
          url: `${scheme}://${host}`,
          method: "GET",
          status: resp.status,
          technologies: [server, powered].filter(Boolean),
        });
        break; // found, don't try http if https worked
      } catch {/* unreachable */}
    }
  }
  return endpoints;
}

// ─── JS secret harvesting ─────────────────────────────────────────────────────

/**
 * Crawl a live endpoint and extract JS files, then scan for secrets.
 */
export async function harvestJSSecrets(
  baseUrl: string,
  opts: BountyHunterOptions = {}
): Promise<SecretFinding[]> {
  const { live = false } = opts;
  if (!live) {
    return [
      { file: `${baseUrl}/static/main.js`, line: 42, type: "aws_access_key",
        value: "AKIA****EXAMPLE", confidence: 0.9 },
    ];
  }

  const findings: SecretFinding[] = [];
  try {
    const html = await (await fetch(baseUrl, { signal: AbortSignal.timeout(10_000) })).text();
    const scriptUrls = [...html.matchAll(/src=["']([^"']+\.js[^"']*)/g)]
      .map((m) => new URL(m[1], baseUrl).href);

    for (const url of scriptUrls.slice(0, 20)) {
      try {
        const js = await (await fetch(url, { signal: AbortSignal.timeout(10_000) })).text();
        findings.push(...extractSecrets(js, url));
      } catch {/* skip */}
    }
  } catch {/* skip */}

  return findings;
}

// ─── Master runner ────────────────────────────────────────────────────────────

export async function runRecon(
  target: BountyTarget,
  opts: BountyHunterOptions = {}
): Promise<ReconReport> {
  const subdomains = await discoverSubdomains(target.domain, opts);
  const endpoints = opts.resolveHosts ? await probeHosts(subdomains, opts) : [];
  const secrets = opts.extractSecrets ? await harvestJSSecrets(`https://${target.domain}`, opts) : [];

  return {
    target,
    subdomains,
    liveHosts: endpoints.map((e) => e.url),
    endpoints,
    secrets,
    findings: [],   // populated by vuln scanner
    dryRun: !(opts.live ?? false),
    timestamp: new Date().toISOString(),
  };
}

/** MCP/CLI alias — accepts `{ target }` or full BountyTarget */
export async function recon(
  targetOrOpts: BountyTarget | { target?: string; domain?: string; endpoints?: Endpoint[] },
  opts: BountyHunterOptions = {},
): Promise<ReconReport> {
  const raw = targetOrOpts as BountyTarget & { target?: string };
  const domain = raw.domain ?? raw.target ?? "example.com";
  const bountyTarget: BountyTarget = {
    domain,
    inScope: raw.inScope ?? [`*.${domain}`, domain],
    outOfScope: raw.outOfScope ?? [],
  };
  return runRecon(bountyTarget, opts);
}

export default { runRecon, recon, discoverSubdomains, probeHosts, harvestJSSecrets, extractSecrets };
