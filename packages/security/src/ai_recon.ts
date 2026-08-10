/**
 * @module ai_recon
 * AI-driven reconnaissance — OSINT aggregation, LinkedIn scraping, email pattern
 * enumeration, breach data correlation, and org-chart reconstruction.
 */

import { spawnSync } from "node:child_process";
import * as crypto from "node:crypto";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface ReconTarget {
  domain: string;
  orgName?: string;
  industry?: string;
}

export interface EmailPattern {
  pattern: string;             // e.g. "{first}.{last}@{domain}"
  confidence: number;          // 0–1
  samplesFound: number;
}

export interface EmployeeRecord {
  fullName: string;
  title: string;
  email?: string;
  linkedInUrl?: string;
  department?: string;
  seniority?: "executive" | "manager" | "ic" | "unknown";
}

export interface ReconResult {
  target: ReconTarget;
  emailPatterns: EmailPattern[];
  employees: EmployeeRecord[];
  subdomains: string[];
  breachHits: string[];
  dryRun: boolean;
  timestamp: string;
}

export interface AIReconOptions {
  live?: boolean;
  maxEmployees?: number;
  huntBreaches?: boolean;
  huntSubdomains?: boolean;
}

// ─── Email pattern inference ──────────────────────────────────────────────────

const COMMON_PATTERNS: string[] = [
  "{first}.{last}@{domain}",
  "{first}{last}@{domain}",
  "{f}{last}@{domain}",
  "{first}_{last}@{domain}",
  "{first}@{domain}",
  "{last}@{domain}",
  "{f}.{last}@{domain}",
];

export function inferEmailPatterns(
  knownEmails: string[],
  domain: string
): EmailPattern[] {
  const domainEmails = knownEmails.filter((e) => e.endsWith(`@${domain}`));
  if (domainEmails.length === 0) {
    return COMMON_PATTERNS.map((p) => ({ pattern: p, confidence: 0.14, samplesFound: 0 }));
  }
  // Score each pattern against known samples
  return COMMON_PATTERNS.map((pattern) => {
    let hits = 0;
    for (const email of domainEmails) {
      const [local] = email.split("@");
      const candidate = pattern
        .replace("{domain}", domain)
        .replace("{first}", local.split(/[._]/)[0] ?? local)
        .replace("{last}", local.split(/[._]/).slice(-1)[0] ?? local)
        .replace("{f}", (local.split(/[._]/)[0] ?? local)[0] ?? "");
      if (candidate === email) hits++;
    }
    return {
      pattern,
      confidence: hits / Math.max(domainEmails.length, 1),
      samplesFound: hits,
    };
  }).sort((a, b) => b.confidence - a.confidence);
}

// ─── OSINT employee enumeration ──────────────────────────────────────────────

/**
 * Enumerate employees for a target domain via OSINT (LinkedIn, GitHub org, etc.).
 *
 * DRY-RUN returns synthetic sample employees.
 * LIVE delegates to `theHarvester` or `linkedin2username` on PATH.
 */
export async function enumerateEmployees(
  target: ReconTarget,
  opts: AIReconOptions = {}
): Promise<EmployeeRecord[]> {
  const { live = false, maxEmployees = 50 } = opts;

  if (!live) {
    return [
      {
        fullName: "Jane Smith",
        title: "Senior Software Engineer",
        email: `jane.smith@${target.domain}`,
        linkedInUrl: "https://linkedin.com/in/example",
        department: "Engineering",
        seniority: "ic",
      },
      {
        fullName: "John Doe",
        title: "Chief Information Officer",
        email: `john.doe@${target.domain}`,
        department: "IT",
        seniority: "executive",
      },
    ].slice(0, maxEmployees);
  }

  const r = spawnSync(
    "theHarvester",
    ["-d", target.domain, "-b", "linkedin,google", "-l", String(maxEmployees)],
    { encoding: "utf8", timeout: 60_000 }
  );

  const lines = (r.stdout ?? "").split("\n");
  const employees: EmployeeRecord[] = [];
  for (const line of lines) {
    if (line.includes("@")) {
      employees.push({
        fullName: "",
        title: "",
        email: line.trim(),
        seniority: "unknown",
      });
    }
  }
  return employees;
}

// ─── Subdomain enumeration ───────────────────────────────────────────────────

/**
 * Enumerate subdomains for a target via passive DNS, crt.sh, and brute-force.
 * DRY-RUN returns synthetic entries.
 */
export async function enumerateSubdomains(
  domain: string,
  opts: AIReconOptions = {}
): Promise<string[]> {
  const { live = false } = opts;

  if (!live) {
    return [
      `mail.${domain}`,
      `vpn.${domain}`,
      `api.${domain}`,
      `dev.${domain}`,
      `staging.${domain}`,
      `admin.${domain}`,
    ];
  }

  // Try crt.sh passive lookup
  try {
    const resp = await fetch(`https://crt.sh/?q=%.${domain}&output=json`);
    if (resp.ok) {
      const items = (await resp.json()) as Array<{ name_value: string }>;
      return [...new Set(items.map((i) => i.name_value.replace("*.", "")).filter(Boolean))];
    }
  } catch {/* fall through */}

  // Fallback: subfinder
  const r = spawnSync("subfinder", ["-d", domain, "-silent"], {
    encoding: "utf8",
    timeout: 120_000,
  });
  return (r.stdout ?? "").split("\n").map((l) => l.trim()).filter(Boolean);
}

// ─── Breach correlation ───────────────────────────────────────────────────────

/**
 * Look up whether emails appear in breach databases (HIBP-style check).
 * DRY-RUN: returns dummy hit.
 */
export async function checkBreaches(
  emails: string[],
  opts: AIReconOptions = {}
): Promise<string[]> {
  const { live = false } = opts;
  if (!live) return emails.length > 0 ? [`${emails[0]} — found in 3 breach datasets (DRY-RUN)`] : [];

  const hits: string[] = [];
  for (const email of emails) {
    try {
      const resp = await fetch(`https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}`, {
        headers: { "hibp-api-key": process.env["HIBP_API_KEY"] ?? "", "User-Agent": "OurMine-ARES/1.0" },
      });
      if (resp.status === 200) hits.push(`${email} — breached`);
    } catch {/* continue */}
  }
  return hits;
}

// ─── Master recon runner ─────────────────────────────────────────────────────

/**
 * Run a full AI-assisted recon sweep against a target organisation.
 */
export async function runRecon(
  target: ReconTarget,
  opts: AIReconOptions = {}
): Promise<ReconResult> {
  const employees = await enumerateEmployees(target, opts);
  const subdomains = opts.huntSubdomains
    ? await enumerateSubdomains(target.domain, opts)
    : [];
  const knownEmails = employees.map((e) => e.email ?? "").filter(Boolean);
  const emailPatterns = inferEmailPatterns(knownEmails, target.domain);
  const breachHits = opts.huntBreaches ? await checkBreaches(knownEmails, opts) : [];

  return {
    target,
    emailPatterns,
    employees,
    subdomains,
    breachHits,
    dryRun: !(opts.live ?? false),
    timestamp: new Date().toISOString(),
  };
}

export default { runRecon, enumerateEmployees, enumerateSubdomains, inferEmailPatterns, checkBreaches };
