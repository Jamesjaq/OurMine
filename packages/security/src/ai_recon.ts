/**
 * @module ai_recon
 * AI-driven reconnaissance — OSINT aggregation, subdomain enumeration,
 * email pattern inference, breach correlation, WHOIS/DNS collection,
 * technology stack detection, and LLM-powered analysis.
 */

import { spawnSync, execFileSync } from "node:child_process";
import { resolveDryRun } from "./exec_options.ts";
import { isToolAvailable } from "./tool_detection.ts";
import { llmComplete, hasLLMKey } from "./llm_client.ts";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface ReconTarget {
  domain: string;
  orgName?: string;
  industry?: string;
}

export interface EmailPattern {
  pattern: string;
  confidence: number;
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

export interface DNSRecord {
  type: string;
  value: string;
  ttl?: number;
}

export interface WHOISData {
  registrar?: string;
  creationDate?: string;
  expirationDate?: string;
  nameServers?: string[];
  registrantOrg?: string;
  registrantCountry?: string;
  rawText?: string;
}

export interface TechStackFingerprint {
  category: string;
  name: string;
  version?: string;
  confidence: number;
}

export interface ReconResult {
  target: ReconTarget;
  emailPatterns: EmailPattern[];
  employees: EmployeeRecord[];
  subdomains: string[];
  dnsRecords: DNSRecord[];
  whois: WHOISData | null;
  breachHits: string[];
  techStack: TechStackFingerprint[];
  llmAnalysis: string | null;
  dryRun: boolean;
  timestamp: string;
}

export interface AIReconOptions {
  live?: boolean;
  dryRun?: boolean;
  maxEmployees?: number;
  deep?: boolean;
  huntBreaches?: boolean;
  huntSubdomains?: boolean;
  collectDNS?: boolean;
  collectWHOIS?: boolean;
  detectTech?: boolean;
  llmAnalysis?: boolean;
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
  "{first}{f}@{domain}",
];

export function inferEmailPatterns(
  knownEmails: string[],
  domain: string,
): EmailPattern[] {
  const domainEmails = knownEmails.filter((e) => e.endsWith(`@${domain}`));
  if (domainEmails.length === 0) {
    return COMMON_PATTERNS.map((p) => ({
      pattern: p,
      confidence: +(1 / COMMON_PATTERNS.length).toFixed(3),
      samplesFound: 0,
    }));
  }

  return COMMON_PATTERNS.map((pattern) => {
    let hits = 0;
    for (const email of domainEmails) {
      const [local] = email.split("@");
      if (!local) continue;
      const parts = local.split(/[._\-]/);
      const first = parts[0] ?? local;
      const last = parts[parts.length - 1] ?? local;
      const f = first[0] ?? "";
      const candidate = pattern
        .replace(/\{domain\}/g, domain)
        .replace(/\{first\}/g, first)
        .replace(/\{last\}/g, last)
        .replace(/\{f\}/g, f);
      if (candidate === email) hits++;
    }
    return {
      pattern,
      confidence: hits / Math.max(domainEmails.length, 1),
      samplesFound: hits,
    };
  }).sort((a, b) => b.confidence - a.confidence);
}

// ─── Dry-run generators ──────────────────────────────────────────────────────

function generateDryRunEmployees(domain: string, max: number): EmployeeRecord[] {
  const firstNames = [
    "Alice", "Bob", "Carol", "David", "Eve", "Frank", "Grace", "Hank",
    "Ivy", "Jack", "Karen", "Leo", "Mona", "Nate", "Olivia", "Paul",
    "Quinn", "Rita", "Sam", "Tina", "Uma", "Vic", "Wendy", "Xander",
    "Yara", "Zane",
  ];
  const lastNames = [
    "Anderson", "Baker", "Chen", "Davis", "Evans", "Fischer", "Garcia",
    "Harris", "Ivanov", "Jackson", "Kim", "Lopez", "Muller", "Nguyen",
    "Okafor", "Park", "Quinn", "Rivera", "Singh", "Tanaka", "Ueda",
    "Volkov", "Wang", "Xu", "Yamamoto", "Zhang",
  ];
  const titles = [
    { title: "Chief Executive Officer", dept: "Executive", seniority: "executive" as const },
    { title: "Chief Information Officer", dept: "IT", seniority: "executive" as const },
    { title: "VP of Engineering", dept: "Engineering", seniority: "executive" as const },
    { title: "Director of Security", dept: "Security", seniority: "manager" as const },
    { title: "Engineering Manager", dept: "Engineering", seniority: "manager" as const },
    { title: "Senior Software Engineer", dept: "Engineering", seniority: "ic" as const },
    { title: "DevOps Engineer", dept: "Infrastructure", seniority: "ic" as const },
    { title: "Security Analyst", dept: "Security", seniority: "ic" as const },
    { title: "Product Manager", dept: "Product", seniority: "manager" as const },
    { title: "Data Scientist", dept: "Data", seniority: "ic" as const },
    { title: "Systems Administrator", dept: "IT", seniority: "ic" as const },
    { title: "Cloud Architect", dept: "Infrastructure", seniority: "ic" as const },
    { title: "Frontend Developer", dept: "Engineering", seniority: "ic" as const },
    { title: "Backend Developer", dept: "Engineering", seniority: "ic" as const },
    { title: "SOC Lead", dept: "Security", seniority: "manager" as const },
  ];

  const employees: EmployeeRecord[] = [];
  const usedNames = new Set<string>();
  const count = Math.min(max, 20);

  for (let i = 0; i < count; i++) {
    let first = firstNames[i % firstNames.length]!;
    let last = lastNames[i % lastNames.length]!;
    let nameKey = `${first}.${last}`;
    let attempt = 0;
    while (usedNames.has(nameKey) && attempt < 10) {
      last = lastNames[(i + attempt + 1) % lastNames.length]!;
      nameKey = `${first}.${last}`;
      attempt++;
    }
    usedNames.add(nameKey);

    const role = titles[i % titles.length]!;
    employees.push({
      fullName: `${first} ${last}`,
      title: role.title,
      email: `${first.toLowerCase()}.${last.toLowerCase()}@${domain}`,
      linkedInUrl: `https://linkedin.com/in/${first.toLowerCase()}-${last.toLowerCase()}-${Math.floor(Math.random() * 9000 + 1000)}`,
      department: role.dept,
      seniority: role.seniority,
    });
  }
  return employees;
}

function generateDryRunSubdomains(domain: string): string[] {
  const prefixes = [
    "mail", "vpn", "api", "dev", "staging", "admin", "portal", "docs",
    "ci", "cdn", "img", "assets", "grafana", "jira", "gitlab", "sso",
    "auth", "status", "monitor", "backup", "db", "redis", "kafka",
  ];
  return prefixes.slice(0, 12).map((p) => `${p}.${domain}`);
}

function generateDryRunDNS(domain: string): DNSRecord[] {
  return [
    { type: "A", value: "203.0.113.42", ttl: 3600 },
    { type: "A", value: "203.0.113.43", ttl: 3600 },
    { type: "AAAA", value: "2001:db8::1", ttl: 3600 },
    { type: "MX", value: `mail.${domain}`, ttl: 3600 },
    { type: "MX", value: `mail2.${domain}`, ttl: 3600 },
    { type: "TXT", value: "v=spf1 include:_spf.google.com ~all", ttl: 3600 },
    { type: "TXT", value: "google-site-verification=abc123", ttl: 3600 },
    { type: "NS", value: `ns1.${domain}`, ttl: 86400 },
    { type: "NS", value: `ns2.${domain}`, ttl: 86400 },
    { type: "CNAME", value: `www.${domain}`, ttl: 3600 },
  ];
}

function generateDryRunWHOIS(domain: string): WHOISData {
  return {
    registrar: "Example Registrar, Inc.",
    creationDate: "2010-03-15T00:00:00Z",
    expirationDate: "2026-03-15T00:00:00Z",
    nameServers: [`ns1.${domain}`, `ns2.${domain}`],
    registrantOrg: "Example Corp",
    registrantCountry: "US",
  };
}

function generateDryRunTechStack(): TechStackFingerprint[] {
  return [
    { category: "Web Server", name: "Nginx", version: "1.24.0", confidence: 0.85 },
    { category: "Language", name: "TypeScript", version: "5.3", confidence: 0.8 },
    { category: "Framework", name: "Next.js", version: "14.0", confidence: 0.75 },
    { category: "Database", name: "PostgreSQL", version: "16", confidence: 0.7 },
    { category: "Cloud", name: "AWS", confidence: 0.9 },
    { category: "CI/CD", name: "GitHub Actions", confidence: 0.8 },
    { category: "Monitoring", name: "Datadog", confidence: 0.6 },
    { category: "DNS", name: "Cloudflare", confidence: 0.85 },
  ];
}

// ─── Live: Subdomain enumeration ─────────────────────────────────────────────

async function enumerateSubdomainsLive(domain: string): Promise<string[]> {
  const subs = new Set<string>();

  // Method 1: crt.sh passive lookup
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 30_000);
    const resp = await fetch(`https://crt.sh/?q=%.${domain}&output=json`, {
      signal: controller.signal,
    });
    clearTimeout(timeout);
    if (resp.ok) {
      const items = (await resp.json()) as Array<{ name_value: string }>;
      for (const item of items) {
        const names = item.name_value.split("\n");
        for (const name of names) {
          const cleaned = name.replace("*.", "").trim().toLowerCase();
          if (cleaned.endsWith(`.${domain}`) || cleaned === domain) {
            subs.add(cleaned);
          }
        }
      }
    }
  } catch (err) {
    console.error(`[ai_recon] crt.sh query failed: ${err}`);
  }

  // Method 2: subfinder if available
  if (isToolAvailable("subfinder")) {
    try {
      const result = spawnSync("subfinder", ["-d", domain, "-silent", "-timeout", "60"], {
        encoding: "utf8",
        timeout: 120_000,
      });
      for (const line of (result.stdout ?? "").split("\n")) {
        const sub = line.trim().toLowerCase();
        if (sub) subs.add(sub);
      }
    } catch (err) {
      console.error(`[ai_recon] subfinder failed: ${err}`);
    }
  }

  // Method 3: amass passive if available
  if (isToolAvailable("amass") && subs.size < 5) {
    try {
      const result = spawnSync("amass", ["enum", "-passive", "-d", domain], {
        encoding: "utf8",
        timeout: 180_000,
      });
      for (const line of (result.stdout ?? "").split("\n")) {
        const sub = line.trim().toLowerCase();
        if (sub.endsWith(`.${domain}`)) subs.add(sub);
      }
    } catch (err) {
      console.error(`[ai_recon] amass failed: ${err}`);
    }
  }

  return [...subs].sort();
}

// ─── Live: DNS record enumeration ────────────────────────────────────────────

async function enumerateDNSLive(domain: string): Promise<DNSRecord[]> {
  const records: DNSRecord[] = [];
  const types = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA", "SRV"];

  if (isToolAvailable("dig")) {
    for (const type of types) {
      try {
        const result = spawnSync("dig", ["+short", domain, type], {
          encoding: "utf8",
          timeout: 10_000,
        });
        const lines = (result.stdout ?? "").split("\n").filter((l) => l.trim());
        for (const line of lines) {
          const value = line.trim().replace(/\.$/, "");
          if (value && !value.startsWith(";")) {
            records.push({ type, value });
          }
        }
      } catch { /* skip failed type */ }
    }
  } else if (isToolAvailable("host")) {
    for (const type of types) {
      try {
        const result = spawnSync("host", ["-t", type, domain], {
          encoding: "utf8",
          timeout: 10_000,
        });
        const lines = (result.stdout ?? "").split("\n").filter((l) => l.trim());
        for (const line of lines) {
          const match = line.match(/has \w+ record (.+)/);
          if (match?.[1]) {
            records.push({ type, value: match[1].trim().replace(/\.$/, "") });
          }
        }
      } catch { /* skip */ }
    }
  } else {
    // Fallback: nslookup-based for A records only
    try {
      const result = spawnSync("nslookup", [domain], {
        encoding: "utf8",
        timeout: 10_000,
      });
      const lines = (result.stdout ?? "").split("\n");
      for (const line of lines) {
        const match = line.match(/Address:\s*(.+)/);
        if (match?.[1] && !match[1].includes("#")) {
          records.push({ type: "A", value: match[1].trim() });
        }
      }
    } catch { /* skip */ }
  }

  return records;
}

// ─── Live: WHOIS data collection ─────────────────────────────────────────────

async function collectWHOISLive(domain: string): Promise<WHOISData | null> {
  if (!isToolAvailable("whois")) return null;

  try {
    const result = spawnSync("whois", [domain], {
      encoding: "utf8",
      timeout: 30_000,
    });
    const raw = result.stdout ?? "";
    if (!raw) return null;

    const extract = (label: string): string | undefined => {
      const match = raw.match(new RegExp(`${label}:\\s*(.+)`, "i"));
      return match?.[1]?.trim();
    };

    const nameServers: string[] = [];
    const nsMatches = raw.match(/Name Server:\s*(.+)/gi);
    if (nsMatches) {
      for (const m of nsMatches) {
        const ns = m.replace(/Name Server:\s*/i, "").trim().toLowerCase();
        if (ns) nameServers.push(ns);
      }
    }

    return {
      registrar: extract("Registrar"),
      creationDate: extract("Creation Date"),
      expirationDate: extract("Expir") || extract("Registry Expiry Date"),
      nameServers: nameServers.length > 0 ? nameServers : undefined,
      registrantOrg: extract("Registrant Organization"),
      registrantCountry: extract("Registrant Country"),
      rawText: raw.slice(0, 4096),
    };
  } catch (err) {
    console.error(`[ai_recon] whois failed: ${err}`);
    return null;
  }
}

// ─── Live: Employee enumeration ───────────────────────────────────────────────

async function enumerateEmployeesLive(
  domain: string,
  maxEmployees: number,
): Promise<EmployeeRecord[]> {
  const employees: EmployeeRecord[] = [];
  const emails = new Set<string>();

  // Method 1: theHarvester
  if (isToolAvailable("theHarvester")) {
    try {
      const result = spawnSync(
        "theHarvester",
        ["-d", domain, "-b", "linkedin,google,bing,duckduckgo", "-l", String(maxEmployees)],
        { encoding: "utf8", timeout: 120_000 },
      );
      const lines = (result.stdout ?? "").split("\n");
      for (const line of lines) {
        const match = line.match(/[\w.+-]+@[\w-]+\.[\w.]+/g);
        if (match) {
          for (const email of match) {
            if (email.endsWith(`@${domain}`)) emails.add(email.toLowerCase());
          }
        }
      }
    } catch (err) {
      console.error(`[ai_recon] theHarvester failed: ${err}`);
    }
  }

  // Method 2: GitHub org member enumeration
  if (isToolAvailable("gh")) {
    try {
      const result = spawnSync("gh", ["api", `orgs/${domain.split(".")[0]}/members`, "--paginate", "--jq", ".[].login"], {
        encoding: "utf8",
        timeout: 30_000,
      });
      const logins = (result.stdout ?? "").split("\n").filter(Boolean);
      for (const login of logins.slice(0, maxEmployees)) {
        emails.add(`${login}@users.noreply.github.com`);
      }
    } catch { /* org may not exist on GitHub */ }
  }

  // Convert collected emails to employee records
  for (const email of emails) {
    const [local] = email.split("@");
    if (!local || local.includes("noreply")) continue;
    const parts = local.split(/[._\-]/);
    const firstName = parts[0] ?? "";
    const lastName = parts[parts.length - 1] ?? "";
    const fullName = `${capitalize(firstName)} ${capitalize(lastName)}`.trim();

    employees.push({
      fullName: fullName || local,
      title: "",
      email,
      seniority: "unknown",
    });
  }

  return employees.slice(0, maxEmployees);
}

function capitalize(s: string): string {
  return s ? s.charAt(0).toUpperCase() + s.slice(1).toLowerCase() : "";
}

// ─── Live: Breach correlation ────────────────────────────────────────────────

async function checkBreachesLive(emails: string[]): Promise<string[]> {
  const apiKey = process.env["HIBP_API_KEY"];
  if (!apiKey) {
    console.error("[ai_recon] HIBP_API_KEY not set, skipping breach check");
    return [];
  }

  const hits: string[] = [];
  for (const email of emails) {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 10_000);
      const resp = await fetch(
        `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}?truncateResponse=false`,
        {
          headers: {
            "hibp-api-key": apiKey,
            "User-Agent": "OurMine-ARES/1.0",
          },
          signal: controller.signal,
        },
      );
      clearTimeout(timeout);

      if (resp.status === 200) {
        const breaches = (await resp.json()) as Array<{ Name: string; Domain: string; BreachDate: string; DataClasses: string[] }>;
        for (const b of breaches) {
          hits.push(`${email} — ${b.Name} (${b.BreachDate}): ${b.DataClasses.join(", ")}`);
        }
      } else if (resp.status === 404) {
        // Not breached — clean
      } else if (resp.status === 429) {
        console.error("[ai_recon] HIBP rate limited, pausing...");
        await sleep(20_000);
      }
    } catch (err) {
      console.error(`[ai_recon] HIBP check failed for ${email}: ${err}`);
    }
  }
  return hits;
}

// ─── Live: Technology stack detection ────────────────────────────────────────

async function detectTechStackLive(domain: string): Promise<TechStackFingerprint[]> {
  const fingerprints: TechStackFingerprint[] = [];

  // HTTP header fingerprinting
  try {
    const resp = await fetch(`https://${domain}/`, {
      redirect: "follow",
      signal: AbortSignal.timeout(15_000),
    });

    const server = resp.headers.get("server");
    if (server) {
      const [name, version] = server.split("/");
      fingerprints.push({
        category: "Web Server",
        name: name?.trim() ?? server,
        version: version?.trim(),
        confidence: 0.9,
      });
    }

    const poweredBy = resp.headers.get("x-powered-by");
    if (poweredBy) {
      const [name, version] = poweredBy.split("/");
      fingerprints.push({
        category: "Framework",
        name: name?.trim() ?? poweredBy,
        version: version?.trim(),
        confidence: 0.85,
      });
    }

    const cfRay = resp.headers.get("cf-ray");
    if (cfRay) {
      fingerprints.push({ category: "CDN", name: "Cloudflare", confidence: 0.95 });
    }

    const body = await resp.text();

    // Content-based fingerprinting
    if (body.includes("__NEXT_DATA__")) fingerprints.push({ category: "Framework", name: "Next.js", confidence: 0.9 });
    if (body.includes("__nuxt")) fingerprints.push({ category: "Framework", name: "Nuxt.js", confidence: 0.9 });
    if (body.includes("react-root") || body.includes("_reactRoot")) fingerprints.push({ category: "Framework", name: "React", confidence: 0.8 });
    if (body.includes("ng-app") || body.includes("angular")) fingerprints.push({ category: "Framework", name: "Angular", confidence: 0.8 });
    if (body.includes("vue-app") || body.includes("v-cloak")) fingerprints.push({ category: "Framework", name: "Vue.js", confidence: 0.8 });
    if (body.includes("wp-content")) fingerprints.push({ category: "CMS", name: "WordPress", confidence: 0.95 });
    if (body.includes("drupal")) fingerprints.push({ category: "CMS", name: "Drupal", confidence: 0.85 });
    if (body.includes("joomla")) fingerprints.push({ category: "CMS", name: "Joomla", confidence: 0.85 });
    if (body.includes("Shopify")) fingerprints.push({ category: "E-Commerce", name: "Shopify", confidence: 0.9 });
    if (body.includes("stripe.js")) fingerprints.push({ category: "Payment", name: "Stripe", confidence: 0.85 });

    // JS library detection
    if (body.includes("jquery")) fingerprints.push({ category: "JS Library", name: "jQuery", confidence: 0.8 });
    if (body.includes("tailwindcss") || body.includes("tailwind")) fingerprints.push({ category: "CSS Framework", name: "Tailwind CSS", confidence: 0.8 });
    if (body.includes("bootstrap")) fingerprints.push({ category: "CSS Framework", name: "Bootstrap", confidence: 0.8 });
  } catch (err) {
    console.error(`[ai_recon] tech detection via HTTPS failed: ${err}`);
  }

  // whatweb fingerprinting if available
  if (isToolAvailable("whatweb")) {
    try {
      const result = spawnSync("whatweb", ["--color=never", "-q", domain], {
        encoding: "utf8",
        timeout: 30_000,
      });
      const output = result.stdout ?? "";
      const techMatches = output.matchAll(/(\w[\w\s.]*)\s+\[([^\]]+)\]/g);
      for (const match of techMatches) {
        const name = match[1]?.trim();
        const version = match[2]?.trim();
        if (name) {
          fingerprints.push({
            category: "Technology",
            name,
            version: version || undefined,
            confidence: 0.75,
          });
        }
      }
    } catch { /* whatweb not critical */ }
  }

  return fingerprints;
}

// ─── LLM-powered analysis ────────────────────────────────────────────────────

async function runLLMAnalysis(result: ReconResult): Promise<string | null> {
  if (!hasLLMKey()) {
    console.error("[ai_recon] No LLM API key available, skipping AI analysis");
    return null;
  }

  const summary = [
    `Target: ${result.target.domain}`,
    `Subdomains found: ${result.subdomains.length}`,
    `Employees enumerated: ${result.employees.length}`,
    `Email patterns: ${result.emailPatterns.slice(0, 3).map((p) => `${p.pattern} (conf: ${p.confidence})`).join(", ")}`,
    `DNS records: ${result.dnsRecords.length}`,
    `Breach hits: ${result.breachHits.length}`,
    `Tech stack: ${result.techStack.map((t) => `${t.name}${t.version ? ` v${t.version}` : ""}`).join(", ")}`,
    result.whois ? `Registrar: ${result.whois.registrar}, Org: ${result.whois.registrantOrg}` : "WHOIS: unavailable",
  ].join("\n");

  const systemPrompt = `You are an offensive security reconnaissance analyst. Analyze the OSINT data below for a penetration testing engagement. Provide:
1. Attack surface summary
2. High-value targets (employees, services)
3. Potential phishing vectors (email patterns, tech stack clues)
4. Recommended next steps for exploitation
5. Risk assessment and notable findings

Be concise, actionable, and use security terminology.`;

  try {
    const response = await llmComplete(summary, {
      system: systemPrompt,
      maxTokens: 2048,
      temperature: 0.3,
    });
    return response.content;
  } catch (err) {
    console.error(`[ai_recon] LLM analysis failed: ${err}`);
    return null;
  }
}

// ─── Sleep helper ────────────────────────────────────────────────────────────

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ─── Master recon runner ─────────────────────────────────────────────────────

/**
 * Run a full AI-assisted recon sweep against a target organisation.
 *
 * @param target  - ReconTarget with domain and optional org info
 * @param opts    - Options controlling live vs dry-run and what to collect
 */
export async function runRecon(
  target: ReconTarget,
  opts: AIReconOptions = {},
): Promise<ReconResult> {
  const dryRun = resolveDryRun(opts);
  const maxEmployees = opts.maxEmployees ?? 50;

  let employees: EmployeeRecord[];
  let subdomains: string[];
  let dnsRecords: DNSRecord[];
  let whois: WHOISData | null;
  let breachHits: string[];
  let techStack: TechStackFingerprint[];
  let llmAnalysis: string | null = null;

  if (dryRun) {
    employees = generateDryRunEmployees(target.domain, maxEmployees);
    subdomains = opts.huntSubdomains !== false ? generateDryRunSubdomains(target.domain) : [];
    dnsRecords = opts.collectDNS !== false ? generateDryRunDNS(target.domain) : [];
    whois = opts.collectWHOIS !== false ? generateDryRunWHOIS(target.domain) : null;
    techStack = opts.detectTech !== false ? generateDryRunTechStack() : [];
    breachHits = [];

    const knownEmails = employees.map((e) => e.email ?? "").filter(Boolean);
    const emailPatterns = inferEmailPatterns(knownEmails, target.domain);

    const result: ReconResult = {
      target,
      emailPatterns,
      employees,
      subdomains,
      dnsRecords,
      whois,
      breachHits,
      techStack,
      llmAnalysis: null,
      dryRun: true,
      timestamp: new Date().toISOString(),
    };

    if (opts.llmAnalysis !== false) {
      result.llmAnalysis = await runLLMAnalysis(result);
    }

    return result;
  }

  // ── LIVE MODE ──────────────────────────────────────────────────────────────

  console.error(`[ai_recon] Starting LIVE recon against ${target.domain}`);

  // Run parallel collections
  const [subdomainResults, dnsResults, whoisResult, employeeResults] = await Promise.all([
    opts.huntSubdomains !== false ? enumerateSubdomainsLive(target.domain) : Promise.resolve([]),
    opts.collectDNS !== false ? enumerateDNSLive(target.domain) : Promise.resolve([]),
    opts.collectWHOIS !== false ? collectWHOISLive(target.domain) : Promise.resolve(null),
    enumerateEmployeesLive(target.domain, maxEmployees),
  ]);

  subdomains = subdomainResults;
  dnsRecords = dnsResults;
  whois = whoisResult;
  employees = employeeResults;

  console.error(`[ai_recon] Subdomains: ${subdomains.length}, DNS: ${dnsRecords.length}, Employees: ${employees.length}`);

  // Derive emails from subdomains (mail servers, etc.) and known patterns
  const knownEmails = employees.map((e) => e.email ?? "").filter(Boolean);
  const emailPatterns = inferEmailPatterns(knownEmails, target.domain);

  // Breach correlation
  breachHits = opts.huntBreaches !== false ? await checkBreachesLive(knownEmails.slice(0, 20)) : [];

  // Technology detection
  techStack = opts.detectTech !== false ? await detectTechStackLive(target.domain) : [];

  console.error(`[ai_recon] Tech stack: ${techStack.length} fingerprints, Breaches: ${breachHits.length}`);

  const result: ReconResult = {
    target,
    emailPatterns,
    employees,
    subdomains,
    dnsRecords,
    whois,
    breachHits,
    techStack,
    llmAnalysis: null,
    dryRun: false,
    timestamp: new Date().toISOString(),
  };

  // LLM analysis
  if (opts.llmAnalysis !== false) {
    result.llmAnalysis = await runLLMAnalysis(result);
  }

  return result;
}

export default {
  runRecon,
  enumerateEmployees: enumerateEmployeesLive,
  enumerateSubdomains: enumerateSubdomainsLive,
  inferEmailPatterns,
  checkBreaches: checkBreachesLive,
  enumerateDNSLive,
  collectWHOISLive,
  detectTechStackLive,
};
