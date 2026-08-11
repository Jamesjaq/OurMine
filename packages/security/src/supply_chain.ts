import { resolveDryRun } from "./exec_options.ts"
import * as fs from "node:fs"
import * as path from "node:path"
/**
 * @module supply_chain
 * Supply Chain Security Auditing — npm/PyPI Registry API Queries, Dependency Confusion Detection,
 * Install Script Analysis, Download Count Comparison, and Typosquatting Pattern Database.
 */

export interface SupplyChainAuditResult {
  packageName: string;
  isTyposquat: boolean;
  typosquatMatches: string[];
  dependencyConfusionRisk: boolean;
  suspiciousInstallScripts: boolean;
  installScripts: InstallScript[];
  downloadCountAnomaly: boolean;
  downloadCountRatio: number;
  registryAge: string;
  maintainers: string[];
  issues: SupplyChainIssue[];
}

export interface InstallScript {
  scriptName: string;
  command: string;
  riskLevel: "low" | "medium" | "high" | "critical";
  flags: string[];
}

export interface SupplyChainIssue {
  severity: "info" | "low" | "medium" | "high" | "critical";
  category: string;
  description: string;
  evidence?: string;
}

export interface RegistryPackageInfo {
  name: string;
  version: string;
  description: string;
  author?: string;
  maintainers: { name: string; email?: string }[];
  created: string;
  modified: string;
  downloads?: { daily: number; weekly: number; monthly: number };
  versions: Record<string, unknown>;
  scripts?: Record<string, string>;
  dependencies?: Record<string, string>;
  repository?: { url: string };
  dist: { tarball: string; unpackedSize: number };
}

const TYPOSQUAT_PATTERNS: { pattern: RegExp; legitimate: string; confidence: number }[] = [
  { pattern: /^reqe?usts?$/, legitimate: "requests", confidence: 0.95 },
  { pattern: /^reqe?sts?$/, legitimate: "requests", confidence: 0.95 },
  { pattern: /^react-doms?$/, legitimate: "react-dom", confidence: 0.95 },
  { pattern: /^lodashs$/, legitimate: "lodash", confidence: 0.9 },
  { pattern: /^expres?s$/, legitimate: "express", confidence: 0.9 },
  { pattern: /^momentjs$/, legitimate: "moment", confidence: 0.85 },
  { pattern: /^axioss$/, legitimate: "axios", confidence: 0.9 },
  { pattern: /^webpackk$/, legitimate: "webpack", confidence: 0.95 },
  { pattern: /^baberl$/, legitimate: "babel", confidence: 0.9 },
  { pattern: /^eslintt$/, legitimate: "eslint", confidence: 0.95 },
  { pattern: /^prettii?er$/, legitimate: "prettier", confidence: 0.9 },
  { pattern: /^typescriptt$/, legitimate: "typescript", confidence: 0.95 },
  { pattern: /^nodess$/, legitimate: "node", confidence: 0.85 },
  { pattern: /^reactt$/, legitimate: "react", confidence: 0.95 },
  { pattern: /^vuejs-?core$/, legitimate: "vue", confidence: 0.8 },
  { pattern: /^angular-?cli$/, legitimate: "@angular/cli", confidence: 0.7 },
  { pattern: /^aws-sdkd$/, legitimate: "aws-sdk", confidence: 0.95 },
  { pattern: /^mysql-?clientt$/, legitimate: "mysql", confidence: 0.9 },
  { pattern: /^mongose$/, legitimate: "mongoose", confidence: 0.95 },
  { pattern: /^flaskk$/, legitimate: "flask", confidence: 0.95 },
  { pattern: /^djangoo$/, legitimate: "django", confidence: 0.95 },
  { pattern: /^numpyy$/, legitimate: "numpy", confidence: 0.95 },
  { pattern: /^pandass$/, legitimate: "pandas", confidence: 0.95 },
  { pattern: /^scipyy$/, legitimate: "scipy", confidence: 0.95 },
  { pattern: /^pilllow$/, legitimate: "Pillow", confidence: 0.9 },
  { pattern: /^beautifulsoup4$/, legitimate: "beautifulsoup4", confidence: 0.7 },
  { pattern: /^cryptog$/, legitimate: "pycryptodome", confidence: 0.8 },
  { pattern: /^requestss$/, legitimate: "requests", confidence: 0.95 },
  { pattern: /^coloramaj$/, legitimate: "colorama", confidence: 0.9 },
  { pattern: /^idnna$/, legitimate: "idna", confidence: 0.9 },
  { pattern: /^certii$/, legitimate: "certifi", confidence: 0.95 },
];

/** Packages flagged in STARDUST CHOLLI / GlassWorm / Shai-Hulud npm campaigns (2025–2026) */
const KNOWN_POISON_INDICATORS: { pattern: RegExp; campaign: string; severity: SupplyChainIssue["severity"] }[] = [
  { pattern: /^easy-day-js$/i, campaign: "APT38/Mastra supply chain (STARDUST CHOLLI)", severity: "critical" },
  { pattern: /^@mastra\//i, campaign: "Mastra framework poison — verify integrity", severity: "high" },
  { pattern: /glassworm|shai-?hulud|trufflehog/i, campaign: "GlassWorm/Shai-Hulud npm worm", severity: "critical" },
  { pattern: /^node-fetch-?native$/i, campaign: "Known typosquat variant", severity: "high" },
  { pattern: /^crossenv$/i, campaign: "cross-env typosquat (historical npm worm)", severity: "critical" },
  { pattern: /^event-?stream$/i, campaign: "event-stream supply chain attack", severity: "critical" },
  { pattern: /^ua-parser-?js$/i, campaign: "ua-parser-js compromise", severity: "critical" },
];

const HIGH_RISK_SCRIPT_PATTERNS: { regex: RegExp; description: string; severity: InstallScript["riskLevel"] }[] = [
  { regex: /\bcurl\b.*\|\s*(?:ba)?sh/i, description: "Downloads and pipes script to shell", severity: "critical" },
  { regex: /\bwget\b.*\|\s*(?:ba)?sh/i, description: "Downloads and pipes script to shell", severity: "critical" },
  { regex: /\bnode\s+-e\s+['"]/i, description: "Executes inline Node.js code", severity: "medium" },
  { regex: /\bpython[23]?\s+-c\s+['"]/i, description: "Executes inline Python code", severity: "medium" },
  { regex: /\beval\s*\(/i, description: "Uses eval() for dynamic code execution", severity: "medium" },
  { regex: /\bexec\s*\(/i, description: "Uses exec() for code execution", severity: "medium" },
  { regex: /\bchild_process\b/i, description: "Uses child_process module", severity: "medium" },
  { regex: /\bspawn\b|\bfork\b|\bexecSync\b|\bexecFileSync\b/i, description: "Spawns child processes", severity: "medium" },
  { regex: /\bchmod\s+[0-7]*7[0-7]*\s+/i, description: "Sets world-writable or executable permissions", severity: "high" },
  { regex: /\bchown\s+.*root/i, description: "Changes ownership to root", severity: "high" },
  { regex: /\b\/etc\/passwd\b|\b\/etc\/shadow\b/i, description: "Accesses sensitive system files", severity: "critical" },
  { regex: /\bsudo\b/i, description: "Uses sudo for privilege escalation", severity: "high" },
  { regex: /\brm\s+-rf\s+\//i, description: "Recursive deletion from root", severity: "critical" },
  { regex: /\bmkfs\b|\bdd\s+if=/i, description: "Formats disk or writes raw disk image", severity: "critical" },
  { regex: /\bnc\s+-l|\bncat\b|\bsocat\b/i, description: "Opens network listener", severity: "high" },
  { regex: /\biptables\b/i, description: "Modifies firewall rules", severity: "high" },
  { regex: /\bcron\b|\bcrontab\b/i, description: "Installs cron jobs", severity: "high" },
  { regex: /\bsystemctl\b|\bsystemd\b/i, description: "Creates systemd services", severity: "high" },
  { regex: /\breg\s+add\b|\bregedit\b/i, description: "Modifies Windows registry", severity: "high" },
  { regex: /\bPowerShell\b.*-enc/i, description: "Executes encoded PowerShell commands", severity: "critical" },
  { regex: /\bInvoke-Expression\b|\bIEX\b/i, description: "PowerShell dynamic code execution", severity: "high" },
  { regex: /\bbase64\s+-d\s*\|\s*(?:ba)?sh/i, description: "Decodes and executes base64 payload", severity: "critical" },
  { regex: /\bxor\b.*\bexec\b|\bexec\b.*\bxor\b/i, description: "XOR-encoded execution pattern", severity: "high" },
  { regex: /\benv\b.*\bHTTP_PROXY\b/i, description: "Sets HTTP proxy environment", severity: "low" },
  { regex: /\bnpm\s+config\s+set\s+proxy/i, description: "Configures npm proxy", severity: "low" },
  { regex: /\bhttps?:\/\/[^\s]+\.(exe|dll|bat|cmd|ps1|vbs|js|wsf)\b/i, description: "Downloads executable files", severity: "high" },
];

const DEPENDENCY_CONFUSION_INDICATORS: { test: (pkg: RegistryPackageInfo, scope?: string) => boolean; description: string; severity: SupplyChainIssue["severity"] }[] = [
  {
    test: (pkg) => (pkg.downloads?.daily ?? 0) < 100 && !pkg.description,
    description: "Low download count with no description — possible placeholder for dependency confusion",
    severity: "high",
  },
  {
    test: (pkg, scope) => Boolean(scope) && pkg.name.startsWith("@") && !pkg.maintainers.some((m) => m.name.includes(scope ?? "")),
    description: "Scoped package with unrelated maintainer namespace",
    severity: "medium",
  },
  {
    test: (pkg) => {
      const age = Date.now() - new Date(pkg.created).getTime();
      return age < 30 * 24 * 60 * 60 * 1000 && (pkg.downloads?.daily ?? 0) < 50;
    },
    description: "Recently published with minimal downloads — potential confusion package",
    severity: "high",
  },
  {
    test: (pkg) => (pkg.dist?.unpackedSize ?? 0) < 1024,
    description: "Extremely small package size — possible placeholder package",
    severity: "medium",
  },
  {
    test: (pkg) => Boolean(pkg.scripts?.preinstall || pkg.scripts?.install || pkg.scripts?.postinstall),
    description: "Package has install scripts — analyze for malicious behavior",
    severity: "medium",
  },
];

async function fetchNpmPackageInfo(packageName: string, dryRun = false): Promise<RegistryPackageInfo | null> {
  if (dryRun) return null

  try {
    const url = `https://registry.npmjs.org/${encodeURIComponent(packageName)}`;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);
    const response = await fetch(url, {
      headers: { Accept: "application/vnd.npm.install-v1+json" },
      signal: controller.signal,
    });
    clearTimeout(timeout);

    if (!response.ok) return null;
    const data = await response.json();

    const latestVersion = data["dist-tags"]?.latest;
    if (!latestVersion) return null;

    const versions = data.versions ?? {};
    const latest = versions[latestVersion];
    if (!latest) return null;

    const dist = latest.dist ?? {};
    const times = data.time ?? {};

    return {
      name: data.name ?? packageName,
      version: latestVersion,
      description: latest.description ?? data.description ?? "",
      author: latest.author?.name ?? latest.author ?? "",
      maintainers: (latest.maintainers ?? data.maintainers ?? []).map((m: { name: string; email?: string }) => ({
        name: m.name,
        email: m.email,
      })),
      created: times.created ?? "",
      modified: times.modified ?? "",
      downloads: undefined,
      versions: Object.keys(versions),
      scripts: latest.scripts ?? {},
      dependencies: latest.dependencies ?? {},
      repository: latest.repository ?? undefined,
      dist: {
        tarball: dist.tarball ?? "",
        unpackedSize: dist.unpackedSize ?? 0,
      },
    };
  } catch {
    return null;
  }
}

async function fetchPypiPackageInfo(packageName: string, dryRun = false): Promise<RegistryPackageInfo | null> {
  if (dryRun) return null

  try {
    const url = `https://pypi.org/pypi/${encodeURIComponent(packageName)}/json`;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);
    const response = await fetch(url, { signal: controller.signal });
    clearTimeout(timeout);

    if (!response.ok) return null;
    const data = await response.json();

    const info = data.info ?? {};
    const releases = data.releases ?? {};
    const latestVersion = info.version;
    const latestRelease = releases[latestVersion]?.[0] ?? {};

    const requiresDist = info.requires_dist ?? [];

    return {
      name: info.name ?? packageName,
      version: latestVersion,
      description: info.summary ?? "",
      author: info.author ?? info.maintainer ?? "",
      maintainers: [{ name: info.author ?? info.maintainer ?? "unknown" }],
      created: "",
      modified: data.last_serial ? new Date(data.last_serial * 1000).toISOString() : "",
      downloads: undefined,
      versions: Object.keys(releases),
      scripts: {},
      dependencies: requiresDist.reduce((acc: Record<string, string>, dep: string) => {
        const match = dep.match(/^([a-zA-Z0-9_-]+)/);
        if (match) acc[match[1]] = dep;
        return acc;
      }, {}),
      dist: {
        tarball: latestRelease.url ?? "",
        unpackedSize: latestRelease.size ?? 0,
      },
    };
  } catch {
    return null;
  }
}

function analyzeInstallScripts(scripts: Record<string, string> = {}): InstallScript[] {
  const results: InstallScript[] = [];

  for (const [scriptName, command] of Object.entries(scripts)) {
    const flags: string[] = [];
    let maxSeverity: InstallScript["riskLevel"] = "low";

    for (const { regex, description, severity } of HIGH_RISK_SCRIPT_PATTERNS) {
      if (regex.test(command)) {
        flags.push(description);
        const severityOrder: Record<string, number> = { low: 0, medium: 1, high: 2, critical: 3 };
        if (severityOrder[severity] > severityOrder[maxSeverity]) {
          maxSeverity = severity;
        }
      }
    }

    results.push({ scriptName, command, riskLevel: maxSeverity, flags });
  }

  return results;
}

function detectTyposquatting(packageName: string): { isTyposquat: boolean; matches: string[] } {
  const matches: string[] = [];
  const lower = packageName.toLowerCase();

  for (const { pattern, legitimate, confidence } of TYPOSQUAT_PATTERNS) {
    if (pattern.test(lower) && lower !== legitimate.toLowerCase()) {
      matches.push(`${legitimate} (confidence: ${(confidence * 100).toFixed(0)}%)`);
    }
  }

  if (lower.length >= 4) {
    for (const { pattern, legitimate } of TYPOSQUAT_PATTERNS) {
      if (pattern.test(legitimate.toLowerCase()) && legitimate.toLowerCase() !== lower) {
        const levenshtein = computeLevenshtein(lower, legitimate.toLowerCase());
        if (levenshtein <= 2 && levenshtein > 0) {
          matches.push(`${legitimate} (Levenshtein distance: ${levenshtein})`);
        }
      }
    }
  }

  const seen = new Set<string>();
  const unique = matches.filter((m) => {
    const key = m.split(" ")[0];
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  return { isTyposquat: unique.length > 0, matches: unique };
}

function computeLevenshtein(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0) as number[]);

  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost);
    }
  }

  return dp[m][n];
}

function detectDependencyConfusion(pkg: RegistryPackageInfo, registry: "npm" | "pypi"): SupplyChainIssue[] {
  const issues: SupplyChainIssue[] = [];

  for (const { test, description, severity } of DEPENDENCY_CONFUSION_INDICATORS) {
    if (test(pkg)) {
      issues.push({ severity, category: "dependency_confusion", description });
    }
  }

  const scope = pkg.name.startsWith("@") ? pkg.name.split("/")[0]?.substring(1) : undefined;
  for (const { test, description, severity } of DEPENDENCY_CONFUSION_INDICATORS) {
    if (test(pkg, scope)) {
      const exists = issues.some((i) => i.description === description);
      if (!exists) {
        issues.push({ severity, category: "dependency_confusion", description, evidence: `Scope: ${scope}` });
      }
    }
  }

  return issues;
}

function analyzeDownloadCounts(pkgInfo: RegistryPackageInfo): { anomaly: boolean; ratio: number } {
  const downloads = pkgInfo.downloads;
  if (!downloads) return { anomaly: false, ratio: 1 };

  const dailyAvg = downloads.weekly / 7;
  const monthlyAvg = downloads.monthly / 30;

  if (dailyAvg === 0) return { anomaly: true, ratio: 0 };

  const ratio = monthlyAvg / dailyAvg;
  const expectedRatio = 30;
  const anomaly = ratio < expectedRatio * 0.3 || ratio > expectedRatio * 3;

  return { anomaly, ratio };
}

export async function auditPackage(
  name: string,
  registry: "npm" | "pypi" = "npm",
  options: { dryRun?: boolean; scope?: string } = {}
): Promise<SupplyChainAuditResult> {
  const { dryRun = false, scope } = options;

  const pkgInfo = registry === "npm"
    ? await fetchNpmPackageInfo(name, dryRun)
    : await fetchPypiPackageInfo(name, dryRun);

  const typosquat = detectTyposquatting(name);

  if (!pkgInfo) {
    const issues: SupplyChainIssue[] = dryRun
      ? (typosquat.isTyposquat
        ? [{ severity: "critical", category: "typosquatting", description: "Package name resembles known popular packages (local heuristic)", evidence: typosquat.matches.join(", ") }]
        : [{ severity: "info", category: "registry", description: "Dry-run: registry fetch skipped — set live:true for full audit" }])
      : [{ severity: "medium", category: "registry", description: "Package not found in registry" }];
    return {
      packageName: name,
      isTyposquat: typosquat.isTyposquat,
      typosquatMatches: typosquat.matches,
      dependencyConfusionRisk: false,
      suspiciousInstallScripts: false,
      installScripts: [],
      downloadCountAnomaly: false,
      downloadCountRatio: 1,
      registryAge: "unknown",
      maintainers: [],
      issues,
    };
  }

  // pkgInfo available — full audit

  const installScripts = analyzeInstallScripts(pkgInfo.scripts);
  const suspiciousInstallScripts = installScripts.some((s) => s.riskLevel === "high" || s.riskLevel === "critical");

  const confusionIssues = detectDependencyConfusion(pkgInfo, registry);
  const dependencyConfusionRisk = confusionIssues.some((i) => i.severity === "high" || i.severity === "critical");

  const downloadAnalysis = analyzeDownloadCounts(pkgInfo);

  const ageMs = pkgInfo.created ? Date.now() - new Date(pkgInfo.created).getTime() : 0;
  const ageDays = Math.floor(ageMs / (24 * 60 * 60 * 1000));
  const registryAge = pkgInfo.created ? `${ageDays} days` : "unknown";

  const allIssues: SupplyChainIssue[] = [...confusionIssues];

  if (typosquat.isTyposquat) {
    allIssues.push({
      severity: "critical",
      category: "typosquatting",
      description: `Package name resembles known popular packages`,
      evidence: typosquat.matches.join(", "),
    });
  }

  if (suspiciousInstallScripts) {
    const critical = installScripts.filter((s) => s.riskLevel === "critical" || s.riskLevel === "high");
    allIssues.push({
      severity: critical[0]?.riskLevel === "critical" ? "critical" : "high",
      category: "install_script",
      description: `Suspicious install scripts detected: ${critical.map((s) => s.scriptName).join(", ")}`,
      evidence: critical.map((s) => s.flags.join("; ")).join(" | "),
    });
  }

  if (downloadAnalysis.anomaly) {
    allIssues.push({
      severity: "medium",
      category: "download_anomaly",
      description: "Download count pattern is anomalous — possible manipulation",
      evidence: `Ratio: ${downloadAnalysis.ratio.toFixed(2)} (expected ~30)`,
    });
  }

  if (ageDays < 30 && (pkgInfo.downloads?.daily ?? 0) < 100) {
    allIssues.push({
      severity: "low",
      category: "new_package",
      description: "Recently published package with low adoption",
    });
  }

  if (pkgInfo.maintainers.length === 0) {
    allIssues.push({
      severity: "medium",
      category: "unmaintained",
      description: "Package has no listed maintainers",
    });
  }

  return {
    packageName: name,
    isTyposquat: typosquat.isTyposquat,
    typosquatMatches: typosquat.matches,
    dependencyConfusionRisk,
    suspiciousInstallScripts,
    installScripts,
    downloadCountAnomaly: downloadAnalysis.anomaly,
    downloadCountRatio: downloadAnalysis.ratio,
    registryAge,
    maintainers: pkgInfo.maintainers.map((m) => m.name),
    issues: allIssues,
  };
}

export async function auditPackageList(
  packages: { name: string; registry?: "npm" | "pypi" }[],
  options: { dryRun?: boolean; parallel?: number } = {}
): Promise<SupplyChainAuditResult[]> {
  const { dryRun = false, parallel = 5 } = options;
  const results: SupplyChainAuditResult[] = [];

  for (let i = 0; i < packages.length; i += parallel) {
    const batch = packages.slice(i, i + parallel);
    const batchResults = await Promise.all(
      batch.map((pkg) => auditPackage(pkg.name, pkg.registry ?? "npm", { dryRun }))
    );
    results.push(...batchResults);
  }

  return results;
}

/** MCP alias — maps package/ecosystem/mode to auditPackage */
export async function analyze(opts: {
  package: string;
  ecosystem?: "npm" | "pypi" | string;
  mode?: "detect" | "audit" | string;
  live?: boolean;
}): Promise<SupplyChainAuditResult> {
  const registry = opts.ecosystem === "pypi" ? "pypi" : "npm";
  return auditPackage(opts.package, registry, { dryRun: !(opts.live ?? false) });
}

export default { auditPackage, auditPackageList, analyze, scanLockfile };

// ─── Lockfile scanning (STARDUST / npm worm detection) ────────────────────────

export interface LockfileScanResult {
  lockfilePath: string
  packageCount: number
  poisonHits: Array<{ name: string; version: string; campaign: string; severity: string }>
  typosquatHits: SupplyChainAuditResult[]
  suspiciousScripts: SupplyChainAuditResult[]
  criticalCount: number
  highCount: number
  issues: SupplyChainIssue[]
  dryRun: boolean
}

function extractPackagesFromLockfile(content: string, filePath: string): Array<{ name: string; version: string }> {
  const packages = new Map<string, string>()
  try {
    const data = JSON.parse(content) as {
      packages?: Record<string, { version?: string }>
      dependencies?: Record<string, { version?: string }>
    }
    if (data.packages) {
      for (const [key, val] of Object.entries(data.packages)) {
        const name = key.replace(/^node_modules\//, "").split("node_modules/").pop() ?? key
        if (name && val.version) packages.set(name, val.version)
      }
    }
    if (data.dependencies) {
      for (const [name, val] of Object.entries(data.dependencies)) {
        if (val.version) packages.set(name, val.version)
      }
    }
  } catch {
    // package-lock v1 or shrinkwrap — regex fallback
    const nameVer = content.matchAll(/"([^"@/][^"]*)":\s*\{\s*"version":\s*"([^"]+)"/g)
    for (const m of nameVer) {
      if (m[1] && m[2]) packages.set(m[1], m[2])
    }
  }
  if (packages.size === 0 && filePath.endsWith("package.json")) {
    try {
      const pkg = JSON.parse(content) as { dependencies?: Record<string, string>; devDependencies?: Record<string, string> }
      for (const [n, v] of Object.entries({ ...pkg.dependencies, ...pkg.devDependencies })) {
        packages.set(n, v.replace(/^[\^~]/, ""))
      }
    } catch { /* ignore */ }
  }
  return [...packages.entries()].map(([name, version]) => ({ name, version }))
}

function checkPoisonIndicators(name: string): { campaign: string; severity: SupplyChainIssue["severity"] } | null {
  for (const ind of KNOWN_POISON_INDICATORS) {
    if (ind.pattern.test(name)) return { campaign: ind.campaign, severity: ind.severity }
  }
  return null
}

/**
 * Scan package-lock.json / npm-shrinkwrap / package.json for STARDUST-style poison packages.
 * Live mode audits each dependency against npm registry.
 */
export async function scanLockfile(
  lockfilePath: string,
  options: { live?: boolean; maxAudit?: number } = {},
): Promise<LockfileScanResult> {
  const live = options.live ?? false
  const maxAudit = options.maxAudit ?? 50
  const resolved = path.resolve(lockfilePath)

  if (!fs.existsSync(resolved)) {
    return {
      lockfilePath: resolved,
      packageCount: 0,
      poisonHits: [],
      typosquatHits: [],
      suspiciousScripts: [],
      criticalCount: 0,
      highCount: 0,
      issues: [{ severity: "medium", category: "lockfile", description: `File not found: ${resolved}` }],
      dryRun: !live,
    }
  }

  const content = fs.readFileSync(resolved, "utf8")
  const deps = extractPackagesFromLockfile(content, resolved)
  const poisonHits: LockfileScanResult["poisonHits"] = []
  const issues: SupplyChainIssue[] = []

  for (const { name, version } of deps) {
    const poison = checkPoisonIndicators(name)
    if (poison) {
      poisonHits.push({ name, version, campaign: poison.campaign, severity: poison.severity })
      issues.push({
        severity: poison.severity,
        category: "known_poison",
        description: `Known supply-chain poison indicator: ${name}@${version}`,
        evidence: poison.campaign,
      })
    }
  }

  const toAudit = deps
    .filter((d) => !poisonHits.some((p) => p.name === d.name))
    .slice(0, maxAudit)

  const auditResults = await auditPackageList(
    toAudit.map((d) => ({ name: d.name, registry: "npm" as const })),
    { dryRun: !live, parallel: 5 },
  )

  const typosquatHits = auditResults.filter((r) => r.isTyposquat)
  const suspiciousScripts = auditResults.filter((r) => r.suspiciousInstallScripts)

  for (const r of typosquatHits) {
    issues.push({
      severity: "critical",
      category: "typosquatting",
      description: `Typosquat in lockfile: ${r.packageName}`,
      evidence: r.typosquatMatches.join(", "),
    })
  }
  for (const r of suspiciousScripts) {
    issues.push({
      severity: "high",
      category: "install_script",
      description: `Suspicious install scripts: ${r.packageName}`,
      evidence: r.installScripts.map((s) => s.scriptName).join(", "),
    })
  }

  const criticalCount = issues.filter((i) => i.severity === "critical").length
  const highCount = issues.filter((i) => i.severity === "high").length

  return {
    lockfilePath: resolved,
    packageCount: deps.length,
    poisonHits,
    typosquatHits,
    suspiciousScripts,
    criticalCount,
    highCount,
    issues,
    dryRun: !live,
  }
}
