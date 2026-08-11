/**
 * @module security/validation_planner
 * ValidationPlanner — bridges a detected finding to a safe, authorized validation plan.
 *
 * Architecture:
 *   VulnNode (suspected) → ValidationCapabilityRegistry.lookup()
 *                        → ValidationPlan (or null = UNVERIFIED, reason given)
 *                        → ValidationEngine.execute(plan)
 *
 * The LLM does NOT invent validation commands.
 * All validators are registered, typed, and pre-authorized as non-destructive.
 */

export type ValidationStrategy =
  | "HTTP_PROBE"        // HTTP request → response characteristic check
  | "TLS_PROBE"         // TLS handshake → cert/protocol observation
  | "SERVICE_BANNER"    // TCP connect → banner grab
  | "HOST_INSPECT"      // Read-only local filesystem/sysfs check
  | "NMAP_SCRIPT"       // Bounded nmap --script probe
  | "DNS_PROBE"         // DNS query → response check

export type ValidationRisk = "none" | "low" | "medium"

export interface ValidationCapability {
  id:               string
  name:             string
  strategy:         ValidationStrategy
  /** Nuclei template IDs, service names, or keyword patterns this validator handles */
  matchPatterns:    string[]
  requiredTool:     string
  riskLevel:        ValidationRisk
  destructive:      false          // only false allowed in registry
  supportedProtocols: string[]
  timeoutMs:        number
}

export interface ValidationPlan {
  planId:         string
  findingId:      string
  capabilityId:   string
  strategy:       ValidationStrategy
  target:         string           // ip:port
  command?:       string           // for shell-based validators
  httpOptions?: {                  // for HTTP_PROBE
    method:       string
    path:         string
    headers?:     Record<string, string>
    body?:        string
    expectedStatus?: number
    expectedBodyContains?: string
    expectedBodyAbsent?: string
  }
  tlsOptions?: {                   // for TLS_PROBE
    minTlsVersion?: string
    checkCert?: boolean
  }
  timeoutMs:      number
  destructive:    false
  authorizedScope: string          // must match AttackSurfaceGraph.target
  fingerprint:    string           // SHA-256(findingId+target+capabilityId) for idempotency
  createdAt:      string
}

export type ValidationOutcome =
  | "VALIDATION_SUCCESS"     // evidence supports the finding
  | "VALIDATION_NEGATIVE"    // evidence contradicts the finding
  | "VALIDATION_FAILED"      // validator threw / errored
  | "VALIDATION_TIMEOUT"     // exceeded timeoutMs
  | "VALIDATION_UNAVAILABLE" // required tool not present
  | "OUT_OF_SCOPE"           // target not in authorized scope

export interface ValidationResult {
  planId:         string
  findingId:      string
  outcome:        ValidationOutcome
  evidence:       string           // raw response/output excerpt
  executionMs:    number
  timestamp:      string
  /** Human-readable interpretation */
  reasoning:      string
}

// ─── Capability Registry ──────────────────────────────────────────────────────

const CAPABILITY_REGISTRY: ValidationCapability[] = [
  // ── HTTP: generic probe ───────────────────────────────────────────────────
  {
    id:                 "http-200-probe",
    name:               "HTTP 200 Response Probe",
    strategy:           "HTTP_PROBE",
    matchPatterns:      ["http", "http-alt", "http-proxy", "tomcat", "apache", "nginx", "iis"],
    requiredTool:       "curl",
    riskLevel:          "none",
    destructive:        false,
    supportedProtocols: ["http", "https"],
    timeoutMs:          5_000,
  },
  // ── HTTP: admin path exposure ─────────────────────────────────────────────
  {
    id:                 "http-admin-path",
    name:               "HTTP Admin Path Probe",
    strategy:           "HTTP_PROBE",
    matchPatterns:      ["admin", "phpmyadmin", "wp-admin", "manager", "console", "dashboard"],
    requiredTool:       "curl",
    riskLevel:          "none",
    destructive:        false,
    supportedProtocols: ["http", "https"],
    timeoutMs:          5_000,
  },
  // ── TLS: version & cert ───────────────────────────────────────────────────
  {
    id:                 "tls-version-check",
    name:               "TLS Version & Certificate Probe",
    strategy:           "TLS_PROBE",
    matchPatterns:      ["ssl", "tls", "https", "weak-tls", "expired-cert"],
    requiredTool:       "nmap",
    riskLevel:          "none",
    destructive:        false,
    supportedProtocols: ["https", "ssl"],
    timeoutMs:          8_000,
  },
  // ── Service banner: generic ───────────────────────────────────────────────
  {
    id:                 "service-banner",
    name:               "Service Banner Grab",
    strategy:           "SERVICE_BANNER",
    matchPatterns:      ["ssh", "ftp", "smtp", "pop3", "imap", "telnet"],
    requiredTool:       "nmap",
    riskLevel:          "none",
    destructive:        false,
    supportedProtocols: ["tcp"],
    timeoutMs:          6_000,
  },
  // ── Nmap: MySQL auth ──────────────────────────────────────────────────────
  {
    id:                 "mysql-empty-password",
    name:               "MySQL Empty Password Check",
    strategy:           "NMAP_SCRIPT",
    matchPatterns:      ["mysql", "mysql-empty-password", "3306"],
    requiredTool:       "nmap",
    riskLevel:          "low",
    destructive:        false,
    supportedProtocols: ["mysql"],
    timeoutMs:          8_000,
  },
  // ── Host: LD_PRELOAD rootkit ──────────────────────────────────────────────
  {
    id:                 "host-ldpreload",
    name:               "LD_PRELOAD Rootkit Check",
    strategy:           "HOST_INSPECT",
    matchPatterns:      ["ld-preload", "rootkit", "ebpf", "preload-hook"],
    requiredTool:       "local-fs",
    riskLevel:          "none",
    destructive:        false,
    supportedProtocols: ["host"],
    timeoutMs:          1_000,
  },
  // ── DNS: zone transfer ────────────────────────────────────────────────────
  {
    id:                 "dns-zone-transfer",
    name:               "DNS Zone Transfer Check",
    strategy:           "DNS_PROBE",
    matchPatterns:      ["dns", "zone-transfer", "axfr", "domain"],
    requiredTool:       "dig",
    riskLevel:          "none",
    destructive:        false,
    supportedProtocols: ["dns"],
    timeoutMs:          5_000,
  },
  // ── Log4Shell (CVE-2021-44228) ────────────────────────────────────────────
  {
    id:                 "log4j-version-probe",
    name:               "Log4Shell Version Header Probe",
    strategy:           "HTTP_PROBE",
    matchPatterns:      ["log4j", "log4shell", "apache-log4j-rce", "CVE-2021-44228"],
    requiredTool:       "curl",
    riskLevel:          "none",
    destructive:        false,
    supportedProtocols: ["http", "https"],
    timeoutMs:          5_000,
  },
  // ── SSRF: internal metadata probe ─────────────────────────────────────────
  {
    id:                 "ssrf-metadata-probe",
    name:               "SSRF Metadata Endpoint Probe",
    strategy:           "HTTP_PROBE",
    matchPatterns:      ["ssrf", "server-side-request", "metadata", "169.254.169.254"],
    requiredTool:       "curl",
    riskLevel:          "low",
    destructive:        false,
    supportedProtocols: ["http", "https"],
    timeoutMs:          5_000,
  },
  // ── SQLi: error-based response diff ───────────────────────────────────────
  {
    id:                 "sqli-error-probe",
    name:               "SQL Injection Error Probe",
    strategy:           "HTTP_PROBE",
    matchPatterns:      ["sqli", "sql-injection", "sqlmap", "mysql-error", "syntax-error"],
    requiredTool:       "curl",
    riskLevel:          "low",
    destructive:        false,
    supportedProtocols: ["http", "https"],
    timeoutMs:          5_000,
  },
  // ── Auth bypass: unauthenticated admin access ─────────────────────────────
  {
    id:                 "auth-bypass-probe",
    name:               "Authentication Bypass Probe",
    strategy:           "HTTP_PROBE",
    matchPatterns:      ["auth-bypass", "unauthenticated", "broken-auth", "idor"],
    requiredTool:       "curl",
    riskLevel:          "none",
    destructive:        false,
    supportedProtocols: ["http", "https"],
    timeoutMs:          5_000,
  },
]

// ─── ValidationPlanner ───────────────────────────────────────────────────────

import * as crypto from "node:crypto"

export class ValidationPlanner {

  /** Look up the best capability for a finding */
  static lookupCapability(
    findingId: string,
    service: string,
    templateId: string,
  ): ValidationCapability | null {
    const search = [service.toLowerCase(), templateId.toLowerCase()].join(" ")
    return (
      CAPABILITY_REGISTRY.find(cap =>
        cap.matchPatterns.some(p => search.includes(p.toLowerCase()))
      ) ?? null
    )
  }

  /**
   * Plan validation for a suspected finding.
   * Returns null when no safe validator exists — caller must mark UNVERIFIED.
   */
  static plan(opts: {
    findingId:      string
    templateId:     string
    service:        string
    target:         string   // "ip:port"
    authorizedScope: string  // graph.target — must match for auth
    protocol?:      string
  }): { plan: ValidationPlan; capability: ValidationCapability } | { plan: null; reason: string } {

    // 1. Scope check — target must be within authorized scope
    if (!opts.target.startsWith(opts.authorizedScope) &&
        !opts.authorizedScope.startsWith(opts.target.split(":")[0]!)) {
      return { plan: null, reason: `OUT_OF_SCOPE: ${opts.target} not in authorized scope ${opts.authorizedScope}` }
    }

    // 2. Find capability
    const cap = this.lookupCapability(opts.findingId, opts.service, opts.templateId)
    if (!cap) {
      return { plan: null, reason: `NO_VALIDATOR: no non-destructive validator registered for service='${opts.service}' template='${opts.templateId}'` }
    }

    // 3. Fingerprint (idempotency key)
    const fingerprint = crypto
      .createHash("sha256")
      .update(`${opts.findingId}:${opts.target}:${cap.id}`)
      .digest("hex")

    // 4. Build plan
    const [ip, portStr] = opts.target.split(":")
    const port = portStr ? parseInt(portStr, 10) : 80
    const protocol = opts.protocol ?? (port === 443 ? "https" : "http")

    let plan: ValidationPlan = {
      planId:          crypto.randomUUID(),
      findingId:       opts.findingId,
      capabilityId:    cap.id,
      strategy:        cap.strategy,
      target:          opts.target,
      timeoutMs:       cap.timeoutMs,
      destructive:     false,
      authorizedScope: opts.authorizedScope,
      fingerprint,
      createdAt:       new Date().toISOString(),
    }

    // Strategy-specific configuration
    if (cap.strategy === "HTTP_PROBE") {
      plan.httpOptions = {
        method:  "GET",
        path:    "/",
        headers: { "User-Agent": "OurMine-Validator/1.0", "Connection": "close" },
        expectedStatus: 200,
      }
      if (cap.matchPatterns.some(p => ["log4j", "log4shell", "CVE-2021-44228"].includes(p))) {
        plan.httpOptions.path = "/"
        plan.httpOptions.expectedBodyAbsent = "log4j"  // safe: just checking headers
      }
      if (cap.matchPatterns.some(p => ["admin", "wp-admin", "phpmyadmin", "manager"].includes(p))) {
        plan.httpOptions.path = "/admin/"
        plan.httpOptions.expectedStatus = undefined   // any response = path exists
      }
      plan.command = `curl -sv --max-time ${cap.timeoutMs / 1000} -o /dev/null -w "%{http_code} %{size_download}" ${protocol}://${opts.target}${plan.httpOptions.path} 2>&1`
    } else if (cap.strategy === "TLS_PROBE") {
      plan.command = `nmap --script ssl-enum-ciphers,ssl-cert -p ${port} ${ip} --open`
      plan.tlsOptions = { checkCert: true, minTlsVersion: "TLSv1.2" }
    } else if (cap.strategy === "SERVICE_BANNER") {
      plan.command = `nmap -sV -p ${port} ${ip} --open`
    } else if (cap.strategy === "NMAP_SCRIPT") {
      if (cap.id === "mysql-empty-password") {
        plan.command = `nmap --script mysql-empty-password -p ${port} ${ip}`
      }
    } else if (cap.strategy === "HOST_INSPECT") {
      plan.command = undefined  // handled entirely by ValidationEngine local file reads
    } else if (cap.strategy === "DNS_PROBE") {
      plan.command = `dig AXFR @${ip} ${opts.authorizedScope} 2>&1`
    }

    return { plan, capability: cap }
  }

  static listCapabilities(): ValidationCapability[] {
    return [...CAPABILITY_REGISTRY]
  }
}

export default ValidationPlanner
