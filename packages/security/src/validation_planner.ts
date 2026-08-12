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
  | "HTTP_STATE_FUZZ"   // Session-aware multi-step HTTP state machine fuzz
  | "L3_BYPASS"         // L3 control-bypass proof within safety envelope
  | "L4_CONTROLLED_IMPACT" // L4 bounded canary/impact proof (non-destructive)
  | "IDOR_BOLA"           // Multi-user IDOR/BOLA proof
  | "PRIVESC_PROOF"       // Controlled privesc flag read
  | "EXPLOIT_REPLAY"      // Exploit replay with rollback envelope
  | "MODBUS_PROBE"        // ICS Modbus FC3 read proof (non-destructive)
  | "DNP3_PROBE"          // ICS DNP3 link probe (non-destructive)
  | "BACNET_PROBE"        // ICS BACnet Who-Is probe (non-destructive)
  | "MQTT_PROBE"          // ICS MQTT CONNACK probe (non-destructive)
  | "COAP_PROBE"          // ICS CoAP discovery probe (non-destructive)
  | "S7_PROBE"            // ICS S7comm handshake probe (non-destructive)
  | "NUCLEI_PROBE"        // Nuclei template re-run for web vuln validation
  | "OAUTH_CONSENT_PROBE" // OAuth consent misconfiguration (policy only)
  | "DEVICE_CODE_PROBE"   // Device-code endpoint reachable (no token issuance)
  | "IAB_CRED_FORMAT"     // IAB credential format check (no login)

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
  stateFuzzFlowId?: string         // for HTTP_STATE_FUZZ / L3_BYPASS
  l3SafetyEnvelope?: "read_only" | "metadata_only"
  tlsOptions?: {                   // for TLS_PROBE
    minTlsVersion?: string
    checkCert?: boolean
  }
  timeoutMs:      number
  destructive:    false
  authorizedScope: string          // must match AttackSurfaceGraph.target
  fingerprint:    string           // SHA-256(findingId+target+capabilityId) for idempotency
  /** Service hint for icsValidationProbe routing (mqtt/coap/s7/modbus/…) */
  serviceHint?:   string
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
  // ── Nuclei: web template validation ───────────────────────────────────────
  {
    id:                 "nuclei-web-validate",
    name:               "Nuclei Template Validation",
    strategy:           "NUCLEI_PROBE",
    matchPatterns:      ["nuclei", "nuclei-vuln", "template-id", "log4j", "cve-", "http-admin-path"],
    requiredTool:       "nuclei",
    riskLevel:          "low",
    destructive:        false,
    supportedProtocols: ["http", "https"],
    timeoutMs:          30_000,
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
  // ── HTTP state machine fuzz (L2→L3) ───────────────────────────────────────
  {
    id:                 "http-state-fuzz",
    name:               "HTTP API State Machine Fuzzer",
    strategy:           "HTTP_STATE_FUZZ",
    matchPatterns:      ["api", "session", "oauth", "jwt", "rest", "graphql", "business-logic"],
    requiredTool:       "curl",
    riskLevel:          "low",
    destructive:        false,
    supportedProtocols: ["http", "https"],
    timeoutMs:          15_000,
  },
  // ── L3 control bypass proof ───────────────────────────────────────────────
  {
    id:                 "l3-bypass-proof",
    name:               "L3 Control Bypass Proof",
    strategy:           "L3_BYPASS",
    matchPatterns:      ["auth-bypass", "idor", "bola", "privilege-escalation", "access-control"],
    requiredTool:       "curl",
    riskLevel:          "low",
    destructive:        false,
    supportedProtocols: ["http", "https"],
    timeoutMs:          20_000,
  },
  // ── L4 controlled impact (canary read / bounded proof) ────────────────────
  {
    id:                 "l4-canary-impact",
    name:               "L4 Controlled Impact Proof",
    strategy:           "L4_CONTROLLED_IMPACT",
    matchPatterns:      ["remote-code-exec", "critical", "data-exposure", "sql-injection", "ssrf", "confirmed", "impact"],
    requiredTool:       "curl",
    riskLevel:          "low",
    destructive:        false,
    supportedProtocols: ["http", "https"],
    timeoutMs:          25_000,
  },
  {
    id:                 "idor-bola-proof",
    name:               "IDOR/BOLA Multi-User Proof",
    strategy:           "IDOR_BOLA",
    matchPatterns:      ["idor", "bola", "access-control", "object-level", "broken-access"],
    requiredTool:       "curl",
    riskLevel:          "low",
    destructive:        false,
    supportedProtocols: ["http", "https"],
    timeoutMs:          20_000,
  },
  {
    id:                 "privesc-flag-proof",
    name:               "Controlled Privesc Flag Proof",
    strategy:           "PRIVESC_PROOF",
    matchPatterns:      ["privesc", "privilege-escalation", "local-escalation", "sudo"],
    requiredTool:       "local-fs",
    riskLevel:          "low",
    destructive:        false,
    supportedProtocols: ["host"],
    timeoutMs:          10_000,
  },
  {
    id:                 "exploit-replay-envelope",
    name:               "Exploit Replay Rollback Envelope",
    strategy:           "EXPLOIT_REPLAY",
    matchPatterns:      ["remote-code-exec", "code-execution", "deserialization", "injection"],
    requiredTool:       "curl",
    riskLevel:          "low",
    destructive:        false,
    supportedProtocols: ["http", "https"],
    timeoutMs:          20_000,
  },
  {
    id:                 "modbus-register-read",
    name:               "Modbus Holding Register Read Proof",
    strategy:           "MODBUS_PROBE",
    matchPatterns:      ["modbus", "scada", "plc", "502"],
    requiredTool:       "modbus-tcp",
    riskLevel:          "none",
    destructive:        false,
    supportedProtocols: ["modbus", "tcp"],
    timeoutMs:          8_000,
  },
  {
    id:                 "dnp3-link-probe",
    name:               "DNP3 Link Layer Probe",
    strategy:           "DNP3_PROBE",
    matchPatterns:      ["dnp3", "20000", "outstation"],
    requiredTool:       "dnp3-tcp",
    riskLevel:          "none",
    destructive:        false,
    supportedProtocols: ["dnp3", "tcp"],
    timeoutMs:          10_000,
  },
  {
    id:                 "bacnet-whois-probe",
    name:               "BACnet Who-Is Probe",
    strategy:           "BACNET_PROBE",
    matchPatterns:      ["bacnet", "47808", "bms"],
    requiredTool:       "bacnet-udp",
    riskLevel:          "none",
    destructive:        false,
    supportedProtocols: ["bacnet", "udp"],
    timeoutMs:          8_000,
  },
  {
    id:                 "mqtt-connack-probe",
    name:               "MQTT CONNACK Probe",
    strategy:           "MQTT_PROBE",
    matchPatterns:      ["mqtt", "1883", "iot-broker"],
    requiredTool:       "mqtt-tcp",
    riskLevel:          "none",
    destructive:        false,
    supportedProtocols: ["mqtt", "tcp"],
    timeoutMs:          8_000,
  },
  {
    id:                 "coap-discovery-probe",
    name:               "CoAP Discovery Probe",
    strategy:           "COAP_PROBE",
    matchPatterns:      ["coap", "5683", "lwm2m"],
    requiredTool:       "coap-udp",
    riskLevel:          "none",
    destructive:        false,
    supportedProtocols: ["coap", "udp"],
    timeoutMs:          8_000,
  },
  {
    id:                 "s7comm-handshake-probe",
    name:               "S7comm Handshake Probe",
    strategy:           "S7_PROBE",
    matchPatterns:      ["s7", "siemens", "profinet", "102", "s7comm"],
    requiredTool:       "s7-tcp",
    riskLevel:          "none",
    destructive:        false,
    supportedProtocols: ["s7", "tcp"],
    timeoutMs:          10_000,
  },
  {
    id:                 "oauth-consent-probe",
    name:               "OAuth Consent Misconfiguration Probe",
    strategy:           "OAUTH_CONSENT_PROBE",
    matchPatterns:      ["oauth", "consent", "admin-consent", "multitenant", "openid"],
    requiredTool:       "curl",
    riskLevel:          "none",
    destructive:        false,
    supportedProtocols: ["http", "https"],
    timeoutMs:          8_000,
  },
  {
    id:                 "device-code-probe",
    name:               "OIDC Device Code Flow Probe",
    strategy:           "DEVICE_CODE_PROBE",
    matchPatterns:      ["device-code", "device_code", "oauth-device", "oidc-device", "T1528"],
    requiredTool:       "curl",
    riskLevel:          "none",
    destructive:        false,
    supportedProtocols: ["http", "https"],
    timeoutMs:          8_000,
  },
  {
    id:                 "iab-cred-format",
    name:               "IAB Credential Format Validator",
    strategy:           "IAB_CRED_FORMAT",
    matchPatterns:      ["iab", "stealer-log", "stealer_log", "vpn-session", "session_cookie", "citrix_aaacookie"],
    requiredTool:       "none",
    riskLevel:          "none",
    destructive:        false,
    supportedProtocols: ["any"],
    timeoutMs:          2_000,
  },
]

// ─── ValidationPlanner ───────────────────────────────────────────────────────

import * as crypto from "node:crypto"

/** Match capability tokens on word boundaries (avoids "protocol" → "ot", "log4j-rce" → bare "rce"). */
function patternMatches(search: string, pattern: string): boolean {
  const p = pattern.toLowerCase()
  if (!p) return false
  const re = new RegExp(`(?:^|[\\s_./:-])${p.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(?:$|[\\s_./:-])`)
  return re.test(` ${search.toLowerCase()} `)
}

export class ValidationPlanner {

  /** Look up the best capability for a finding */
  static lookupCapability(
    findingId: string,
    service: string,
    templateId: string,
  ): ValidationCapability | null {
    const svc = service.toLowerCase()
    const tpl = templateId.toLowerCase()
    const search = [svc, tpl, findingId.toLowerCase()].join(" ")
    const priority = ["L4_CONTROLLED_IMPACT", "L3_BYPASS", "IDOR_BOLA", "MODBUS_PROBE", "DNP3_PROBE", "BACNET_PROBE", "MQTT_PROBE", "COAP_PROBE", "S7_PROBE", "NUCLEI_PROBE", "EXPLOIT_REPLAY", "PRIVESC_PROOF", "HTTP_STATE_FUZZ", "NMAP_SCRIPT", "HTTP_PROBE"]
    const matches = CAPABILITY_REGISTRY.filter(cap =>
      cap.matchPatterns.some(p => patternMatches(search, p)),
    )
    if (!matches.length) return null
    const tplRank = (cap: ValidationCapability) =>
      cap.id === tpl || cap.matchPatterns.some(p => patternMatches(tpl, p)) ? 0 : 1
    matches.sort((a, b) => {
      const aTpl = tplRank(a)
      const bTpl = tplRank(b)
      if (aTpl !== bTpl) return aTpl - bTpl
      const aSvc = a.matchPatterns.some(p => patternMatches(svc, p)) ? 0 : 1
      const bSvc = b.matchPatterns.some(p => patternMatches(svc, p)) ? 0 : 1
      if (aSvc !== bSvc) return aSvc - bSvc
      const ai = priority.indexOf(a.strategy)
      const bi = priority.indexOf(b.strategy)
      return (ai === -1 ? 99 : ai) - (bi === -1 ? 99 : bi)
    })
    return matches[0] ?? null
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
    } else if (cap.strategy === "HTTP_STATE_FUZZ" || cap.strategy === "L3_BYPASS") {
      plan.stateFuzzFlowId = cap.strategy === "L3_BYPASS" ? "auth-bypass-chain" : "session-chain"
      plan.l3SafetyEnvelope = "read_only"
      plan.httpOptions = { method: "GET", path: "/" }
    } else if (cap.strategy === "L4_CONTROLLED_IMPACT") {
      plan.stateFuzzFlowId = "l4-canary-chain"
      plan.l3SafetyEnvelope = "read_only"
      plan.httpOptions = { method: "GET", path: "/api/v1/users" }
    } else if (cap.strategy === "IDOR_BOLA") {
      plan.stateFuzzFlowId = "idor-bola-multi-user"
      plan.l3SafetyEnvelope = "read_only"
      plan.httpOptions = { method: "GET", path: "/api/v1/users/1" }
    } else if (cap.strategy === "PRIVESC_PROOF") {
      plan.command = undefined
      plan.l3SafetyEnvelope = "read_only"
    } else if (cap.strategy === "EXPLOIT_REPLAY") {
      plan.stateFuzzFlowId = "exploit-replay"
      plan.l3SafetyEnvelope = "read_only"
      plan.httpOptions = { method: "POST", path: "/api/v1/users" }
    } else if (
      cap.strategy === "MODBUS_PROBE" || cap.strategy === "DNP3_PROBE" || cap.strategy === "BACNET_PROBE"
      || cap.strategy === "MQTT_PROBE" || cap.strategy === "COAP_PROBE" || cap.strategy === "S7_PROBE"
    ) {
      plan.serviceHint = opts.service
      plan.command = `# ${cap.strategy} — executed in-process via ics_validation.ts`
    } else if (cap.strategy === "NUCLEI_PROBE") {
      const url = `${protocol}://${opts.target.split(":")[0]}:${port}`
      plan.command = `nuclei -u ${url} -severity critical,high,medium -json -silent -timeout ${Math.floor(cap.timeoutMs / 1000)}`
    } else if (cap.strategy === "OAUTH_CONSENT_PROBE") {
      plan.httpOptions = {
        method: "GET",
        path: "/.well-known/openid-configuration",
        expectedBodyContains: "authorization_endpoint",
      }
      plan.command = `curl -sS -m ${Math.floor(cap.timeoutMs / 1000)} ${protocol}://${opts.target.split(":")[0]}:${port}/.well-known/openid-configuration`
    } else if (cap.strategy === "DEVICE_CODE_PROBE") {
      plan.httpOptions = {
        method: "GET",
        path: "/.well-known/openid-configuration",
        expectedBodyContains: "device_authorization_endpoint",
      }
      plan.command = `curl -sS -m ${Math.floor(cap.timeoutMs / 1000)} ${protocol}://${opts.target.split(":")[0]}:${port}/.well-known/openid-configuration`
    } else if (cap.strategy === "IAB_CRED_FORMAT") {
      plan.command = `# ${cap.strategy} — format validation in-process`
    }

    return { plan, capability: cap }
  }

  static listCapabilities(): ValidationCapability[] {
    return [...CAPABILITY_REGISTRY]
  }
}

export default ValidationPlanner
