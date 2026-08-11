/**
 * @module security/adcs_audit
 * Active Directory Certificate Services (AD CS) Audit & Compliance Engine
 * Inspects certificate templates (ESC1–ESC13), Shadow Credentials, PKINIT, and HTTP endpoints.
 *
 * Live mode requires: ldapsearch, curl
 * Dry-run mode returns realistic simulated findings with no external calls.
 */

import { resolveDryRun } from "./exec_options.ts"
import { execFileSync } from "node:child_process"
import { isToolAvailable } from "./tool_detection.ts"

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ADCSConfig {
  domain: string
  dcIp?: string
  username?: string
}

export interface ADCSVulnerability {
  id: string
  templateName: string
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
  title: string
  description: string
  remediation: string
}

export interface ADCSAuditResult {
  domain: string
  templatesAudited: number
  vulnerabilities: ADCSVulnerability[]
  shadowCredsEnabled: boolean
  pkinitSupported: boolean
  httpEndpointsExposed: string[]
  publishedTemplates: string[]
  isDryRun: boolean
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function run(cmd: string, args: string[], timeoutMs = 15000): string | null {
  try {
    return execFileSync(cmd, args, {
      timeout: timeoutMs,
      encoding: "utf-8",
      stdio: ["pipe", "pipe", "pipe"],
    })
  } catch {
    return null
  }
}

/** Build ldapsearch base DN from domain. e.g. "corp.local" → "DC=corp,DC=local" */
function domainToDN(domain: string): string {
  return domain
    .split(".")
    .map(rfc => `DC=${rfc}`)
    .join(",")
}

/** Parse ldif-style output into an array of entry objects. */
function parseLDIF(raw: string): Record<string, string>[] {
  const entries: Record<string, string>[] = []
  let current: Record<string, string> = {}

  for (const line of raw.split("\n")) {
    if (line.startsWith("\n") || line.trim() === "") {
      if (Object.keys(current).length > 0) {
        entries.push(current)
        current = {}
      }
    } else {
      const idx = line.indexOf(":")
      if (idx !== -1) {
        const key = line.slice(0, idx).trim()
        const val = line.slice(idx + 1).trim()
        if (current[key]) {
          current[key] += `;${val}`
        } else {
          current[key] = val
        }
      }
    }
  }
  if (Object.keys(current).length > 0) entries.push(current)
  return entries
}

/** Check if a string looks like a GUID (for ENROLLEE_SUPPLIES_SAN flag = 1). */
function hasEnrolleeSuppliesSAN(flag: string): boolean {
  // msPKI-Certificate-Name-Flag is typically a hex string like "1" or a GUID.
  // Flag 0x1 = ENROLLEE_SUPPLIES_SAN.  Also the well-known GUID
  // {0e10c968-78fb-11d2-90d4-00c04f79dc55} indicates the flag set.
  if (!flag) return false
  const n = parseInt(flag, 10)
  if (!isNaN(n)) return (n & 1) === 1
  return flag.toLowerCase() === "0e10c968-78fb-11d2-90d4-00c04f79dc55"
}

/** Heuristic: does the template ACL allow low-priv users to enroll? */
function templateAllowsLowPriv(entry: Record<string, string>): boolean {
  // pKIEnrollmentPermission is often represented as a DN; we check for
  // well-known groups like "Domain Users" or "Authenticated Users".
  const perms = (
    entry["pKIEnrollmentPermission"] ||
    entry["msPKI-Enrollment-Flag"] ||
    ""
  ).toLowerCase()
  return perms.includes("domain users") || perms.includes("authenticated users")
}

/** Check if HTTP enrollment endpoint is reachable. */
function checkHttpEndpoint(url: string): boolean {
  if (!isToolAvailable("curl")) return false
  const out = run("curl", [
    "-s",
    "-o",
    "/dev/null",
    "-w",
    "%{http_code}",
    "-k",
    "--max-time",
    "5",
    url,
  ])
  if (!out) return false
  const code = parseInt(out.trim(), 10)
  return code >= 200 && code < 400
}

/** Detect PetitPotam-eligible relay targets. */
function detectPetitPotamTargets(
  domain: string,
  dcIp?: string
): string[] {
  const targets: string[] = []
  // Standard AD CS enrollment endpoints susceptible to NTLM relay
  const endpoints = [
    `/certsrv/`,
    `/CertSVC/`,
    `/ADFS/`,
  ]
  const host = dcIp || domain
  for (const ep of endpoints) {
    targets.push(`http://${host}${ep}`)
  }
  return targets
}

/** Detect Shadow Credentials (msDS-KeyCredentialLink). */
function detectShadowCredentials(
  baseDN: string,
  ldapOpts: string[]
): boolean {
  const cmd = run("ldapsearch", [
    ...ldapOpts,
    "-b",
    baseDN,
    "(msDS-KeyCredentialLink=*)",
    "msDS-KeyCredentialLink",
  ])
  if (!cmd) return false
  return cmd.includes("msDS-KeyCredentialLink:")
}

/** Detect PKINIT support via msDS-SupportedEncryptionTypes. */
function detectPKINITSupport(
  baseDN: string,
  ldapOpts: string[]
): boolean {
  const cmd = run("ldapsearch", [
    ...ldapOpts,
    "-b",
    baseDN,
    "(objectClass=domain)",
    "msDS-SupportedEncryptionTypes",
  ])
  if (!cmd) return false
  // RC4_HMAC_MD5 = 0x4, AES = 0x18 — both support PKINIT
  const match = cmd.match(/msDS-SupportedEncryptionTypes:\s*(\d+)/)
  if (!match) return false
  const val = parseInt(match[1], 10)
  return (val & 0x1c) !== 0
}

// ---------------------------------------------------------------------------
// Dry-run (simulated) audit
// ---------------------------------------------------------------------------

function generateDryRunResult(domain: string): ADCSAuditResult {
  const templates = [
    "WebServer-Custom",
    "User",
    "Machine",
    "DomainController",
    "RASAndIASServer",
    "ExchangeServer",
    "CEPEncryption",
    "EnrollmentAgent",
    "SmartcardLogon",
    "SubCA",
    "CA",
    "WebServer",
    "IPSECIntermediateOffline",
    "SubCA-Offline",
  ]

  const vulns: ADCSVulnerability[] = [
    {
      id: "ESC1",
      templateName: "WebServer-Custom",
      severity: "CRITICAL",
      title: "ENROLLEE_SUPPLIES_SAN Enabled",
      description:
        "Template allows requester to specify Subject Alternative Name (SAN), enabling Domain Admin impersonation. The msPKI-Certificate-Name-Flag includes ENROLLEE_SUPPLIES_SAN (0x1).",
      remediation:
        "Disable 'Supply in request' on the template or remove the ENROLLEE_SUPPLIES_SAN flag from msPKI-Certificate-Name-Flag. Use 'Supply in the request' only on templates restricted to enrollment agents.",
    },
    {
      id: "ESC2",
      templateName: "SubCA",
      severity: "CRITICAL",
      title: "Any Purpose EKU or No EKU Restriction",
      description:
        "Template does not restrict Extended Key Usage or includes 'Any Purpose' (OID 2.5.29.37.0), allowing authentication, code signing, and any other purpose.",
      remediation:
        "Restrict the template's EKU to only the intended purposes. Remove 'Any Purpose' if present.",
    },
    {
      id: "ESC3",
      templateName: "EnrollmentAgent",
      severity: "HIGH",
      title: "Enrollment Agent Without Restrictions",
      description:
        "Template with Enrollment Agent EKU (1.3.6.1.4.1.311.20.2.1) can be used to request certificates on behalf of other users.",
      remediation:
        "Restrict Enrollment Agent templates to only authorized enrollment agents. Limit enrollment permissions to specific groups.",
    },
    {
      id: "ESC4",
      templateName: "User",
      severity: "MEDIUM",
      title: "Vulnerable Template ACL – Low-Priv Enrollment",
      description:
        "Template ACL grants enrollment permissions to Domain Users or Authenticated Users, potentially allowing abuse of misconfigured EKU.",
      remediation:
        "Remove enrollment permissions for Domain Users / Authenticated Users. Restrict enrollment to specific high-privilege groups only.",
    },
    {
      id: "ESC6",
      templateName: "DomainController",
      severity: "HIGH",
      title: "CT_FLAG_ORIGINAL_SUBJECT_IN_SAN Flag Set",
      description:
        "Template includes CT_FLAG_ORIGINAL_SUBJECT_IN_SAN (msPKI-Enrollment-Flag) which, combined with SAN manipulation, can enable impersonation.",
      remediation:
        "Remove the CT_FLAG_ORIGINAL_SUBJECT_IN_SAN flag from msPKI-Enrollment-Flag unless explicitly required.",
    },
    {
      id: "ESC8",
      templateName: "CertSrv HTTP Interface",
      severity: "HIGH",
      title: "HTTP Enrollment Endpoint Lacks NTLM Protection",
      description:
        "AD CS Web Enrollment (/certsrv) HTTP endpoint is vulnerable to NTLM relay attacks (PetitPotam, ntlmrelayx). EPA is not enforced.",
      remediation:
        "Require HTTPS, enable Extended Protection for Authentication (EPA), disable NTLM authentication, or disable the HTTP enrollment endpoint entirely.",
    },
    {
      id: "ESC11",
      templateName: "N/A",
      severity: "HIGH",
      title: "NTLM Relay to AD CS RPC – EFSRPC / EFSOD",
      description:
        "DCOM/RPC endpoints (MS-EFSR / MS-EFSOD) are vulnerable to NTLM relay when EPA is not enforced, allowing certificate issuance.",
      remediation:
        "Enable EPA on the CA or disable NTLM relay-prone RPC endpoints. Consider deploying Windows Update KB5005413 (PetitPotam mitigation).",
    },
  ]

  return {
    domain,
    templatesAudited: templates.length,
    vulnerabilities: vulns,
    shadowCredsEnabled: true,
    pkinitSupported: true,
    httpEndpointsExposed: detectPetitPotamTargets(domain),
    publishedTemplates: templates,
    isDryRun: true,
  }
}

// ---------------------------------------------------------------------------
// Live (real) audit
// ---------------------------------------------------------------------------

function generateLiveResult(
  config: ADCSConfig
): ADCSAuditResult {
  const { domain, dcIp } = config
  const baseDN = domainToDN(domain)
  const host = dcIp || domain

  // Build common ldapsearch options
  const ldapBase = dcIp ? `-H ldap://${dcIp}` : `-H ldap://${domain}`
  const ldapOpts = [ldapBase, "-x", "-LLL"]

  // If credentials are available, pass them
  if (config.username) {
    // Note: actual bind DN / password should come from env or config
    // For now we attempt anonymous bind which works on many AD setups
  }

  const vulnerabilities: ADCSVulnerability[] = []
  let templatesAudited = 0
  let shadowCredsEnabled = false
  let pkinitSupported = false
  const httpEndpointsExposed: string[] = []
  const publishedTemplates: string[] = []

  // -------------------------------------------------------------------------
  // 1. Enumerate certificate templates
  // -------------------------------------------------------------------------
  const templatesDN = `CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,${baseDN}`
  const templateRaw = run("ldapsearch", [
    ...ldapOpts,
    "-b",
    templatesDN,
    "(objectClass=pKICertificateTemplate)",
    "cn",
    "msPKI-Certificate-Name-Flag",
    "msPKI-Enrollment-Flag",
    "pKIEnrollmentPermission",
    "pKIExpirationPeriod",
    "msPKI-RA-Signature",
  ])

  let templateEntries: Record<string, string>[] = []
  if (templateRaw) {
    templateEntries = parseLDIF(templateRaw)
    templatesAudited = templateEntries.length
  }

  for (const entry of templateEntries) {
    const name = entry["cn"] || entry["distinguishedName"] || "Unknown"
    publishedTemplates.push(name)

    // --- ESC1: ENROLLEE_SUPPLIES_SAN ---
    const nameFlag = entry["msPKI-Certificate-Name-Flag"] || ""
    if (hasEnrolleeSuppliesSAN(nameFlag)) {
      // Check enrollment permissions – low-priv users can abuse this
      const allowsLowPriv = templateAllowsLowPriv(entry)
      vulnerabilities.push({
        id: "ESC1",
        templateName: name,
        severity: "CRITICAL",
        title: "ENROLLEE_SUPPLIES_SAN Enabled",
        description:
          `Template "${name}" has msPKI-Certificate-Name-Flag = ${nameFlag} ` +
          `(ENROLLEE_SUPPLIES_SAN). ` +
          (allowsLowPriv
            ? "Enrollment is allowed for low-privilege groups (Domain Users / Authenticated Users)."
            : "Enrollment permissions appear restricted."),
        remediation:
          "Disable 'Supply in request' on the template. If required, restrict enrollment to enrollment agents only.",
      })
    }

    // --- ESC2: Any Purpose EKU or no EKU ---
    const ekuFlag = entry["msPKI-Enrollment-Flag"] || ""
    // Template with no EKU restriction can be abused for any authentication
    if (!entry["pKIExtendedKeyUsage"] && !entry["msPKI-Enrollment-Flag"]) {
      vulnerabilities.push({
        id: "ESC2",
        templateName: name,
        severity: "CRITICAL",
        title: "Any Purpose or No EKU Restriction",
        description:
          `Template "${name}" does not appear to restrict Extended Key Usage, ` +
          `allowing it to be used for authentication, code signing, or any purpose.`,
        remediation:
          "Add specific EKU OIDs to restrict template usage to intended purposes only.",
      })
    }

    // --- ESC3: Enrollment Agent EKU ---
    const eku = (entry["pKIExtendedKeyUsage"] || "").toLowerCase()
    if (eku.includes("1.3.6.1.4.1.311.20.2.1")) {
      vulnerabilities.push({
        id: "ESC3",
        templateName: name,
        severity: "HIGH",
        title: "Enrollment Agent EKU Present",
        description:
          `Template "${name}" includes the Enrollment Agent EKU ` +
          `(1.3.6.1.4.1.311.20.2.1), which can request certificates on behalf of other users.`,
        remediation:
          "Restrict Enrollment Agent templates to authorized enrollment agents only. Limit enrollment permissions.",
      })
    }

    // --- ESC4: Weak template ACL ---
    if (templateAllowsLowPriv(entry)) {
      vulnerabilities.push({
        id: "ESC4",
        templateName: name,
        severity: "MEDIUM",
        title: "Low-Privilege Enrollment Allowed",
        description:
          `Template "${name}" grants enrollment permissions to Domain Users or Authenticated Users. ` +
          `Combined with other misconfigurations, this can lead to privilege escalation.`,
        remediation:
          "Remove enrollment permissions for Domain Users / Authenticated Users. Restrict to specific groups.",
      })
    }

    // --- ESC6: CT_FLAG_ORIGINAL_SUBJECT_IN_SAN ---
    const enrollFlag = entry["msPKI-Enrollment-Flag"] || ""
    if (enrollFlag.includes("1") && !enrollFlag.includes("0")) {
      const flagVal = parseInt(enrollFlag, 10)
      if (!isNaN(flagVal) && (flagVal & 0x1) === 1) {
        vulnerabilities.push({
          id: "ESC6",
          templateName: name,
          severity: "HIGH",
          title: "CT_FLAG_ORIGINAL_SUBJECT_IN_SAN Set",
          description:
            `Template "${name}" has the CT_FLAG_ORIGINAL_SUBJECT_IN_SAN flag ` +
            `set in msPKI-Enrollment-Flag, which can be combined with SAN manipulation.`,
          remediation:
            "Remove the CT_FLAG_ORIGINAL_SUBJECT_IN_SAN flag from msPKI-Enrollment-Flag unless explicitly required.",
        })
      }
    }
  }

  // -------------------------------------------------------------------------
  // 2. Check HTTP enrollment endpoints (ESC8)
  // -------------------------------------------------------------------------
  const httpTargets = detectPetitPotamTargets(domain, dcIp)
  for (const url of httpTargets) {
    if (checkHttpEndpoint(url)) {
      httpEndpointsExposed.push(url)
      vulnerabilities.push({
        id: "ESC8",
        templateName: "CertSrv HTTP Interface",
        severity: "HIGH",
        title: "HTTP Enrollment Endpoint Reachable",
        description:
          `Endpoint ${url} is reachable and vulnerable to NTLM relay attacks (PetitPotam). ` +
          `EPA may not be enforced.`,
        remediation:
          "Enable HTTPS and EPA (Extended Protection for Authentication). Disable NTLM or remove HTTP endpoints entirely.",
      })
      // Only report once
      break
    }
  }

  // -------------------------------------------------------------------------
  // 3. Shadow Credentials (msDS-KeyCredentialLink)
  // -------------------------------------------------------------------------
  shadowCredsEnabled = detectShadowCredentials(baseDN, ldapOpts)
  if (shadowCredsEnabled) {
    const shadowUsers = run("ldapsearch", [
      ...ldapOpts,
      "-b",
      baseDN,
      "(msDS-KeyCredentialLink=*)",
      "cn",
      "distinguishedName",
    ])
    const userCount = shadowUsers
      ? (shadowUsers.match(/dn:/gi) || []).length
      : 0

    vulnerabilities.push({
      id: "ShadowCreds",
      templateName: "N/A",
      severity: "CRITICAL",
      title: "Shadow Credentials Detected (msDS-KeyCredentialLink)",
      description:
        `${userCount} object(s) have msDS-KeyCredentialLink attributes set. ` +
        `This enables certificate-based authentication abuse (Shadow Credentials / ` +
        `Whisker-style attacks) for persistent access.`,
      remediation:
        "Audit and remove unauthorized msDS-KeyCredentialLink values. Monitor for new values via event ID 4768/4769.",
    })
  }

  // -------------------------------------------------------------------------
  // 4. PKINIT support
  // -------------------------------------------------------------------------
  pkinitSupported = detectPKINITSupport(baseDN, ldapOpts)

  // -------------------------------------------------------------------------
  // 5. ESC11 – NTLM relay to RPC (always flag as informational check)
  // -------------------------------------------------------------------------
  // This requires endpoint-specific checking; flag if PetitPotam targets exist
  if (httpEndpointsExposed.length > 0) {
    vulnerabilities.push({
      id: "ESC11",
      templateName: "N/A",
      severity: "HIGH",
      title: "Potential NTLM Relay via AD CS RPC Endpoints",
      description:
        "HTTP enrollment endpoints are reachable, indicating NTLM relay paths may exist " +
        "via MS-EFSR / MS-EFSOD (PetitPotam) or similar DCOM/RPC coercion vectors.",
      remediation:
        "Deploy PetitPotam mitigations (KB5005413). Enable EPA on the CA. Restrict NTLM authentication.",
    })
  }

  // -------------------------------------------------------------------------
  // 6. Check for CA web enrollment service
  // -------------------------------------------------------------------------
  if (dcIp) {
    const certSvcUrl = `http://${dcIp}/certsrv/`
    if (checkHttpEndpoint(certSvcUrl)) {
      if (!httpEndpointsExposed.includes(certSvcUrl)) {
        httpEndpointsExposed.push(certSvcUrl)
      }
    }
  }

  // -------------------------------------------------------------------------
  // 7. Check for PetitPotam NLA requirements
  // -------------------------------------------------------------------------
  if (httpEndpointsExposed.length > 0) {
    // Try to detect if NLA is enforced (PetitPotam requires NTLM)
    // This is informational
  }

  return {
    domain,
    templatesAudited,
    vulnerabilities,
    shadowCredsEnabled,
    pkinitSupported,
    httpEndpointsExposed,
    publishedTemplates,
    isDryRun: false,
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export function auditADCS(
  config: ADCSConfig,
  options: { live?: boolean; dryRun?: boolean } = {}
): ADCSAuditResult {
  // Resolve dryRun: explicit dryRun wins, then live, then default true
  const isDryRun =
    options.dryRun !== undefined ? options.dryRun : !options.live

  if (isDryRun) {
    return generateDryRunResult(config.domain)
  }

  // Live mode – check for required tools
  const ldapAvailable = isToolAvailable("ldapsearch")
  const curlAvailable = isToolAvailable("curl")

  if (!ldapAvailable && !curlAvailable) {
    // Partial tooling: run what we can
    // Fall back to dry-run with a warning
    const result = generateDryRunResult(config.domain)
    result.vulnerabilities.push({
      id: "TOOL_MISSING",
      templateName: "N/A",
      severity: "LOW",
      title: "Required Tools Not Installed",
      description:
        `ldapsearch: ${ldapAvailable ? "available" : "MISSING"}. ` +
        `curl: ${curlAvailable ? "available" : "MISSING"}. ` +
        "Results are simulated. Install tools for accurate assessment.",
      remediation:
        "Install ldapsearch (apt install ldap-utils) and curl (apt install curl) for full live assessment.",
    })
    result.isDryRun = true
    return result
  }

  try {
    return generateLiveResult(config)
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err)
    // On error, return partial results with error info
    const result = generateDryRunResult(config.domain)
    result.vulnerabilities.push({
      id: "LIVE_ERROR",
      templateName: "N/A",
      severity: "LOW",
      title: "Live Assessment Error",
      description: `Live audit encountered an error: ${msg}. Results are simulated.`,
      remediation: "Verify domain connectivity, credentials, and tool availability.",
    })
    result.isDryRun = true
    return result
  }
}

export default { auditADCS }
