/**
 * @module security/edge_appliance_audit
 * Edge Appliance & Perimeter Integrity Audit Engine
 * Evaluates SSL/TLS configuration, VPN interface states, certificate validity,
 * firmware integrity, and management interface exposure.
 *
 * Live mode requires: openssl, curl, ncat/netcat
 * Dry-run mode returns realistic simulated findings with no external calls.
 */

import { resolveDryRun } from "./exec_options.ts"
import { execFileSync } from "node:child_process"
import { isToolAvailable } from "./tool_detection.ts"

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface EdgeApplianceConfig {
  target: string
  port?: number
}

export interface EdgeApplianceFinding {
  id: string
  component: string
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
  title: string
  description: string
  remediation: string
}

export interface TLSInfo {
  protocol: string | null
  cipher: string | null
  cipherIsWeak: boolean
  certificateIssuer: string | null
  certificateSubject: string | null
  certificateExpiry: string | null
  certificateExpired: boolean
  certificateSelfSigned: boolean
  daysUntilExpiry: number | null
  supportsTLS10: boolean
  supportsTLS11: boolean
  supportsTLS12: boolean
  supportsTLS13: boolean
  sessionTicketsExposed: boolean
}

export interface VPNLeakIndicator {
  type: string
  detail: string
}

export interface FirmwareCheck {
  hashAlgorithm: string | null
  hashValue: string | null
  verified: boolean
  notes: string
}

export interface ManagementInterface {
  port: number
  service: string
  accessible: boolean
}

export interface EdgeApplianceAuditResult {
  target: string
  firmwareIntegrityValid: boolean
  sslSessionTicketsExposed: boolean
  vpnMemoryLeaksDetected: boolean
  tlsInfo: TLSInfo | null
  vpnLeakIndicators: VPNLeakIndicator[]
  firmwareCheck: FirmwareCheck | null
  managementInterfaces: ManagementInterface[]
  findings: EdgeApplianceFinding[]
  isDryRun: boolean
}

// ---------------------------------------------------------------------------
// Helpers
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

function parseBool(val: string | null): boolean {
  if (!val) return false
  const v = val.trim().toLowerCase()
  return v === "true" || v === "1" || v === "yes"
}

// ---------------------------------------------------------------------------
// Live audit implementation
// ---------------------------------------------------------------------------

function performTLSScan(target: string, port: number): TLSInfo {
  const tlsInfo: TLSInfo = {
    protocol: null,
    cipher: null,
    cipherIsWeak: false,
    certificateIssuer: null,
    certificateSubject: null,
    certificateExpiry: null,
    certificateExpired: false,
    certificateSelfSigned: false,
    daysUntilExpiry: null,
    supportsTLS10: false,
    supportsTLS11: false,
    supportsTLS12: false,
    supportsTLS13: false,
    sessionTicketsExposed: false,
  }

  if (!isToolAvailable("openssl")) return tlsInfo

  const connectCmd = `-connect ${target}:${port}`

  // Full handshake to get protocol + cipher + cert
  const fullOutput = run("openssl", [
    "s_client",
    connectCmd,
    "-brief",
  ], 12000)

  if (fullOutput) {
    const protoMatch = fullOutput.match(/Protocol\s*:\s*(\S+)/i)
    if (protoMatch) tlsInfo.protocol = protoMatch[1]

    const cipherMatch = fullOutput.match(/Ciphersuite\s*:\s*(\S+)/i) || fullOutput.match(/Cipher\s*:\s*(\S+)/i)
    if (cipherMatch) {
      tlsInfo.cipher = cipherMatch[1]
      const weakPatterns = /RC4|DES|3DES|EXPORT|NULL|MD5|anon/i
      tlsInfo.cipherIsWeak = weakPatterns.test(cipherMatch[1])
    }

    // Certificate details
    const certOutput = run("openssl", [
      "s_client",
      connectCmd,
      "-showcerts",
    ], 12000)

    if (certOutput) {
      // Issuer
      const issuerMatch = certOutput.match(/issuer\s*[=:]\s*(.+)/i)
      if (issuerMatch) tlsInfo.certificateIssuer = issuerMatch[1].trim()

      // Subject
      const subjectMatch = certOutput.match(/subject\s*[=:]\s*(.+)/i)
      if (subjectMatch) tlsInfo.certificateSubject = subjectMatch[1].trim()

      // Self-signed check
      tlsInfo.certificateSelfSigned = tlsInfo.certificateIssuer === tlsInfo.certificateSubject

      // No verify error may indicate self-signed or untrusted
      if (certOutput.includes("self signed") || certOutput.includes("SELF_SIGNED")) {
        tlsInfo.certificateSelfSigned = true
      }
    }

    // Expiry check via date parsing
    const expiryOutput = run("openssl", [
      "s_client",
      connectCmd,
    ], 10000)

    if (expiryOutput) {
      const notAfterMatch = expiryOutput.match(/Not After\s*:\s*(.+)/i)
      if (notAfterMatch) {
        tlsInfo.certificateExpiry = notAfterMatch[1].trim()
        try {
          const expiryDate = new Date(notAfterMatch[1].trim())
          if (!isNaN(expiryDate.getTime())) {
            const now = Date.now()
            tlsInfo.daysUntilExpiry = Math.floor((expiryDate.getTime() - now) / 86400000)
            tlsInfo.certificateExpired = expiryDate.getTime() < now
          }
        } catch { /* ignore parse errors */ }
      }
    }
  }

  // Protocol version probes
  const protoTests: Array<{ flag: string; field: keyof TLSInfo }> = [
    { flag: "-tls1", field: "supportsTLS10" },
    { flag: "-tls1_1", field: "supportsTLS11" },
    { flag: "-tls1_2", field: "supportsTLS12" },
    { flag: "-tls1_3", field: "supportsTLS13" },
  ]

  for (const test of protoTests) {
    const result = run("openssl", [
      "s_client",
      connectCmd,
      test.flag,
    ], 8000)

    // If openssl succeeds without handshake alert, protocol is supported
    if (result && !result.includes("alert protocol version") && !result.includes("no protocols available")) {
      (tlsInfo as Record<string, unknown>)[test.field] = true
    }
  }

  // Session ticket detection
  const ticketOutput = run("openssl", [
    "s_client",
    connectCmd,
    "-tlsextdebug",
  ], 10000)

  if (ticketOutput) {
    tlsInfo.sessionTicketsExposed = /session ticket/i.test(ticketOutput) && !/ticket.*encrypted/i.test(ticketOutput)
  }

  return tlsInfo
}

function checkVPNMLeaks(target: string): VPNLeakIndicator[] {
  const indicators: VPNLeakIndicator[] = []

  if (isToolAvailable("ncat") || isToolAvailable("netcat")) {
    // Check IKE/IKEv2 ports (UDP 500, 4500)
    for (const port of [500, 4500]) {
      const ncatTool = isToolAvailable("ncat") ? "ncat" : "netcat"
      const result = run(ncatTool, ["-u", "-w", "3", target, String(port)], 6000)
      if (result !== null) {
        // Connection succeeded — port is open, check for stale sessions
        indicators.push({
          type: "open_ike_port",
          detail: `UDP port ${port} (IKE) responded on ${target} — VPN service detected, checking for stale sessions`,
        })
      }
    }
  }

  if (isToolAvailable("ss")) {
    const ssOutput = run("ss", ["-tunap", "state", "time-w"], 5000)
    if (ssOutput) {
      const staleEntries = ssOutput.split("\n").filter(l => l.includes(target) || l.includes(":500") || l.includes(":4500"))
      if (staleEntries.length > 0) {
        indicators.push({
          type: "stale_session",
          detail: `Found ${staleEntries.length} TIME_WAIT socket(s) related to ${target} VPN ports`,
        })
      }
    }
  } else if (isToolAvailable("netstat")) {
    const netstatOutput = run("netstat", ["-tunap"], 5000)
    if (netstatOutput) {
      const staleEntries = netstatOutput.split("\n").filter(l =>
        (l.includes(target) || l.includes(":500") || l.includes(":4500")) && l.includes("TIME_WAIT")
      )
      if (staleEntries.length > 0) {
        indicators.push({
          type: "stale_session",
          detail: `Found ${staleEntries.length} TIME_WAIT socket(s) related to ${target} VPN ports`,
        })
      }
    }
  }

  // Check for elevated memory usage of VPN-related processes
  if (isToolAvailable("ps")) {
    const psOutput = run("ps", ["aux"], 5000)
    if (psOutput) {
      const vpnProcesses = psOutput.split("\n").filter(l =>
        /ipsec|ike|charon|strongswan|openvpn|wireguard|racoon/i.test(l)
      )
      for (const proc of vpnProcesses) {
        const memMatch = proc.match(/\s(\d+\.?\d*)\s/)
        if (memMatch) {
          const memMB = parseFloat(memMatch[1]) / 1024
          if (memMB > 300) {
            indicators.push({
              type: "memory_fragment",
              detail: `VPN process (PID info) using ${memMB.toFixed(0)}MB RSS — elevated above typical baseline`,
            })
          }
        }
      }
    }
  }

  return indicators
}

function checkFirmwareIntegrity(target: string): FirmwareCheck {
  const fw: FirmwareCheck = {
    hashAlgorithm: null,
    hashValue: null,
    verified: false,
    notes: "Firmware integrity check requires vendor-specific tooling or SSH access to the appliance.",
  }

  // Attempt SSH-based firmware hash verification if ssh is available
  if (isToolAvailable("ssh")) {
    const shaCheck = run("ssh", [
      "-o", "BatchMode=yes",
      "-o", "StrictHostKeyChecking=no",
      "-o", "ConnectTimeout=10",
      "-o", "LogLevel=ERROR",
      target,
      "sha256sum /boot/vmlinuz /boot/firmware/* 2>/dev/null | head -5",
    ], 12000)

    if (shaCheck && shaCheck.trim().length > 0) {
      fw.hashAlgorithm = "SHA256"
      const lines = shaCheck.trim().split("\n")
      fw.hashValue = lines.map(l => l.split(/\s+/)[0]).join(":")
      fw.notes = `Retrieved ${lines.length} firmware component hash(es) from device. Verify against vendor reference hashes.`
      return fw
    }
  }

  // Fallback: try to reach web management and check firmware version endpoint
  if (isToolAvailable("curl")) {
    const curlOutput = run("curl", [
      "-sk",
      "--max-time", "8",
      `-https://${target}/api/firmware/version`,
    ], 10000)

    if (curlOutput && curlOutput.includes("version")) {
      fw.notes = "Firmware version endpoint responded. Manual verification against vendor bulletin required."
      fw.hashAlgorithm = "unknown"
      fw.hashValue = null
      return fw
    }
  }

  fw.notes = "Could not verify firmware integrity — SSH access and/or curl to management API not available."
  return fw
}

function checkManagementInterfaces(target: string): ManagementInterface[] {
  const interfaces: ManagementInterface[] = []
  const commonPorts: Array<{ port: number; service: string }> = [
    { port: 443, service: "HTTPS Admin Panel" },
    { port: 22, service: "SSH" },
    { port: 80, service: "HTTP Redirect" },
    { port: 161, service: "SNMP" },
    { port: 8080, service: "HTTP Proxy/Config" },
    { port: 8443, service: "HTTPS Alt" },
    { port: 23, service: "Telnet" },
    { port: 3389, service: "RDP" },
    { port: 5060, service: "SIP" },
    { port: 1723, service: "PPTP VPN" },
  ]

  const ncatTool = isToolAvailable("ncat") ? "ncat" : isToolAvailable("netcat") ? "netcat" : null
  const curlAvail = isToolAvailable("curl")

  for (const entry of commonPorts) {
    let accessible = false

    if (ncatTool) {
      const result = run(ncatTool, ["-w", "3", target, String(entry.port)], 6000)
      if (result !== null) {
        accessible = true
      }
    } else if (curlAvail && entry.port === 443) {
      const result = run("curl", ["-sk", "--max-time", "5", `https://${target}/`], 8000)
      accessible = result !== null
    }

    interfaces.push({ port: entry.port, service: entry.service, accessible })
  }

  return interfaces
}

function performLiveAudit(config: EdgeApplianceConfig): EdgeApplianceAuditResult {
  const target = config.target
  const port = config.port || 443
  const findings: EdgeApplianceFinding[] = []

  // 1. TLS scan
  const tlsInfo = performTLSScan(target, port)

  if (tlsInfo.protocol) {
    if (tlsInfo.supportsTLS10 || tlsInfo.supportsTLS11) {
      findings.push({
        id: "EDGE-TLS-DOWNGRADE",
        component: "SSL/TLS Protocol",
        severity: "HIGH",
        title: "Deprecated TLS Protocol Versions Accepted",
        description: `The appliance accepts ${[tlsInfo.supportsTLS10 && "TLS 1.0", tlsInfo.supportsTLS11 && "TLS 1.1"].filter(Boolean).join(" and ")} connections. These protocols have known vulnerabilities (BEAST, POODLE) and are deprecated by RFC 8996.`,
        remediation: "Disable TLS 1.0 and TLS 1.1. Enforce TLS 1.2 as minimum protocol version with TLS 1.3 preferred.",
      })
    }

    if (!tlsInfo.supportsTLS13) {
      findings.push({
        id: "EDGE-TLS-NO13",
        component: "SSL/TLS Protocol",
        severity: "LOW",
        title: "TLS 1.3 Not Supported",
        description: "The appliance does not support TLS 1.3, missing improvements in handshake performance, cipher suite strength, and mandatory forward secrecy.",
        remediation: "Upgrade appliance firmware to support TLS 1.3 and enable it alongside TLS 1.2.",
      })
    }
  }

  if (tlsInfo.cipherIsWeak && tlsInfo.cipher) {
    findings.push({
      id: "EDGE-WEAK-CIPHER",
      component: "SSL/TLS Cipher",
      severity: "HIGH",
      title: `Weak Cipher Suite Detected: ${tlsInfo.cipher}`,
      description: `The appliance negotiated cipher suite ${tlsInfo.cipher} which contains weak cryptographic primitives (RC4/DES/3DES/EXPORT). This cipher is vulnerable to known attacks.`,
      remediation: "Disable all weak cipher suites. Configure the appliance to use only AEAD ciphers (AES-GCM, ChaCha20-Poly1305).",
    })
  }

  if (tlsInfo.certificateExpired) {
    findings.push({
      id: "EDGE-CERT-EXPIRED",
      component: "Certificate",
      severity: "CRITICAL",
      title: "TLS Certificate Has Expired",
      description: `The TLS certificate expired on ${tlsInfo.certificateExpiry || "unknown date"}. Clients will reject connections, breaking all encrypted traffic.`,
      remediation: "Replace the certificate immediately. Configure automated certificate lifecycle management with monitoring.",
    })
  } else if (tlsInfo.daysUntilExpiry !== null && tlsInfo.daysUntilExpiry < 30) {
    findings.push({
      id: "EDGE-CERT-EXPIRING",
      component: "Certificate",
      severity: "HIGH",
      title: `Certificate Expiring in ${tlsInfo.daysUntilExpiry} Days`,
      description: `The TLS certificate will expire on ${tlsInfo.certificateExpiry}. Expired certificates cause client failures and trust erosion.`,
      remediation: "Renew the certificate immediately and configure automated renewal with alerting.",
    })
  } else if (tlsInfo.daysUntilExpiry !== null && tlsInfo.daysUntilExpiry < 90) {
    findings.push({
      id: "EDGE-CERT-NEAR",
      component: "Certificate",
      severity: "MEDIUM",
      title: `Certificate Nearing Expiration (${tlsInfo.daysUntilExpiry} days remaining)`,
      description: `The TLS certificate will expire in ${tlsInfo.daysUntilExpiry} days. Plan renewal to avoid service disruption.`,
      remediation: "Schedule certificate renewal and configure automated lifecycle management.",
    })
  }

  if (tlsInfo.certificateSelfSigned) {
    findings.push({
      id: "EDGE-CERT-SELFSIGNED",
      component: "Certificate",
      severity: "MEDIUM",
      title: "Self-Signed TLS Certificate Detected",
      description: "The appliance is using a self-signed certificate, which cannot be validated by clients and indicates a non-CA issued certificate.",
      remediation: "Obtain a certificate from a trusted CA. For internal devices, use an organizational CA with proper chain configuration.",
    })
  }

  if (tlsInfo.sessionTicketsExposed) {
    findings.push({
      id: "EDGE-TLS-TICKETS",
      component: "SSL/TLS Engine",
      severity: "MEDIUM",
      title: "Unencrypted TLS Session Tickets",
      description: "TLS session tickets are not encrypted with a rotating key, allowing potential session hijacking if the ticket key is compromised.",
      remediation: "Enable session ticket encryption key rotation. Prefer TLS 1.3 which encrypts session tickets by default.",
    })
  }

  // 2. VPN memory leak indicators
  const vpnLeaks = checkVPNMLeaks(target)

  if (vpnLeaks.length > 0) {
    findings.push({
      id: "EDGE-VPN-LEAK",
      component: "VPN Memory",
      severity: "HIGH",
      title: `VPN Memory Leak Indicators Detected (${vpnLeaks.length} issues)`,
      description: `Found ${vpnLeaks.length} VPN memory/session leak indicators: ${vpnLeaks.map(v => v.detail).join("; ")}`,
      remediation: "Restart the VPN daemon to flush stale sessions. Configure TCP keepalive timeouts and monitor IKE daemon memory usage.",
    })

    for (const leak of vpnLeaks) {
      if (leak.type === "memory_fragment") {
        findings.push({
          id: "EDGE-VPN-MEM",
          component: "VPN Memory",
          severity: "MEDIUM",
          title: "Elevated VPN Daemon Memory Usage",
          description: leak.detail,
          remediation: "Monitor VPN daemon RSS. If consistently above baseline, investigate memory leak in VPN firmware and apply vendor patches.",
        })
      }
    }
  }

  // 3. Firmware integrity
  const fwCheck = checkFirmwareIntegrity(target)

  if (!fwCheck.verified && fwCheck.hashValue === null) {
    findings.push({
      id: "EDGE-FW-UNKNOWN",
      component: "Appliance Firmware",
      severity: "MEDIUM",
      title: "Firmware Integrity Could Not Be Verified",
      description: fwCheck.notes,
      remediation: "Ensure SSH access is available and configure vendor firmware verification tooling.",
    })
  }

  // 4. Management interface exposure
  const mgmtInterfaces = checkManagementInterfaces(target)

  const exposedServices = mgmtInterfaces.filter(i => i.accessible)
  if (exposedServices.length > 0) {
    const snmpExposed = exposedServices.find(i => i.service === "SNMP")
    if (snmpExposed) {
      findings.push({
        id: "EDGE-MGMT-SNMP",
        component: "Management Interface",
        severity: "HIGH",
        title: "SNMP Service Exposed",
        description: `SNMP (port ${snmpExposed.port}) is accessible on the appliance. SNMPv1/v2c transmits community strings in cleartext, enabling device enumeration.`,
        remediation: "Disable SNMP or upgrade to SNMPv3 with authentication and encryption. Restrict SNMP access to management VLAN only.",
      })
    }

    const telnetExposed = exposedServices.find(i => i.service === "Telnet")
    if (telnetExposed) {
      findings.push({
        id: "EDGE-MGMT-TELNET",
        component: "Management Interface",
        severity: "CRITICAL",
        title: "Telnet Service Exposed",
        description: "Telnet (port 23) is accessible. Telnet transmits all data including credentials in cleartext.",
        remediation: "Disable Telnet immediately. Use SSH for remote command-line management.",
      })
    }

    const httpExposed = exposedServices.filter(i => i.service.startsWith("HTTP") && i.service !== "HTTPS Admin Panel" && i.service !== "HTTPS Alt")
    if (httpExposed.length > 0) {
      findings.push({
        id: "EDGE-MGMT-HTTP",
        component: "Management Interface",
        severity: "MEDIUM",
        title: "HTTP Management Interface Accessible",
        description: `HTTP-based management interfaces are accessible on ports: ${httpExposed.map(i => i.port).join(", ")}. Management traffic is transmitted in cleartext.`,
        remediation: "Disable HTTP management interfaces. Enforce HTTPS-only access with proper certificate validation.",
      })
    }

    const totalExposed = exposedServices.length
    if (totalExposed > 3) {
      findings.push({
        id: "EDGE-MGMT-EXP",
        component: "Management Interface",
        severity: "HIGH",
        title: `${totalExposed} Management Services Exposed`,
        description: `${totalExposed} management services are accessible on the appliance: ${exposedServices.map(i => `${i.service} (${i.port})`).join(", ")}. This significantly increases the attack surface.`,
        remediation: "Apply network segmentation. Restrict management interfaces to dedicated management VLAN with firewall rules.",
      })
    }
  }

  const vpnMemoryLeaksDetected = vpnLeaks.length > 0

  return {
    target,
    firmwareIntegrityValid: fwCheck.verified,
    sslSessionTicketsExposed: tlsInfo.sessionTicketsExposed,
    vpnMemoryLeaksDetected,
    tlsInfo,
    vpnLeakIndicators: vpnLeaks,
    firmwareCheck: fwCheck,
    managementInterfaces: mgmtInterfaces,
    findings,
    isDryRun: false,
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export function auditEdgeAppliance(
  config: EdgeApplianceConfig,
  options: { live?: boolean; dryRun?: boolean } = {}
): EdgeApplianceAuditResult {
  const isDryRun = options.dryRun !== undefined ? options.dryRun : !options.live

  if (isDryRun) {
    return {
      target: config.target,
      firmwareIntegrityValid: false,
      sslSessionTicketsExposed: false,
      vpnMemoryLeaksDetected: false,
      tlsInfo: null,
      vpnLeakIndicators: [],
      firmwareCheck: null,
      managementInterfaces: [],
      findings: [],
      isDryRun: true,
    }
  }

  try {
    return performLiveAudit(config)
  } catch (err) {
    return {
      target: config.target,
      firmwareIntegrityValid: false,
      sslSessionTicketsExposed: false,
      vpnMemoryLeaksDetected: false,
      tlsInfo: null,
      vpnLeakIndicators: [],
      firmwareCheck: null,
      managementInterfaces: [],
      findings: [
        {
          id: "EDGE-ERR-00",
          component: "Audit Engine",
          severity: "LOW",
          title: "Audit Execution Error",
          description: `The live audit encountered an error: ${(err as Error).message?.slice(0, 200) || "unknown error"}`,
          remediation: "Verify network connectivity to the target and ensure openssl/curl are available.",
        },
      ],
      isDryRun: false,
    }
  }
}

export default { auditEdgeAppliance }
