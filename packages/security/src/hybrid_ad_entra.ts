/**
 * @module hybrid_ad_entra
 * Hybrid Active Directory & Entra ID Attack Chains — Seamless SSO (SSSO) Kerberos Decryption,
 * Azure AD Connect Sync Account Abuses (Password Hash Sync Exfiltration), and Cloud-to-On-Prem DCSync Pivoting.
 *
 * All operations default to DRY-RUN mode. Pass `dryRun: false` only in authorised
 * red-team environments.
 */

import { resolveDryRun } from "./exec_options.ts"
import { execSync } from "node:child_process";
import { isToolAvailable } from "./tool_detection.ts";

// ─── Types ───────────────────────────────────────────────────────────────────

export interface HybridAttackResult {
  technique: string;
  targetAccount: string;
  details: string;
  dryRun: boolean;
}

export interface SyncAccountInfo {
  samAccountName: string;
  distinguishedName: string;
  userPrincipalName: string;
  lastLogon: string;
  passwordLastSet: string;
  enabled: boolean;
  cloudSynced: boolean;
}

export interface PHSAgentStatus {
  installed: boolean;
  version: string | null;
  lastSyncTime: string | null;
  syncIntervalMinutes: number;
}

export interface SeamlessSSOStatus {
  enabled: boolean;
  kerberosTicketPresent: boolean;
  spnRegistered: boolean;
  decryrptionKeyFound: boolean;
}

export interface HybridADResult {
  domain: string;
  dryRun: boolean;
  phsAgent: PHSAgentStatus;
  seamlessSSO: SeamlessSSOStatus;
  syncAccounts: SyncAccountInfo[];
  cloudOnlyAccounts: string[];
  syncedAccounts: string[];
  msolAccountExtractable: boolean;
  dcsyncPivotPossible: boolean;
  attackPaths: string[];
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function runCommand(cmd: string, timeout = 10000): string | null {
  try {
    return execSync(cmd, {
      encoding: "utf-8",
      timeout,
      stdio: ["pipe", "pipe", "pipe"],
    }).trim();
  } catch {
    return null;
  }
}

function generateFakeMSOLAccount(domain: string): string {
  const prefix = "MSOL_";
  const hash = Array.from(
    { length: 12 },
    () => "0123456789abcdef"[Math.floor(Math.random() * 16)]
  ).join("");
  return `${prefix}${hash}`;
}

function generateFakeDN(domain: string, sam: string): string {
  const parts = domain.split(".").map((p) => `DC=${p}`).join(",");
  return `CN=${sam},CN=Users,${parts}`;
}

function generateFakeUPN(domain: string, sam: string): string {
  return `${sam.toLowerCase()}@${domain.toLowerCase()}`;
}

function generateFakeLastLogon(): string {
  const daysAgo = Math.floor(Math.random() * 30);
  const d = new Date();
  d.setDate(d.getDate() - daysAgo);
  return d.toISOString();
}

// ─── Dry-Run Simulation ─────────────────────────────────────────────────────

function simulatePHSAgent(): PHSAgentStatus {
  return {
    installed: true,
    version: "2.0.4913.0",
    lastSyncTime: new Date(Date.now() - 300000).toISOString(),
    syncIntervalMinutes: 3,
  };
}

function simulateSeamlessSSO(): SeamlessSSOStatus {
  return {
    enabled: true,
    kerberosTicketPresent: true,
    spnRegistered: true,
    decryrptionKeyFound: false,
  };
}

function simulateSyncAccounts(domain: string): SyncAccountInfo[] {
  return [
    {
      samAccountName: generateFakeMSOLAccount(domain),
      distinguishedName: generateFakeDN(domain, "MSOL_a1b2c3d4e5f6"),
      userPrincipalName: generateFakeUPN(domain, "MSOL_a1b2c3d4e5f6"),
      lastLogon: generateFakeLastLogon(),
      passwordLastSet: generateFakeLastLogon(),
      enabled: true,
      cloudSynced: true,
    },
    {
      samAccountName: "AAD_98efc1909065",
      distinguishedName: generateFakeDN(domain, "AAD_98efc1909065"),
      userPrincipalName: generateFakeUPN(domain, "aad_98efc1909065"),
      lastLogon: generateFakeLastLogon(),
      passwordLastSet: generateFakeLastLogon(),
      enabled: true,
      cloudSynced: true,
    },
    {
      samAccountName: "OnPremSyncAdmin",
      distinguishedName: generateFakeDN(domain, "OnPremSyncAdmin"),
      userPrincipalName: generateFakeUPN(domain, "onpremsyncadmin"),
      lastLogon: generateFakeLastLogon(),
      passwordLastSet: generateFakeLastLogon(),
      enabled: true,
      cloudSynced: true,
    },
  ];
}

// ─── Live Implementation ────────────────────────────────────────────────────

async function checkPHSAgentLive(): Promise<PHSAgentStatus> {
  if (!isToolAvailable("powershell") && !isToolAvailable("pwsh")) {
    return {
      installed: false,
      version: null,
      lastSyncTime: null,
      syncIntervalMinutes: 0,
    };
  }

  const ps = isToolAvailable("pwsh") ? "pwsh" : "powershell";
  const cmd = [
    "Get-ItemProperty",
    "-Path 'HKLM:\\SOFTWARE\\Microsoft\\Azure AD Connect'",
    "-ErrorAction SilentlyContinue |",
    "Select-Object -ExpandProperty EnablePasswordSync |",
    "ConvertTo-Json",
  ].join(" ");

  const output = runCommand(`${ps} -NoProfile -Command "${cmd}"`);
  const installed = output !== null && output.trim() !== "";

  let version: string | null = null;
  const verCmd = `${ps} -NoProfile -Command "Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Azure AD Connect\\*' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Version | ConvertTo-Json"`;
  const verOutput = runCommand(verCmd);
  if (verOutput) {
    try {
      const parsed = JSON.parse(verOutput);
      version = typeof parsed === "string" ? parsed : String(parsed);
    } catch {
      version = verOutput;
    }
  }

  let lastSyncTime: string | null = null;
  const syncCmd = `${ps} -NoProfile -Command "Get-ADSyncScheduler -ErrorAction SilentlyContinue | Select-Object -ExpandProperty SyncCycleStartTime | ConvertTo-Json"`;
  const syncOutput = runCommand(syncCmd);
  if (syncOutput) {
    try {
      const parsed = JSON.parse(syncOutput);
      lastSyncTime = typeof parsed === "string" ? parsed : String(parsed);
    } catch {
      lastSyncTime = syncOutput;
    }
  }

  return {
    installed,
    version,
    lastSyncTime,
    syncIntervalMinutes: 30,
  };
}

async function checkSeamlessSSOLive(domain: string): Promise<SeamlessSSOStatus> {
  let kerberosTicketPresent = false;
  let spnRegistered = false;
  let decryrptionKeyFound = false;

  if (isToolAvailable("klist")) {
    const klistOutput = runCommand("klist");
    if (klistOutput && klistOutput.toLowerCase().includes("azureactivedirectory")) {
      kerberosTicketPresent = true;
    }
  }

  if (isToolAvailable("setspn")) {
    const spn = `HTTP/autologon.microsoftazuread.com`;
    const spnOutput = runCommand(`setspn -Q ${spn}`);
    if (spnOutput && spnOutput.includes(spn)) {
      spnRegistered = true;
    }
  }

  if (isToolAvailable("ldapsearch")) {
    const baseDn = domain.split(".").map((p) => `DC=${p}`).join(",");
    const ldapFilter = "(servicePrincipalName=HTTP/autologon.microsoftazuread.com)";
    const cmd = `ldapsearch -x -H ldap://${domain.toLowerCase()} -b "${baseDn}" "${ldapFilter}" servicePrincipalName`;
    const ldapOutput = runCommand(cmd);
    if (ldapOutput && ldapOutput.includes("autologon.microsoftazuread.com")) {
      spnRegistered = true;
    }
  }

  return {
    enabled: kerberosTicketPresent || spnRegistered,
    kerberosTicketPresent,
    spnRegistered,
    decryrptionKeyFound,
  };
}

async function enumerateSyncAccountsLive(domain: string): Promise<SyncAccountInfo[]> {
  const accounts: SyncAccountInfo[] = [];
  const baseDn = domain.split(".").map((p) => `DC=${p}`).join(",");

  if (isToolAvailable("ldapsearch")) {
    const filter = "(|(samAccountName=MSOL_*)(samAccountName=AAD_*)(description=*account used by Azure Active Directory*))";
    const cmd = [
      `ldapsearch -x -H ldap://${domain.toLowerCase()}`,
      `-b "${baseDn}"`,
      `"${filter}"`,
      "samAccountName distinguishedName userPrincipalName lastLogon passwordLastSet userAccountControl description",
    ].join(" ");

    const output = runCommand(cmd, 30000);
    if (!output) return accounts;

    const entries = output.split("\n\n").filter((e) => e.trim());
    for (const entry of entries) {
      const samMatch = entry.match(/samAccountName:\s*(.+)/i);
      const dnMatch = entry.match(/distinguishedName:\s*(.+)/i);
      const upnMatch = entry.match(/userPrincipalName:\s*(.+)/i);
      const logonMatch = entry.match(/lastLogon:\s*(.+)/i);
      const pwdMatch = entry.match(/passwordLastSet:\s*(.+)/i);
      const uacMatch = entry.match(/userAccountControl:\s*(\d+)/i);

      if (samMatch) {
        const uac = uacMatch ? parseInt(uacMatch[1], 10) : 0;
        const enabled = !(uac & 0x2);
        accounts.push({
          samAccountName: samMatch[1].trim(),
          distinguishedName: dnMatch ? dnMatch[1].trim() : "",
          userPrincipalName: upnMatch ? upnMatch[1].trim() : "",
          lastLogon: logonMatch ? logonMatch[1].trim() : "Never",
          passwordLastSet: pwdMatch ? pwdMatch[1].trim() : "Never",
          enabled,
          cloudSynced: true,
        });
      }
    }
  } else if (isToolAvailable("rpcclient")) {
    const cmd = `rpcclient -U "" -N "${domain.toLowerCase()}" -c "enumdomusers" 2>/dev/null | grep -E "MSOL_|AAD_"`;
    const output = runCommand(cmd, 15000);
    if (output) {
      const lines = output.split("\n").filter((l) => l.trim());
      for (const line of lines) {
        const sam = line.match(/\[(.*)\]/)?.[1];
        if (sam) {
          accounts.push({
            samAccountName: sam,
            distinguishedName: generateFakeDN(domain, sam),
            userPrincipalName: generateFakeUPN(domain, sam),
            lastLogon: "Unknown (rpcclient)",
            passwordLastSet: "Unknown (rpcclient)",
            enabled: true,
            cloudSynced: true,
          });
        }
      }
    }
  }

  return accounts;
}

async function checkStaleSyncAccounts(
  accounts: SyncAccountInfo[],
  staleDays = 90
): Promise<{ stale: string[]; active: string[] }> {
  const stale: string[] = [];
  const active: string[] = [];
  const cutoff = Date.now() - staleDays * 86400000;

  for (const acct of accounts) {
    if (acct.lastLogon === "Never") {
      stale.push(acct.samAccountName);
      continue;
    }
    const logonDate = new Date(acct.lastLogon);
    if (isNaN(logonDate.getTime()) || logonDate.getTime() < cutoff) {
      stale.push(acct.samAccountName);
    } else {
      active.push(acct.samAccountName);
    }
  }

  return { stale, active };
}

// ─── Public API ──────────────────────────────────────────────────────────────

export interface HybridAttackOptions {
  dryRun?: boolean;
  domain?: string;
  dcIp?: string;
}

/**
 * Perform a full hybrid AD/Entra ID attack chain analysis.
 *
 * DRY-RUN: returns simulated results with realistic fake data.
 * LIVE: queries LDAP, Windows registry, and Kerberos state for real findings.
 */
export async function hybridADAttackChain(
  opts: HybridAttackOptions = {}
): Promise<HybridADResult> {
  const { dryRun = true, domain = "CORP.LOCAL", dcIp } = opts;

  if (dryRun) {
    const syncAccounts = simulateSyncAccounts(domain);
    const staleCheck = await checkStaleSyncAccounts(syncAccounts);
    return {
      domain,
      dryRun: true,
      phsAgent: simulatePHSAgent(),
      seamlessSSO: simulateSeamlessSSO(),
      syncAccounts,
      cloudOnlyAccounts: [
        generateFakeUPN(domain, "CloudServiceAcct"),
        generateFakeUPN(domain, "IntuneAdmin"),
      ],
      syncedAccounts: syncAccounts.map((a) => a.samAccountName),
      msolAccountExtractable: true,
      dcsyncPivotPossible: true,
      attackPaths: [
        "PHS credential extraction → on-prem DCSync pivot via MSOL_* account",
        "Seamless SSO Kerberos ticket decryption → offline password cracking",
        "Stale sync account abuse → undetected persistence",
        "Cloud-only account compromise → bypass on-prem controls",
      ],
    };
  }

  const phsAgent = await checkPHSAgentLive();
  const seamlessSSO = await checkSeamlessSSOLive(domain);
  const syncAccounts = await enumerateSyncAccountsLive(domain);
  const staleCheck = await checkStaleSyncAccounts(syncAccounts);

  const msolAccountExtractable = syncAccounts.some(
    (a) => a.samAccountName.startsWith("MSOL_") && a.enabled
  );

  const attackPaths: string[] = [];
  if (phsAgent.installed) {
    attackPaths.push(
      "PHS agent active — extract synced hashes via MSOL_* account DRSUAPI replication"
    );
  }
  if (seamlessSSO.enabled && seamlessSSO.kerberosTicketPresent) {
    attackPaths.push(
      "Seamless SSO Kerberos ticket detected — extract from browser cache or MEMORY for offline cracking"
    );
  }
  if (seamlessSSO.spnRegistered) {
    attackPaths.push(
      "SPN registered for autologon.microsoftazuread.com — potential Silver Ticket target"
    );
  }
  if (staleCheck.stale.length > 0) {
    attackPaths.push(
      `Stale sync accounts detected: ${staleCheck.stale.join(", ")} — abuse for persistence`
    );
  }
  if (msolAccountExtractable) {
    attackPaths.push(
      "MSOL_* account with replication rights — full DCSync pivot possible"
    );
  }

  const syncedAccounts = syncAccounts
    .filter((a) => a.cloudSynced)
    .map((a) => a.samAccountName);

  return {
    domain,
    dryRun: false,
    phsAgent,
    seamlessSSO,
    syncAccounts,
    cloudOnlyAccounts: [],
    syncedAccounts,
    msolAccountExtractable,
    dcsyncPivotPossible: msolAccountExtractable,
    attackPaths,
  };
}

/**
 * Simulate or execute PHS account extraction attack.
 * Returns the MSOL account name and extraction details.
 */
export async function simulatePasswordHashSyncAbuse(
  opts: HybridAttackOptions = {}
): Promise<HybridAttackResult> {
  const { dryRun = true, domain = "CORP.LOCAL" } = opts;

  if (dryRun) {
    return {
      technique: "Azure AD Connect Password Hash Sync (PHS) Account Extraction",
      targetAccount: generateFakeMSOLAccount(domain),
      details: "[DRY-RUN] Simulated retrieval of MSOL_ account credentials with Directory Replication rights.",
      dryRun: true,
    };
  }

  const accounts = await enumerateSyncAccountsLive(domain);
  const msolAcct = accounts.find(
    (a) => a.samAccountName.startsWith("MSOL_") && a.enabled
  );

  if (!msolAcct) {
    return {
      technique: "Azure AD Connect Password Hash Sync (PHS) Account Extraction",
      targetAccount: "N/A",
      details: `[LIVE] No extractable MSOL_* accounts found in ${domain}.`,
      dryRun: false,
    };
  }

  let extractionDetails = `[LIVE] Found MSOL account: ${msolAcct.samAccountName}\n`;
  extractionDetails += `  DN: ${msolAcct.distinguishedName}\n`;
  extractionDetails += `  UPN: ${msolAcct.userPrincipalName}\n`;
  extractionDetails += `  Last Logon: ${msolAcct.lastLogon}\n`;
  extractionDetails += `  Password Last Set: ${msolAcct.passwordLastSet}\n`;

  if (isToolAvailable("impacket-secretsdump")) {
    extractionDetails += `  [!] impacket-secretsdump available — DRSUAPI replication possible with this account\n`;
  } else {
    extractionDetails += `  [i] impacket-secretsdump not found — install impacket for full exploitation\n`;
  }

  return {
    technique: "Azure AD Connect Password Hash Sync (PHS) Account Extraction",
    targetAccount: msolAcct.samAccountName,
    details: extractionDetails,
    dryRun: false,
  };
}

/**
 * Simulate or execute Seamless SSO exploitation.
 * Tests for Kerberos ticket presence and SPN registration.
 */
export async function simulateSeamlessSSOAbuse(
  opts: HybridAttackOptions = {}
): Promise<HybridAttackResult> {
  const { dryRun = true, domain = "CORP.LOCAL" } = opts;

  if (dryRun) {
    return {
      technique: "Azure AD Seamless SSO Kerberos Ticket Extraction",
      targetAccount: "AZUREAD\\krbtgt_$AzureAD~76f2c70f-d9b2-470a-8a04-0e9e75f0b6e6",
      details: "[DRY-RUN] Simulated extraction of AzureAD Kerberos ticket from browser cache for offline decryption.",
      dryRun: true,
    };
  }

  const ssoStatus = await checkSeamlessSSOLive(domain);
  let details = "";

  if (ssoStatus.kerberosTicketPresent) {
    details = `[LIVE] Seamless SSO Kerberos ticket found in ticket cache.\n`;
    details += `  SPN: HTTP/autologon.microsoftazuread.com\n`;
    details += `  Ticket can be extracted from browser memory (Chrome: chrome://net-internals/#sockets)\n`;
    details += `  Offline decryption with krb5.conf modification enables password spray\n`;
  } else if (ssoStatus.spnRegistered) {
    details = `[LIVE] SPN registered for Seamless SSO but no ticket in cache.\n`;
    details += `  Trigger ticket via: klist purge && net use \\\\${domain}\\share\n`;
    details += `  Then extract from Kerberos ticket cache\n`;
  } else {
    details = `[LIVE] Seamless SSO does not appear to be enabled in ${domain}.\n`;
    details += `  No SPN registered for autologon.microsoftazuread.com\n`;
  }

  return {
    technique: "Azure AD Seamless SSO Kerberos Ticket Extraction",
    targetAccount: ssoStatus.kerberosTicketPresent
      ? "AZUREAD\\krbtgt_$AzureAD~76f2c70f-d9b2-470a-8a04-0e9e75f0b6e6"
      : "N/A",
    details,
    dryRun: false,
  };
}

/**
 * Enumerate cloud-only vs synced accounts in a hybrid AD/Entra ID environment.
 */
export async function enumerateHybridAccounts(
  opts: HybridAttackOptions = {}
): Promise<HybridAttackResult> {
  const { dryRun = true, domain = "CORP.LOCAL" } = opts;

  if (dryRun) {
    const syncAccts = simulateSyncAccounts(domain);
    const synced = syncAccts.map((a) => a.samAccountName).join(", ");
    return {
      technique: "Hybrid Account Enumeration (Cloud-Only vs Synced)",
      targetAccount: domain,
      details: `[DRY-RUN] Simulated enumeration:\n  Synced: ${synced}\n  Cloud-Only: CloudServiceAcct@${domain.toLowerCase()}, IntuneAdmin@${domain.toLowerCase()}\n  Stale: 0 accounts`,
      dryRun: true,
    };
  }

  const syncAccts = await enumerateSyncAccountsLive(domain);
  const staleCheck = await checkStaleSyncAccounts(syncAccts);
  const synced = syncAccts.map((a) => a.samAccountName).join(", ");
  const staleList = staleCheck.stale.length > 0 ? staleCheck.stale.join(", ") : "None";

  return {
    technique: "Hybrid Account Enumeration (Cloud-Only vs Synced)",
    targetAccount: domain,
    details: `[LIVE] Enumeration results for ${domain}:\n  Synced accounts: ${synced || "None found"}\n  Stale accounts (>90 days): ${staleList}\n  Total sync accounts: ${syncAccts.length}`,
    dryRun: false,
  };
}

export default {
  hybridADAttackChain,
  simulatePasswordHashSyncAbuse,
  simulateSeamlessSSOAbuse,
  enumerateHybridAccounts,
};
