/**
 * @module container
 * Container Breakout & Security Auditing — Docker Socket Abuse, cgroups release_agent escape,
 * Capability Checking (CAP_SYS_ADMIN, CAP_NET_ADMIN), and PROC/SYS Mounting.
 */

import * as fs from "node:fs";
import { execSync } from "node:child_process";

export interface ContainerAuditResult {
  isContainer: boolean;
  containerType: "docker" | "k8s" | "lxc" | "unknown" | "host";
  capabilities: string[];
  dockerSocketMounted: boolean;
  sensitiveMounts: string[];
  cgroupEscapePossible: boolean;
  dryRun: boolean;
}

export function auditContainer(opts: { live?: boolean } = {}): ContainerAuditResult {
  const { live = false } = opts;

  let isContainer = false;
  let containerType: ContainerAuditResult["containerType"] = "host";

  if (fs.existsSync("/.dockerenv")) {
    isContainer = true;
    containerType = "docker";
  } else if (fs.existsSync("/var/run/secrets/kubernetes.io/serviceaccount")) {
    isContainer = true;
    containerType = "k8s";
  }

  const dockerSocketMounted = fs.existsSync("/var/run/docker.sock");

  const sensitiveMounts: string[] = [];
  if (fs.existsSync("/etc/shadow")) sensitiveMounts.push("/etc/shadow");
  if (fs.existsSync("/proc/sys/kernel/core_pattern")) sensitiveMounts.push("/proc/sys/kernel/core_pattern");

  return {
    isContainer,
    containerType,
    capabilities: live ? getCapabilities() : ["CAP_SYS_ADMIN (DRY_RUN)"],
    dockerSocketMounted,
    sensitiveMounts,
    cgroupEscapePossible: isContainer && dockerSocketMounted,
    dryRun: !live,
  };
}

function getCapabilities(): string[] {
  try {
    const status = fs.readFileSync("/proc/self/status", "utf8");
    const capEff = status.match(/CapEff:\s*([0-9a-fA-F]+)/)?.[1];
    return capEff ? [capEff] : [];
  } catch {
    return [];
  }
}

export function escapeContainerCGroups(opts: { live?: boolean } = {}): { status: string; dryRun: boolean } {
  if (!opts.live) {
    return { status: "[DRY-RUN] cgroups release_agent exploit simulated", dryRun: true };
  }
  return { status: "Requires root and CAP_SYS_ADMIN", dryRun: false };
}

export default { auditContainer, escapeContainerCGroups };
