/**
 * OurMine Security Module: Container & Kubernetes Security Auditor (container_k8s.ts)
 *
 * Live Kubernetes cluster security audit with RBAC analysis,
 * Pod Security Standards enforcement, and container escape risk detection.
 */

import { resolveDryRun } from "./exec_options.ts"
import { execFileSync } from "node:child_process";
import { isToolAvailable } from "./tool_detection.ts";

export interface K8sAuditOptions {
  targetCluster?: string;
  kubeconfigPath?: string;
  dryRun?: boolean;
}

export interface K8sAuditResult {
  cluster: string;
  rbacIssues: string[];
  podSecurityPolicies: string[];
  containerEscapeRisks: string[];
  findingsCount: number;
  /** Flattened findings list for CLI/tests */
  findings: string[];
  simulated: boolean;
}

interface RawPermission {
  apiGroup: string;
  resource: string;
  verb: string;
}

interface RawRoleBinding {
  metadata: { name: string; namespace?: string };
  subjects?: Array<{
    kind: string;
    name: string;
    namespace?: string;
  }>;
  roleRef: {
    apiGroup: string;
    kind: string;
    name: string;
  };
}

interface RawPod {
  metadata: { name: string; namespace: string };
  spec: {
    hostNetwork?: boolean;
    hostPID?: boolean;
    hostIPC?: boolean;
    containers: Array<{
      name: string;
      securityContext?: {
        privileged?: boolean;
        capabilities?: { add?: string[] };
        runAsRoot?: boolean;
        readOnlyRootFilesystem?: boolean;
      };
      volumeMounts?: Array<{ name: string; mountPath: string }>;
    }>;
    volumes?: Array<{
      name: string;
      hostPath?: { path: string };
    }>;
  };
}

interface RawServiceAccount {
  metadata: { name: string; namespace: string };
  automountServiceAccountToken?: boolean;
}

function kubectl(args: string[], options: { kubeconfig?: string; timeout?: number } = {}): string {
  const cmdArgs = [...args, "-o", "json"];
  if (options.kubeconfig) {
    cmdArgs.unshift("--kubeconfig", options.kubeconfig);
  }
  return execFileSync("kubectl", cmdArgs, {
    encoding: "utf-8",
    timeout: options.timeout ?? 15000,
    stdio: ["pipe", "pipe", "pipe"],
  });
}

function kubectlRaw(args: string[], options: { kubeconfig?: string; timeout?: number } = {}): string {
  const cmdArgs = [...args];
  if (options.kubeconfig) {
    cmdArgs.unshift("--kubeconfig", options.kubeconfig);
  }
  return execFileSync("kubectl", cmdArgs, {
    encoding: "utf-8",
    timeout: options.timeout ?? 15000,
    stdio: ["pipe", "pipe", "pipe"],
  });
}

function parseJson<T>(raw: string): T {
  return JSON.parse(raw) as T;
}

function auditPermissions(rawPermissions: RawPermission[]): string[] {
  const issues: string[] = [];
  const wildcardVerbs = new Set(["*"]);
  const dangerousResources = new Set(["secrets", "clusterrolebindings", "roles", "clusterroles", "configmaps"]);

  const permissionsByApiGroup: Record<string, RawPermission[]> = {};
  for (const perm of rawPermissions) {
    const key = perm.apiGroup || "";
    if (!permissionsByApiGroup[key]) permissionsByApiGroup[key] = [];
    permissionsByApiGroup[key].push(perm);
  }

  for (const [apiGroup, perms] of Object.entries(permissionsByApiGroup)) {
    const wildcardResources = perms.filter((p) => p.resource === "*");
    const wildcardVerbsOnResource = perms.filter((p) => p.verb === "*");

    if (wildcardResources.length > 0) {
      issues.push(
        `Wildcard resource access in API group '${apiGroup || "core"}': can perform all operations on all resources`
      );
    }

    if (wildcardVerbsOnResource.length > 0) {
      const resources = wildcardVerbsOnResource.map((p) => p.resource).join(", ");
      issues.push(
        `Full verb wildcard in API group '${apiGroup || "core"}' for resources: ${resources}`
      );
    }

    for (const perm of perms) {
      if (perm.verb === "create" && perm.resource === "pods" && apiGroup === "") {
        issues.push("Can create pods (potential for arbitrary code execution in cluster)");
      }
      if (perm.verb === "get" && perm.resource === "secrets" && apiGroup === "") {
        issues.push("Can read secrets (sensitive data exposure risk)");
      }
      if (
        (perm.verb === "update" || perm.verb === "patch" || perm.verb === "create") &&
        perm.resource === "clusterrolebindings"
      ) {
        issues.push("Can modify clusterrolebindings (privilege escalation vector)");
      }
      if (perm.verb === "delete" && dangerousResources.has(perm.resource)) {
        issues.push(`Can delete sensitive resource: ${perm.resource}`);
      }
    }
  }

  return [...new Set(issues)];
}

function auditClusterRoleBindings(bindings: RawRoleBinding[]): string[] {
  const issues: string[] = [];

  for (const binding of bindings) {
    const subjects = binding.subjects || [];
    const roleName = binding.roleRef.name;

    for (const subject of subjects) {
      if (roleName === "cluster-admin") {
        if (subject.kind === "User" && subject.name === "system:anonymous") {
          issues.push(
            `ClusterRoleBinding '${binding.metadata.name}' grants cluster-admin to system:anonymous`
          );
        }
        if (subject.kind === "ServiceAccount" && subject.name === "default") {
          issues.push(
            `ClusterRoleBinding '${binding.metadata.name}' grants cluster-admin to default ServiceAccount`
          );
        }
      }
      if (subject.kind === "Group" && subject.name === "system:unauthenticated") {
        issues.push(
          `ClusterRoleBinding '${binding.metadata.name}' grants '${roleName}' to unauthenticated users`
        );
      }
    }
  }

  return [...new Set(issues)];
}

function auditPodSecurity(pods: RawPod[]): string[] {
  const issues: string[] = [];

  for (const pod of pods) {
    const ns = pod.metadata.namespace;
    const name = pod.metadata.name;
    const spec = pod.spec;

    if (spec.hostNetwork) {
      issues.push(`Pod '${name}' in namespace '${ns}' uses hostNetwork (shares host network namespace)`);
    }
    if (spec.hostPID) {
      issues.push(`Pod '${name}' in namespace '${ns}' uses hostPID (shares host PID namespace)`);
    }
    if (spec.hostIPC) {
      issues.push(`Pod '${name}' in namespace '${ns}' uses hostIPC (shares host IPC namespace)`);
    }

    for (const container of spec.containers) {
      const ctx = container.securityContext;

      if (ctx?.privileged) {
        issues.push(
          `Container '${container.name}' in pod '${name}' runs in privileged mode`
        );
      }

      const caps = ctx?.capabilities?.add || [];
      if (caps.includes("CAP_SYS_ADMIN") || caps.includes("SYS_ADMIN")) {
        issues.push(
          `Container '${container.name}' in pod '${name}' has CAP_SYS_ADMIN capability (escape risk)`
        );
      }
      if (caps.includes("CAP_NET_ADMIN") || caps.includes("NET_ADMIN")) {
        issues.push(
          `Container '${container.name}' in pod '${name}' has CAP_NET_ADMIN capability`
        );
      }

      if (spec.volumes) {
        for (const vol of spec.volumes) {
          if (vol.hostPath?.path === "/var/run/docker.sock") {
            issues.push(
              `Container '${container.name}' in pod '${name}' mounts Docker socket`
            );
          }
          if (vol.hostPath?.path === "/etc/kubernetes" || vol.hostPath?.path === "/etc/kubernetes/pki") {
            issues.push(
              `Container '${container.name}' in pod '${name}' mounts Kubernetes credentials: ${vol.hostPath.path}`
            );
          }
          if (vol.hostPath?.path === "/") {
            issues.push(
              `Container '${container.name}' in pod '${name}' mounts host root filesystem`
            );
          }
        }
      }
    }
  }

  return [...new Set(issues)];
}

function auditServiceAccounts(sas: RawServiceAccount[]): string[] {
  const issues: string[] = [];

  for (const sa of sas) {
    if (sa.metadata.name === "default" && sa.automountServiceAccountToken !== false) {
      issues.push(
        `Default ServiceAccount in namespace '${sa.metadata.namespace}' has auto-mounted token (disable automountServiceAccountToken)`
      );
    }
    if (sa.automountServiceAccountToken === true && sa.metadata.name !== "default") {
      issues.push(
        `ServiceAccount '${sa.metadata.name}' in namespace '${sa.metadata.namespace}' explicitly enables token auto-mount`
      );
    }
  }

  return [...new Set(issues)];
}

function getDryRunFindings(cluster: string): K8sAuditResult {
  const rbacIssues = [
    "Wildcard resource access in API group 'core': can perform all operations on all resources",
    "ClusterRoleBinding 'cluster-admin-binding' grants cluster-admin to ServiceAccount 'default'",
    "Can create pods (potential for arbitrary code execution in cluster)",
    "Can read secrets (sensitive data exposure risk)",
    "ClusterRoleBinding 'unauthenticated-admin' grants 'edit' to unauthenticated users",
  ];

  const podSecurityPolicies = [
    "Pod 'nginx-deployment-7d5f6b8c4-xk2m9' in namespace 'production' uses hostNetwork (shares host network namespace)",
    "Container 'redis' in pod 'redis-cache-a1b2c3' runs in privileged mode",
    "Container 'sidecar' in pod 'app-workload-d4e5f6' has CAP_SYS_ADMIN capability (escape risk)",
    "Pod 'debug-pod-9g8h7' in namespace 'kube-system' uses hostPID (shares host PID namespace)",
  ];

  const containerEscapeRisks = [
    "Container 'jenkins-agent' in pod 'ci-runner-3f4g5' mounts Docker socket",
    "Container 'kubelet-reader' in pod 'monitoring-6h7i8' mounts Kubernetes credentials: /etc/kubernetes",
    "Container 'debug-utils' in pod 'pentest-pod-9j0k1' mounts host root filesystem",
  ];

  return {
    cluster,
    rbacIssues,
    podSecurityPolicies,
    containerEscapeRisks,
    findingsCount: rbacIssues.length + podSecurityPolicies.length + containerEscapeRisks.length,
    findings: [...rbacIssues, ...podSecurityPolicies, ...containerEscapeRisks],
    simulated: true,
  };
}

export class K8sSecurityAuditor {
  async auditCluster(options: K8sAuditOptions = {}): Promise<K8sAuditResult> {
    const cluster = options.targetCluster || "localhost:6443";
    const isDryRun = resolveDryRun(options);

    console.log(`[OurMine Security] Auditing K8s cluster '${cluster}' (dryRun: ${isDryRun})...`);

    if (isDryRun) {
      console.log("[OurMine Security] Dry-run mode: returning simulated findings.");
      return getDryRunFindings(cluster);
    }

    if (!isToolAvailable("kubectl")) {
      throw new Error(
        "kubectl not found on PATH. Install: https://kubernetes.io/docs/tasks/tools/"
      );
    }

    const kubeconfig = options.kubeconfigPath;

    try {
      kubectlRaw(["cluster-info"], { kubeconfig, timeout: 10000 });
    } catch (err: any) {
      const msg = err.stderr || err.message || "";
      if (msg.includes("Unable to connect") || msg.includes("connection refused")) {
        throw new Error(
          `Cannot connect to Kubernetes cluster '${cluster}'. Is kubeconfig configured and the API server reachable?`
        );
      }
      if (msg.includes("The connection to the server was refused")) {
        throw new Error(
          `Connection refused to Kubernetes API server. Ensure the cluster is running.`
        );
      }
      throw new Error(`kubectl cluster-info failed: ${msg.slice(0, 200)}`);
    }

    const rbacIssues: string[] = [];
    const podSecurityPolicies: string[] = [];
    const containerEscapeRisks: string[] = [];

    try {
      const permissionsRaw = kubectlRaw(
        ["auth", "can-i", "--list", "--as=system:anonymous"],
        { kubeconfig, timeout: 20000 }
      );
      const parsed = permissionsRaw
        .split("\n")
        .filter((l) => l.trim() && !l.startsWith("Resources"))
        .map((line) => {
          const parts = line.trim().split(/\s+/);
          return {
            apiGroup: parts[3] === "<none>" ? "" : parts[3] || "",
            resource: parts[1] || "",
            verb: parts[0] || "",
          };
        })
        .filter((p) => p.resource && p.verb);

      rbacIssues.push(...auditPermissions(parsed));
    } catch (err: any) {
      console.warn(`[OurMine Security] Warning: Could not enumerate permissions via 'auth can-i --list': ${err.message?.slice(0, 100)}`);
    }

    try {
      const bindingsRaw = kubectl(["get", "clusterrolebindings"], { kubeconfig });
      const bindingsData = parseJson<{ items: RawRoleBinding[] }>(bindingsRaw);
      rbacIssues.push(...auditClusterRoleBindings(bindingsData.items || []));
    } catch (err: any) {
      console.warn(`[OurMine Security] Warning: Could not fetch clusterrolebindings: ${err.message?.slice(0, 100)}`);
    }

    try {
      const podsRaw = kubectl(["get", "pods", "--all-namespaces"], { kubeconfig });
      const podsData = parseJson<{ items: RawPod[] }>(podsRaw);
      podSecurityPolicies.push(...auditPodSecurity(podsData.items || []));
    } catch (err: any) {
      console.warn(`[OurMine Security] Warning: Could not fetch pods: ${err.message?.slice(0, 100)}`);
    }

    try {
      const saRaw = kubectl(["get", "serviceaccounts", "--all-namespaces"], { kubeconfig });
      const saData = parseJson<{ items: RawServiceAccount[] }>(saRaw);
      const saIssues = auditServiceAccounts(saData.items || []);
      rbacIssues.push(...saIssues);
    } catch (err: any) {
      console.warn(`[OurMine Security] Warning: Could not fetch serviceaccounts: ${err.message?.slice(0, 100)}`);
    }

    const allRbac = [...new Set(rbacIssues)];
    const allPsp = [...new Set(podSecurityPolicies)];
    const allEscape = [...new Set(containerEscapeRisks)];

    const result: K8sAuditResult = {
      cluster,
      rbacIssues: allRbac,
      podSecurityPolicies: allPsp,
      containerEscapeRisks: allEscape,
      findingsCount: allRbac.length + allPsp.length + allEscape.length,
      findings: [...allRbac, ...allPsp, ...allEscape],
      simulated: false,
    };

    console.log(
      `[OurMine Security] Audit complete: ${result.findingsCount} finding(s) ` +
      `(${allRbac.length} RBAC, ${allPsp.length} PSP/PSS, ${allEscape.length} escape risks)`
    );

    return result;
  }
}

/** Convenience wrapper for CLI/tests */
export async function auditCluster(options: K8sAuditOptions = {}): Promise<K8sAuditResult> {
  return new K8sSecurityAuditor().auditCluster(options);
}
