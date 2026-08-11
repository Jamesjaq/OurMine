/**
 * @module security/cicd_k8s_audit
 * CI/CD Pipeline & Kubernetes RBAC Audit Engine
 * Evaluates GitHub Actions workflows, secret leakage in build pipelines,
 * and Kubernetes ServiceAccount RBAC permissions.
 */

import { resolveDryRun } from "./exec_options.ts"
import * as fs from "node:fs"
import * as path from "node:path"
import { execFileSync } from "node:child_process"
import { isToolAvailable } from "./tool_detection.ts"

// ─── Types ────────────────────────────────────────────────────────────────────

export interface CICDConfig {
  repositoryOrCluster?: string
  dryRun?: boolean
  repoPath?: string
  kubeConfig?: string
}

export interface CICDK8sFinding {
  id: string
  target: string
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
  title: string
  description: string
  remediation: string
}

export interface CICDK8sAuditResult {
  target: string
  workflowsAudited: number
  k8sServiceAccountsChecked: number
  findings: CICDK8sFinding[]
  isDryRun: boolean
}

// ─── Constants ────────────────────────────────────────────────────────────────

const DANGEROUS_TRIGGERS = new Set([
  "workflow_dispatch",
  "pull_request_target",
  "workflow_run",
])

const SECRET_PATTERNS: Array<{ label: string; regex: RegExp }> = [
  { label: "AWS Secret Access Key", regex: /(?:aws[_-]?secret[_-]?access[_-]?key|AKIA[0-9A-Z]{16})/i },
  { label: "GitHub Token", regex: /gh[pousr]_[A-Za-z0-9_]{36,}/ },
  { label: "Generic API Key", regex: /(?:api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*['"][A-Za-z0-9_\-]{20,}['"]/i },
  { label: "Private Key Block", regex: /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/ },
  { label: "Generic Secret", regex: /(?:secret|password|passwd|pwd)\s*[:=]\s*['"][^'"]{8,}['"]/i },
  { label: "Slack Token", regex: /xox[baprs]-[0-9]{10,}-[0-9a-z\-]+/ },
  { label: "NPM Token", regex: /npm_[A-Za-z0-9]{36}/ },
  { label: "PyPI Token", regex: /pypi-[A-Za-z0-9_\-]{60,}/ },
]

// ─── Helpers ──────────────────────────────────────────────────────────────────

let findingCounter = 0

function makeFinding(
  target: string,
  severity: CICDK8sFinding["severity"],
  title: string,
  description: string,
  remediation: string,
): CICDK8sFinding {
  findingCounter++
  const prefix = severity === "CRITICAL" ? "CICD" : severity === "HIGH" ? "K8S" : "AUD"
  return { id: `${prefix}-${String(findingCounter).padStart(2, "0")}`, target, severity, title, description, remediation }
}

function execSafe(args: string[], options: { timeout?: number; cwd?: string } = {}): string | null {
  try {
    return execFileSync(args[0], args.slice(1), {
      encoding: "utf-8",
      timeout: options.timeout ?? 15000,
      cwd: options.cwd,
      stdio: ["pipe", "pipe", "pipe"],
    })
  } catch {
    return null
  }
}

function kubectl(args: string[], kubeConfig?: string): string | null {
  const fullArgs = [...args, "-o", "json"]
  if (kubeConfig) fullArgs.unshift("--kubeconfig", kubeConfig)
  return execSafe(["kubectl", ...fullArgs], { timeout: 15000 })
}

function kubectlRaw(args: string[], kubeConfig?: string): string | null {
  const fullArgs = [...args]
  if (kubeConfig) fullArgs.unshift("--kubeconfig", kubeConfig)
  return execSafe(["kubectl", ...fullArgs], { timeout: 15000 })
}

// ─── CI/CD Live Audit ─────────────────────────────────────────────────────────

interface WorkflowFile {
  name: string
  content: string
}

function findWorkflowFiles(repoPath: string): WorkflowFile[] {
  const workflowsDir = path.join(repoPath, ".github", "workflows")
  const files: WorkflowFile[] = []

  if (!fs.existsSync(workflowsDir)) return files

  let entries: string[]
  try {
    entries = fs.readdirSync(workflowsDir)
  } catch {
    return files
  }

  for (const entry of entries) {
    if (!entry.endsWith(".yml") && !entry.endsWith(".yaml")) continue
    const fullPath = path.join(workflowsDir, entry)
    try {
      const content = fs.readFileSync(fullPath, "utf-8")
      files.push({ name: `.github/workflows/${entry}`, content })
    } catch {
      // skip unreadable files
    }
  }

  return files
}

function auditWorkflow(workflow: WorkflowFile): CICDK8sFinding[] {
  const findings: CICDK8sFinding[] = []
  const lines = workflow.content.split("\n")

  // Check for dangerous triggers
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]
    for (const trigger of DANGEROUS_TRIGGERS) {
      if (line.includes(trigger)) {
        findings.push(
          makeFinding(
            workflow.name,
            trigger === "pull_request_target" ? "CRITICAL" : "HIGH",
            `Dangerous workflow trigger: ${trigger}`,
            `Workflow uses '${trigger}' which can be exploited by attackers via malicious PRs or fork contributions to execute code with access to repository secrets.`,
            trigger === "pull_request_target"
              ? "Switch to 'pull_request' trigger or ensure no secret-exposing steps run on untrusted code."
              : "Review trigger conditions and ensure secrets are not exposed to untrusted inputs.",
          ),
        )
      }
    }
  }

  // Check for hardcoded secrets
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]
    // Skip comments and env var references
    if (line.trimStart().startsWith("#")) continue
    if (line.includes("${{") && line.includes("secrets.")) continue

    for (const { label, regex } of SECRET_PATTERNS) {
      if (regex.test(line)) {
        findings.push(
          makeFinding(
            workflow.name,
            "CRITICAL",
            `Potential hardcoded ${label}`,
            `Line ${i + 1} appears to contain a hardcoded ${label} instead of using GitHub encrypted secrets.`,
            `Move the secret to GitHub repository secrets and reference it via \${{ secrets.SECRET_NAME }}.`,
          ),
        )
      }
    }
  }

  // Check for overly broad permissions
  let inPermissions = false
  for (const line of lines) {
    if (line.trim().startsWith("permissions:")) {
      inPermissions = true
    } else if (inPermissions && line.trim().startsWith("contents: write")) {
      findings.push(
        makeFinding(
          workflow.name,
          "MEDIUM",
          "Overly broad workflow permissions",
          "Workflow grants 'contents: write' which allows pushing code changes, potentially bypassing branch protection.",
          "Apply least-privilege permissions. Use 'contents: read' unless write is strictly required.",
        ),
      )
      inPermissions = false
    } else if (inPermissions && !line.trim().startsWith("-") && !line.trim().startsWith("permissions:")) {
      inPermissions = false
    }
  }

  // Check for unsafe artifact handling
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].includes("upload-artifact") || lines[i].includes("actions/upload-artifact")) {
      // Check if next lines reference sensitive paths
      const context = lines.slice(Math.max(0, i - 2), Math.min(lines.length, i + 5)).join(" ")
      if (
        context.includes(".env") ||
        context.includes("credentials") ||
        context.includes(".pem") ||
        context.includes(".key") ||
        context.includes("kubeconfig")
      ) {
        findings.push(
          makeFinding(
            workflow.name,
            "HIGH",
            "Sensitive files in artifact upload",
            "Workflow uploads artifacts that may contain sensitive files (.env, credentials, keys, kubeconfig).",
            "Exclude sensitive paths from artifact uploads. Use .gitignore patterns and upload-artifact 'path' exclusions.",
          ),
        )
      }
    }
  }

  return findings
}

// ─── Kubernetes Live Audit ────────────────────────────────────────────────────

interface ServiceAccountInfo {
  name: string
  namespace: string
  automountToken: boolean
}

function getNamespaces(kubeConfig?: string): string[] {
  const raw = kubectl(["get", "namespaces"], kubeConfig)
  if (!raw) return []

  try {
    const parsed = JSON.parse(raw) as { items: Array<{ metadata: { name: string } }> }
    return parsed.items.map((ns) => ns.metadata.name)
  } catch {
    return []
  }
}

function getServiceAccounts(namespace: string, kubeConfig?: string): ServiceAccountInfo[] {
  const raw = kubectl(["get", "serviceaccounts", "-n", namespace], kubeConfig)
  if (!raw) return []

  try {
    const parsed = JSON.parse(raw) as {
      items: Array<{
        metadata: { name: string; namespace: string }
        automountServiceAccountToken?: boolean
      }>
    }
    return parsed.items.map((sa) => ({
      name: sa.metadata.name,
      namespace: sa.metadata.namespace || namespace,
      automountToken: sa.automountServiceAccountToken !== false,
    }))
  } catch {
    return []
  }
}

function checkPermissions(sa: ServiceAccountInfo, kubeConfig?: string): CICDK8sFinding[] {
  const findings: CICDK8sFinding[] = []
  const saRef = `${sa.namespace}/${sa.name}`

  // Check automount token
  if (sa.automountToken && sa.name !== "default") {
    findings.push(
      makeFinding(
        `ServiceAccount: ${saRef}`,
        "MEDIUM",
        "ServiceAccount auto-mounts token",
        `ServiceAccount '${saRef}' auto-mounts its API token into pods. This can be leveraged for lateral movement if a pod is compromised.`,
        "Set automountServiceAccountToken: false on the ServiceAccount and mount tokens explicitly only when needed.",
      ),
    )
  }

  // Use kubectl auth can-i --list for this SA
  const raw = kubectlRaw(["auth", "can-i", "--list", `-n`, sa.namespace, `--as=system:serviceaccount:${sa.namespace}:${sa.name}`], kubeConfig)
  if (!raw) return findings

  const lines = raw.split("\n").filter((l) => l.trim())
  let hasWildcardVerbs = false
  let hasSecretsAccess = false
  let hasClusterAdmin = false
  let hasCreatePods = false
  let hasPrivilegeEscalation = false

  for (const line of lines) {
    const parts = line.split(/\s+/)
    if (parts.length < 3) continue
    const [apiGroup, resource, verb] = parts

    if (verb === "*") hasWildcardVerbs = true
    if (resource === "secrets" && (verb === "get" || verb === "list" || verb === "*")) hasSecretsAccess = true
    if (resource === "clusterrolebindings" && ["create", "update", "patch", "*"].includes(verb)) hasPrivilegeEscalation = true
    if (resource === "pods" && verb === "create") hasCreatePods = true

    // Check for cluster-admin equivalent (wildcard on everything)
    if (apiGroup === "*" && resource === "*" && verb === "*") hasClusterAdmin = true
  }

  if (hasClusterAdmin) {
    findings.push(
      makeFinding(
        `ServiceAccount: ${saRef}`,
        "CRITICAL",
        "ServiceAccount has cluster-admin equivalent",
        `ServiceAccount '${saRef}' has wildcard permissions on all resources and verbs — equivalent to cluster-admin.`,
        "Apply least-privilege RBAC. Create a Role with only the specific verbs and resources the SA requires.",
      ),
    )
  }

  if (hasWildcardVerbs && !hasClusterAdmin) {
    findings.push(
      makeFinding(
        `ServiceAccount: ${saRef}`,
        "HIGH",
        "Wildcard verb access detected",
        `ServiceAccount '${saRef}' has wildcard verb ('*') permissions on one or more resources.`,
        "Replace wildcard verbs with explicit verb lists (get, list, watch, create, etc.).",
      ),
    )
  }

  if (hasSecretsAccess && !hasClusterAdmin) {
    findings.push(
      makeFinding(
        `ServiceAccount: ${saRef}`,
        "HIGH",
        "ServiceAccount can read secrets",
        `ServiceAccount '${saRef}' has get/list access to secrets, which may contain credentials, TLS keys, or tokens.`,
        "Restrict secrets access to only the specific secrets the SA needs. Use resource names in RBAC rules.",
      ),
    )
  }

  if (hasPrivilegeEscalation) {
    findings.push(
      makeFinding(
        `ServiceAccount: ${saRef}`,
        "CRITICAL",
        "ServiceAccount can modify RBAC",
        `ServiceAccount '${saRef}' can create/update/patch clusterrolebindings, enabling privilege escalation to any role.`,
        "Remove RBAC modification permissions. Audit all ClusterRoleBindings created by this SA.",
      ),
    )
  }

  if (hasCreatePods && !hasClusterAdmin) {
    findings.push(
      makeFinding(
        `ServiceAccount: ${saRef}`,
        "HIGH",
        "ServiceAccount can create pods",
        `ServiceAccount '${saRef}' can create pods, which can be abused to run arbitrary code in the cluster or escape to the host.`,
        "Restrict pod creation permissions. If needed, use PodSecurityStandards/PodSecurityAdmissions to limit privileged pods.",
      ),
    )
  }

  return findings
}

function auditPodSecurity(kubeConfig?: string): CICDK8sFinding[] {
  const findings: CICDK8sFinding[] = []

  const raw = kubectl(["get", "pods", "-A"], kubeConfig)
  if (!raw) return findings

  try {
    const parsed = JSON.parse(raw) as {
      items: Array<{
        metadata: { name: string; namespace: string }
        spec: {
          hostNetwork?: boolean
          hostPID?: boolean
          hostIPC?: boolean
          containers: Array<{
            name: string
            securityContext?: {
              privileged?: boolean
              capabilities?: { add?: string[] }
            }
            volumeMounts?: Array<{ name: string; mountPath: string }>
          }>
          volumes?: Array<{
            name: string
            hostPath?: { path: string }
          }>
        }
      }>
    }

    for (const pod of parsed.items) {
      const { name, namespace } = pod.metadata
      const podRef = `${namespace}/${name}`
      const spec = pod.spec

      if (spec.hostNetwork) {
        findings.push(
          makeFinding(
            `Pod: ${podRef}`,
            "HIGH",
            "Pod uses host network namespace",
            `Pod '${name}' in namespace '${namespace}' shares the host network namespace, allowing sniffing of host traffic.`,
            "Remove hostNetwork: true from the pod spec.",
          ),
        )
      }

      if (spec.hostPID) {
        findings.push(
          makeFinding(
            `Pod: ${podRef}`,
            "HIGH",
            "Pod shares host PID namespace",
            `Pod '${name}' shares the host PID namespace, enabling viewing all host processes and potential ptrace attacks.`,
            "Remove hostPID: true from the pod spec.",
          ),
        )
      }

      if (spec.hostIPC) {
        findings.push(
          makeFinding(
            `Pod: ${podRef}`,
            "HIGH",
            "Pod shares host IPC namespace",
            `Pod '${name}' shares the host IPC namespace, enabling shared memory attacks against host processes.`,
            "Remove hostIPC: true from the pod spec.",
          ),
        )
      }

      for (const container of spec.containers) {
        if (container.securityContext?.privileged) {
          findings.push(
            makeFinding(
              `Pod: ${podRef} / Container: ${container.name}`,
              "CRITICAL",
              "Privileged container detected",
              `Container '${container.name}' in pod '${name}' runs in privileged mode with full host access.`,
              "Remove privileged: true. Use specific capabilities if needed instead of full privileged mode.",
            ),
          )
        }

        const caps = container.securityContext?.capabilities?.add || []
        if (caps.includes("SYS_ADMIN") || caps.includes("NET_ADMIN") || caps.includes("SYS_PTRACE")) {
          findings.push(
            makeFinding(
              `Pod: ${podRef} / Container: ${container.name}`,
              "HIGH",
              "Dangerous capabilities added to container",
              `Container '${container.name}' has elevated capabilities: ${caps.join(", ")}. These can be used for container escape.`,
              "Remove unnecessary capabilities. Drop all capabilities and add only what is required.",
            ),
          )
        }
      }

      // Check for hostPath volume mounts
      for (const vol of spec.volumes || []) {
        if (vol.hostPath) {
          const dangerousPaths = ["/", "/etc", "/var/run/docker.sock", "/proc", "/sys", "/root"]
          const isDangerous = dangerousPaths.some((p) => vol.hostPath!.path === p || vol.hostPath!.path.startsWith(p + "/"))
          if (isDangerous) {
            findings.push(
              makeFinding(
                `Pod: ${podRef}`,
                "CRITICAL",
                "Dangerous hostPath volume mount",
                `Volume '${vol.name}' mounts host path '${vol.hostPath!.path}' into the pod, enabling host filesystem access.`,
                "Remove hostPath volume mounts. Use PersistentVolumeClaims or emptyDir instead.",
              ),
            )
          } else {
            findings.push(
              makeFinding(
                `Pod: ${podRef}`,
                "MEDIUM",
                "hostPath volume mount detected",
                `Volume '${vol.name}' mounts host path '${vol.hostPath!.path}' into the pod.`,
                "Review if hostPath is necessary. Prefer PersistentVolumeClaims or ConfigMaps.",
              ),
            )
          }
        }
      }
    }
  } catch {
    // JSON parse failure — skip pod audit
  }

  return findings
}

function checkClusterRoles(kubeConfig?: string): CICDK8sFinding[] {
  const findings: CICDK8sFinding[] = []

  const raw = kubectl(["get", "clusterrolebindings", "-A"], kubeConfig)
  if (!raw) return findings

  try {
    const parsed = JSON.parse(raw) as {
      items: Array<{
        metadata: { name: string }
        subjects?: Array<{ kind: string; name: string; namespace?: string }>
        roleRef: { name: string }
      }>
    }

    for (const binding of parsed.items) {
      const subjects = binding.subjects || []
      const roleName = binding.roleRef.name

      if (roleName !== "cluster-admin") continue

      for (const subject of subjects) {
        if (subject.kind === "User" && subject.name === "system:anonymous") {
          findings.push(
            makeFinding(
              `ClusterRoleBinding: ${binding.metadata.name}`,
              "CRITICAL",
              "cluster-admin granted to anonymous users",
              `ClusterRoleBinding '${binding.metadata.name}' grants cluster-admin to system:anonymous, allowing unauthenticated full cluster access.`,
              "Remove the binding immediately. Audit for unauthorized changes.",
            ),
          )
        }
        if (subject.kind === "ServiceAccount" && subject.name === "default") {
          findings.push(
            makeFinding(
              `ClusterRoleBinding: ${binding.metadata.name}`,
              "CRITICAL",
              "cluster-admin granted to default ServiceAccount",
              `ClusterRoleBinding '${binding.metadata.name}' grants cluster-admin to the default ServiceAccount.`,
              "Remove the binding. Create a dedicated ServiceAccount with minimal permissions.",
            ),
          )
        }
        if (subject.kind === "Group" && subject.name === "system:unauthenticated") {
          findings.push(
            makeFinding(
              `ClusterRoleBinding: ${binding.metadata.name}`,
              "CRITICAL",
              "cluster-admin granted to unauthenticated users",
              `ClusterRoleBinding '${binding.metadata.name}' grants '${roleName}' to unauthenticated users.`,
              "Remove the binding immediately.",
            ),
          )
        }
      }
    }
  } catch {
    // JSON parse failure
  }

  return findings
}


// ─── Main Entry Point ─────────────────────────────────────────────────────────

export function auditCICDAndK8s(
  config: CICDConfig = {},
): CICDK8sAuditResult {
  const isDryRun = config.dryRun !== false
  const target = config.repositoryOrCluster ?? "local-workspace"
  const repoPath = config.repoPath ?? process.cwd()
  const kubeConfig = config.kubeConfig

  if (isDryRun) {
    findingCounter = 0
    const findings: CICDK8sFinding[] = []
    let workflowsAudited = 0
    try {
      const workflowFiles = findWorkflowFiles(repoPath)
      workflowsAudited = workflowFiles.length
      for (const wf of workflowFiles) {
        findings.push(...auditWorkflow(wf))
      }
    } catch (err) {
      findings.push(
        makeFinding(
          repoPath,
          "MEDIUM",
          "CI/CD local audit error",
          `Failed to audit workflows: ${err instanceof Error ? err.message : String(err)}`,
          "Ensure repo path contains .github/workflows/",
        ),
      )
    }
    return {
      target,
      workflowsAudited,
      k8sServiceAccountsChecked: 0,
      findings,
      isDryRun: true,
    }
  }

  // ── Live mode ──────────────────────────────────────────────────────────────
  findingCounter = 0
  const findings: CICDK8sFinding[] = []
  let workflowsAudited = 0
  let k8sServiceAccountsChecked = 0

  // CI/CD Audit
  try {
    const workflowFiles = findWorkflowFiles(repoPath)
    workflowsAudited = workflowFiles.length

    for (const wf of workflowFiles) {
      findings.push(...auditWorkflow(wf))
    }
  } catch (err) {
    findings.push(
      makeFinding(
        repoPath,
        "MEDIUM",
        "CI/CD audit error",
        `Failed to audit CI/CD workflows: ${err instanceof Error ? err.message : String(err)}`,
        "Ensure the repository path is valid and contains .github/workflows/ directory.",
      ),
    )
  }

  // Kubernetes Audit
  const kubectlAvailable = isToolAvailable("kubectl")

  if (kubectlAvailable) {
    // Verify cluster connectivity
    const clusterCheck = kubectlRaw(["cluster-info"], kubeConfig)
    if (clusterCheck) {
      try {
        // Audit namespaces and service accounts
        const namespaces = getNamespaces(kubeConfig)

        for (const ns of namespaces) {
          const serviceAccounts = getServiceAccounts(ns, kubeConfig)
          for (const sa of serviceAccounts) {
            if (sa.name === "system:default" || sa.name.startsWith("system:")) continue
            k8sServiceAccountsChecked++
            findings.push(...checkPermissions(sa, kubeConfig))
          }
        }

        // Audit pod security
        findings.push(...auditPodSecurity(kubeConfig))

        // Audit cluster role bindings
        findings.push(...checkClusterRoles(kubeConfig))
      } catch (err) {
        findings.push(
          makeFinding(
            target,
            "MEDIUM",
            "Kubernetes audit error",
            `Failed to audit Kubernetes cluster: ${err instanceof Error ? err.message : String(err)}`,
            "Ensure kubectl is configured and has cluster access.",
          ),
        )
      }
    } else {
      findings.push(
        makeFinding(
          target,
          "MEDIUM",
          "Cannot connect to Kubernetes cluster",
          "kubectl cluster-info failed. No cluster connection available.",
          "Configure kubeconfig or verify cluster accessibility.",
        ),
      )
    }
  } else {
    findings.push(
      makeFinding(
        target,
        "LOW",
        "kubectl not available",
        "kubectl is not installed or not on PATH. Kubernetes audit was skipped.",
        "Install kubectl: https://kubernetes.io/docs/tasks/tools/",
      ),
    )
  }

  return {
    target,
    workflowsAudited,
    k8sServiceAccountsChecked,
    findings,
    isDryRun: false,
  }
}

export default { auditCICDAndK8s }
