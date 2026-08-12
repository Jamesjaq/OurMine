/**
 * @module chaindrop_oidc
 * CI runner OIDC token extraction simulation — GitHub Actions / GitLab CI patterns.
 */
import * as fs from "node:fs"
import * as path from "node:path"
import { resolveDryRun } from "./exec_options.ts"

export interface ChainDropFinding {
  id: string
  severity: "critical" | "high" | "medium" | "low"
  title: string
  mitre: string
  pattern?: string
}

export interface ChainDropOidcResult {
  target: string
  dryRun: boolean
  ciProvider: "github" | "gitlab" | "unknown"
  envPatterns: string[]
  findings: ChainDropFinding[]
  federatedCredRisk: boolean
  recommendations: string[]
  summary: string
}

const OIDC_ENV_PATTERNS = [
  "ACTIONS_ID_TOKEN_REQUEST_URL",
  "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
  "OIDC_TOKEN",
  "CI_JOB_JWT",
  "CI_JOB_JWT_V2",
  "GITLAB_OIDC_TOKEN",
  "AWS_WEB_IDENTITY_TOKEN_FILE",
  "AZURE_FEDERATED_TOKEN_FILE",
]

const WORKFLOW_PATTERNS = [
  { re: /id-token:\s*write/i, id: "gh-id-token-write", title: "GitHub workflow requests id-token write", mitre: "T1528" },
  { re: /permissions:\s*\{[^}]*id-token/i, id: "gh-perm-id-token", title: "Workflow permissions include id-token", mitre: "T1078.004" },
  { re: /azure\/login@v/i, id: "azure-login-oidc", title: "Azure OIDC federated login in CI", mitre: "T1078.004" },
  { re: /aws-actions\/configure-aws-credentials/i, id: "aws-oidc-creds", title: "AWS OIDC credential configuration", mitre: "T1552.001" },
]

function detectCiProvider(cwd: string): "github" | "gitlab" | "unknown" {
  if (fs.existsSync(path.join(cwd, ".github", "workflows"))) return "github"
  if (fs.existsSync(path.join(cwd, ".gitlab-ci.yml"))) return "gitlab"
  return "unknown"
}

function scanWorkflows(cwd: string): ChainDropFinding[] {
  const findings: ChainDropFinding[] = []
  const wfDir = path.join(cwd, ".github", "workflows")
  if (!fs.existsSync(wfDir)) return findings

  for (const file of fs.readdirSync(wfDir).filter((f) => f.endsWith(".yml") || f.endsWith(".yaml"))) {
    const content = fs.readFileSync(path.join(wfDir, file), "utf8")
    for (const p of WORKFLOW_PATTERNS) {
      if (p.re.test(content)) {
        findings.push({
          id: p.id,
          severity: "high",
          title: `${p.title} (${file})`,
          mitre: p.mitre,
          pattern: p.re.source,
        })
      }
    }
  }
  return findings
}

export function auditChainDropOidc(
  target: string,
  opts: { dryRun?: boolean; repoPath?: string; live?: boolean } = {},
): ChainDropOidcResult {
  const dryRun = resolveDryRun(opts)
  const cwd = opts.repoPath ?? process.cwd()
  const ciProvider = detectCiProvider(cwd)
  const findings = scanWorkflows(cwd)

  const envPresent = OIDC_ENV_PATTERNS.filter((k) => process.env[k])
  if (envPresent.length) {
    findings.push({
      id: "oidc-env-present",
      severity: "critical",
      title: `OIDC env vars present in runner context: ${envPresent.join(", ")}`,
      mitre: "T1528",
    })
  }

  if (!findings.length) {
    findings.push({
      id: "oidc-pattern-stub",
      severity: "medium",
      title: "No OIDC workflow patterns detected — assess federated credential scope",
      mitre: "T1078.004",
    })
  }

  const federatedCredRisk = findings.some((f) => f.mitre === "T1078.004" || f.mitre === "T1528")

  return {
    target,
    dryRun,
    ciProvider,
    envPatterns: OIDC_ENV_PATTERNS,
    findings,
    federatedCredRisk,
    recommendations: [
      "Restrict federated credentials to specific repo + environment + branch",
      "Use short-lived tokens with minimal cloud scope",
      "Audit workflows with id-token: write permission",
    ],
    summary: `ChainDrop OIDC ${ciProvider} scan — ${findings.length} findings (${dryRun ? "dry-run" : "live"})`,
  }
}

export default { auditChainDropOidc }
