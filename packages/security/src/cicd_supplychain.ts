/**
 * @module security/cicd_supplychain
 * CI/CD Pipeline & Supply Chain Security Auditor
 * Evaluates GitHub Actions workflows for dangerous triggers, hardcoded secrets,
 * dependency vulnerabilities, typosquatting, Dockerfile misconfigs, and .npmrc registry overrides.
 */

import { resolveDryRun } from "./exec_options.ts"
import * as fs from "node:fs"
import * as path from "node:path"
import { execFileSync } from "node:child_process"
import { isToolAvailable } from "./tool_detection.ts"

// ─── Types ───────────────────────────────────────────────────────────────────

export interface CicdFinding {
  id: string
  file: string
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
  title: string
  description: string
  remediation: string
}

export interface CicdAuditOptions {
  repoUrl?: string
  ciPlatform?: "github-actions" | "gitlab-ci" | "jenkins"
  dryRun?: boolean
  /** Working directory to audit (defaults to process.cwd()) */
  cwd?: string
}

export interface CicdAuditResult {
  repo: string
  cwd: string
  untrustedRunnerRisk: boolean
  poisonedPipelineSecrets: string[]
  dependencyConfusionVulnerabilities: string[]
  findings: CicdFinding[]
  workflowsParsed: number
  dependenciesChecked: number
  npmAuditVulnerabilities: number
  dockerfileIssues: number
  simulated: boolean
}

// ─── Constants ───────────────────────────────────────────────────────────────

const DANGEROUS_TRIGGERS = [
  "workflow_dispatch",
  "pull_request_target",
  "workflow_run",
] as const

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

const POPULAR_PACKAGES = new Set([
  "react", "react-dom", "lodash", "axios", "express", "moment", "chalk",
  "commander", "webpack", "babel", "typescript", "eslint", "prettier",
  "jest", "mocha", "next", "vue", "angular", "svelte", "jquery",
  "underscore", "async", "request", "body-parser", "cors",
  "helmet", "morgan", "uuid", "crypto-js", "bcrypt", "jsonwebtoken",
  "dotenv", "semver", "minimist", "glob", "fs-extra",
  "node-fetch", "got", "superagent", "socket.io", "ws",
])

// ─── Typosquatting Detection ─────────────────────────────────────────────────

function levenshtein(a: string, b: string): number {
  const m = a.length
  const n = b.length
  const dp: number[][] = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0))
  for (let i = 0; i <= m; i++) dp[i][0] = i
  for (let j = 0; j <= n; j++) dp[0][j] = j
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] = Math.min(
        dp[i - 1][j] + 1,
        dp[i][j - 1] + 1,
        dp[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1),
      )
    }
  }
  return dp[m][n]
}

function detectTyposquat(name: string): { suspicious: boolean; reason: string } {
  const lower = name.toLowerCase()
  for (const popular of POPULAR_PACKAGES) {
    if (lower === popular) continue
    const dist = levenshtein(lower, popular)
    if (dist >= 1 && dist <= 2) {
      return { suspicious: true, reason: `Edit distance ${dist} from popular package '${popular}'` }
    }
    if (lower.startsWith(popular) && lower.length > popular.length && lower.length <= popular.length + 3) {
      return { suspicious: true, reason: `Suspicious suffix appended to '${popular}'` }
    }
    if (lower.endsWith(popular) && lower.length > popular.length && lower.length <= popular.length + 3) {
      return { suspicious: true, reason: `Suspicious prefix added to '${popular}'` }
    }
  }
  return { suspicious: false, reason: "" }
}

// ─── Lightweight YAML Workflow Parser ────────────────────────────────────────

interface ParsedWorkflow {
  filename: string
  triggers: string[]
  steps: Array<{ uses?: string; run?: string }>
  secretRefs: string[]
  hasHardcodedSecrets: boolean
}

function parseWorkflowYaml(content: string, filename: string): ParsedWorkflow {
  const triggers: string[] = []
  const steps: ParsedWorkflow["steps"] = []
  const secretRefs: string[] = []
  let hasHardcodedSecrets = false

  const triggerBlockMatch = content.match(/^on\s*:\s*\n((?:\s{2}.+\n)*)/m)
  if (triggerBlockMatch) {
    const triggerLines = triggerBlockMatch[1].match(/^\s{2}(\w[\w_-]*)\s*:/gm)
    if (triggerLines) {
      for (const tl of triggerLines) {
        triggers.push(tl.trim().replace(/:$/, "").replace(/^\s{2}/, ""))
      }
    }
  }
  const singleTrigger = content.match(/^on\s*:\s*(\w[\w_-]*)\s*$/m)
  if (singleTrigger && triggers.length === 0) {
    triggers.push(singleTrigger[1])
  }

  for (const m of content.matchAll(/^\s*-?\s*uses\s*:\s*(.+)/gm)) {
    steps.push({ uses: m[1].trim() })
  }
  for (const m of content.matchAll(/^\s*-?\s*run\s*:\s*(.+)/gm)) {
    steps.push({ run: m[1].trim() })
  }

  for (const m of content.matchAll(/\$\{\{\s*secrets\.(\w+)\s*\}\}/g)) {
    secretRefs.push(m[1])
  }

  for (const m of content.matchAll(/(\w+)\s*[:=]\s*['"]([A-Za-z0-9_\-]{20,})['"]/g)) {
    const key = m[1].toLowerCase()
    if (key.includes("key") || key.includes("secret") || key.includes("token") || key.includes("password")) {
      secretRefs.push(`${m[1]}=***`)
      hasHardcodedSecrets = true
    }
  }

  return { filename, triggers, steps, secretRefs, hasHardcodedSecrets }
}

// ─── Workflow Audit ──────────────────────────────────────────────────────────

function auditWorkflows(cwd: string, findings: CicdFinding[]): { parsed: number; poisonedSecrets: string[] } {
  const poisonedSecrets: string[] = []
  const workflowsDir = path.join(cwd, ".github", "workflows")

  if (!fs.existsSync(workflowsDir)) {
    return { parsed: 0, poisonedSecrets }
  }

  let files: string[]
  try {
    files = fs.readdirSync(workflowsDir).filter(f => f.endsWith(".yml") || f.endsWith(".yaml"))
  } catch {
    return { parsed: 0, poisonedSecrets }
  }

  for (const file of files) {
    const filePath = path.join(workflowsDir, file)
    let content: string
    try {
      content = fs.readFileSync(filePath, "utf-8")
    } catch {
      continue
    }

    const wf = parseWorkflowYaml(content, file)

    for (const trigger of wf.triggers) {
      if ((DANGEROUS_TRIGGERS as readonly string[]).includes(trigger)) {
        const severity: CicdFinding["severity"] = trigger === "pull_request_target" ? "CRITICAL" : "HIGH"
        findings.push({
          id: `CICD-WF-${findings.length + 1}`,
          file: `.github/workflows/${file}`,
          severity,
          title: `Dangerous workflow trigger: ${trigger}`,
          description: `Workflow '${file}' uses the '${trigger}' trigger. This can allow untrusted code execution with elevated repository permissions.`,
          remediation: trigger === "pull_request_target"
            ? "Switch to 'pull_request' trigger. If pull_request_target is required, avoid checking out head branch code and restrict secret access."
            : `Review '${trigger}' trigger configuration. Ensure it cannot be triggered by untrusted actors.`,
        })
      }
    }

    if (wf.hasHardcodedSecrets) {
      for (const ref of wf.secretRefs) {
        if (ref.includes("=")) {
          poisonedSecrets.push(`${file}: ${ref}`)
          findings.push({
            id: `CICD-SEC-${findings.length + 1}`,
            file: `.github/workflows/${file}`,
            severity: "CRITICAL",
            title: `Hardcoded secret in workflow: ${ref.split("=")[0]}`,
            description: `Workflow '${file}' contains what appears to be a hardcoded secret value. Secrets should never be committed to source control.`,
            remediation: "Move this secret to GitHub Actions Secrets and reference it via ${{ secrets.SECRET_NAME }}.",
          })
        }
      }
    }

    for (const step of wf.steps) {
      if (step.run && /echo\s+.*\$\{\{\s*secrets\./.test(step.run)) {
        findings.push({
          id: `CICD-LOG-${findings.length + 1}`,
          file: `.github/workflows/${file}`,
          severity: "HIGH",
          title: "Secret exposed in workflow log output",
          description: `Workflow '${file}' appears to echo a secret value, which will be visible in build logs.`,
          remediation: "Remove echo statements that output secret values. Use GitHub Actions mask feature if needed.",
        })
      }
    }

    for (const step of wf.steps) {
      if (step.uses) {
        const parts = step.uses.split("@")
        if (parts.length === 2 && parts[1] === "master") {
          findings.push({
            id: `CICD-PIN-${findings.length + 1}`,
            file: `.github/workflows/${file}`,
            severity: "MEDIUM",
            title: `Action pinned to mutable ref: ${step.uses}`,
            description: `Workflow '${file}' uses action '${step.uses}' pinned to 'master' branch. A compromised action could inject malicious code.`,
            remediation: "Pin actions to a full-length commit SHA instead of a branch name.",
          })
        }
      }
    }
  }

  return { parsed: files.length, poisonedSecrets }
}

// ─── Dependency Audit ────────────────────────────────────────────────────────

function auditDependencies(cwd: string, findings: CicdFinding[]): { checked: number; vulnCount: number } {
  let checked = 0
  let vulnCount = 0

  const lockFiles = ["package-lock.json", "yarn.lock", "pnpm-lock.yaml"]
  let hasLock = false
  let hasPackageJson = false

  for (const lf of lockFiles) {
    if (fs.existsSync(path.join(cwd, lf))) {
      hasLock = true
      break
    }
  }

  const pkgJsonPath = path.join(cwd, "package.json")
  if (fs.existsSync(pkgJsonPath)) {
    hasPackageJson = true
    let pkgJson: Record<string, unknown>
    try {
      pkgJson = JSON.parse(fs.readFileSync(pkgJsonPath, "utf-8"))
    } catch {
      findings.push({
        id: `CICD-PKG-${findings.length + 1}`,
        file: "package.json",
        severity: "MEDIUM",
        title: "Malformed package.json",
        description: "package.json could not be parsed. This may indicate corruption or tampering.",
        remediation: "Verify package.json is valid JSON and restore from a known-good source.",
      })
      return { checked: 0, vulnCount: 0 }
    }

    const allDeps: Record<string, string> = {
      ...((pkgJson.dependencies as Record<string, string>) || {}),
      ...((pkgJson.devDependencies as Record<string, string>) || {}),
    }
    checked = Object.keys(allDeps).length

    for (const [name, version] of Object.entries(allDeps)) {
      const typosquat = detectTyposquat(name)
      if (typosquat.suspicious) {
        findings.push({
          id: `CICD-TYPO-${findings.length + 1}`,
          file: "package.json",
          severity: "HIGH",
          title: `Possible typosquatting: ${name}`,
          description: `Dependency '${name}' (${version}) - ${typosquat.reason}.`,
          remediation: `Verify '${name}' is the intended package. Check npmjs.com for the correct name.`,
        })
      }

      if (version === "latest" || version === "*") {
        findings.push({
          id: `CICD-PINDEP-${findings.length + 1}`,
          file: "package.json",
          severity: "MEDIUM",
          title: `Unpinned dependency: ${name}@${version}`,
          description: `Dependency '${name}' is not pinned to a specific version. A breaking or malicious update could be pulled in automatically.`,
          remediation: `Pin '${name}' to a specific version range (e.g. ^1.2.3 or ~1.2.3).`,
        })
      }
    }
  }

  if (!hasPackageJson) {
    return { checked: 0, vulnCount: 0 }
  }

  if (!hasLock) {
    findings.push({
      id: `CICD-LOCK-${findings.length + 1}`,
      file: "package-lock.json",
      severity: "MEDIUM",
      title: "No lockfile found",
      description: "No package-lock.json, yarn.lock, or pnpm-lock.yaml found. Without a lockfile, dependency resolution is non-deterministic.",
      remediation: "Run 'npm install' or 'yarn install' to generate a lockfile and commit it.",
    })
  }

  if (isToolAvailable("npm")) {
    try {
      const auditOutput = execFileSync("npm", ["audit", "--json"], {
        cwd,
        timeout: 30000,
        encoding: "utf-8",
        stdio: ["pipe", "pipe", "pipe"],
      })
      try {
        const auditResult = JSON.parse(auditOutput)
        if (auditResult.metadata?.vulnerabilities) {
          const vulns = auditResult.metadata.vulnerabilities
          vulnCount = (vulns.critical || 0) + (vulns.high || 0) + (vulns.moderate || 0) + (vulns.low || 0)

          if (vulns.critical > 0) {
            findings.push({
              id: `CICD-AUDIT-${findings.length + 1}`,
              file: "npm audit",
              severity: "CRITICAL",
              title: `${vulns.critical} critical vulnerability(ies) found by npm audit`,
              description: `npm audit found ${vulns.critical} critical and ${vulns.high || 0} high severity vulnerabilities.`,
              remediation: "Run 'npm audit fix' or 'npm audit fix --force' to remediate. Review breaking changes before applying.",
            })
          } else if (vulns.high > 0) {
            findings.push({
              id: `CICD-AUDIT-${findings.length + 1}`,
              file: "npm audit",
              severity: "HIGH",
              title: `${vulns.high} high severity vulnerability(ies) found by npm audit`,
              description: `npm audit found ${vulns.high} high and ${vulns.moderate || 0} moderate severity vulnerabilities.`,
              remediation: "Run 'npm audit fix' to remediate known vulnerabilities.",
            })
          }
        }
      } catch {
        // npm audit returns non-zero exit code when vulns are found; output may still be valid JSON
      }
    } catch {
      // npm not available or timed out
    }
  }

  return { checked, vulnCount }
}

// ─── .npmrc Registry Override Audit ──────────────────────────────────────────

function auditNpmrc(cwd: string, findings: CicdFinding[]): void {
  const npmrcPath = path.join(cwd, ".npmrc")
  if (!fs.existsSync(npmrcPath)) return

  let content: string
  try {
    content = fs.readFileSync(npmrcPath, "utf-8")
  } catch {
    return
  }

  const registryLines = content.match(/^registry\s*=/gm)
  if (registryLines && registryLines.length > 0) {
    const registries = content.match(/^registry\s*=\s*(.+)/gm)
    findings.push({
      id: `CICD-NPMRC-${findings.length + 1}`,
      file: ".npmrc",
      severity: "HIGH",
      title: "Custom registry override in .npmrc",
      description: `.npmrc defines custom registry URL(s): ${registries?.map(r => r.replace(/^registry\s*=\s*/, "").trim()).join(", ")}. This could redirect package installs to a malicious registry.`,
      remediation: "Verify the registry URL is legitimate. Use scope-specific registries (@myorg:registry=...) instead of global overrides.",
    })
  }

  if (/always-auth\s*=\s*true/i.test(content)) {
    findings.push({
      id: `CICD-AUTH-${findings.length + 1}`,
      file: ".npmrc",
      severity: "MEDIUM",
      title: "always-auth enabled in .npmrc",
      description: "Authentication tokens are sent to the registry on every request, increasing the risk of token leakage.",
      remediation: "Remove 'always-auth=true' unless strictly required. Use npm's built-in auth token management.",
    })
  }

  const tokenMatches = content.match(/(_authToken|_auth)\s*=\s*(?!$)(.+)/g)
  if (tokenMatches) {
    findings.push({
      id: `CICD-TOKEN-${findings.length + 1}`,
      file: ".npmrc",
      severity: "CRITICAL",
      title: "Hardcoded auth token in .npmrc",
      description: `.npmrc contains ${tokenMatches.length} hardcoded authentication token(s). This file should not be committed to version control.`,
      remediation: "Remove tokens from .npmrc, add .npmrc to .gitignore, and use environment variables or CI secrets for authentication.",
    })
  }
}

// ─── Dockerfile Audit ────────────────────────────────────────────────────────

function auditDockerfile(cwd: string, findings: CicdFinding[]): number {
  let issues = 0
  const dockerfilePath = path.join(cwd, "Dockerfile")
  if (!fs.existsSync(dockerfilePath)) return 0

  let content: string
  try {
    content = fs.readFileSync(dockerfilePath, "utf-8")
  } catch {
    return 0
  }

  const lines = content.split("\n").map(l => l.trim()).filter(l => l && !l.startsWith("#"))

  let hasUserDirective = false
  for (const line of lines) {
    if (/^USER\s+/i.test(line)) {
      hasUserDirective = true
      const user = line.replace(/^USER\s+/i, "").trim()
      if (user === "root") {
        findings.push({
          id: `CICD-DOCKER-${findings.length + 1}`,
          file: "Dockerfile",
          severity: "HIGH",
          title: "Container runs as root",
          description: "Dockerfile explicitly sets USER root. Running containers as root increases the blast radius of container escapes.",
          remediation: "Create a non-root user and switch to it with 'USER <non-root-user>' after installing dependencies.",
        })
        issues++
      }
    }
  }

  if (!hasUserDirective) {
    findings.push({
      id: `CICD-DOCKER-${findings.length + 1}`,
      file: "Dockerfile",
      severity: "MEDIUM",
      title: "No USER directive found",
      description: "Dockerfile has no USER directive, so the container will run as root by default.",
      remediation: "Add a 'USER <non-root-user>' directive before the CMD/ENTRYPOINT.",
    })
    issues++
  }

  for (const line of lines) {
    const fromMatch = line.match(/^FROM\s+(\S+)/i)
    if (fromMatch) {
      const image = fromMatch[1]
      if (image.endsWith(":latest") || !image.includes(":")) {
        findings.push({
          id: `CICD-DOCKER-${findings.length + 1}`,
          file: "Dockerfile",
          severity: "MEDIUM",
          title: `Mutable base image tag: ${image}`,
          description: `Base image '${image}' uses a mutable tag. A compromised or updated upstream image could introduce vulnerabilities.`,
          remediation: "Pin base images to a specific version tag or digest (e.g. node:20.9.0-slim or node@sha256:...).",
        })
        issues++
      }
    }
  }

  const secretEnvPattern = /(?:password|secret|token|key|credential)\s*=\s*\S+/i
  for (const line of lines) {
    if (/^ENV\s+/i.test(line) && secretEnvPattern.test(line)) {
      findings.push({
        id: `CICD-DOCKER-${findings.length + 1}`,
        file: "Dockerfile",
        severity: "CRITICAL",
        title: "Secret exposed in ENV directive",
        description: `Dockerfile ENV contains a suspicious secret-like value: ${line.substring(0, 80)}...`,
        remediation: "Use build secrets (--mount=type=secret) or runtime environment variables instead of baking secrets into ENV.",
      })
      issues++
    }
  }

  for (const line of lines) {
    if (/^COPY\s+/i.test(line)) {
      const copyArgs = line.replace(/^COPY\s+/i, "").trim()
      const src = copyArgs.split(/\s+/)[0]
      if (src === ".env" || src.includes(".env.") || src.includes("credentials") || src.includes(".pem") || src.includes(".key")) {
        findings.push({
          id: `CICD-DOCKER-${findings.length + 1}`,
          file: "Dockerfile",
          severity: "CRITICAL",
          title: `Sensitive file copied into image: ${src}`,
          description: `Dockerfile copies '${src}' into the container image. Sensitive files should never be baked into images.`,
          remediation: `Remove COPY for '${src}' and use Docker secrets or mount at runtime.`,
        })
        issues++
      }
    }
  }

  return issues
}

// ─── Dry-Run Simulated Findings ──────────────────────────────────────────────

function buildDryRunResult(repo: string, cwd: string): CicdAuditResult {
  return {
    repo,
    cwd,
    untrustedRunnerRisk: true,
    poisonedPipelineSecrets: [
      "GITHUB_TOKEN has write permission on pull_request_target event",
      "AWS_SECRET_ACCESS_KEY exposed in unencrypted workflow step logs",
      "NPM_TOKEN hardcoded in .github/workflows/publish.yml env block",
    ],
    dependencyConfusionVulnerabilities: [
      "Internal npm scope @internal-lib not pinned to private registry",
      "PyPI fallback enabled for internal package company-core",
      "Unpinned dependency lodash@* allows supply chain substitution",
    ],
    findings: [
      {
        id: "CICD-WF-1",
        file: ".github/workflows/ci.yml",
        severity: "CRITICAL",
        title: "Dangerous workflow trigger: pull_request_target",
        description: "Workflow 'ci.yml' uses the 'pull_request_target' trigger with GITHUB_TOKEN write access and checks out head branch code, enabling arbitrary code execution from untrusted PRs.",
        remediation: "Switch to 'pull_request' trigger. If pull_request_target is required, avoid checking out head branch code and restrict secret access.",
      },
      {
        id: "CICD-WF-2",
        file: ".github/workflows/deploy.yml",
        severity: "HIGH",
        title: "Dangerous workflow trigger: workflow_run",
        description: "Workflow 'deploy.yml' uses 'workflow_run' trigger which can be invoked by untrusted workflow completions.",
        remediation: "Review 'workflow_run' trigger configuration. Ensure it cannot be triggered by untrusted actors.",
      },
      {
        id: "CICD-SEC-1",
        file: ".github/workflows/publish.yml",
        severity: "CRITICAL",
        title: "Hardcoded secret in workflow: NPM_TOKEN",
        description: "Workflow 'publish.yml' contains what appears to be a hardcoded NPM_TOKEN in the env block.",
        remediation: "Move this secret to GitHub Actions Secrets and reference it via ${{ secrets.NPM_TOKEN }}.",
      },
      {
        id: "CICD-SEC-2",
        file: ".github/workflows/deploy.yml",
        severity: "CRITICAL",
        title: "Hardcoded secret in workflow: AWS_SECRET_ACCESS_KEY",
        description: "Workflow 'deploy.yml' contains what appears to be a hardcoded AWS secret key.",
        remediation: "Move this secret to GitHub Actions Secrets and reference it via ${{ secrets.AWS_SECRET_ACCESS_KEY }}.",
      },
      {
        id: "CICD-LOG-1",
        file: ".github/workflows/ci.yml",
        severity: "HIGH",
        title: "Secret exposed in workflow log output",
        description: "Workflow 'ci.yml' echoes a secret value in a debug step, which will be visible in build logs.",
        remediation: "Remove echo statements that output secret values. Use GitHub Actions mask feature if needed.",
      },
      {
        id: "CICD-PIN-1",
        file: ".github/workflows/ci.yml",
        severity: "MEDIUM",
        title: "Action pinned to mutable ref: actions/checkout@master",
        description: "Workflow uses action 'actions/checkout@master' pinned to a mutable branch. A compromised action could inject malicious code.",
        remediation: "Pin actions to a full-length commit SHA instead of a branch name.",
      },
      {
        id: "CICD-TYPO-1",
        file: "package.json",
        severity: "HIGH",
        title: "Possible typosquatting: reqeusts",
        description: "Dependency 'reqeusts' (1.0.0) - Edit distance 2 from popular package 'request'.",
        remediation: "Verify 'reqeusts' is the intended package. Check npmjs.com for the correct name.",
      },
      {
        id: "CICD-PINDEP-1",
        file: "package.json",
        severity: "MEDIUM",
        title: "Unpinned dependency: lodash@*",
        description: "Dependency 'lodash' is not pinned to a specific version. A breaking or malicious update could be pulled in automatically.",
        remediation: "Pin 'lodash' to a specific version range (e.g. ^4.17.21).",
      },
      {
        id: "CICD-AUDIT-1",
        file: "npm audit",
        severity: "CRITICAL",
        title: "3 critical vulnerability(ies) found by npm audit",
        description: "npm audit found 3 critical and 7 high severity vulnerabilities in current dependency tree.",
        remediation: "Run 'npm audit fix' or 'npm audit fix --force' to remediate. Review breaking changes before applying.",
      },
      {
        id: "CICD-LOCK-1",
        file: "package-lock.json",
        severity: "MEDIUM",
        title: "No lockfile found",
        description: "No package-lock.json, yarn.lock, or pnpm-lock.yaml found. Without a lockfile, dependency resolution is non-deterministic.",
        remediation: "Run 'npm install' or 'yarn install' to generate a lockfile and commit it.",
      },
      {
        id: "CICD-NPMRC-1",
        file: ".npmrc",
        severity: "HIGH",
        title: "Custom registry override in .npmrc",
        description: ".npmrc defines a custom registry URL: https://registry.npmjs.org/.evil.com/. This could redirect package installs to a malicious registry.",
        remediation: "Verify the registry URL is legitimate. Use scope-specific registries (@myorg:registry=...) instead of global overrides.",
      },
      {
        id: "CICD-DOCKER-1",
        file: "Dockerfile",
        severity: "HIGH",
        title: "Container runs as root",
        description: "Dockerfile explicitly sets USER root. Running containers as root increases the blast radius of container escapes.",
        remediation: "Create a non-root user and switch to it with 'USER <non-root-user>' after installing dependencies.",
      },
      {
        id: "CICD-DOCKER-2",
        file: "Dockerfile",
        severity: "MEDIUM",
        title: "Mutable base image tag: node:latest",
        description: "Base image 'node:latest' uses a mutable tag. A compromised or updated upstream image could introduce vulnerabilities.",
        remediation: "Pin base images to a specific version tag or digest (e.g. node:20.9.0-slim or node@sha256:...).",
      },
      {
        id: "CICD-DOCKER-3",
        file: "Dockerfile",
        severity: "CRITICAL",
        title: "Secret exposed in ENV directive",
        description: "Dockerfile ENV contains a suspicious secret-like value: ENV DATABASE_PASSWORD=supersecretpassword123...",
        remediation: "Use build secrets (--mount=type=secret) or runtime environment variables instead of baking secrets into ENV.",
      },
      {
        id: "CICD-DOCKER-4",
        file: "Dockerfile",
        severity: "CRITICAL",
        title: "Sensitive file copied into image: .env",
        description: "Dockerfile copies '.env' into the container image. Sensitive files should never be baked into images.",
        remediation: "Remove COPY for '.env' and use Docker secrets or mount at runtime.",
      },
    ],
    workflowsParsed: 8,
    dependenciesChecked: 47,
    npmAuditVulnerabilities: 10,
    dockerfileIssues: 4,
    simulated: true,
  }
}

// ─── Main Auditor Class ──────────────────────────────────────────────────────

export class CicdSupplyChainAuditor {
  async auditPipeline(options: CicdAuditOptions = {}): Promise<CicdAuditResult> {
    const repo = options.repoUrl || "https://github.com/org/repo"
    const isDryRun = resolveDryRun(options)
    const cwd = options.cwd || process.cwd()

    console.log(`[OurMine Security] Auditing CI/CD pipeline for '${repo}' (cwd: ${cwd})...`)

    if (isDryRun) {
      console.log("[OurMine Security] Dry-run mode: returning simulated audit findings.")
      return buildDryRunResult(repo, cwd)
    }

    const findings: CicdFinding[] = []
    const poisonedPipelineSecrets: string[] = []
    const dependencyConfusionVulnerabilities: string[] = []
    let workflowsParsed = 0
    let dependenciesChecked = 0
    let npmAuditVulnerabilities = 0
    let dockerfileIssues = 0
    let untrustedRunnerRisk = false

    try {
      const wfResult = auditWorkflows(cwd, findings)
      workflowsParsed = wfResult.parsed
      poisonedPipelineSecrets.push(...wfResult.poisonedSecrets)

      if (findings.some(f => f.severity === "CRITICAL" && f.title.includes("trigger"))) {
        untrustedRunnerRisk = true
      }
    } catch (err) {
      console.error(`[OurMine Security] Workflow audit failed: ${(err as Error).message}`)
    }

    try {
      const depResult = auditDependencies(cwd, findings)
      dependenciesChecked = depResult.checked
      npmAuditVulnerabilities = depResult.vulnCount
    } catch (err) {
      console.error(`[OurMine Security] Dependency audit failed: ${(err as Error).message}`)
    }

    try {
      auditNpmrc(cwd, findings)
    } catch (err) {
      console.error(`[OurMine Security] .npmrc audit failed: ${(err as Error).message}`)
    }

    try {
      dockerfileIssues = auditDockerfile(cwd, findings)
    } catch (err) {
      console.error(`[OurMine Security] Dockerfile audit failed: ${(err as Error).message}`)
    }

    for (const f of findings) {
      if (f.title.includes("typosquat") || f.title.includes("registry override")) {
        dependencyConfusionVulnerabilities.push(f.description)
      }
    }

    console.log(
      `[OurMine Security] Audit complete: ${findings.length} findings across ` +
      `${workflowsParsed} workflows, ${dependenciesChecked} dependencies, ` +
      `${dockerfileIssues} Dockerfile issues.`
    )

    return {
      repo,
      cwd,
      untrustedRunnerRisk,
      poisonedPipelineSecrets,
      dependencyConfusionVulnerabilities,
      findings,
      workflowsParsed,
      dependenciesChecked,
      npmAuditVulnerabilities,
      dockerfileIssues,
      simulated: false,
    }
  }
}
