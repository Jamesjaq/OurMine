/**
 * @module multi_cloud_asm
 * Multi-cloud attack surface fusion — AWS/GCP/Azure correlation into graph.
 */
import type { AttackSurfaceGraph } from "./attack_surface.ts"
import { ToolBroker } from "./tool_broker.ts"
import { resolveLiveMode } from "./exec_options.ts"

export interface CloudAsset {
  provider: "aws" | "gcp" | "azure" | "unknown"
  assetType: string
  identifier: string
  exposure: "public" | "internal" | "metadata"
  detail: string
}

export interface MultiCloudAsmResult {
  assets: CloudAsset[]
  fusedCount: number
  providers: string[]
  summary: string
}

const PROBE_COMMANDS: Array<{ provider: CloudAsset["provider"]; cmd: string; assetType: string }> = [
  { provider: "aws", cmd: "curl -sS --max-time 3 http://169.254.169.254/latest/meta-data/", assetType: "imds" },
  { provider: "gcp", cmd: "curl -sS --max-time 3 -H 'Metadata-Flavor: Google' http://169.254.169.254/computeMetadata/v1/", assetType: "imds" },
  { provider: "azure", cmd: "curl -sS --max-time 3 -H Metadata:true http://169.254.169.254/metadata/instance?api-version=2021-02-01", assetType: "imds" },
]

export async function fuseMultiCloudAsm(
  graph: AttackSurfaceGraph,
  opts: { live?: boolean; broker?: ToolBroker; target?: string } = {},
): Promise<MultiCloudAsmResult> {
  const live = resolveLiveMode(opts)
  const broker = opts.broker ?? new ToolBroker()
  const assets: CloudAsset[] = []

  if (!live) {
    return {
      assets: [],
      fusedCount: 0,
      providers: [],
      summary: "Multi-cloud ASM requires live execution",
    }
  }

  for (const probe of PROBE_COMMANDS) {
    try {
      const exec = await broker.executeSafe(probe.cmd, process.cwd())
      const out = (exec.stdout + exec.stderr).slice(0, 500)
      if (exec.exitCode === 0 && out.length > 5 && !out.includes("Connection refused")) {
        assets.push({
          provider: probe.provider,
          assetType: probe.assetType,
          identifier: `169.254.169.254/${probe.provider}`,
          exposure: "metadata",
          detail: out.slice(0, 200),
        })
        const ev = graph.makeEvidence("multi_cloud_asm", probe.provider, out.slice(0, 100), 0.9)
        graph.upsertAsset(`cloud-${probe.provider}`)
      }
    } catch { /* unreachable IMDS */ }
  }

  const target = opts.target ?? graph.toJSON().target ?? "unknown"
  const dnsCmd = `dig +short ${target} A 2>/dev/null; dig +short _azure.${target} TXT 2>/dev/null | head -3`
  try {
    const exec = await broker.executeSafe(dnsCmd, process.cwd())
    const out = exec.stdout.trim()
    if (out) {
      assets.push({
        provider: "unknown",
        assetType: "dns",
        identifier: target,
        exposure: "public",
        detail: out.slice(0, 200),
      })
    }
  } catch { /* ignore */ }

  const providers = [...new Set(assets.map((a) => a.provider))]
  return {
    assets,
    fusedCount: assets.length,
    providers,
    summary: `Fused ${assets.length} cloud asset(s) from ${providers.length} provider(s)`,
  }
}

export default { fuseMultiCloudAsm }
