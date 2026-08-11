/**
 * @module segment_tunnel_orchestrator
 * Auto-wire SOCKS/SSH/chisel tunnels from AttackSurfaceGraph segment topology.
 */
import type { AttackSurfaceGraph } from "./attack_surface.ts"
import { createPortForwarderAsync, type TunnelConfig } from "./pivot_tunnel.ts"
import { resolveLiveMode } from "./exec_options.ts"

export interface SegmentTunnel {
  segment: string
  method: TunnelConfig["type"]
  localPort: number
  remoteHost: string
  remotePort: number
  status: string
  live: boolean
}

export interface TunnelOrchestrationResult {
  tunnels: SegmentTunnel[]
  segments: string[]
  summary: string
}

function graphAssets(graph: AttackSurfaceGraph): string[] {
  return Object.keys((graph.toJSON() as { assets?: Record<string, unknown> }).assets ?? {})
}

function pickTunnelMethod(port: number): TunnelConfig["type"] {
  if (port === 22) return "port_forward"
  if (port === 1080 || port === 9050) return "socks5"
  return "chisel"
}

export async function orchestrateSegmentTunnels(
  graph: AttackSurfaceGraph,
  opts: { live?: boolean; basePort?: number } = {},
): Promise<TunnelOrchestrationResult> {
  const live = resolveLiveMode(opts)
  const assets = graphAssets(graph)
  const segments = [...new Set(assets.map((a) => a.split(".").slice(-2).join(".") || a))]
  const tunnels: SegmentTunnel[] = []
  const basePort = opts.basePort ?? 1080

  for (let i = 1; i < assets.length; i++) {
    const remoteHost = assets[i]!
    const localPort = basePort + i - 1
    const method = pickTunnelMethod(22)
    const cfg: TunnelConfig = { type: method, localPort, remoteHost, remotePort: 22 }
    const result = await createPortForwarderAsync(cfg, live)
    tunnels.push({
      segment: segments[i] ?? remoteHost,
      method,
      localPort: result.localPort ?? localPort,
      remoteHost,
      remotePort: 22,
      status: result.status,
      live: !result.dryRun,
    })
  }

  return {
    tunnels,
    segments,
    summary: live
      ? `Orchestrated ${tunnels.filter((t) => t.live).length} live segment tunnel(s) across ${segments.length} segment(s)`
      : `Planned ${Math.max(0, assets.length - 1)} segment tunnel(s) — live execution required`,
  }
}

export default { orchestrateSegmentTunnels }
