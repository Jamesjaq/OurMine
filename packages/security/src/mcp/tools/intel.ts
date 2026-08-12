import * as fs from "node:fs"
import * as security from "../../index.ts"
import * as dispatch from "../../mcp_dispatch.ts"
import { PentestAgent } from "../../pentestgpt_agent.ts"
import { ContextGuard } from "../../context_guard.ts"
import { gateExecution } from "../../opsec_gate.ts"
import type { McpTool } from "../../mcp_tool_types.ts"
import { buildActionablePlan } from "../../pentest_plan_builder.ts"
import { runEngagementSlice } from "../../engagement_slice.ts"
import { runEngagementAutopilot } from "../../engagement_autopilot.ts"
import { readArtifact } from "../../mcp_artifacts.ts"
import { mcpContext } from "../context.ts"

export function buildIntelTools(): McpTool[] {
  const { mcpLive, toolBroker, globalThrottleEngine } = mcpContext
  return [
    {
        name: "ares_intel_feed",
        description: "Query threat intel feeds by actor, CVE, family, or target. Returns enrichTarget/pollFeeds metadata (no malware binaries). Use ares_threat_intel for persona-aware APT tradecraft.",
        inputSchema: {
          type: "object",
          properties: {
            target: { type: "string", description: "Target host/domain/IP" },
            actor: { type: "string", description: "APT profile id filter" },
            cve: { type: "string", description: "CVE id filter" },
            family: { type: "string", description: "vx malware family name" },
            poll: { type: "boolean", description: "Poll live KEV/Ransomwatch feeds" },
            apt: { type: "boolean", description: "Return persona-aware APT intel (delegates to ares_threat_intel)" },
            persona: { type: "string", description: "Target persona for APT intel routing" },
            objective: { type: "string", description: "Campaign objective hint" },
            refresh: { type: "boolean", description: "Refresh .ourmine/intel cache" },
          },
        },
        async handler({ target, actor, cve, family, poll, apt, persona, objective, refresh }) {
          const live = mcpLive()
          if (apt || actor) {
            const intel = await security.apt_intel_feed.getThreatIntel({
              target: target ? String(target) : undefined,
              actor: actor ? String(actor) : undefined,
              aptHint: actor ? String(actor) : undefined,
              persona: persona ? String(persona) as import("./target_flow.ts").TargetPersona : undefined,
              objective: objective ? String(objective) as import("./target_flow.ts").FlowObjective : undefined,
              live,
              refresh: Boolean(refresh),
            })
            if (intel) return intel
          }
          if (poll) {
            const records = await security.intel_feeds.pollFeeds({ live })
            return { records, count: records.length }
          }
          if (family) {
            return { family: security.intel_feeds.lookupVxFamily(String(family)) }
          }
          if (target) {
            const brief = await security.intel_feeds.enrichTarget(String(target), { live })
            if (actor) {
              brief.activeProfiles = brief.activeProfiles.filter((p) => p.id === String(actor))
            }
            if (cve) {
              brief.priorityCves = brief.priorityCves.filter((c) => c.cve === String(cve))
            }
            return brief
          }
          return {
            cves: security.intel_feeds.loadCvePriority(),
            vxFamilies: security.intel_feeds.loadVxFamilyIndex().slice(0, 20),
          }
        },
      },

    {
        name: "ares_threat_intel",
        description: "Autonomous threat intel prefetch: MITRE ATT&CK, CISA KEV, stack CVEs, ransomwatch TTPs, PoC hints. Returns intelDigest (≤150 chars) + artifactId. Set OURMINE_INTEL_REFRESH=1 for live feed pull.",
        inputSchema: {
          type: "object",
          properties: {
            target: { type: "string", description: "Target host/domain/IP" },
            actor: { type: "string", description: "APT name or id (e.g. Volt Typhoon, lazarus)" },
            persona: { type: "string", description: "Target persona: hybrid_it_ot, enterprise_ad, ot_scada_plant, etc." },
            objective: { type: "string", description: "Campaign objective hint" },
            refresh: { type: "boolean", description: "Force live KEV/ransomwatch when OURMINE_INTEL_REFRESH=1 or live mode" },
          },
        },
        async handler({ target, actor, persona, objective, refresh }) {
          const live = mcpLive() || Boolean(refresh)
          if (refresh) process.env.OURMINE_INTEL_REFRESH = "1"
    
          const t = target ? String(target) : "intel-prefetch"
          const flow = security.target_flow.buildFlowProfile(t, undefined, actor ? String(actor) : objective ? String(objective) : t)
          const prefetch = await security.intel_autonomous.runIntelPrefetch(
            t,
            (persona ? String(persona) : flow.persona) as import("./target_flow.ts").TargetPersona,
            {
              objective: objective ? String(objective) as import("./target_flow.ts").FlowObjective : undefined,
              aptHint: actor ? String(actor) : undefined,
              live,
              hint: actor ? String(actor) : objective ? String(objective) : undefined,
            },
          )
    
          return {
            intelDigest: prefetch.intelDigest,
            intelSnippet: prefetch.intelDigest,
            artifactId: prefetch.artifactId,
            profileId: prefetch.profileId ?? "",
            profileName: prefetch.profileName ?? "",
            objectiveHint: prefetch.objective,
            techniques: prefetch.techniques,
            modules: prefetch.modules,
            kevCount: prefetch.kevHits.length,
            kevHits: prefetch.kevHits,
            stackCves: prefetch.stackCves.slice(0, 5),
            ransomActions: prefetch.ransomActions.slice(0, 3),
            pocHints: prefetch.pocHints.slice(0, 4),
            recommendedNextActions: prefetch.recommendedNextActions,
            ransomGroupCount: prefetch.ransomActions.length,
          }
        },
      },

    {
        name: "ares_intel_watch",
        description: "Watch org/domain against ransomwatch + cached intel feeds for stealer-log / victim matches.",
        inputSchema: {
          type: "object",
          properties: {
            org: { type: "string", description: "Organization name" },
            domains: { type: "array", items: { type: "string" }, description: "Domains to watch" },
          },
          required: ["org"],
        },
        async handler({ org, domains }) {
          const live = mcpLive()
          const domainList = Array.isArray(domains) ? domains.map(String) : []
          const watch = security.intel_feeds.watchOrg(String(org), domainList)
          const ransom = await security.intel_feeds.fetchRansomwatch(live)
          const matches = ransom.filter((r) =>
            String(r.ioc ?? "").toLowerCase().includes(String(org).toLowerCase()) ||
            domainList.some((d) => String(r.ioc ?? "").includes(d)),
          )
          return { ...watch, ransomMatches: matches }
        },
      },

    {
        name: "ares_vx_lookup",
        description: "Hash or vx-underground family metadata lookup (metadata only — never downloads samples).",
        inputSchema: {
          type: "object",
          properties: {
            hash: { type: "string", description: "SHA256 hash" },
            family: { type: "string", description: "Malware family name" },
          },
        },
        async handler({ hash, family }) {
          if (hash) return security.intel_feeds.lookupHash(String(hash))
          if (family) return { entry: security.intel_feeds.lookupVxFamily(String(family)) }
          return { vxFamilies: security.intel_feeds.loadVxFamilyIndex().slice(0, 50) }
        },
      },

    {
        name: "ares_ai_surface",
        description: "Scan for exposed AI/ML stack (Langflow, Nacos, n8n, MinIO). Live-only probes.",
        inputSchema: {
          type: "object",
          properties: {
            target: { type: "string", description: "Target host or URL" },
          },
          required: ["target"],
        },
        async handler({ target }) {
          const live = mcpLive()
          return security.intel_feeds.scanAiSurface(String(target), live)
        },
      },

    {
        name: "ares_stix_ingest",
        description: "Ingest STIX/TAXII threat intel collection into target graph. Enable feeds in data/intel/taxii_feeds.json.",
        inputSchema: {
          type: "object",
          properties: {
            target: { type: "string", description: "Target host/domain for IOC matching" },
            baseUrl: { type: "string", description: "TAXII 2.1 server base URL" },
            collectionId: { type: "string", description: "TAXII collection ID" },
            pollAll: { type: "boolean", description: "Poll all enabled feeds from taxii_feeds.json" },
          },
          required: ["target"],
        },
        async handler({ target, baseUrl, collectionId, pollAll }) {
          const live = mcpLive()
          const { AttackSurfaceGraph } = await import("./attack_surface.ts")
          const graph = new AttackSurfaceGraph(String(target))
          graph.upsertAsset(String(target).replace(/^https?:\/\//, "").split("/")[0]!)
          if (pollAll) {
            const records = await security.intel_feeds.pollStixFeeds(graph, { live })
            return { records, count: records.length, hits: records.length }
          }
          if (baseUrl && collectionId) {
            return security.intel_feeds.ingestStixTaxii(String(baseUrl), String(collectionId), graph, {})
          }
          const feeds = security.intel_feeds.loadTaxiiFeeds().filter((f) => f.enabled)
          return { feeds, note: "Enable feeds in taxii_feeds.json or pass baseUrl+collectionId" }
        },
      },

    {
        name: "ares_proof_export",
        description: "Build tamper-evident proof pack (JSON + HTML + PDF) from target engagement graph.",
        inputSchema: {
          type: "object",
          properties: {
            target: { type: "string", description: "Engagement target" },
          },
          required: ["target"],
        },
        async handler({ target }) {
          const { AttackSurfaceGraph } = await import("./attack_surface.ts")
          const { buildProofPack, writeProofPack } = await import("./proof_pack.ts")
          const graph = new AttackSurfaceGraph(String(target))
          graph.upsertAsset(String(target).replace(/^https?:\/\//, "").split("/")[0]!)
          const pack = buildProofPack(graph)
          const path = writeProofPack(pack)
          return { path, merkleRoot: pack.merkleRoot, findings: pack.findings.length }
        },
      }
  ]
}
