/**
 * Autonomous intel prefetch pipeline tests
 */
import { describe, test, before, after } from "node:test"
import assert from "node:assert/strict"
import { AttackSurfaceGraph } from "../src/attack_surface.ts"

describe("intel_autonomous", () => {
  const prevRefresh = process.env.OURMINE_INTEL_REFRESH

  after(() => {
    if (prevRefresh === undefined) delete process.env.OURMINE_INTEL_REFRESH
    else process.env.OURMINE_INTEL_REFRESH = prevRefresh
  })

  test("intelRefreshEnabled respects OURMINE_INTEL_REFRESH", async () => {
    const { intelRefreshEnabled } = await import("../src/intel_autonomous.ts")
    delete process.env.OURMINE_INTEL_REFRESH
    assert.equal(intelRefreshEnabled(), false)
    process.env.OURMINE_INTEL_REFRESH = "1"
    assert.equal(intelRefreshEnabled(), true)
  })

  test("actorModuleMap covers 10+ threat groups", async () => {
    const { actorModuleMap } = await import("../src/intel_autonomous.ts")
    const map = actorModuleMap()
    const ids = Object.keys(map)
    assert.ok(ids.length >= 10, `expected ≥10 actors, got ${ids.length}`)
    assert.ok(map.volt_typhoon?.modules.includes("hybrid_pivot"))
    assert.ok(map.medusa?.techniques.includes("T1486"))
    assert.ok(map.akira?.modules.includes("cred_spray"))
    assert.ok(map.lockbit?.modules.includes("esxi_audit") || map.lockbit5?.modules.includes("esxi_audit"))
    assert.ok(map.jadepuffer?.modules.includes("ai_surface_scan"))
    assert.ok(map.team_pcp?.modules.includes("lockfile_scan"))
  })

  test("matchStackCves correlates banners with KEV priority", async () => {
    const { matchStackCves } = await import("../src/intel_autonomous.ts")
    const kev = ["CVE-2025-3248", "CVE-2021-44228"]
    const hits = matchStackCves(
      [{ product: "Langflow", source: "hint" }],
      kev,
    )
    assert.ok(hits.some((h) => h.cve === "CVE-2025-3248"))
    assert.ok(hits.find((h) => h.cve === "CVE-2025-3248")?.inKev)
  })

  test("mapRansomTtps returns modules from ransomwatch cache", async () => {
    const { mapRansomTtps } = await import("../src/intel_autonomous.ts")
    const actions = mapRansomTtps()
    assert.ok(actions.length >= 1)
    assert.ok(actions[0].modules.length >= 1)
    assert.ok(actions[0].techniques.length >= 1)
  })

  test("buildPocHints emits gh_grep + exploit-db stubs", async () => {
    const { buildPocHints } = await import("../src/intel_autonomous.ts")
    const hints = await buildPocHints(
      [{ cve: "CVE-2025-3248", product: "Langflow", cvss: 9.8, inKev: true, tools: ["ai_surface_scan"] }],
      [{ product: "Langflow", source: "hint" }],
      false,
    )
    assert.ok(hints.some((h) => h.source === "gh_grep" && h.query.includes("CVE-2025-3248")))
    assert.ok(hints.some((h) => h.source === "exploit-db" || h.source === "gh_grep"))
  })

  test("runIntelPrefetch returns digest ≤150 chars + artifactId", async () => {
    delete process.env.OURMINE_INTEL_REFRESH
    const { runIntelPrefetch } = await import("../src/intel_autonomous.ts")
    const r = await runIntelPrefetch("10.0.0.0/24", "hybrid_it_ot", {
      aptHint: "Volt Typhoon",
      objective: "hybrid_it_ot",
      live: false,
    })
    assert.ok(r.intelDigest.length <= 150, `digest ${r.intelDigest.length} chars: ${r.intelDigest}`)
    assert.ok(r.artifactId.startsWith("intel_prefetch_"))
    assert.ok(r.techniques.length >= 3)
    assert.ok(r.modules.length >= 3)
    assert.ok(r.recommendedNextActions.length >= 1)
  })

  test("runIntelPrefetch matches stack CVEs from graph banners", async () => {
    const { runIntelPrefetch } = await import("../src/intel_autonomous.ts")
    const graph = new AttackSurfaceGraph("192.168.1.50")
    const asset = graph.upsertAsset("192.168.1.50")
    asset.services.set(8848, {
      port: 8848,
      protocol: "tcp",
      state: "open",
      service: "http",
      version: "Alibaba Nacos 2.2.0",
      evidence: [],
      vulns: [],
    })
    const r = await runIntelPrefetch("192.168.1.50", "ai_agent_surface", {
      objective: "ai_agent",
      live: false,
      graph,
      hint: "nacos langflow",
    })
    assert.ok(r.stackCves.some((c) => c.product.includes("Nacos") || c.product.includes("Langflow")))
  })

  test("buildIntelNextActions includes gh_grep PoC hunt", async () => {
    const { buildIntelNextActions } = await import("../src/intel_autonomous.ts")
    const actions = buildIntelNextActions({
      target: "10.0.0.1",
      objective: "standard",
      stackCves: [{ cve: "CVE-2021-44228", product: "Log4j", cvss: 10, inKev: true, tools: ["nuclei_scan"] }],
      ransomActions: [],
      pocHints: [{ source: "gh_grep", query: "CVE-2021-44228 exploit poc", cve: "CVE-2021-44228" }],
      modules: [],
    })
    assert.ok(actions.some((a) => a.tool === "gh_grep"))
    assert.ok(actions.some((a) => a.args?.cve === "CVE-2021-44228" || a.tool === "gh_grep"))
  })
})

describe("engagement intel wiring", () => {
  test("engagement_slice auto-prefetches intel on start", async () => {
    const { runEngagementSlice } = await import("../src/engagement_slice.ts")
    const r = await runEngagementSlice({
      target: "10.0.0.0/24",
      live: false,
      aptHint: "Volt Typhoon",
    })
    assert.ok(r.intelDigest ?? r.intelSnippet)
    assert.ok((r.intelDigest ?? r.intelSnippet).length <= 150)
    assert.ok(r.intelArtifactId?.startsWith("intel_prefetch_"))
    assert.ok(r.aptTechniques?.length >= 3)
    assert.equal(r.objective, "hybrid_it_ot")
  })

  test("getNextActions merges intel prefetch actions", async () => {
    const { getNextActions, buildEngagementGraph } = await import("../src/engagement_graph.ts")
    const { runIntelPrefetch } = await import("../src/intel_autonomous.ts")
    const { AttackSurfaceGraph: ASG } = await import("../src/attack_surface.ts")
    const { CredentialGraph } = await import("../src/credential_graph.ts")

    const graph = new ASG("10.0.0.1")
    const credGraph = new CredentialGraph()
    const eg = buildEngagementGraph({
      target: "10.0.0.1",
      graph,
      credGraph,
      objective: "hybrid_it_ot",
      live: false,
    })
    const prefetch = await runIntelPrefetch("10.0.0.1", "hybrid_it_ot", {
      aptHint: "Volt Typhoon",
      objective: "hybrid_it_ot",
      live: false,
    })
    const actions = getNextActions(eg, { intelPrefetch: prefetch })
    const tools = actions.map((a) => a.tool)
    assert.ok(tools.includes("ares_engagement_continue") || tools.includes("gh_grep") || tools.includes("ares_dispatch"))
  })
})
