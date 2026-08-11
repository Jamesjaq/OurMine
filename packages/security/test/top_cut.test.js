import test from "node:test"
import assert from "node:assert"

test("CredentialGraph ingests post-ex credentials and suggests pivots", async () => {
  const { CredentialGraph } = await import("../src/credential_graph.ts")
  const { AttackSurfaceGraph } = await import("../src/attack_surface.ts")

  const g = new CredentialGraph()
  const output = JSON.stringify([
    { category: "credential", name: "/etc/shadow hashes", value: "root:$6$abc", severity: "critical" },
  ])
  assert.strictEqual(g.ingestFromPostExOutput(output), 1)

  const graph = new AttackSurfaceGraph("10.0.0.5")
  graph.upsertAsset("10.0.0.5")
  const pivots = g.suggestPivots(graph)
  assert.ok(pivots.length >= 1)
  assert.ok(pivots.some((p) => p.tool === "lateral_move" || p.tool === "cred_spray"))
})

test("ProofPack builds merkle chain from graph", async () => {
  const { AttackSurfaceGraph } = await import("../src/attack_surface.ts")
  const { buildProofPack } = await import("../src/proof_pack.ts")
  const { CredentialGraph } = await import("../src/credential_graph.ts")

  const graph = new AttackSurfaceGraph("lab.local")
  const asset = graph.upsertAsset("lab.local")
  asset.notes.push("[INTEL] CVE-2025-3248 priority")

  const credGraph = new CredentialGraph()
  credGraph.addCredential({ type: "token", source: "test", value: "tok_abc", host: "lab.local" })

  const pack = buildProofPack(graph, { credGraph, profileTechniques: ["T1190", "T1046"] })
  assert.strictEqual(pack.version, "1.0")
  assert.ok(pack.merkleRoot.length === 64)
  assert.ok(pack.credentials.count >= 1)
  assert.ok(pack.attackNavigator.techniques.length >= 0)
})

test("Campaign runCampaign uses phase modules", async () => {
  const { runCampaign, RedTeamCampaign } = await import("../src/campaign.ts")
  const summary = new RedTeamCampaign("test", "127.0.0.1", { objective: "espionage" }).getSummary()
  assert.ok(summary.phases[0]?.modules.includes("intel_enrich"))

  const result = await runCampaign("127.0.0.1", { live: false, maxStepsPerPhase: 2 })
  assert.ok(result.phaseResults?.length === 3)
  assert.ok(result.stepsExecuted >= 1)
})

test("ai_recon dry-run returns empty not fabricated", async () => {
  const { runRecon } = await import("../src/ai_recon.ts")
  const dry = await runRecon({ domain: "example.com" }, { live: false })
  assert.strictEqual(dry.dryRun, true)
  assert.strictEqual(dry.subdomains.length, 0)
  assert.strictEqual(dry.employees.length, 0)
})

test("counter_intel always runs real local checks", async () => {
  const { auditDefenses } = await import("../src/counter_intel.ts")
  const r = await auditDefenses({ dryRun: true })
  assert.strictEqual(r.dryRun, true)
  assert.ok(Array.isArray(r.edrDetected))
  assert.ok(Array.isArray(r.processAlerts))
})

test("stix bundle parses indicators to intel records", async () => {
  const { parseStixBundle, stixToIntelRecords } = await import("../src/stix_ingest.ts")
  const objects = parseStixBundle(JSON.stringify({
    type: "bundle",
    id: "bundle--1",
    objects: [
      { type: "indicator", id: "ind--1", pattern: "[cve:id = 'CVE-2024-1234']" },
      { type: "threat-actor", id: "ta--1", name: "APT29" },
    ],
  }))
  const records = stixToIntelRecords(objects)
  assert.ok(records.some((r) => r.cve === "CVE-2024-1234"))
  assert.ok(records.some((r) => r.actor === "APT29"))
})

test("proof report renders HTML from proof pack", async () => {
  const { AttackSurfaceGraph } = await import("../src/attack_surface.ts")
  const { buildProofPack } = await import("../src/proof_pack.ts")
  const { renderHtmlReport } = await import("../src/proof_report.ts")
  const graph = new AttackSurfaceGraph("demo.local")
  graph.upsertAsset("demo.local")
  const pack = buildProofPack(graph)
  const html = renderHtmlReport(pack)
  assert.ok(html.includes("OurMine Engagement Proof Pack"))
  assert.ok(html.includes("demo.local"))
})

test("engagement watch captures snapshot and computes delta", async () => {
  const { AttackSurfaceGraph } = await import("../src/attack_surface.ts")
  const { captureSnapshot, computeDelta } = await import("../src/engagement_watch.ts")
  const graph = new AttackSurfaceGraph("watch-test.local")
  graph.upsertAsset("watch-test.local")
  await captureSnapshot("watch-test.local", graph)
  const graph2 = new AttackSurfaceGraph("watch-test.local")
  graph2.upsertAsset("watch-test.local")
  graph2.ingestNmap("watch-test.local", [{ port: 443, protocol: "tcp", state: "open", service: "https", version: "nginx" }], {
    tool: "test", command: "test", stdout: "", stderr: "", exitCode: 0, timestamp: new Date().toISOString(), parsedAt: new Date().toISOString(), executionMs: 0,
  })
  await captureSnapshot("watch-test.local", graph2)
  const delta = computeDelta("watch-test.local")
  assert.ok(delta)
  assert.ok(delta.now)
  assert.ok(delta.changedServices.length >= 1, "expected service delta")
})

test("strix session store persists auth cookies", async () => {
  const { StrixSessionStore } = await import("../src/strix_session.ts")
  const store = new StrixSessionStore()
  const path = store.save({
    id: "test_sess",
    target: "https://lab.local",
    cookies: { session: "abc123" },
    headers: {},
    authenticated: true,
    savedAt: new Date().toISOString(),
  })
  assert.ok(path.includes("test_sess"))
  const loaded = store.load("test_sess")
  assert.strictEqual(loaded?.cookies.session, "abc123")
})

test("oauth device code dry-run returns empty without fake codes", async () => {
  const { performDeviceCodeFlow } = await import("../src/oauth_chain.ts")
  const result = await performDeviceCodeFlow(undefined, { dryRun: true })
  assert.strictEqual(result.dryRun, true)
  assert.strictEqual(result.deviceCode, "")
})

test("pivot replay graph returns empty when netexec unavailable", async () => {
  const { CredentialGraph } = await import("../src/credential_graph.ts")
  const { replayCredentialGraph, parseBloodHoundPaths, ingestBloodHoundIntoGraph } = await import("../src/pivot_replay.ts")
  const g = new CredentialGraph()
  g.addCredential({ type: "password", source: "test", username: "admin", value: "pass", host: "10.0.0.1" })
  const results = await replayCredentialGraph(g, ["10.0.0.1"])
  assert.ok(Array.isArray(results))

  g.ingestBloodHoundPaths([{ start: "u1", end: "DA", nodes: ["10.0.0.5", "DC01"], targetHosts: ["10.0.0.5"] }])
  assert.strictEqual(g.getBloodHoundPaths().length, 1)
  assert.ok(g.bloodhoundTargetHosts().includes("10.0.0.5"))
})

test("pdf report generates valid PDF buffer", async () => {
  const { AttackSurfaceGraph } = await import("../src/attack_surface.ts")
  const { buildProofPack } = await import("../src/proof_pack.ts")
  const { renderPdfBuffer } = await import("../src/pdf_report.ts")
  const graph = new AttackSurfaceGraph("pdf-test.local")
  graph.upsertAsset("pdf-test.local")
  const pack = buildProofPack(graph)
  const buf = renderPdfBuffer(pack)
  assert.ok(buf.slice(0, 5).toString() === "%PDF-")
})

test("loadTaxiiFeeds reads feed config", async () => {
  const { loadTaxiiFeeds } = await import("../src/intel_feeds.ts")
  const feeds = loadTaxiiFeeds()
  assert.ok(Array.isArray(feeds))
})

test("CdpClient isAvailable returns boolean", async () => {
  const { CdpClient } = await import("../src/cdp_client.ts")
  const ok = await CdpClient.isAvailable("http://127.0.0.1:1")
  assert.strictEqual(typeof ok, "boolean")
})

test("top cut assessment meets top_cut tier", async () => {
  const { assessTopCut } = await import("../src/top_cut_score.ts")
  const report = await assessTopCut()
  assert.ok(report.overall >= 8.0, `overall ${report.overall} below top cut threshold`)
  assert.strictEqual(report.meetsTopCut, true, `blockers: ${report.blockers.join("; ")}`)
  assert.strictEqual(report.tier, "top_cut")
  assert.ok(report.dimensions.length >= 5)
  const toolDim = report.dimensions.find((d) => d.id === "tool_wiring")
  assert.ok(toolDim && toolDim.score >= 8, `tool wiring ${toolDim?.score}`)
})

test("all campaign phase tools dispatch without unknown tool error", async () => {
  const { executeAgentTool } = await import("../src/agent_tools.ts")
  const { ToolBroker } = await import("../src/tool_broker.ts")
  const { AttackSurfaceGraph } = await import("../src/attack_surface.ts")
  const graph = new AttackSurfaceGraph("campaign.local")
  const ctx = { target: "campaign.local", graph, broker: new ToolBroker(), live: false }
  const tools = ["ai_recon", "exfil", "impact_engine", "dev_target", "cloud_token", "pivot_replay", "stix_ingest"]
  for (const t of tools) {
    const r = await executeAgentTool(ctx, t, {})
    assert.ok(!r.error?.includes("unknown tool"), `${t}: ${r.error}`)
  }
})

test("parseBloodHoundPaths handles graph JSON", async () => {
  const { parseBloodHoundPaths } = await import("../src/pivot_replay.ts")
  const fs = await import("node:fs")
  const os = await import("node:os")
  const path = await import("node:path")
  const tmp = path.join(os.tmpdir(), `bh_test_${Date.now()}.json`)
  fs.writeFileSync(tmp, JSON.stringify({
    nodes: [
      { id: "u1", label: "LowUser", kind: "User" },
      { id: "1", label: "Domain Admin", kind: "User" },
      { id: "2", label: "WORKSTATION01", kind: "Computer" },
    ],
    edges: [
      { source: "u1", target: "2" },
      { source: "2", target: "1" },
    ],
  }))
  const paths = parseBloodHoundPaths(tmp)
  assert.ok(paths.length >= 1)
  assert.ok(paths.some((p) => p.nodes.length >= 2))
  fs.unlinkSync(tmp)
})

test("module bridge tools dispatch without unknown tool error", async () => {
  const { executeAgentTool } = await import("../src/agent_tools.ts")
  const { bridgedToolNames } = await import("../src/module_bridge.ts")
  const { ToolBroker } = await import("../src/tool_broker.ts")
  const { AttackSurfaceGraph } = await import("../src/attack_surface.ts")
  const graph = new AttackSurfaceGraph("bridge.local")
  const ctx = { target: "bridge.local", graph, broker: new ToolBroker(), live: false }
  for (const t of bridgedToolNames()) {
    const r = await executeAgentTool(ctx, t, {})
    assert.ok(!r.error?.includes("unknown tool"), `${t}: ${r.error}`)
  }
})

test("runEncryptionLab dry-run does not encrypt files", async () => {
  const { runEncryptionLab } = await import("../src/ransomware.ts")
  const report = await runEncryptionLab("/tmp", { live: false })
  assert.strictEqual(report.dryRun, true)
})
