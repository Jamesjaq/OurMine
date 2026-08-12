/**
 * IdP/OAuth audit — live flag wiring and no-fake-findings on live mode.
 */
import { describe, test, beforeEach, afterEach, mock } from "node:test"
import assert from "node:assert/strict"

const ENV_BACKUP = { ...process.env }

beforeEach(() => {
  process.env = {
    ...ENV_BACKUP,
    OURMINE_ALLOW_DRY_RUN: "1",
    OURMINE_LIVE: "0",
  }
  delete process.env.OURMINE_GRAPH_TOKEN
  delete process.env.AZURE_ACCESS_TOKEN
  delete process.env.GRAPH_ACCESS_TOKEN
})

afterEach(() => {
  process.env = ENV_BACKUP
  mock.restoreAll()
})

describe("idp_oauth_audit live flag", () => {
  test("live:false resolves to dry run with no fabricated findings", async () => {
    const { auditIdPAndOAuth } = await import("../src/idp_oauth_audit.ts")
    const r = await auditIdPAndOAuth({ domain: "example.com" }, { live: false })
    assert.equal(r.isDryRun, true)
    assert.equal(r.findings.length, 0)
    assert.equal(r.totalOAuthApps, 0)
    assert.equal(r.oauthApps.length, 0)
  })

  test("live:true without token is not dry run and reports blocker only", async () => {
    const originalFetch = globalThis.fetch
    globalThis.fetch = async (url) => {
      if (String(url).includes("devicecode")) {
        return {
          ok: true,
          json: async () => ({
            device_code: "dc-test",
            user_code: "ABCD-1234",
            verification_uri: "https://microsoft.com/devicelogin",
            interval: 5,
            expires_in: 900,
          }),
        }
      }
      throw new Error(`unexpected fetch: ${url}`)
    }

    try {
      const { auditIdPAndOAuth } = await import("../src/idp_oauth_audit.ts")
      const r = await auditIdPAndOAuth({ domain: "example.com" }, { live: true })
      assert.equal(r.isDryRun, false)
      assert.equal(r.totalOAuthApps, 0)
      assert.ok(r.findings.some((f) => f.title === "No Access Token Provided"))
      assert.ok(
        r.findings[0].description.includes("OURMINE_GRAPH_TOKEN") ||
          r.findings[0].remediation.includes("OURMINE_GRAPH_TOKEN"),
      )
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  test("live:true with accessToken performs Graph calls (mocked, no fake apps)", async () => {
    const originalFetch = globalThis.fetch
    globalThis.fetch = async (url) => {
      const u = String(url)
      if (u.includes("/applications")) {
        return { ok: true, json: async () => ({ value: [] }) }
      }
      if (u.includes("/authenticationMethodConfigurations")) {
        return { ok: true, json: async () => ({ value: [] }) }
      }
      if (u.includes("/policies/authenticationMethodsPolicy")) {
        return { ok: true, json: async () => ({ tokenBinding: {} }) }
      }
      if (u.includes("/servicePrincipals")) {
        return { ok: true, json: async () => ({ value: [] }) }
      }
      return { ok: false, status: 404, json: async () => ({}) }
    }

    try {
      const { auditIdPAndOAuth } = await import("../src/idp_oauth_audit.ts")
      const r = await auditIdPAndOAuth(
        { domain: "example.com" },
        { live: true, accessToken: "test-graph-token" },
      )
      assert.equal(r.isDryRun, false)
      assert.equal(r.totalOAuthApps, 0)
      assert.ok(!r.findings.some((f) => f.title === "No Access Token Provided"))
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  test("OURMINE_GRAPH_TOKEN env is used when live and no options.accessToken", async () => {
    process.env.OURMINE_GRAPH_TOKEN = "env-graph-token"
    const originalFetch = globalThis.fetch
    let sawAuth = false
    globalThis.fetch = async (url, init) => {
      const u = String(url)
      const auth = init?.headers?.Authorization ?? init?.headers?.authorization
      if (auth === "Bearer env-graph-token") sawAuth = true
      if (u.includes("/applications")) {
        return { ok: true, json: async () => ({ value: [] }) }
      }
      if (u.includes("/authenticationMethodConfigurations")) {
        return { ok: true, json: async () => ({ value: [] }) }
      }
      if (u.includes("/policies/authenticationMethodsPolicy")) {
        return { ok: true, json: async () => ({ tokenBinding: {} }) }
      }
      if (u.includes("/servicePrincipals")) {
        return { ok: true, json: async () => ({ value: [] }) }
      }
      return { ok: false, status: 404, json: async () => ({}) }
    }

    try {
      const { auditIdPAndOAuth } = await import("../src/idp_oauth_audit.ts")
      const r = await auditIdPAndOAuth({ domain: "example.com" }, { live: true })
      assert.equal(r.isDryRun, false)
      assert.equal(sawAuth, true)
    } finally {
      globalThis.fetch = originalFetch
    }
  })
})
