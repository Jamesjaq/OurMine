/**
 * Credential parse + ARES auto-chain tests
 */
import { describe, test } from "node:test"
import assert from "node:assert/strict"
import { parseSecretsdumpOutput, extractDomainSid } from "../src/cred_parse.ts"
import { CredentialGraph } from "../src/credential_graph.ts"
import { resolveAdChainContext, planOrchestratorModules } from "../src/ares/_chain.ts"

const SAMPLE_DUMP = `
CORP.LOCAL/krbtgt:502:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
CORP.LOCAL/DC01$:502:aad3b435b51404eeaad3b435b51404ee:11223344556677889900112233445566:::
Domain SID: S-1-5-21-1234567890-1234567890-1234567890
`

describe("cred_parse", () => {
  test("parseSecretsdumpOutput extracts krbtgt and DC machine", () => {
    const accts = parseSecretsdumpOutput(SAMPLE_DUMP)
    assert.ok(accts.some((a) => a.role === "krbtgt" && a.username === "krbtgt"))
    assert.ok(accts.some((a) => a.role === "dc_machine" && a.username === "DC01$"))
  })

  test("extractDomainSid parses SID line", () => {
    assert.equal(extractDomainSid(SAMPLE_DUMP), "S-1-5-21-1234567890-1234567890-1234567890")
  })
})

describe("CredentialGraph AD ingest", () => {
  test("ingestSecretsdumpOutput stores typed creds and domain context", () => {
    const g = new CredentialGraph()
    const n = g.ingestSecretsdumpOutput(SAMPLE_DUMP, { source: "test", host: "10.0.0.1" })
    assert.equal(n, 2)
    assert.equal(g.findKrbtgtHash("CORP.LOCAL"), "31d6cfe0d16ae931b73c59d7e0c089c0")
    assert.equal(g.findDcMachineHash("CORP.LOCAL"), "11223344556677889900112233445566")
    const ctx = g.getAdContext()
    assert.equal(ctx.domainSid, "S-1-5-21-1234567890-1234567890-1234567890")
    assert.equal(ctx.dcName, "DC01")
  })
})

describe("ARES chain prerequisites", () => {
  test("resolveAdChainContext enables Kerberos when krbtgt present", () => {
    const g = new CredentialGraph()
    g.ingestSecretsdumpOutput(SAMPLE_DUMP, { source: "test" })
    const ctx = resolveAdChainContext(g, { domain: "CORP.LOCAL", target: "10.0.0.5" })
    assert.equal(ctx.canKerberos, true)
    assert.equal(ctx.canLateral, true)
    assert.equal(ctx.canRemoteFileless, true)
    assert.equal(ctx.krbtgtHash, "31d6cfe0d16ae931b73c59d7e0c089c0")
  })

  test("planOrchestratorModules skips Kerberos without creds", () => {
    const g = new CredentialGraph()
    const ctx = resolveAdChainContext(g, { target: "127.0.0.1" })
    const plan = planOrchestratorModules(ctx, "127.0.0.1")
    const kerb = plan.find((p) => p.name === "ares_kerberos_advanced")
    assert.equal(kerb?.run, false)
    const hyper = plan.find((p) => p.name === "ares_hypervisor_rootkit")
    assert.equal(hyper?.run, false)
  })

  test("planOrchestratorModules runs Kerberos when krbtgt in graph", () => {
    const g = new CredentialGraph()
    g.ingestSecretsdumpOutput(SAMPLE_DUMP, { source: "test" })
    const ctx = resolveAdChainContext(g, { target: "10.0.0.5" })
    const plan = planOrchestratorModules(ctx, "10.0.0.5")
    assert.equal(plan.find((p) => p.name === "ares_kerberos_advanced")?.run, true)
    assert.equal(plan.find((p) => p.name === "ares_lateral_scale")?.run, true)
  })
})
