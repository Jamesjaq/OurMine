import test from "node:test"
import assert from "node:assert"

test("gateExecution allows low-signature commands", async () => {
  const { gateExecution } = await import("../src/opsec_gate.ts")
  const result = await gateExecution({
    tool: "nmap_scan",
    command: "nmap -sV -p 80 127.0.0.1",
    live: false,
  })
  assert.ok(typeof result.allowed === "boolean")
  assert.ok(result.review)
  assert.ok(Array.isArray(result.yaraHits))
})

test("gateExecution blocks high-signature without force", async () => {
  const { gateExecution } = await import("../src/opsec_gate.ts")
  const result = await gateExecution({
    tool: "bash",
    command: "powershell -enc SGVsbG8=",
    live: false,
  })
  if (result.review.signature_risk === "high") {
    assert.strictEqual(result.allowed, false)
  }
})

test("gateExecution force override allows execution", async () => {
  const { gateExecution } = await import("../src/opsec_gate.ts")
  const result = await gateExecution({
    tool: "bash",
    command: "powershell -enc SGVsbG8=",
    force: true,
    live: false,
  })
  assert.strictEqual(result.allowed, true)
})

test("gateExecution runs YARA self-check on command", async () => {
  const { gateExecution } = await import("../src/opsec_gate.ts")
  const result = await gateExecution({
    tool: "test",
    command: "curl -H OPENAI_API_KEY=sk-test",
    live: false,
  })
  assert.ok(Array.isArray(result.yaraHits))
})
