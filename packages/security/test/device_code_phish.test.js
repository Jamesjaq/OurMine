/**
 * Device-code phishing playbook — Phase 2.1
 */
import { describe, test } from "node:test"
import assert from "node:assert/strict"
import { auditDeviceCodeFlow } from "../src/device_code_phish.ts"
import { runBridgedModule } from "../src/module_bridge.ts"
import { isExecutableModule } from "../src/module_registry.ts"

describe("device_code_phish", () => {
  test("dry-run returns simulated user code + findings", () => {
    const r = auditDeviceCodeFlow("corp.example.com", { dryRun: true })
    assert.equal(r.dryRun, true)
    assert.ok(r.userCodeSimulation?.userCode)
    assert.ok(r.findings.some((f) => f.mitre === "T1528"))
  })

  test("device_code_audit is executable via module bridge", async () => {
    assert.ok(isExecutableModule("device_code_audit"))
    const r = await runBridgedModule(
      { target: "corp.example.com", live: false, sessionId: "test" },
      "device_code_audit",
      { target: "corp.example.com" },
    )
    assert.ok(r.success)
    const payload = JSON.parse(r.output)
    assert.ok(payload.findings?.length >= 1)
    assert.ok(r.output.length <= 8000)
  })
})
