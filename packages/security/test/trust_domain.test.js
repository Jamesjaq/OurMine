import { test } from "node:test"
import assert from "node:assert"
import { PolicyDaemon, requestPolicyToken } from "../src/policy_daemon.ts"
import { SandboxRunner } from "../src/sandbox_runner.ts"

test("Out-of-Process Policy Daemon & Sandbox Isolation Suite", async (t) => {

  await t.test("Policy Daemon IPC socket token issuance & denial", async () => {
    const daemon = new PolicyDaemon()
    await daemon.start()

    try {
      // 1. Valid token request over Unix socket
      const token = await requestPolicyToken("agent_1", "NETWORK_RECON", "corp.local")
      assert.ok(token.length > 20, "Token issued by independent daemon over IPC socket")

      // 2. Denied capability (interpreter/shell request)
      await assert.rejects(
        () => requestPolicyToken("agent_1", "SHELL_EXECUTE", "corp.local"),
        /Policy Daemon Denial/,
        "Daemon rejects dangerous shell/interpreter request"
      )
    } finally {
      await daemon.stop()
    }
  })

  await t.test("SandboxRunner credential & environment stripping", () => {
    const dirtyEnv = {
      PATH: "/usr/bin",
      AWS_SECRET_ACCESS_KEY: "secret123",
      OPENAI_API_KEY: "sk-proj-xyz",
      GITHUB_TOKEN: "ghp_abc",
      NORMAL_VAR: "safe_value",
    }

    const clean = SandboxRunner.sanitizeEnvironment(dirtyEnv)
    assert.strictEqual(clean["AWS_SECRET_ACCESS_KEY"], undefined)
    assert.strictEqual(clean["OPENAI_API_KEY"], undefined)
    assert.strictEqual(clean["GITHUB_TOKEN"], undefined)
    assert.strictEqual(clean["NORMAL_VAR"], "safe_value")
    assert.strictEqual(clean["PATH"], "/usr/local/bin:/usr/bin:/bin")
  })

})
