import { runAresOrchestrator } from "../packages/security/src/ares/orchestrator.ts"

async function main() {
  console.log("=== ARES v5.0 PURE SYNTHESIS TEST (ZERO HARDCODED DOMAINS) ===")
  const target = "192.168.200.99"
  const objective = "Infiltrate orbital quantum weather satellite uplink, intercept encrypted telemetry streams, and establish sovereign deep-space C2 persistence."

  const result = await runAresOrchestrator({
    live: true,
    target,
    objective
  })

  console.log("\n=== MISSION SUMMARY ===")
  console.log(result.summary)
  console.log("\n=== CHAIN OF COMMAND & DYNAMIC SYNDICATE ===")
  console.log(result.mission.chainOfCommand)
  console.log("\n=== MODULES EXECUTED ===")
  for (const m of result.modulesExecuted) {
    console.log(`[${m.success ? "SUCCESS" : "FAIL"}] ${m.name}: ${m.summary}`)
  }
}

main().catch(console.error)
