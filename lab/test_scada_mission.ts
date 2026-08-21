import { runAresOrchestrator } from "../packages/security/src/ares/orchestrator.ts";

async function main() {
  console.log("=== ARES v5.0 SCADA/ICS LIVE-FIRE ENGAGEMENT ===");
  const result = await runAresOrchestrator({
    target: "127.0.0.1",
    objective: "Industrial interdiction and PLC subversion of the chemical plant cooling system on port 5020",
    live: true
  });

  console.log("\n=== MISSION SUMMARY ===");
  console.log(result.summary);
  console.log("\n=== MODULES EXECUTED ===");
  result.modulesExecuted.forEach(m => {
    console.log(`[${m.success ? "SUCCESS" : "FAILED"}] ${m.name}: ${m.summary}`);
  });

  console.log("\n=== CRITICAL FINDINGS ===");
  result.findings.forEach(f => {
    console.log(`[${f.severity.toUpperCase()}] ${f.title}: ${f.description}`);
  });
}

main().catch(console.error);
