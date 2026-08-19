/**
 * ARES v3.3 "Global Adversary" Verification Script
 * Audits the specific findings and execution paths of the new Syndicate cells.
 */

import { runAresOrchestrator } from "../src/ares/orchestrator.ts"

async function verifyV33() {
  console.log("🚀 Starting ARES v3.3 Global Adversary Verification...")
  
  const objective = "Compromise supply chain, deploy cognitive lures, disrupt financial gateways, and tap undersea fiber."
  const target = "127.0.0.1"
  
  const result = await runAresOrchestrator({
    target,
    objective
  }, { live: true })

  console.log("\n📊 Mission Result Summary:")
  console.log(result.summary)
  
  console.log("\n🔍 Operatives Spawned:")
  const plan = result.data as any
  if (plan && plan.operatives) {
    plan.operatives.forEach((o: any) => {
      console.log(`  - [${o.callsign}] ${o.title} (${o.department}) -> Tool: ${o.assignedTool}`)
    })
  }

  console.log("\n💎 Critical Findings Audited:")
  if (result.findings) {
    result.findings.forEach(f => {
      console.log(`  [${f.severity.toUpperCase()}] ${f.id}: ${f.title}`)
      console.log(`    ${f.description}`)
    })
  }

  const newModules = ["sc-gha-01", "cog-01", "fin-01", "imp-fiber-01", "dec-01"]
  const detected = result.findings.map(f => f.id)
  const missing = newModules.filter(m => !detected.includes(m))

  if (missing.length === 0) {
    console.log("\n✅ ALL v3.3 GLOBAL ADVERSARY VECTORS VERIFIED LIVE.")
  } else {
    console.log(`\n⚠️ Missing v3.3 Vectors: ${missing.join(", ")}`)
  }
}

verifyV33().catch(console.error)
