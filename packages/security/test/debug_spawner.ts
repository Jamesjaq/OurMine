import { SyndicateSpawner } from "../src/ares/syndicate_spawn.ts"

const spawner = new SyndicateSpawner()
const target = "127.0.0.1"
const objective = "Infiltrate the energy grid's corporate network, pivot to OT to override substation controls, compromise the internal npm registry, and use a synthetic voice lure to authorize a financial clearing bypass, all while masking as APT29."

console.log("Objective:", objective)
const plan = spawner.assembleForMission(target, objective)

console.log("\nPlan Summary:")
console.log("Total Departments:", plan.syndicateStructure.totalDepartments)
console.log("Total Operatives:", plan.syndicateStructure.totalOperatives)

console.log("\nOperatives:")
plan.operatives.forEach(o => {
  console.log(`- [${o.callsign}] ${o.department} (${o.assignedTool})`)
})

console.log("\nExecution Graph:")
console.log(plan.executionGraph.join(", "))
