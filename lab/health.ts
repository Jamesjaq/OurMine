/**
 * Lab Health Check
 */

import http from "node:http"
import { ToolBroker } from "../packages/security/src/tool_broker.ts"
import { ValidationPlanner } from "../packages/security/src/validation_planner.ts"

async function checkHealth() {
  console.log("=== OurMine Lab Health Check ===")
  let healthy = true

  // 1. Target HTTP Reachability
  const targetOk = await new Promise<boolean>((resolve) => {
    const req = http.request({ host: "127.0.0.1", port: 8080, path: "/", method: "GET" }, (res) => {
      resolve(res.statusCode === 200)
    })
    req.on("error", () => {
      resolve(false)
    })
    req.setTimeout(2000, () => {
      req.destroy()
      resolve(false)
    })
    req.end()
  })

  console.log(`Target HTTP (127.0.0.1:8080): ${targetOk ? "OK" : "FAILED"}`)
  if (!targetOk) healthy = false

  // 2. ToolBroker Operational
  const broker = new ToolBroker()
  console.log(`ToolBroker Operational: OK`)

  // 3. Validation Capabilities
  const caps = ValidationPlanner.listCapabilities()
  console.log(`Validation Capabilities Registered: ${caps.length}`)

  if (healthy) {
    console.log("\nLAB HEALTH: OK")
    process.exit(0)
  } else {
    console.log("\nLAB HEALTH: FAILED — Run 'bash lab/setup.sh' first.")
    process.exit(1)
  }
}

checkHealth()
