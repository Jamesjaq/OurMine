/**
 * Lab target daemon launcher
 */
import { spawn } from "node:child_process"
import * as path from "node:path"
import * as fs from "node:fs"

export function startTargetServer(): number {
  const targetScript = path.resolve("lab/target_server.js")
  const outLog = fs.openSync(path.resolve("lab/target.log"), "a")

  const child = spawn(process.execPath, [targetScript], {
    detached: true,
    stdio: ["ignore", outLog, outLog],
  })

  child.unref()
  fs.writeFileSync(path.resolve("lab/.target.pid"), String(child.pid))
  return child.pid ?? 0
}

if (process.argv[1]?.endsWith("start_target.js")) {
  const pid = startTargetServer()
  console.log(`Started target server PID ${pid}`)
}
