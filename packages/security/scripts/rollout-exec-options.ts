#!/usr/bin/env node
/**
 * Adds resolveDryRun import to security modules that use live/dryRun but don't import exec_options yet.
 */
import * as fs from "node:fs"
import * as path from "node:path"
import { fileURLToPath } from "node:url"

const srcDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../src")
const SKIP = new Set(["index.ts", "exec_options.ts", "module_helpers.ts", "mcp_server.ts", "mcp_dispatch.ts"])

let updated = 0
for (const file of fs.readdirSync(srcDir).filter((f) => f.endsWith(".ts") && !SKIP.has(f))) {
  const fp = path.join(srcDir, file)
  let content = fs.readFileSync(fp, "utf8")
  if (content.includes("exec_options.ts") || content.includes("module_helpers.ts")) continue
  if (!/\bdryRun\b|\blive\?\:/.test(content)) continue

  const importLine = `import { resolveDryRun } from "./exec_options.ts"\n`
  const firstImport = content.search(/^import /m)
  if (firstImport === -1) {
    content = importLine + content
  } else {
    content = content.slice(0, firstImport) + importLine + content.slice(firstImport)
  }

  content = content.replace(
    /const dryRun = opts\.dryRun ?? true/g,
    "const dryRun = resolveDryRun(opts)",
  )
  content = content.replace(
    /const dryRun = opts\.dryRun !== undefined \? opts\.dryRun : !\(opts\.live ?? false\)/g,
    "const dryRun = resolveDryRun(opts)",
  )
  content = content.replace(
    /const isDryRun = options\.dryRun !== false/g,
    "const isDryRun = resolveDryRun(options)",
  )
  content = content.replace(
    /const isDryRun = options\.dryRun !== undefined \? options\.dryRun : !\(options\.live ?? false\)/g,
    "const isDryRun = resolveDryRun(options)",
  )

  fs.writeFileSync(fp, content)
  updated++
}

console.log(`Updated ${updated} modules with resolveDryRun import`)
