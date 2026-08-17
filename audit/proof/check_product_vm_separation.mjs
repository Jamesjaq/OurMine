import fs from "node:fs"
import path from "node:path"

const roots = ["bin", "packages/security/src"]
const forbidden = /validation\/vm|(^|[^A-Za-z0-9_])lab\//
const offenders = []
for (const root of roots) {
  const walk = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const file = path.join(dir, entry.name)
      if (entry.isDirectory()) walk(file)
      else if (/\.(ts|js)$/.test(entry.name)) {
        const text = fs.readFileSync(file, "utf8")
        if (forbidden.test(text)) offenders.push(file)
      }
    }
  }
  walk(root)
}
const packageJson = JSON.parse(fs.readFileSync("package.json", "utf8"))
const legacyScripts = Object.keys(packageJson.scripts).filter((key) => /^lab:/.test(key))
const result = { productRoots: roots, forbiddenPathOffenders: offenders, legacyLabScripts: legacyScripts, pass: offenders.length === 0 && legacyScripts.length === 0 }
fs.writeFileSync("audit/proof/product-vm-separation.json", JSON.stringify(result, null, 2) + "\n")
console.log(JSON.stringify(result, null, 2))
if (!result.pass) process.exit(1)
