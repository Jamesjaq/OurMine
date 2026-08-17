import fs from "node:fs"

const phase1 = JSON.parse(fs.readFileSync("audit/proof/capability-proof.json", "utf8"))
const evidence = JSON.parse(fs.readFileSync("audit/proof/capability-evidence.json", "utf8"))
const proven = new Map(evidence.proofs.filter((p) => p.status === "PROVEN").map((p) => [p.id, p]))
const namespaceByPath = new Map(phase1.capabilities.map((c) => [c.implementation, c.capability]))

const trustedPrimitives = evidence.proofs
  .filter((p) => p.status === "PROVEN" && p.id !== "lab-lifecycle")
  .map((p) => ({
    id: p.id,
    status: "TRUSTED_PRIMITIVE",
    evidence: p.evidence,
    claims: p.claims,
    namespace: p.id.split(".")[0],
    namespaceStatus: "PARTIALLY_PROVEN",
  }))

const uncertainNamespaces = phase1.capabilities
  .filter((c) => ![...proven.keys()].some((id) => id.startsWith(`${c.capability}.`)))
  .map((c) => ({ capability: c.capability, status: "UNCERTAIN", implementation: c.implementation }))

const output = {
  generatedAt: new Date().toISOString(),
  policy: "Only scoped primitives with independent evidence are trusted; namespace-level status is never inferred.",
  sourcePhase1Counts: phase1.counts,
  trustedPrimitiveCount: trustedPrimitives.length,
  trustedPrimitives,
  uncertainNamespaceCount: uncertainNamespaces.length,
  uncertainNamespaces,
}
fs.writeFileSync("audit/proof/phase2-trust-registry.json", JSON.stringify(output, null, 2) + "\n")
console.log(JSON.stringify({ trusted: trustedPrimitives.length, uncertainNamespaces: uncertainNamespaces.length }, null, 2))
