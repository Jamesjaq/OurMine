/**
 * @module proof_pack
 * Tamper-evident evidence export — validation chain + ATT&CK coverage for customer delivery.
 */
import * as crypto from "node:crypto"
import * as fs from "node:fs"
import * as path from "node:path"
import type { AttackSurfaceGraph } from "./attack_surface.ts"
import { exportNavigatorLayer, coverageScore } from "./attack_navigator.ts"
import type { CredentialGraph } from "./credential_graph.ts"
import { writeHtmlReport } from "./proof_report.ts"
import { writePdfReport, writePdfReportBest } from "./pdf_report.ts"

export interface ProofPackEntry {
  seq: number
  ts: string
  type: "evidence" | "finding" | "credential" | "tool_call"
  hash: string
  payload: Record<string, unknown>
}

export interface ProofPack {
  version: "1.0"
  target: string
  generatedAt: string
  merkleRoot: string
  graphSummary: Record<string, unknown>
  findings: Array<{ id: string; title: string; severity: string; state: string; technique?: string }>
  attackNavigator: ReturnType<typeof exportNavigatorLayer>
  coverage: ReturnType<typeof coverageScore>
  credentials: { count: number; types: string[] }
  chain: ProofPackEntry[]
}

function sha256(data: string): string {
  return crypto.createHash("sha256").update(data).digest("hex")
}

function buildChain(entries: ProofPackEntry[]): string {
  let root = ""
  for (const e of entries) {
    root = sha256(`${root}:${e.hash}`)
  }
  return root
}

export function buildProofPack(
  graph: AttackSurfaceGraph,
  opts: {
    credGraph?: CredentialGraph
    profileTechniques?: string[]
    engagementId?: string
  } = {},
): ProofPack {
  const session = graph.toJSON()
  const chain: ProofPackEntry[] = []
  const graphFindings: ProofPack["findings"] = []
  let seq = 0

  const assets = session.assets ?? {}
  for (const [ip, asset] of Object.entries(assets)) {
    const notes = (asset as { notes?: string[] }).notes ?? []
    for (const note of notes) {
      seq++
      const payload = { ip, note }
      chain.push({
        seq,
        ts: new Date().toISOString(),
        type: "evidence",
        hash: sha256(JSON.stringify(payload)),
        payload,
      })
    }
    for (const svc of Object.values((asset as { services?: Record<string, { vulns?: unknown[] }> }).services ?? {})) {
      for (const v of svc.vulns ?? []) {
        const vuln = v as { id?: string; title?: string; severity?: string; state?: string; template?: string }
        graphFindings.push({
          id: vuln.id ?? crypto.randomUUID(),
          title: vuln.title ?? "finding",
          severity: vuln.severity ?? "info",
          state: vuln.state ?? "SUSPECTED",
          technique: vuln.template,
        })
        seq++
        chain.push({
          seq,
          ts: new Date().toISOString(),
          type: "finding",
          hash: sha256(JSON.stringify(vuln)),
          payload: vuln as Record<string, unknown>,
        })
      }
    }
  }

  const credData = opts.credGraph?.toJSON()
  if (credData?.credentials.length) {
    for (const c of credData.credentials) {
      seq++
      chain.push({
        seq,
        ts: c.discoveredAt,
        type: "credential",
        hash: sha256(`${c.type}:${c.source}:${c.username ?? ""}`),
        payload: { type: c.type, source: c.source, username: c.username, host: c.host },
      })
    }
  }

  const navFindings = graphFindings.map((f) => ({
    title: f.title,
    severity: f.severity,
    technique_id: f.technique,
  }))
  const profileTech = opts.profileTechniques ?? []
  const coverage = coverageScore(navFindings, profileTech)

  return {
    version: "1.0",
    target: graph.summary().target,
    generatedAt: new Date().toISOString(),
    merkleRoot: buildChain(chain),
    graphSummary: graph.summary() as unknown as Record<string, unknown>,
    findings: graphFindings,
    attackNavigator: exportNavigatorLayer(navFindings, { name: opts.engagementId ?? "OurMine Proof Pack" }),
    coverage,
    credentials: {
      count: credData?.credentials.length ?? 0,
      types: [...new Set(credData?.credentials.map((c) => c.type) ?? [])],
    },
    chain,
  }
}

export function writeProofPack(pack: ProofPack, outDir = path.join(process.cwd(), ".ourmine", "proof")): string {
  fs.mkdirSync(outDir, { recursive: true })
  const file = path.join(outDir, `proof_${pack.target.replace(/[^a-zA-Z0-9._-]/g, "_")}_${Date.now()}.json`)
  fs.writeFileSync(file, JSON.stringify(pack, null, 2))
  writeHtmlReport(pack, outDir)
  void writePdfReportBest(pack, outDir).catch(() => { writePdfReport(pack, outDir) })
  return file
}

export default { buildProofPack, writeProofPack }
