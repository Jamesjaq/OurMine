import test from "node:test"
import assert from "node:assert/strict"
import fs from "node:fs"
import os from "node:os"
import path from "node:path"
import { SecurityWorldModel } from "../src/security_world_model.ts"

test("world model syncs attack-surface facts with provenance and status", () => {
  const model = new SecurityWorldModel("authorized.example")
  const evidence = model.graph.makeEvidence("unit", "probe authorized.example", "open", 1)
  model.graph.ingestNmap("10.0.0.10", [{ port: 443, protocol: "tcp", state: "open", service: "https", version: "1" }], evidence)
  model.syncAttackSurface()
  const host = model.snapshot().entities.find((e) => e.kind === "HOST" && e.label === "10.0.0.10")
  const service = model.snapshot().entities.find((e) => e.kind === "SERVICE" && e.label === "10.0.0.10:443")
  assert.equal(host?.status, "OBSERVED")
  assert.equal(service?.status, "OBSERVED")
  assert.ok(service?.evidenceIds.includes(evidence.id))
  assert.equal(model.findPaths(host.id, service.id).length, 1)
})

test("world model keeps inferred uncertainty separate from verification", () => {
  const model = new SecurityWorldModel("authorized.example")
  const host = model.upsertEntity({ kind: "HOST", label: "10.0.0.11", properties: {}, status: "OBSERVED", confidence: 0.8, evidenceIds: [] })
  const app = model.upsertEntity({ kind: "APPLICATION", label: "10.0.0.11/admin", properties: {}, status: "INFERRED", confidence: 0.4, evidenceIds: [] })
  model.relate(host.id, app.id, "SERVES", "HYPOTHESIZED", 0.4)
  assert.equal(model.uncertainties().length, 2)
  assert.equal(model.findPaths(host.id, app.id).length, 0)
  assert.equal(model.findPaths(host.id, app.id, true).length, 1)
})

test("only trusted primitives enter the reasoning registry and state persists", () => {
  const model = new SecurityWorldModel("authorized.example")
  assert.throws(() => model.registerCapability({ id: "uncertain", namespace: "x", status: "UNCERTAIN", preconditions: [], effects: [], observableEffects: [], failureModes: [], rollback: [], evidenceIds: [], confidence: 0.2 }))
  model.registerCapability({ id: "http-probe", namespace: "agent_tools", status: "TRUSTED_PRIMITIVE", preconditions: ["authorized scope"], effects: ["service observed"], observableEffects: ["HTTP status"], failureModes: ["timeout"], rollback: [], evidenceIds: ["ev-1"], confidence: 0.9 })
  model.addObjective({ description: "map exposed services", constraints: ["authorized scope"], successCriteria: ["service evidence"] })
  const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "ourmine-world-")), "world.json")
  model.save(file)
  const loaded = SecurityWorldModel.load(file)
  assert.equal(loaded.snapshot().capabilities.length, 1)
  assert.equal(loaded.snapshot().objectives.length, 1)
  assert.equal(loaded.target, "authorized.example")
})
