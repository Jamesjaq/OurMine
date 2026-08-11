import test from "node:test"
import assert from "node:assert/strict"
import http from "node:http"
import { ApplicationSecurityEngine } from "../src/app_security_engine.ts"
import { ImpactDemonstrationEngine } from "../src/impact_engine.ts"
import { AttackSurfaceGraph } from "../src/attack_surface.ts"

test("ApplicationSecurityEngine — discovers and parses OpenAPI schemas", async () => {
  const server = http.createServer((req, res) => {
    if (req.url === "/openapi.json") {
      res.writeHead(200, { "Content-Type": "application/json" })
      return res.end(JSON.stringify({
        openapi: "3.0.0",
        info: { title: "Test API", version: "1.0.0" },
        paths: {
          "/api/v1/users": {
            get: {
              parameters: [{ name: "limit", in: "query", type: "integer" }]
            }
          }
        }
      }))
    }
    res.writeHead(404)
    res.end()
  })

  await new Promise(r => server.listen(8091, "127.0.0.1", r))

  try {
    const engine = new ApplicationSecurityEngine("http://127.0.0.1:8091")
    const schema = await engine.discoverOpenApiSchema()

    assert.ok(schema)
    assert.equal(schema?.title, "Test API")
    assert.equal(schema?.endpoints.length, 1)
    assert.equal(schema?.endpoints[0].path, "/api/v1/users")

    const graph = new AttackSurfaceGraph("127.0.0.1")
    if (schema) {
      const nodes = engine.ingestSchemaToGraph(graph, "127.0.0.1", 8091, schema)
      assert.equal(nodes.length, 1)
      assert.equal(nodes[0].path, "/api/v1/users")
    }
  } finally {
    server.close()
  }
})

test("ImpactDemonstrationEngine — generates bounded non-destructive L4 proof", () => {
  const proof = ImpactDemonstrationEngine.demonstrateImpact(
    { id: "v1", vulnId: "v1", severity: "high", confidence: "confirmed", state: "CONFIRMED", title: "IDOR", evidence: [] },
    "http://127.0.0.1:8080/api/users",
    JSON.stringify({ status: "success", data: "Superuser Access Granted" })
  )

  assert.ok(proof)
  assert.equal(proof?.level, "L4_CONTROLLED_IMPACT")
  assert.equal(proof?.proofType, "CANARY_OBJECT_ACCESS")
  assert.equal(proof?.safeProofMarker, "PROOF_CANARY_READ_SUCCESS")
})
