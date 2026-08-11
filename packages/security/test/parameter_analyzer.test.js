import test from "node:test"
import assert from "node:assert/strict"
import http from "node:http"
import { ParameterAnalyzer } from "../src/parameter_analyzer.ts"

test("ParameterAnalyzer — detects response diffs on parameter mutation", async () => {
  const server = http.createServer((req, res) => {
    const url = new URL(req.url || "/", "http://127.0.0.1:8089")
    const id = url.searchParams.get("id")
    if (id === "admin") {
      res.writeHead(200, { "Content-Type": "text/html", "X-Powered-By": "Log4j/2.14.1" })
      return res.end("<h1>Admin Dashboard</h1><p>Superuser Access Granted</p>")
    }
    res.writeHead(404, { "Content-Type": "text/html" })
    res.end("404 Not Found")
  })

  await new Promise(r => server.listen(8089, "127.0.0.1", r))

  try {
    const result = await ParameterAnalyzer.analyzeParameter({
      url: "http://127.0.0.1:8089/",
      parameter: "id",
      baselineValue: "guest",
      testValue: "admin",
    })

    assert.equal(result.classification, "BEHAVIORAL_DIFFERENCE")
    assert.equal(result.statusChanged, true)
    assert.equal(result.baselineStatus, 404)
    assert.equal(result.testStatus, 200)
    assert.equal(result.anomalousHeader, "Log4j/2.14.1")
  } finally {
    server.close()
  }
})
