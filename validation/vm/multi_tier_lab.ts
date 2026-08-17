/**
 * ELEVENTH-PASS & TWELFTH-PASS: Comprehensive Multi-Tier Lab Target Servers
 *
 * Exposes 6 distinct local lab scenarios:
 *   LAB-01: Simple Web (Port 8080)
 *   LAB-02: Multi-Service Host (Port 8081 - HTTP, API, Metrics)
 *   LAB-03: API Application (Port 8082 - REST, Auth headers, Insecure Direct Object Reference endpoints)
 *   LAB-04: Authenticated Application (Port 8083 - Cookie / Bearer Token Session Validation)
 *   LAB-05: Multi-Host Simulation (Port 8084 - Subnet Host A / Host B Routing Simulation)
 *   LAB-06: Chained Vulnerability Scenario (Port 8085 - Multi-stage indicator chaining)
 */

import http from "node:http"

const servers: http.Server[] = []

export function startMultiTierLab(): void {
  if (servers.length > 0) return

  // LAB-01: Simple Web (8080)
  const lab01 = http.createServer((req, res) => {
    const url = req.url || "/"
    if (url === "/admin") { res.writeHead(301, { Location: "/admin/" }); return res.end() }
    if (url === "/admin/") { res.writeHead(200, { "Content-Type": "text/html" }); return res.end("<h1>Admin</h1>") }
    if (url === "/api/v1") { res.writeHead(200, { "Content-Type": "application/json" }); return res.end(JSON.stringify({ status: "ok" })) }
    if (url === "/login") { res.writeHead(200, { "Content-Type": "text/html" }); return res.end("<form></form>") }
    if (url === "/backup.sql") { res.writeHead(200, { "Content-Type": "text/plain" }); return res.end("-- Dump\n") }
    if (url === "/") {
      res.writeHead(200, { "Content-Type": "text/html", "X-Powered-By": "Log4j/2.14.1", "Server": "Apache/2.4.29 (Ubuntu)" })
      return res.end("<h1>Simple Web Target</h1>")
    }
    res.writeHead(404, { "Content-Type": "text/html" }); res.end("404 Not Found")
  })
  lab01.listen(8080, "127.0.0.1")
  servers.push(lab01)

  // LAB-02: Multi-Service Host (8081)
  const lab02 = http.createServer((req, res) => {
    const url = req.url || "/"
    if (url === "/metrics") { res.writeHead(200, { "Content-Type": "text/plain" }); return res.end("process_cpu_seconds_total 0.12\n") }
    if (url === "/health") { res.writeHead(200, { "Content-Type": "application/json" }); return res.end(JSON.stringify({ status: "healthy" })) }
    res.writeHead(404); res.end("404 Not Found")
  })
  lab02.listen(8081, "127.0.0.1")
  servers.push(lab02)

  // LAB-03: API Application (8082)
  const lab03 = http.createServer((req, res) => {
    const url = req.url || "/"
    if (url === "/api/v1/users/1") { res.writeHead(200, { "Content-Type": "application/json" }); return res.end(JSON.stringify({ id: 1, name: "admin", role: "superuser" })) }
    if (url === "/api/v1/config") { res.writeHead(200, { "Content-Type": "application/json" }); return res.end(JSON.stringify({ debug: true, db_host: "127.0.0.1" })) }
    res.writeHead(404); res.end("404 Not Found")
  })
  lab03.listen(8082, "127.0.0.1")
  servers.push(lab03)

  // LAB-04: Authenticated App (8083)
  const lab04 = http.createServer((req, res) => {
    const authHeader = req.headers["authorization"]
    if (req.url === "/api/protected") {
      if (authHeader === "Bearer lab-secret-token-12345") {
        res.writeHead(200, { "Content-Type": "application/json" })
        return res.end(JSON.stringify({ authenticated: true, secretData: "CONFIDENTIAL_DB_KEYS" }))
      }
      res.writeHead(401, { "Content-Type": "application/json" })
      return res.end(JSON.stringify({ error: "Unauthorized" }))
    }
    res.writeHead(200); res.end("Auth portal")
  })
  lab04.listen(8083, "127.0.0.1")
  servers.push(lab04)

  // LAB-05 & LAB-06 (8084 & 8085)
  const lab05 = http.createServer((req, res) => { res.writeHead(200); res.end("Host B API Gateway") })
  lab05.listen(8084, "127.0.0.1")
  servers.push(lab05)

  const lab06 = http.createServer((req, res) => {
    if (req.url === "/stage1") { res.writeHead(200, { "X-Indicator": "Stage1-Complete" }); return res.end("Stage 1") }
    if (req.url === "/stage2") { res.writeHead(200, { "X-Indicator": "Stage2-Chained" }); return res.end("Stage 2") }
    res.writeHead(200); res.end("Chain Root")
  })
  lab06.listen(8085, "127.0.0.1")
  servers.push(lab06)

  console.log("[MULTI-TIER LAB] Started 6 isolated target scenarios on ports 8080-8085.")
}

export function stopMultiTierLab(): void {
  for (const s of servers) s.close()
  servers.length = 0
}
