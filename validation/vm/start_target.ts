/**
 * Lab target in-process server launcher
 */
import http from "node:http"

let serverInstance: http.Server | null = null

export function ensureTargetServerRunning(port = 8080): void {
  if (serverInstance) return

  serverInstance = http.createServer((req, res) => {
    const url = req.url || "/"

    if (url === "/admin") {
      res.writeHead(301, { Location: "/admin/" })
      return res.end("Redirecting to /admin/")
    }

    if (url === "/admin/") {
      res.writeHead(200, { "Content-Type": "text/html" })
      return res.end("<h1>Admin Dashboard</h1><p>Restricted Area</p>")
    }

    if (url === "/api/v1") {
      res.writeHead(200, { "Content-Type": "application/json" })
      return res.end(JSON.stringify({ status: "ok", version: "1.0.0" }))
    }

    if (url === "/login") {
      res.writeHead(200, { "Content-Type": "text/html" })
      return res.end("<form method='POST'><input name='user'/><input name='pass'/></form>")
    }

    if (url === "/backup.sql") {
      res.writeHead(200, { "Content-Type": "text/plain" })
      return res.end("-- Database Dump\nCREATE TABLE users (id INT, username VARCHAR(50));\n")
    }

    if (url === "/") {
      res.writeHead(200, {
        "Content-Type": "text/html",
        "X-Powered-By": "Log4j/2.14.1",
        "Server": "Apache/2.4.29 (Ubuntu)"
      })
      return res.end("<html><body><h1>Vulnerable Web App</h1><p>Welcome to OurMine Lab Target</p></body></html>")
    }

    // Proper 404 for all other non-existent URLs
    res.writeHead(404, { "Content-Type": "text/html" })
    res.end("<html><body><h1>404 Not Found</h1></body></html>")
  })

  serverInstance.listen(port, "127.0.0.1")
  console.log(`[TARGET] In-process target server listening on http://127.0.0.1:${port}`)
}

export function stopTargetServer(): void {
  if (serverInstance) {
    serverInstance.close()
    serverInstance = null
  }
}
