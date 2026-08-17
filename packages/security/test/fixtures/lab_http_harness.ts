/**
 * @module lab_http_harness
 * Shared live HTTP lab server for tier-1 validation benchmarks and tests.
 */
import http from "node:http"

export interface LabHttpHarness {
  port: number
  baseUrl: string
  server: http.Server
  close: () => Promise<void>
}

const users = new Map([
  ["user_a", { id: 1, token: "token_a_secret", role: "user" }],
  ["user_b", { id: 2, token: "token_b_secret", role: "user" }],
])

export function startTier1LabServer(preferredPort = 18080): Promise<LabHttpHarness> {
  return new Promise((resolve, reject) => {
    const handler = (req: http.IncomingMessage, res: http.ServerResponse) => {
      const url = req.url ?? "/"
      const bodyChunks: Buffer[] = []
      req.on("data", (c) => bodyChunks.push(c))
      req.on("end", () => {
        const body = Buffer.concat(bodyChunks).toString("utf8")

        if (url === "/login" && req.method === "POST") {
          try {
            const parsed = JSON.parse(body || "{}") as { username?: string; password?: string }
            const u = users.get(parsed.username ?? "")
            if (u) {
              res.writeHead(200, { "Content-Type": "application/json" })
              return res.end(JSON.stringify({ token: u.token, user: parsed.username }))
            }
          } catch { /* ignore */ }
          res.writeHead(401, { "Content-Type": "application/json" })
          return res.end(JSON.stringify({ error: "invalid" }))
        }

        if (url.startsWith("/api/v1/users/")) {
          const auth = req.headers.authorization ?? ""
          const id = url.split("/").pop()
          const userData = id === "1"
            ? { id: 1, name: "user_a", role: "user" }
            : { id: 2, name: "user_b", role: "admin", email: "user_b@lab.local" }
          if (auth.includes("token_a") && id === "2") {
            res.writeHead(200, { "Content-Type": "application/json", "X-Data": "CONFIDENTIAL" })
            return res.end(JSON.stringify(userData))
          }
          if (auth.includes("token_a") && id === "1") {
            res.writeHead(200, { "Content-Type": "application/json" })
            return res.end(JSON.stringify(userData))
          }
          res.writeHead(403, { "Content-Type": "application/json" })
          return res.end(JSON.stringify({ error: "forbidden" }))
        }

        if (url === "/api/v1/users") {
          res.writeHead(200, {
            "Content-Type": "application/json",
            "X-Powered-By": "Log4j/2.14.1",
          })
          return res.end(JSON.stringify([{ id: 1, name: "admin", role: "administrator", secret: "CONFIDENTIAL" }]))
        }

        if (url === "/admin") {
          res.writeHead(200, { "Content-Type": "text/html" })
          return res.end("<html><body>admin panel CONFIDENTIAL password=lab</body></html>")
        }

        if (url === "/api/v1/mfa/push" && req.method === "POST") {
          res.writeHead(200, { "Content-Type": "application/json" })
          return res.end(JSON.stringify({ status: "sent" }))
        }

        res.writeHead(404)
        res.end("not found")
      })
    }

    const tryPort = (port: number) => {
      const server = http.createServer(handler)
      server.on("error", () => {
        if (port < preferredPort + 10) tryPort(port + 1)
        else reject(new Error("Could not bind lab server"))
      })
      server.listen(port, "127.0.0.1", () => {
        resolve({
          port,
          baseUrl: `http://127.0.0.1:${port}`,
          server,
          close: () => new Promise((r) => server.close(() => r())),
        })
      })
    }
    tryPort(preferredPort)
  })
}

export default { startTier1LabServer }
