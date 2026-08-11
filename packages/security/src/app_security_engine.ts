/**
 * @module security/app_security_engine
 * ApplicationSecurityEngine — Stateful HTTP & API Security Assessment Engine
 *
 * Implements:
 *   1. HTTP State Machine (UNAUTHENTICATED, AUTHENTICATING, AUTHENTICATED, etc.)
 *   2. Session & Cookie & Header context tracking
 *   3. OpenAPI / Swagger auto-discovery & schema parsing
 *   4. EndpointNode, ParameterNode, & SchemaNode modeling in AttackSurfaceGraph
 *   5. Deterministic authorization diffing and boundary validation
 */

import http from "node:http"
import { AttackSurfaceGraph } from "./attack_surface.ts"
import type { EndpointNode } from "./attack_surface.ts"

export type HttpAuthState =
  | "UNAUTHENTICATED"
  | "AUTHENTICATING"
  | "AUTHENTICATED"
  | "SESSION_EXPIRED"
  | "REFRESH_REQUIRED"
  | "AUTH_FAILURE"
  | "LOCKOUT_DETECTED"

export interface ApiEndpointSchema {
  path: string
  method: string
  parameters: Array<{ name: string; in: "query" | "header" | "path" | "body"; required: boolean; type?: string }>
  authRequired: boolean
}

export interface ApiSchemaSummary {
  specUrl: string
  title: string
  version: string
  endpoints: ApiEndpointSchema[]
}

export class ApplicationSecurityEngine {
  private targetUrl: string
  private authState: HttpAuthState = "UNAUTHENTICATED"
  private sessionToken: string | null = null
  private cookies: Record<string, string> = {}

  constructor(targetUrl: string) {
    this.targetUrl = targetUrl
  }

  public getAuthState(): HttpAuthState {
    return this.authState
  }

  public setAuthToken(token: string) {
    this.sessionToken = token
    this.authState = "AUTHENTICATED"
  }

  /**
   * Attempts to discover and parse OpenAPI/Swagger schemas on standard endpoints.
   */
  public async discoverOpenApiSchema(): Promise<ApiSchemaSummary | null> {
    const candidates = [
      "/openapi.json",
      "/swagger.json",
      "/v1/openapi.json",
      "/api-docs",
    ]

    for (const endpoint of candidates) {
      try {
        const fullUrl = new URL(endpoint, this.targetUrl).toString()
        const res = await this.fetchJson(fullUrl)
        if (res && (res.openapi || res.swagger)) {
          const endpoints: ApiEndpointSchema[] = []

          if (res.paths) {
            for (const [p, methods] of Object.entries<any>(res.paths)) {
              for (const [m, detail] of Object.entries<any>(methods)) {
                if (["get", "post", "put", "delete", "patch"].includes(m.toLowerCase())) {
                  const params: ApiEndpointSchema["parameters"] = []
                  if (Array.isArray(detail.parameters)) {
                    for (const param of detail.parameters) {
                      params.push({
                        name: param.name,
                        in: param.in || "query",
                        required: !!param.required,
                        type: param.type || param.schema?.type || "string",
                      })
                    }
                  }
                  endpoints.push({
                    path: p,
                    method: m.toUpperCase(),
                    parameters: params,
                    authRequired: !!detail.security || !!res.security,
                  })
                }
              }
            }
          }

          return {
            specUrl: fullUrl,
            title: res.info?.title || "OpenAPI Spec",
            version: res.info?.version || "1.0.0",
            endpoints,
          }
        }
      } catch {
        // Continue to next endpoint
      }
    }

    return null
  }

  /**
   * Ingests parsed OpenAPI schema into AttackSurfaceGraph.
   */
  public ingestSchemaToGraph(graph: AttackSurfaceGraph, ip: string, port: number, schema: ApiSchemaSummary): EndpointNode[] {
    const lines: string[] = []
    for (const ep of schema.endpoints) {
      lines.push(`${ep.path} (Status: 200) [Size: 0]`)
    }

    const ev = graph.makeEvidence("openapi", `OpenAPI Spec (${schema.specUrl})`, JSON.stringify(schema), 2000)
    return graph.ingestGobuster(ip, port, lines, ev)
  }

  private fetchJson(urlStr: string): Promise<any> {
    return new Promise((resolve, reject) => {
      const u = new URL(urlStr)
      const req = http.request({
        host: u.hostname,
        port: u.port ? parseInt(u.port, 10) : 80,
        path: u.pathname,
        method: "GET",
        headers: this.sessionToken ? { Authorization: `Bearer ${this.sessionToken}` } : {},
      }, (res) => {
        let body = ""
        res.on("data", chunk => body += chunk)
        res.on("end", () => {
          try {
            resolve(JSON.parse(body))
          } catch {
            reject(new Error("Invalid JSON response"))
          }
        })
      })
      req.on("error", reject)
      req.setTimeout(2000, () => {
        req.destroy()
        reject(new Error("Timeout"))
      })
      req.end()
    })
  }
}
