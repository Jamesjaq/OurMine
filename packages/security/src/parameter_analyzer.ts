/**
 * @module security/parameter_analyzer
 * Deterministic HTTP Parameter Analysis & Response Diffing Engine
 *
 * Performs safe baseline vs mutated HTTP request/response comparison.
 * Detects status code changes, response length deltas, header anomalies,
 * and structural diffs without destructive exploitation.
 */

import http from "node:http"

export interface ParameterMutationTest {
  url: string
  parameter: string
  baselineValue: string
  testValue: string
}

export interface DiffResult {
  parameter: string
  baselineStatus: number
  baselineSize: number
  testStatus: number
  testSize: number
  statusChanged: boolean
  sizeDelta: number
  anomalousHeader: string | null
  classification: "BEHAVIORAL_DIFFERENCE" | "NO_DIFFERENCE" | "ERROR"
  evidenceSnippet: string
}

export class ParameterAnalyzer {
  /**
   * Executes a baseline GET request and a mutated GET request against a local HTTP target,
   * comparing response metadata and structural indicators.
   */
  public static async analyzeParameter(test: ParameterMutationTest): Promise<DiffResult> {
    try {
      // 1. Baseline Request
      const baselineUrl = new URL(test.url)
      baselineUrl.searchParams.set(test.parameter, test.baselineValue)
      const baseline = await this.fetchHttp(baselineUrl.toString())

      // 2. Mutated Request
      const testUrl = new URL(test.url)
      testUrl.searchParams.set(test.parameter, test.testValue)
      const mutated = await this.fetchHttp(testUrl.toString())

      const statusChanged = baseline.status !== mutated.status
      const sizeDelta = Math.abs(baseline.body.length - mutated.body.length)
      const anomalousHeader = mutated.headers["x-powered-by"] || mutated.headers["server"] || null

      let classification: DiffResult["classification"] = "NO_DIFFERENCE"
      if (statusChanged || sizeDelta > 20 || (anomalousHeader && !baseline.headers[anomalousHeader.toLowerCase()])) {
        classification = "BEHAVIORAL_DIFFERENCE"
      }

      const evidenceSnippet = `Baseline (${baseline.status}, ${baseline.body.length}b) vs Mutated (${mutated.status}, ${mutated.body.length}b)`

      return {
        parameter: test.parameter,
        baselineStatus: baseline.status,
        baselineSize: baseline.body.length,
        testStatus: mutated.status,
        testSize: mutated.body.length,
        statusChanged,
        sizeDelta,
        anomalousHeader,
        classification,
        evidenceSnippet,
      }
    } catch (err: any) {
      return {
        parameter: test.parameter,
        baselineStatus: 0,
        baselineSize: 0,
        testStatus: 0,
        testSize: 0,
        statusChanged: false,
        sizeDelta: 0,
        anomalousHeader: null,
        classification: "ERROR",
        evidenceSnippet: `HTTP fetch failed: ${err.message}`,
      }
    }
  }

  private static fetchHttp(targetUrl: string): Promise<{ status: number; headers: Record<string, string>; body: string }> {
    return new Promise((resolve, reject) => {
      const u = new URL(targetUrl)
      const req = http.request({
        host: u.hostname,
        port: u.port ? parseInt(u.port, 10) : 80,
        path: u.pathname + u.search,
        method: "GET",
      }, (res) => {
        let body = ""
        res.on("data", chunk => body += chunk)
        res.on("end", () => {
          const headers: Record<string, string> = {}
          for (const [k, v] of Object.entries(res.headers)) {
            if (typeof v === "string") headers[k.toLowerCase()] = v
          }
          resolve({
            status: res.statusCode || 0,
            headers,
            body,
          })
        })
      })
      req.on("error", reject)
      req.setTimeout(3000, () => {
        req.destroy()
        reject(new Error("Timeout"))
      })
      req.end()
    })
  }
}
