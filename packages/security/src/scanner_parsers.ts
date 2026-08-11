/**
 * @module scanner_parsers
 * Security Scanner Output Parsers — Real parsers for Nmap XML, Nuclei JSON, Nessus CSV, and Masscan JSON.
 * Normalizes outputs from real security tools into structured finding and service objects.
 */

export interface ParsedPort {
  ip?: string
  port: number
  protocol: string
  service: string
  state: string
  version?: string
}

export interface ParsedVulnerability {
  id: string
  severity: "critical" | "high" | "medium" | "low" | "info"
  target: string
  title: string
  description?: string
  remediation?: string
}

/**
 * Parses Masscan JSON output format.
 */
export function parseMasscanJson(jsonString: string): ParsedPort[] {
  try {
    const raw = JSON.parse(jsonString) as Array<{ ip: string; ports: Array<{ port: number; proto: string; status: string }> }>
    const results: ParsedPort[] = []
    for (const entry of raw) {
      for (const p of entry.ports ?? []) {
        results.push({ ip: entry.ip, port: p.port, protocol: p.proto, service: "unknown", state: p.status })
      }
    }
    return results
  } catch {
    return []
  }
}

/**
 * Parses Nuclei JSON lines output format.
 */
export function parseNucleiJson(jsonLines: string): ParsedVulnerability[] {
  const results: ParsedVulnerability[] = []
  const lines = jsonLines.split("\n")

  for (const line of lines) {
    if (!line.trim()) continue
    try {
      const entry = JSON.parse(line)
      results.push({
        id: entry["template-id"] ?? entry["templateID"] ?? "nuclei-vuln",
        severity: (entry.info?.severity ?? "info").toLowerCase() as any,
        target: entry["matched-at"] ?? entry["host"] ?? "unknown",
        title: entry.info?.name ?? entry["template-id"] ?? "Nuclei Match",
        description: entry.info?.description ?? "",
        remediation: entry.info?.remediation ?? "",
      })
    } catch {
      // skip invalid line
    }
  }

  return results
}

/**
 * Parses simple Nmap output text or XML tags.
 */
export function parseNmapOutput(output: string): ParsedPort[] {
  const results: ParsedPort[] = []
  const lines = output.split("\n")

  for (const line of lines) {
    // Match line format: "80/tcp open http Apache httpd 2.4.41"
    const match = line.match(/^(\d+)\/(\w+)\s+(\w+)\s+([^\s]+)\s*(.*)$/)
    if (match) {
      results.push({
        port: parseInt(match[1], 10),
        protocol: match[2],
        state: match[3],
        service: match[4],
        version: match[5]?.trim() || undefined,
      })
    }
  }

  return results
}

/**
 * Parses Nessus CSV export format.
 */
export function parseNessusCsv(csvContent: string): ParsedVulnerability[] {
  const results: ParsedVulnerability[] = []
  const lines = csvContent.split("\n")
  if (lines.length < 2) return results

  for (let i = 1; i < lines.length; i++) {
    const cols = lines[i].split(",").map(c => c.replace(/^"|"$/g, "").trim())
    if (cols.length >= 7) {
      results.push({
        id: cols[0] || `nessus-${i}`,
        severity: (cols[3] || "info").toLowerCase() as any,
        target: cols[4] || "unknown",
        title: cols[5] || "Nessus Plugin Match",
        description: cols[6] || "",
      })
    }
  }

  return results
}

export interface ParsedEndpoint {
  path:    string
  status:  number
  size?:   number
  method:  string
}

/**
 * Parses Gobuster dir output into structured endpoint list.
 * Handles both standard and `--no-progress` formats:
 *   /admin (Status: 200) [Size: 1234]
 *   /.git/ (Status: 301) [Size: 0] [--> /.git//]
 */
export function parseGobusterOutput(output: string): ParsedEndpoint[] {
  const results: ParsedEndpoint[] = []
  for (const line of output.split("\n")) {
    const m = line.trim().match(/^(\/?[^\s]+)[\s\t]+\(Status:\s*(\d+)\)(?:\s+\[Size:\s*(\d+)\])?/)
    if (!m) continue
    const rawPath = m[1]!
    if (rawPath.startsWith("==") || rawPath.startsWith("[+]") || rawPath.startsWith("Finished")) continue
    const path = rawPath.startsWith("/") ? rawPath : "/" + rawPath
    results.push({
      path,
      status: parseInt(m[2]!, 10),
      size:   m[3] ? parseInt(m[3], 10) : undefined,
      method: "GET",
    })
  }
  return results
}

export function parse(format: "nmap" | "masscan" | "nuclei" | "nessus" | "gobuster", content: string): any {
  switch (format) {
    case "masscan":  return parseMasscanJson(content)
    case "nuclei":   return parseNucleiJson(content)
    case "nmap":     return parseNmapOutput(content)
    case "nessus":   return parseNessusCsv(content)
    case "gobuster": return parseGobusterOutput(content)
    default:         return []
  }
}

export default { parseMasscanJson, parseNucleiJson, parseNmapOutput, parseNessusCsv, parseGobusterOutput, parse }

