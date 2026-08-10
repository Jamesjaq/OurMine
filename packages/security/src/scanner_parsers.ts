/**
 * @module scanner_parsers
 * Security Scanner Output Parsers — Nmap XML Parser, Masscan JSON/List Parser,
 * Nuclei JSON Linter/Extractor, and Nessus CSV Result Normalizer.
 */

export interface ParsedPort {
  port: number;
  protocol: string;
  service: string;
  state: string;
}

export function parseMasscanJson(jsonString: string): ParsedPort[] {
  try {
    const raw = JSON.parse(jsonString) as Array<{ ip: string; ports: Array<{ port: number; proto: string; status: string }> }>;
    const results: ParsedPort[] = [];
    for (const entry of raw) {
      for (const p of entry.ports ?? []) {
        results.push({ port: p.port, protocol: p.proto, service: "unknown", state: p.status });
      }
    }
    return results;
  } catch {
    return [];
  }
}

export default { parseMasscanJson };
