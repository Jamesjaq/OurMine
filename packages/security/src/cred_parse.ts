/**
 * @module cred_parse
 * Parse impacket secretsdump / DCSync output into typed AD credentials.
 */
export interface ParsedDumpAccount {
  domain: string
  username: string
  rid: string
  lmHash: string
  ntHash: string
  role: "krbtgt" | "dc_machine" | "user" | "service"
}

const NTHASH = /^[a-fA-F0-9]{32}$/
const DUMP_LINE = /^([^/\\]+)[/\\]([^:]+):(\d+):([a-fA-F0-9]{32}):([a-fA-F0-9]{32})/

function classify(username: string, rid: string): ParsedDumpAccount["role"] {
  const u = username.toLowerCase()
  if (u === "krbtgt") return "krbtgt"
  if (username.endsWith("$") && (/^dc/i.test(username) || rid === "502")) return "dc_machine"
  if (username.endsWith("$")) return "service"
  return "user"
}

export function parseSecretsdumpLine(line: string): ParsedDumpAccount | null {
  const trimmed = line.trim()
  if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith("[")) return null
  const m = trimmed.match(DUMP_LINE)
  if (!m) return null
  const [, domain, username, rid, lmHash, ntHash] = m
  if (!NTHASH.test(ntHash!)) return null
  return {
    domain: domain!,
    username: username!,
    rid: rid!,
    lmHash: lmHash!,
    ntHash: ntHash!,
    role: classify(username!, rid!),
  }
}

export function parseSecretsdumpOutput(output: string): ParsedDumpAccount[] {
  const seen = new Set<string>()
  const out: ParsedDumpAccount[] = []
  for (const line of output.split("\n")) {
    const acct = parseSecretsdumpLine(line)
    if (!acct) continue
    const key = `${acct.domain}/${acct.username}:${acct.ntHash}`
    if (seen.has(key)) continue
    seen.add(key)
    out.push(acct)
  }
  return out
}

export function extractDomainSid(output: string): string | undefined {
  const m = output.match(/Domain SID:\s*(S-1-5-21-[0-9-]+)/i)
    ?? output.match(/(S-1-5-21-\d+-\d+-\d+)/)
  return m?.[1]
}

export default { parseSecretsdumpLine, parseSecretsdumpOutput, extractDomainSid }
