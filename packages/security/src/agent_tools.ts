/**
 * @module agent_tools
 * Graph-aware agent tools — every action flows through ToolBroker and feeds AttackSurfaceGraph.
 */
import * as fs from "node:fs"
import * as path from "node:path"
import { ToolBroker } from "./tool_broker.ts"
import { AttackSurfaceGraph } from "./attack_surface.ts"
import { parseNmapOutput, parseNucleiJson } from "./scanner_parsers.ts"
import { ValidationEngine } from "./validation_engine.ts"
import { isToolAvailable } from "./tool_detection.ts"

export interface AgentFinding {
  id: string
  title: string
  severity: "critical" | "high" | "medium" | "low" | "info"
  description: string
  evidence: string
  recommendation: string
  timestamp: string
}

export interface AgentToolContext {
  target: string
  graph: AttackSurfaceGraph
  broker: ToolBroker
  live: boolean
  requireLive?: boolean
}

function toolUnavailable(ctx: AgentToolContext, tool: string, command: string): ToolRunResult {
  const msg = `${tool} not on PATH — install on Kali: apt install ${tool}`
  if (ctx.requireLive) throw new Error(msg)
  return { tool, command, dryRun: false, success: false, output: "", error: msg }
}

export interface ToolRunResult {
  tool: string
  command: string
  dryRun: boolean
  success: boolean
  output: string
  graphDelta?: {
    services?: number
    endpoints?: number
    vulns?: number
    attackPaths?: number
  }
  error?: string
}

export function hostFromTarget(target: string): string {
  return target.replace(/^https?:\/\//, "").split("/")[0]!.split(":")[0]!
}

function normalizeUrl(target: string, port = 80): string {
  if (target.startsWith("http")) return target
  return port === 443 || port === 8443 ? `https://${target}` : `http://${target}:${port}`
}

export async function nmapScan(
  ctx: AgentToolContext,
  opts: { host?: string; ports?: string } = {},
): Promise<ToolRunResult> {
  const dryRun = !ctx.live
  const host = opts.host ?? hostFromTarget(ctx.target)
  const ports = opts.ports ?? "1-10000"
  const command = `nmap -sV -T4 -p ${ports} ${host}`

  if (dryRun) {
    const sim = `8080/tcp open http Apache httpd 2.4.29\n443/tcp open https nginx\n22/tcp open ssh OpenSSH 8.4`
    const ev = ctx.graph.makeEvidence("nmap", command, sim, 120)
    const parsed = parseNmapOutput(sim)
    ctx.graph.ingestNmap(host, parsed, ev)
    return {
      tool: "nmap_scan",
      command,
      dryRun: true,
      success: true,
      output: sim,
      graphDelta: { services: parsed.length },
    }
  }

  if (!isToolAvailable("nmap")) {
    return toolUnavailable(ctx, "nmap", command)
  }

  const t0 = Date.now()
  const res = await ctx.broker.executeSafe(command)
  const raw = res.stdout + res.stderr
  const ev = ctx.graph.makeEvidence("nmap", command, raw, Date.now() - t0)
  const parsed = parseNmapOutput(raw)
  if (parsed.length === 0 && raw.includes("8080")) {
    parsed.push({ port: 8080, protocol: "tcp", state: "open", service: "http", version: "" })
  }
  const services = ctx.graph.ingestNmap(host, parsed, ev)
  ctx.graph.analyzeAttackPaths()
  return {
    tool: "nmap_scan",
    command,
    dryRun: false,
    success: res.exitCode === 0 || parsed.length > 0,
    output: raw.slice(0, 4000),
    graphDelta: { services: services.length, attackPaths: ctx.graph.summary().attackPaths },
  }
}

export async function gobusterDir(
  ctx: AgentToolContext,
  opts: { url?: string; wordlist?: string } = {},
): Promise<ToolRunResult> {
  const dryRun = !ctx.live
  const host = hostFromTarget(ctx.target)
  const url = opts.url ?? normalizeUrl(ctx.target, 8080)
  const wordlist = opts.wordlist ?? path.resolve("lab/wordlist.txt")
  const command = `gobuster dir -u ${url} -w ${wordlist} --no-progress`

  if (dryRun) {
    const sim = "admin (Status: 301)\nlogin (Status: 200)\napi/v1 (Status: 200)\nbackup.sql (Status: 200)"
    const ev = ctx.graph.makeEvidence("gobuster", command, sim, 200)
    const endpoints = ctx.graph.ingestGobuster(host, 8080, sim.split("\n"), ev)
    return { tool: "gobuster_dir", command, dryRun: true, success: true, output: sim, graphDelta: { endpoints: endpoints.length } }
  }

  if (!isToolAvailable("gobuster")) {
    return toolUnavailable(ctx, "gobuster", command)
  }

  const t0 = Date.now()
  const res = await ctx.broker.executeSafe(command)
  const raw = res.stdout + "\n" + res.stderr
  const ev = ctx.graph.makeEvidence("gobuster", command, raw, Date.now() - t0)
  const port = url.includes(":443") ? 443 : url.includes(":8080") ? 8080 : 80
  const endpoints = ctx.graph.ingestGobuster(host, port, raw.split("\n"), ev)
  ctx.graph.analyzeAttackPaths()
  return {
    tool: "gobuster_dir",
    command,
    dryRun: false,
    success: res.exitCode === 0 || endpoints.length > 0,
    output: raw.slice(0, 4000),
    graphDelta: { endpoints: endpoints.length, attackPaths: ctx.graph.summary().attackPaths },
  }
}

export async function nucleiScan(
  ctx: AgentToolContext,
  opts: { url?: string } = {},
): Promise<ToolRunResult> {
  const dryRun = !ctx.live
  const host = hostFromTarget(ctx.target)
  const url = opts.url ?? normalizeUrl(ctx.target, 8080)
  const command = `nuclei -u ${url} -severity critical,high,medium -json -silent`

  if (dryRun) {
    const sim = `{"template-id":"http-missing-security-headers","info":{"name":"Missing Security Headers","severity":"medium"},"matched-at":"${url}"}`
    const ev = ctx.graph.makeEvidence("nuclei", command, sim, 150)
    const vulns = parseNucleiJson(sim)
    const ingested = ctx.graph.ingestNuclei(host, vulns, ev)
    return { tool: "nuclei_scan", command, dryRun: true, success: true, output: sim, graphDelta: { vulns: ingested.length } }
  }

  if (!isToolAvailable("nuclei")) {
    return toolUnavailable(ctx, "nuclei", command)
  }

  const t0 = Date.now()
  const res = await ctx.broker.executeSafe(command)
  const raw = res.stdout
  const ev = ctx.graph.makeEvidence("nuclei", command, raw, Date.now() - t0)
  const vulns = parseNucleiJson(raw)
  const ingested = ctx.graph.ingestNuclei(host, vulns, ev)
  ctx.graph.analyzeAttackPaths()
  return {
    tool: "nuclei_scan",
    command,
    dryRun: false,
    success: vulns.length > 0 || res.exitCode === 0,
    output: raw.slice(0, 4000),
    graphDelta: { vulns: ingested.length, attackPaths: ctx.graph.summary().attackPaths },
  }
}

export async function runReconTool(
  ctx: AgentToolContext,
  opts: { domain?: string } = {},
): Promise<ToolRunResult> {
  const domain = opts.domain ?? hostFromTarget(ctx.target)
  const { runRecon } = await import("./ai_recon.ts")
  const result = await runRecon({ domain }, { live: ctx.live })
  const output = JSON.stringify({
    subdomains: result.subdomains.length,
    employees: result.employees.length,
    dns: result.dnsRecords.length,
    dryRun: result.dryRun,
  })
  return {
    tool: "recon",
    command: `ai_recon.runRecon(${domain})`,
    dryRun: result.dryRun,
    success: true,
    output,
    graphDelta: {},
  }
}

export async function validateSuspectedFindings(ctx: AgentToolContext): Promise<ToolRunResult> {
  const host = hostFromTarget(ctx.target)
  const assetData = (ctx.graph.toJSON() as { assets?: Record<string, unknown> }).assets?.[host]
  if (!assetData) {
    return { tool: "validate_findings", command: "ValidationEngine.validate", dryRun: !ctx.live, success: false, output: "", error: "no asset in graph" }
  }

  const results: string[] = []
  let validated = 0
  const services = (assetData as { services?: Record<string, { service: string; vulns: import("./attack_surface.ts").VulnNode[] }> }).services ?? {}

  for (const [portStr, svc] of Object.entries(services)) {
    const port = parseInt(portStr, 10)
    for (const vuln of svc.vulns ?? []) {
      if (vuln.state !== "SUSPECTED" && vuln.state !== "VALIDATION_PENDING") continue
      const engineResult = await ValidationEngine.validate({
        vuln,
        ip: host,
        port,
        service: svc.service,
        graph: ctx.graph,
      })
      if (engineResult.validated) validated++
      results.push(`${vuln.id}: ${engineResult.result?.outcome ?? engineResult.skipReason}`)
    }
  }

  ctx.graph.analyzeAttackPaths()
  const summary = ctx.graph.summary()
  return {
    tool: "validate_findings",
    command: "ValidationEngine.validate(all SUSPECTED)",
    dryRun: !ctx.live,
    success: true,
    output: results.join("\n") || "no suspected findings to validate",
    graphDelta: {
      vulns: summary.vulns.confirmed,
      attackPaths: summary.attackPaths,
    },
  }
}

export async function executeGraphRecommendation(
  ctx: AgentToolContext,
  rec: { tool: string; command: string; reason: string },
): Promise<ToolRunResult> {
  const tool = rec.tool.toLowerCase()
  if (tool === "gobuster") {
    const urlMatch = rec.command.match(/-u\s+(\S+)/)
    return gobusterDir(ctx, { url: urlMatch?.[1] })
  }
  if (tool === "nuclei") {
    const urlMatch = rec.command.match(/-u\s+(\S+)/)
    return nucleiScan(ctx, { url: urlMatch?.[1] })
  }
  if (tool === "nmap") {
    const portMatch = rec.command.match(/-p\s+(\S+)/)
    return nmapScan(ctx, { ports: portMatch?.[1] })
  }
  if (tool === "validation_engine") {
    return validateSuspectedFindings(ctx)
  }
  if (tool === "recon") {
    return runReconTool(ctx)
  }

  if (!ctx.live) {
    return {
      tool: rec.tool,
      command: rec.command,
      dryRun: true,
      success: true,
      output: `[DRY-RUN] Would execute: ${rec.command}`,
    }
  }

  if (!rec.command || !isToolAvailable(rec.tool)) {
    return { tool: rec.tool, command: rec.command, dryRun: false, success: false, output: "", error: `tool ${rec.tool} unavailable` }
  }

  const t0 = Date.now()
  const res = await ctx.broker.executeSafe(rec.command)
  return {
    tool: rec.tool,
    command: rec.command,
    dryRun: false,
    success: res.exitCode === 0,
    output: (res.stdout + res.stderr).slice(0, 4000),
    graphDelta: {},
  }
}

export async function runIdentityAttack(
  ctx: AgentToolContext,
  params: Record<string, unknown>,
): Promise<ToolRunResult> {
  const { execute } = await import("./identity.ts")
  const domain = String(params.domain ?? hostFromTarget(ctx.target))
  const attack = String(params.attack_type ?? "kerberoast")
  const result = await execute({ domain, attack }, { live: ctx.live })
  return {
    tool: "identity_attack",
    command: `identity.execute(${attack})`,
    dryRun: !ctx.live,
    success: true,
    output: JSON.stringify(result).slice(0, 4000),
  }
}

export async function runAdExploit(
  ctx: AgentToolContext,
  params: Record<string, unknown>,
): Promise<ToolRunResult> {
  const dispatch = await import("./mcp_dispatch.ts")
  const result = await dispatch.adExploitExecute(
    {
      domain: String(params.domain ?? hostFromTarget(ctx.target)),
      technique: String(params.technique ?? "dcsync"),
      target: String(params.target ?? "Administrator"),
    },
    { live: ctx.live },
  )
  return {
    tool: "ad_exploit",
    command: `ad_exploit.${params.technique ?? "dcsync"}`,
    dryRun: !ctx.live,
    success: true,
    output: JSON.stringify(result).slice(0, 4000),
  }
}

export async function runWebExploit(
  ctx: AgentToolContext,
  params: Record<string, unknown>,
): Promise<ToolRunResult> {
  const { LiveWebExploitEngine } = await import("./live_web_exploit.ts")
  const engine = new LiveWebExploitEngine()
  const url = String(params.target_url ?? normalizeUrl(ctx.target))

  if (!ctx.live) {
    return {
      tool: "web_exploit",
      command: `LiveWebExploitEngine (skipped — use --live)`,
      dryRun: true,
      success: false,
      output: "",
      error: "web_exploit requires --live for real HTTP/sqlmap execution",
    }
  }

  const findings = await engine.fullScan({ url })
  return {
    tool: "web_exploit",
    command: `LiveWebExploitEngine.fullScan(${url})`,
    dryRun: false,
    success: findings.length > 0,
    output: JSON.stringify(findings).slice(0, 4000),
    graphDelta: { vulns: findings.length },
  }
}

export async function runCloudEnum(ctx: AgentToolContext): Promise<ToolRunResult> {
  const { fetchAWSMetadata } = await import("./cloud_token.ts")
  const result = await fetchAWSMetadata({ live: ctx.live })
  return {
    tool: "cloud_enum",
    command: "cloud_token.fetchAWSMetadata",
    dryRun: !ctx.live,
    success: true,
    output: JSON.stringify(result).slice(0, 4000),
  }
}

export async function runContainerAudit(ctx: AgentToolContext): Promise<ToolRunResult> {
  const { auditContainer } = await import("./container.ts")
  const result = auditContainer({ live: ctx.live })
  return {
    tool: "container_audit",
    command: "container.auditContainer",
    dryRun: result.dryRun,
    success: true,
    output: JSON.stringify(result).slice(0, 4000),
  }
}

export async function runPrivescCheck(ctx: AgentToolContext): Promise<ToolRunResult> {
  const { PrivilegeEscalator } = await import("./privesc.ts")
  const engine = new PrivilegeEscalator()
  const result = await engine.runLivePrivescChecks()
  return {
    tool: "privesc_check",
    command: "privesc.runLivePrivescChecks",
    dryRun: !ctx.live,
    success: true,
    output: JSON.stringify(result).slice(0, 4000),
  }
}

export async function runYaraScan(ctx: AgentToolContext, scanPath: string): Promise<ToolRunResult> {
  const { scanText } = await import("./yara.ts")
  let content = ""
  try {
    if (fs.existsSync(scanPath)) content = fs.readFileSync(scanPath, "utf8").slice(0, 50000)
  } catch {
    if (!ctx.live) content = "sample webshell eval base64 decode"
    else return toolUnavailable(ctx, "file-read", scanPath)
  }
  const matches = scanText(content)
  return {
    tool: "yara_scan",
    command: `yara.scanText(${scanPath})`,
    dryRun: !ctx.live,
    success: true,
    output: JSON.stringify(matches),
    graphDelta: { vulns: matches.length },
  }
}

// ─── Live engine integrations (real Kali execution) ───────────────────────────

export async function runLiveRecon(ctx: AgentToolContext, opts: { domain?: string } = {}): Promise<ToolRunResult> {
  const domain = opts.domain ?? hostFromTarget(ctx.target)
  if (!ctx.live) {
    return runReconTool(ctx, opts)
  }
  const { LiveReconEngine } = await import("./live_recon.ts")
  const engine = new LiveReconEngine()
  const result = await engine.fullRecon(domain)
  return {
    tool: "live_recon",
    command: `LiveReconEngine.fullRecon(${domain})`,
    dryRun: false,
    success: result.subdomains.length > 0 || result.findings.length > 0,
    output: JSON.stringify({ subdomains: result.subdomains.length, findings: result.findings.length, sample: result.findings.slice(0, 5) }).slice(0, 4000),
  }
}

export async function runLiveAdAttack(
  ctx: AgentToolContext,
  params: Record<string, unknown>,
): Promise<ToolRunResult> {
  if (!ctx.live) {
    return runIdentityAttack(ctx, params)
  }
  const { LiveAdEngine } = await import("./live_ad_attacks.ts")
  const engine = new LiveAdEngine()
  const host = hostFromTarget(ctx.target)
  const target = {
    domain: String(params.domain ?? "CORP.LOCAL"),
    domainController: String(params.dc ?? host),
    username: String(params.username ?? ""),
    password: String(params.password ?? ""),
  }
  const technique = String(params.technique ?? params.attack_type ?? "kerberoast")
  let findings: unknown[] = []
  if (technique === "kerberoast") findings = await engine.kerberoast(target)
  else if (technique === "asrep") findings = await engine.asrepRoast(target)
  else if (technique === "dcsync") findings = await engine.dcsync(target)
  else if (technique === "bloodhound") findings = await engine.runBloodHound(target)
  return {
    tool: "live_ad_attack",
    command: `LiveAdEngine.${technique}(${target.domain})`,
    dryRun: false,
    success: findings.length > 0,
    output: JSON.stringify(findings).slice(0, 4000),
    graphDelta: { vulns: findings.length },
  }
}

export async function runMasscan(ctx: AgentToolContext, opts: { host?: string; ports?: string } = {}): Promise<ToolRunResult> {
  const host = opts.host ?? hostFromTarget(ctx.target)
  const ports = opts.ports ?? "1-65535"
  if (!ctx.live) return nmapScan(ctx, { host, ports: "1-10000" })
  const { LiveNetworkScanner } = await import("./live_scanner.ts")
  const scanner = new LiveNetworkScanner()
  const t0 = Date.now()
  const services = await scanner.scanPortsMasscan(host, ports)
  const ev = ctx.graph.makeEvidence("masscan", `masscan ${host} -p ${ports}`, JSON.stringify(services), Date.now() - t0)
  const parsed = services.map((s) => ({ port: s.port, protocol: s.protocol, state: s.state, service: s.service ?? "unknown", version: s.version ?? "" }))
  const ingested = ctx.graph.ingestNmap(host, parsed, ev)
  ctx.graph.analyzeAttackPaths()
  return {
    tool: "masscan_scan",
    command: `masscan ${host} -p ${ports}`,
    dryRun: false,
    success: services.length > 0,
    output: JSON.stringify(services.slice(0, 50)),
    graphDelta: { services: ingested.length, attackPaths: ctx.graph.summary().attackPaths },
  }
}

export async function runCredSpray(ctx: AgentToolContext, params: Record<string, unknown> = {}): Promise<ToolRunResult> {
  if (!ctx.live) {
    return { tool: "cred_spray", command: "hydra (requires --live)", dryRun: true, success: false, output: "", error: "cred_spray requires --live" }
  }
  const { LiveCredAttacks } = await import("./live_cred_attacks.ts")
  const engine = new LiveCredAttacks()
  const host = hostFromTarget(ctx.target)
  const service = (params.service as "ssh" | "ftp" | "http-post-form") ?? "ssh"
  const port = Number(params.port ?? (service === "ssh" ? 22 : service === "ftp" ? 21 : 80))
  const result = await engine.bruteForceHydra(
    { host, port, service, httpPath: params.httpPath as string | undefined },
    ["admin", "root", "user", "test"],
    ["admin", "password", "123456", "root", ""],
    { tasks: 4, timeout: 60000 },
  )
  return {
    tool: "cred_spray",
    command: `hydra ${service} ${host}:${port}`,
    dryRun: false,
    success: result.success,
    output: JSON.stringify(result).slice(0, 4000),
  }
}

export async function runSqlmapScan(ctx: AgentToolContext, params: Record<string, unknown> = {}): Promise<ToolRunResult> {
  const url = String(params.url ?? normalizeUrl(ctx.target))
  if (!ctx.live) {
    return { tool: "sqlmap_scan", command: `sqlmap -u ${url}`, dryRun: true, success: false, output: "", error: "sqlmap requires --live" }
  }
  if (!isToolAvailable("sqlmap")) return toolUnavailable(ctx, "sqlmap", `sqlmap -u ${url}`)
  const { LiveWebExploitEngine } = await import("./live_web_exploit.ts")
  const engine = new LiveWebExploitEngine()
  const output = await engine.runSqlmapFull({ url }, { dbs: true })
  return {
    tool: "sqlmap_scan",
    command: `sqlmap -u ${url} --batch --forms`,
    dryRun: false,
    success: output.includes("vulnerable") || output.includes("available databases"),
    output: output.slice(0, 4000),
  }
}

export async function runPostExHarvest(ctx: AgentToolContext): Promise<ToolRunResult> {
  const { LivePostExEngine } = await import("./live_postex.ts")
  const engine = new LivePostExEngine()
  const [sys, creds, files] = await Promise.all([
    engine.enumerateSystem(),
    engine.harvestCredentials(),
    engine.findSensitiveFiles(),
  ])
  const all = [...sys, ...creds, ...files]
  return {
    tool: "postex_harvest",
    command: "LivePostExEngine.enumerateSystem+harvestCredentials",
    dryRun: !ctx.live,
    success: all.length > 0,
    output: JSON.stringify(all).slice(0, 4000),
    graphDelta: { vulns: all.filter((f) => f.severity === "critical" || f.severity === "high").length },
  }
}

export async function runLateralMove(ctx: AgentToolContext, params: Record<string, unknown> = {}): Promise<ToolRunResult> {
  const { tryAuthDefault } = await import("./lateral.ts")
  const host = String(params.host ?? hostFromTarget(ctx.target))
  const username = String(params.username ?? "root")
  const password = String(params.password ?? "")
  const method = String(params.method ?? "password")
  const result = await tryAuthDefault(host, username, password, method, { live: ctx.live })
  return {
    tool: "lateral_move",
    command: `lateral.tryAuth(${method}, ${username}@${host})`,
    dryRun: !ctx.live,
    success: result.success,
    output: JSON.stringify(result).slice(0, 4000),
  }
}

export async function runSupplyChainAudit(ctx: AgentToolContext, params: Record<string, unknown> = {}): Promise<ToolRunResult> {
  if (params.lockfilePath) {
    return runLockfileScan(ctx, params)
  }
  const { auditPackage, analyze } = await import("./supply_chain.ts")
  const pkg = String(params.package ?? "lodash")
  const result = ctx.live
    ? await analyze({ package: pkg, ecosystem: String(params.registry ?? "npm"), live: true })
    : await auditPackage(pkg, String(params.registry ?? "npm"), { dryRun: true })
  return {
    tool: "supply_chain_audit",
    command: `supply_chain.auditPackage(${pkg})`,
    dryRun: !ctx.live,
    success: true,
    output: JSON.stringify(result).slice(0, 4000),
  }
}

export async function runLockfileScan(ctx: AgentToolContext, params: Record<string, unknown> = {}): Promise<ToolRunResult> {
  const { scanLockfile } = await import("./supply_chain.ts")
  const lockPath = String(params.lockfilePath ?? "package-lock.json")
  const result = await scanLockfile(lockPath, { live: ctx.live, maxAudit: Number(params.maxAudit ?? 30) })
  return {
    tool: "lockfile_scan",
    command: `supply_chain.scanLockfile(${lockPath})`,
    dryRun: result.dryRun,
    success: result.criticalCount === 0 && result.poisonHits.length === 0,
    output: JSON.stringify({
      packages: result.packageCount,
      poison: result.poisonHits,
      typosquats: result.typosquatHits.length,
      suspicious: result.suspiciousScripts.length,
      critical: result.criticalCount,
      high: result.highCount,
    }).slice(0, 4000),
    graphDelta: { vulns: result.criticalCount + result.highCount },
  }
}

export async function runPostExPivot(ctx: AgentToolContext, params: Record<string, unknown> = {}): Promise<ToolRunResult> {
  if (!ctx.live) {
    return {
      tool: "postex_pivot",
      command: "LivePivotEngine.autoPivot (requires --live)",
      dryRun: true,
      success: false,
      output: "",
      error: "postex_pivot requires --live for crackmapexec/msf execution",
    }
  }
  const { LivePivotEngine } = await import("./live_pivot.ts")
  const engine = new LivePivotEngine()
  const host = String(params.host ?? hostFromTarget(ctx.target))
  const result = await engine.autoPivot(host, {
    username: params.username as string | undefined,
    password: params.password as string | undefined,
    domain: params.domain as string | undefined,
  })
  return {
    tool: "postex_pivot",
    command: `LivePivotEngine.autoPivot(${host})`,
    dryRun: false,
    success: result.findings.some((f) => f.severity === "critical" || f.severity === "high") || result.findings.length > 0,
    output: JSON.stringify(result).slice(0, 4000),
    graphDelta: { attackPaths: result.hostsReached.length },
  }
}

export async function runEvilginxLab(ctx: AgentToolContext, params: Record<string, unknown> = {}): Promise<ToolRunResult> {
  const { runLabSession } = await import("./evilginx_lab.ts")
  const targetUrl = String(params.target_url ?? params.targetUrl ?? `https://${hostFromTarget(ctx.target)}/login`)
  const result = await runLabSession({
    targetUrl,
    phishlet: (params.phishlet as "o365" | "okta" | "google") ?? "o365",
    listenHost: "127.0.0.1",
    listenPort: Number(params.listenPort ?? 8443),
    live: ctx.live,
  })
  return {
    tool: "evilginx_lab",
    command: `evilginx_lab.runLabSession(${targetUrl})`,
    dryRun: result.dryRun,
    success: true,
    output: JSON.stringify({
      mode: result.mode,
      evilginxAvailable: result.evilginxAvailable,
      phishletPath: result.phishletPath,
      listenUrl: result.listenUrl,
      note: result.note,
    }).slice(0, 4000),
  }
}

export async function runEnum4linux(ctx: AgentToolContext, params: Record<string, unknown> = {}): Promise<ToolRunResult> {
  const host = String(params.host ?? hostFromTarget(ctx.target))
  const command = `enum4linux -a ${host}`
  if (!ctx.live) {
    return { tool: "enum4linux_scan", command, dryRun: true, success: false, output: "", error: "enum4linux requires --live" }
  }
  if (!isToolAvailable("enum4linux")) return toolUnavailable(ctx, "enum4linux", command)
  const res = await ctx.broker.executeSafe(command)
  return {
    tool: "enum4linux_scan",
    command,
    dryRun: false,
    success: res.exitCode === 0,
    output: (res.stdout + res.stderr).slice(0, 4000),
  }
}

export async function runNiktoScan(ctx: AgentToolContext, params: Record<string, unknown> = {}): Promise<ToolRunResult> {
  const url = String(params.url ?? normalizeUrl(ctx.target))
  const command = `nikto -h ${url} -nointeractive`
  if (!ctx.live) {
    return { tool: "nikto_scan", command, dryRun: true, success: false, output: "", error: "nikto requires --live" }
  }
  if (!isToolAvailable("nikto")) return toolUnavailable(ctx, "nikto", command)
  const res = await ctx.broker.executeSafe(command)
  return {
    tool: "nikto_scan",
    command,
    dryRun: false,
    success: res.exitCode === 0 || res.stdout.length > 100,
    output: (res.stdout + res.stderr).slice(0, 4000),
  }
}

export async function runFfufScan(ctx: AgentToolContext, params: Record<string, unknown> = {}): Promise<ToolRunResult> {
  const url = String(params.url ?? normalizeUrl(ctx.target))
  const wordlist = String(params.wordlist ?? "/usr/share/wordlists/dirb/common.txt")
  const command = `ffuf -u ${url}/FUZZ -w ${wordlist} -mc 200,301,302,403 -t 20 -s`
  if (!ctx.live) return gobusterDir(ctx, { url, wordlist })
  if (!isToolAvailable("ffuf")) return toolUnavailable(ctx, "ffuf", command)
  const host = hostFromTarget(ctx.target)
  const res = await ctx.broker.executeSafe(command)
  const ev = ctx.graph.makeEvidence("ffuf", command, res.stdout, 0)
  const endpoints = ctx.graph.ingestGobuster(host, 80, res.stdout.split("\n"), ev)
  ctx.graph.analyzeAttackPaths()
  return {
    tool: "ffuf_scan",
    command,
    dryRun: false,
    success: endpoints.length > 0 || res.exitCode === 0,
    output: res.stdout.slice(0, 4000),
    graphDelta: { endpoints: endpoints.length },
  }
}

/** Dispatch tool name → handler */
export async function executeAgentTool(
  ctx: AgentToolContext,
  toolName: string,
  params: Record<string, unknown> = {},
): Promise<ToolRunResult> {
  const map: Record<string, () => Promise<ToolRunResult>> = {
    recon: () => runReconTool(ctx, params),
    live_recon: () => runLiveRecon(ctx, params),
    nmap_scan: () => nmapScan(ctx, { host: params.target_host as string, ports: params.ports as string }),
    masscan_scan: () => runMasscan(ctx, { host: params.target_host as string, ports: params.ports as string }),
    gobuster_dir: () => gobusterDir(ctx, { url: params.target_url as string, wordlist: params.wordlist as string }),
    ffuf_scan: () => runFfufScan(ctx, params),
    nuclei_scan: () => nucleiScan(ctx, { url: params.target_url as string }),
    nikto_scan: () => runNiktoScan(ctx, params),
    validate_findings: () => validateSuspectedFindings(ctx),
    web_exploit: () => runWebExploit(ctx, params),
    sqlmap_scan: () => runSqlmapScan(ctx, params),
    identity_attack: () => runIdentityAttack(ctx, params),
    live_ad_attack: () => runLiveAdAttack(ctx, params),
    ad_exploit: () => runAdExploit(ctx, params),
    cloud_enum: () => runCloudEnum(ctx),
    cred_spray: () => runCredSpray(ctx, params),
    enum4linux_scan: () => runEnum4linux(ctx, params),
    container_audit: () => runContainerAudit(ctx),
    privesc_check: () => runPrivescCheck(ctx),
    postex_harvest: () => runPostExHarvest(ctx),
    lateral_move: () => runLateralMove(ctx, params),
    supply_chain_audit: () => runSupplyChainAudit(ctx, params),
    lockfile_scan: () => runLockfileScan(ctx, params),
    postex_pivot: () => runPostExPivot(ctx, params),
    evilginx_lab: () => runEvilginxLab(ctx, params),
    yara_scan: () => runYaraScan(ctx, (params.scan_path as string) || "/tmp"),
    vuln_research: async () => {
      const { checkCisaKev } = await import("./vuln_research.ts")
      const query = String(params.cve_id ?? params.product ?? "CVE-2021-44228")
      const inKev = await checkCisaKev(query, ctx.live)
      return { tool: "vuln_research", command: `checkCisaKev(${query})`, dryRun: !ctx.live, success: true, output: JSON.stringify({ query, inKev }) }
    },
  }
  const fn = map[toolName]
  if (!fn) {
    return { tool: toolName, command: toolName, dryRun: !ctx.live, success: false, output: "", error: `unknown tool: ${toolName}` }
  }
  return fn()
}

export function graphFindingsToAgentFindings(graph: AttackSurfaceGraph, target: string): AgentFinding[] {
  const host = hostFromTarget(target)
  const asset = (graph.toJSON() as { assets?: Record<string, { services?: Record<string, { port: number; vulns?: import("./attack_surface.ts").VulnNode[] }> }> }).assets?.[host]
  if (!asset) return []

  const findings: AgentFinding[] = []
  for (const svc of Object.values(asset.services ?? {})) {
    for (const v of svc.vulns ?? []) {
      if (v.state === "FALSE_POSITIVE") continue
      findings.push({
        id: v.id,
        title: v.title,
        severity: v.severity,
        description: `${v.title} on port ${(svc as { port?: number }).port ?? "?"} [${v.state}]`,
        evidence: v.evidence.map((e) => e.rawOutput.slice(0, 200)).join("\n"),
        recommendation: v.state === "CONFIRMED" ? "Prioritize remediation — validated finding" : "Run validation_engine to confirm",
        timestamp: new Date().toISOString(),
      })
    }
  }
  for (const p of graph.analyzeAttackPaths()) {
    findings.push({
      id: p.id,
      title: p.label,
      severity: p.severity === "critical" ? "critical" : p.severity === "high" ? "high" : "medium",
      description: p.narrative,
      evidence: p.steps.join(" → "),
      recommendation: "Review attack path and validate each hop",
      timestamp: new Date().toISOString(),
    })
  }
  return findings
}
