/**
 * Eighth-Pass Integration Test: Attack Surface Graph end-to-end validation
 *
 * Tests the full evidence chain WITHOUT the LLM:
 *   Nmap parser → Attack Surface Graph → Nuclei parser → Vuln ingestion
 *   → Adaptive next-step recommendations → Attack path analysis
 *
 * This is the "without LLM" capability baseline established in the Eighth-Pass audit.
 */
import { test } from "node:test"
import assert from "node:assert"
import { readFileSync, readdirSync } from "node:fs"
import { AttackSurfaceGraph } from "../src/attack_surface.ts"
import { parseNmapOutput, parseNucleiJson } from "../src/scanner_parsers.ts"

const NMAP_REAL_OUTPUT = `
Starting Nmap 7.94 ( https://nmap.org )
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 7.6p1 Ubuntu (Ubuntu Linux; protocol 2.0)
80/tcp   open  http     Apache httpd 2.4.29 ((Ubuntu))
3306/tcp open  mysql    MySQL 5.7.42
8080/tcp open  http     Apache Tomcat 9.0.37
`

const NUCLEI_REAL_OUTPUT = `{"template-id":"apache-log4j-rce","info":{"name":"Log4j RCE","severity":"critical","description":"Log4Shell CVE-2021-44228"},"matched-at":"http://192.168.1.100:8080/"}
{"template-id":"mysql-empty-password","info":{"name":"MySQL Empty Password","severity":"high","description":"MySQL root with no password"},"matched-at":"http://192.168.1.100:3306/"}`

test("Attack Surface Graph — Full Evidence Chain (No LLM Required)", async (t) => {

  await t.test("Stage 1: Nmap parse → asset + service ingestion", () => {
    const graph = new AttackSurfaceGraph("192.168.1.100")
    const ev = graph.makeEvidence("nmap", "nmap -sV 192.168.1.100", NMAP_REAL_OUTPUT, 1230)
    const ports = parseNmapOutput(NMAP_REAL_OUTPUT)

    assert.ok(ports.length >= 4, `Expected ≥4 ports, got ${ports.length}`)
    assert.strictEqual(ports.find(p => p.port === 22)?.service, "ssh")
    assert.strictEqual(ports.find(p => p.port === 3306)?.service, "mysql")

    const added = graph.ingestNmap("192.168.1.100", ports, ev)
    const summary = graph.summary()

    assert.strictEqual(summary.assets, 1)
    assert.ok(summary.services >= 4, `Expected ≥4 services, got ${summary.services}`)
    assert.ok(summary.openPorts.includes(80),   "Port 80 in graph")
    assert.ok(summary.openPorts.includes(3306), "Port 3306 in graph")
    assert.strictEqual(summary.toolCalls, 1)
  })

  await t.test("Stage 2: Nuclei parse → vuln ingestion with confidence 'suspected'", () => {
    const graph = new AttackSurfaceGraph("192.168.1.100")
    const nmapEv = graph.makeEvidence("nmap", "nmap -sV 192.168.1.100", NMAP_REAL_OUTPUT, 1230)
    graph.ingestNmap("192.168.1.100", parseNmapOutput(NMAP_REAL_OUTPUT), nmapEv)

    const nucleiEv = graph.makeEvidence("nuclei", "nuclei -u http://192.168.1.100:8080 -json", NUCLEI_REAL_OUTPUT, 3400)
    const vulns = parseNucleiJson(NUCLEI_REAL_OUTPUT)
    const added = graph.ingestNuclei("192.168.1.100", vulns, nucleiEv)

    assert.strictEqual(added.length, 2)
    assert.strictEqual(added[0].confidence, "suspected", "New findings start as 'suspected'")
    assert.strictEqual(added[0].capLevel, 2, "Nuclei findings are Level 2 (Detection)")

    const summary = graph.summary()
    assert.strictEqual(summary.vulns.suspected, 2, "2 suspected vulns")
    assert.strictEqual(summary.vulns.confirmed, 0, "0 confirmed until validated")
  })

  await t.test("Stage 3: Adaptive next-step recommendations (deterministic, no LLM)", () => {
    const graph = new AttackSurfaceGraph("192.168.1.100")
    const ev = graph.makeEvidence("nmap", "nmap -sV 192.168.1.100", NMAP_REAL_OUTPUT, 1230)
    graph.ingestNmap("192.168.1.100", parseNmapOutput(NMAP_REAL_OUTPUT), ev)

    const recs = graph.recommendNextActions("192.168.1.100")

    assert.ok(recs.length > 0, "Recommendations generated")
    const tools = recs.map(r => r.tool)
    assert.ok(tools.includes("gobuster"), "Gobuster recommended for HTTP service")
    assert.ok(tools.includes("nuclei"),   "Nuclei recommended for HTTP service")
    assert.ok(tools.includes("nmap"),     "Nmap recommended for database service")

    // Confirm the MySQL recommendation is contextualized to the actual discovered port
    const mysqlRec = recs.find(r => r.command.includes("3306"))
    assert.ok(mysqlRec, "MySQL-specific recommendation targets port 3306")
  })

  await t.test("Stage 4: Validation promotes confidence confirmed/false_positive", () => {
    const graph = new AttackSurfaceGraph("192.168.1.100")
    const nmapEv = graph.makeEvidence("nmap", "nmap -sV 192.168.1.100", NMAP_REAL_OUTPUT, 1230)
    graph.ingestNmap("192.168.1.100", parseNmapOutput(NMAP_REAL_OUTPUT), nmapEv)
    const nucleiEv = graph.makeEvidence("nuclei", "nuclei -u http://192.168.1.100:8080 -json", NUCLEI_REAL_OUTPUT, 3400)
    const vulns = parseNucleiJson(NUCLEI_REAL_OUTPUT)
    graph.ingestNuclei("192.168.1.100", vulns, nucleiEv)

    const validationEv = graph.makeEvidence(
      "curl",
      "curl -sv http://192.168.1.100:8080/ 2>&1",
      "HTTP/1.1 200 OK\nApache Tomcat/9.0.37",
      250
    )
    const result = graph.validateFinding("192.168.1.100", 8080, "apache-log4j-rce", validationEv, true)

    assert.ok(result, "Validation found the vuln node")
    assert.strictEqual(result.confidence, "confirmed")
    assert.strictEqual(result.capLevel, 3)
    assert.ok(result.validatedAt, "Validation timestamp recorded")

    const summary = graph.summary()
    assert.strictEqual(summary.vulns.confirmed, 1, "1 confirmed vuln after validation")
  })

  await t.test("Stage 5: Attack-path analysis across confirmed findings", () => {
    const graph = new AttackSurfaceGraph("192.168.1.100")
    const nmapEv = graph.makeEvidence("nmap", "nmap -sV 192.168.1.100", NMAP_REAL_OUTPUT, 1230)
    graph.ingestNmap("192.168.1.100", parseNmapOutput(NMAP_REAL_OUTPUT), nmapEv)
    const nucleiEv = graph.makeEvidence("nuclei", "nuclei -json", NUCLEI_REAL_OUTPUT, 3400)
    graph.ingestNuclei("192.168.1.100", parseNucleiJson(NUCLEI_REAL_OUTPUT), nucleiEv)

    const paths = graph.analyzeAttackPaths()
    assert.ok(paths.length > 0, "Attack paths identified")

    const critical = paths.find(p => p.severity === "critical" || p.severity === "high")
    assert.ok(critical, "At least one critical/high attack path found")
  })

  await t.test("Stage 6: Session persistence and reload", () => {
    const graph = new AttackSurfaceGraph("192.168.1.100")
    const ev = graph.makeEvidence("nmap", "nmap -sV 192.168.1.100", NMAP_REAL_OUTPUT, 1230)
    graph.ingestNmap("192.168.1.100", parseNmapOutput(NMAP_REAL_OUTPUT), ev)

    const tmpDir = `/tmp/ourmine-test-${Date.now()}`
    graph.save(tmpDir)

    const files = readdirSync(tmpDir)
    assert.ok(files.length === 1, "One session file written")

    const saved = JSON.parse(readFileSync(`${tmpDir}/${files[0]}`, "utf8"))
    assert.strictEqual(saved.target, "192.168.1.100")
    assert.ok(saved.services >= 4, `Saved graph has ≥4 services, got ${saved.services}`)
  })
})
