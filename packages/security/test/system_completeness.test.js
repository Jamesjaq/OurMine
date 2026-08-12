/**
 * ARES system completeness — playbook modules, SCADA actions, institutional live I/O.
 */
import { describe, test } from "node:test"
import assert from "node:assert/strict"
import * as fs from "node:fs"
import * as path from "node:path"
import { fileURLToPath } from "node:url"
import {
  resolveExecutableModule,
  findUnresolvedModules,
  MCP_SCADA_ACTIONS,
  scadaActionImplemented,
  MCP_FIRMWARE_ACTIONS,
  firmwareActionImplemented,
  EXTERNAL_MODULES_BY_DESIGN,
} from "../src/module_registry.ts"
import { bridgedToolNames } from "../src/module_bridge.ts"
import { AGENT_TOOL_NAMES } from "../src/agent_tools.ts"
import { loadAptPlaybookMappings, loadMitreTechniques } from "../src/apt_intel_feed.ts"
import {
  detectInstitutionalSector,
  modulesForSector,
  reconInstitutionalSector,
  probeSectorPorts,
  allInstitutionalSectors,
} from "../src/institutional_hints.ts"
import { executeScadaAction } from "../src/iot_scada.ts"
import { actorModuleMap } from "../src/intel_autonomous.ts"

const INTEL_DIR = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../data/intel",
)

function collectPlaybookModules() {
  const mappings = loadAptPlaybookMappings()
  const mods = new Set()
  for (const m of Object.values(mappings)) {
    for (const mod of m.modules ?? []) mods.add(mod)
  }
  for (const t of loadMitreTechniques()) {
    for (const mod of t.modules ?? []) mods.add(mod)
  }
  const sectors = JSON.parse(
    fs.readFileSync(path.join(INTEL_DIR, "institutional_sectors.json"), "utf8"),
  )
  for (const def of Object.values(sectors.sectors)) {
    for (const mod of def.modules ?? []) mods.add(mod)
  }
  return [...mods].sort()
}

describe("system_completeness", () => {
  test("playbook + intel modules resolve to bridge, agent, MCP, or external-by-design", () => {
    const all = collectPlaybookModules()
    const unresolved = findUnresolvedModules(all)
    const external = all.filter((m) => EXTERNAL_MODULES_BY_DESIGN.has(m))
    const resolved = all.filter((m) => resolveExecutableModule(m).kind !== "unresolved")

    assert.ok(all.length >= 40, `expected rich module catalog, got ${all.length}`)
    assert.ok(
      resolved.length + external.length >= all.length - 3,
      `unresolved playbook modules: ${unresolved.join(", ")}`,
    )
    assert.ok(!unresolved.includes("live_recon"))
    assert.ok(!unresolved.includes("recon"))
  })

  test("bridged MODULE_BRIDGE keys are registered", () => {
    const bridge = bridgedToolNames()
    assert.ok(bridge.length >= 80)
    assert.ok(bridge.includes("ares_autopilot"))
    assert.ok(bridge.includes("iot_scada"))
    assert.ok(bridge.includes("institutional_recon"))
  })

  test("agent tool registry covers playbook agent keys", () => {
    const agentSet = new Set(AGENT_TOOL_NAMES)
    for (const a of [
      "live_recon", "dev_target", "postex_harvest", "evilginx_lab", "idp_audit",
      "cloud_token", "ransomware_assess", "social_eng_assess", "nuclei_scan",
    ]) {
      assert.ok(agentSet.has(a), `missing agent tool: ${a}`)
    }
  })

  test("ares_iot_scada MCP actions are implemented in executeScadaAction", () => {
    for (const action of MCP_SCADA_ACTIONS) {
      assert.ok(scadaActionImplemented(action), `SCADA action not implemented: ${action}`)
    }
  })

  test("ares_firmware MCP actions are implemented in executeFirmwareAction", () => {
    for (const action of MCP_FIRMWARE_ACTIONS) {
      assert.ok(firmwareActionImplemented(action), `firmware action not implemented: ${action}`)
    }
  })

  test("executeScadaAction dry-run rejects live-only path explicitly", async () => {
    const r = await executeScadaAction(
      { host: "127.0.0.1", protocol: "modbus", action: "read" },
      { live: false },
    )
    assert.equal(r.dryRun, true)
    assert.ok(r.error?.includes("live"))
  })

  test("institutional sector modules are executable", () => {
    for (const sector of allInstitutionalSectors()) {
      const mods = modulesForSector(sector)
      assert.ok(mods.length >= 2, `${sector} should have module hints`)
      const bad = findUnresolvedModules(mods)
      assert.equal(bad.length, 0, `${sector} unresolved: ${bad.join(", ")}`)
    }
  })

  test("institutional recon live path performs TCP probe I/O", async () => {
    const sector = detectInstitutionalSector("hl7 dicom pacs hospital", "10.255.255.1")
    assert.equal(sector, "healthcare")
    const probe = await probeSectorPorts("127.0.0.1", [{ port: 65533, protocol: "tcp", service: "test", note: "test" }])
    assert.equal(probe.probed, 1)
    const live = await reconInstitutionalSector(sector, "127.0.0.1", { live: true })
    assert.equal(live.dryRun, false)
    assert.ok(live.findings.some((f) => f.id.includes("live")))
  })

  test("intel_autonomous actorModuleMap entries resolve", () => {
    const map = actorModuleMap()
    assert.ok(Object.keys(map).length >= 10)
    for (const [actor, { modules }] of Object.entries(map)) {
      const bad = findUnresolvedModules(modules)
      assert.equal(bad.length, 0, `${actor} unresolved modules: ${bad.join(", ")}`)
    }
  })

  test("module alias ares_recon maps to recon", () => {
    const r = resolveExecutableModule("ares_recon")
    assert.equal(r.kind, "agent")
    assert.equal(r.resolved, "recon")
  })

  test("apt_playbook_infra infra + fallback keys resolve via MODULE_ALIASES", () => {
    const infraPath = path.join(INTEL_DIR, "apt_playbook_infra.json")
    const profiles = JSON.parse(fs.readFileSync(infraPath, "utf8"))
    const keys = new Set()
    for (const p of profiles) {
      for (const k of p.infra ?? []) keys.add(k)
      for (const k of p.fallbackChain ?? []) keys.add(k)
    }
    const gapFixKeys = [
      "backup_discovery", "cicd_token", "cloud_lotc", "covert_c2", "dead_drop_dns_txt",
      "domain_front_cdn", "edge_implant", "exfil_staging", "mfa_fatigue", "npm_typosquat",
      "redirector_vps", "tor_payment", "vishing_playbook",
    ]
    for (const k of gapFixKeys) assert.ok(keys.has(k), `apt_playbook_infra fixture missing ${k}`)
    const bad = findUnresolvedModules([...keys])
    assert.equal(bad.length, 0, `apt_playbook_infra unresolved: ${bad.join(", ")}`)
    for (const k of gapFixKeys) {
      const r = resolveExecutableModule(k)
      assert.notEqual(r.kind, "unresolved", `${k} → ${r.resolved ?? r.kind}`)
      assert.ok(["bridge", "agent", "mcp"].includes(r.kind), `${k} kind=${r.kind}`)
    }
    assert.equal(resolveExecutableModule("voip_vishing").kind, "bridge")
    assert.equal(resolveExecutableModule("mfa_fatigue").resolved, "identity_playbooks")
  })

  test("completeness score baseline >= 7/10", () => {
    const all = collectPlaybookModules()
    const unresolved = findUnresolvedModules(all)
    const score = Math.round(((all.length - unresolved.length) / all.length) * 10)
    assert.ok(score >= 7, `completeness score ${score}/10; unresolved: ${unresolved.join(", ")}`)
  })

  test("intel catalog gates — profiles, ransomware, MITRE", () => {
    const aptPath = path.join(INTEL_DIR, "apt_profiles.json")
    const aptRaw = JSON.parse(fs.readFileSync(aptPath, "utf8"))
    const profiles = Array.isArray(aptRaw) ? aptRaw : (aptRaw.profiles ?? Object.values(aptRaw).filter((p) => p && typeof p === "object" && "id" in p))
    assert.ok(profiles.length >= 50, `APT profiles ${profiles.length} < 50`)

    const ransom = JSON.parse(fs.readFileSync(path.join(INTEL_DIR, "ransomware_groups.json"), "utf8"))
    const groups = Array.isArray(ransom) ? ransom : (ransom.groups ?? [])
    assert.ok(groups.length >= 18, `ransomware groups ${groups.length} < 18`)

    const mitre = loadMitreTechniques()
    assert.ok(mitre.length >= 200, `MITRE techniques ${mitre.length} < 200`)

    const mappings = loadAptPlaybookMappings()
    const playbookModCount = Object.values(mappings).reduce((n, m) => n + (m.modules?.length ?? 0), 0)
    assert.ok(playbookModCount >= 80, `playbook module refs ${playbookModCount} < 80`)
  })
})
