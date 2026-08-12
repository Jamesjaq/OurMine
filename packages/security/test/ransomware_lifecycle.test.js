/**
 * Ransomware lifecycle corrections — ALPHV defunct, Play independent
 */
import { describe, test } from "node:test"
import assert from "node:assert/strict"
import * as fs from "node:fs"
import * as path from "node:path"
import { fileURLToPath } from "node:url"
import { resolveAptProfile } from "../src/apt_intel_feed.ts"
import { mapRansomTtps } from "../src/intel_autonomous.ts"

const INTEL = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../data/intel",
)

describe("ransomware_lifecycle", () => {
  test("ALPHV profile status is defunct", () => {
    const profiles = JSON.parse(fs.readFileSync(path.join(INTEL, "apt_profiles.json"), "utf8"))
    const alphv = profiles.find((p) => p.id === "alphv_blackcat")
    assert.ok(alphv)
    assert.equal(alphv.status, "defunct")
    assert.equal(alphv.successor, "play")
  })

  test("Play resolves independently from LockBit", () => {
    const play = resolveAptProfile("Play")
    assert.ok(play)
    assert.equal(play.id, "play")
    const lockbit = resolveAptProfile("LockBit")
    assert.ok(lockbit)
    assert.equal(lockbit.id, "lockbit")
    assert.notEqual(play.id, lockbit.id)
  })

  test("mapRansomTtps maps play group to play modules not lockbit", () => {
    const actions = mapRansomTtps([
      { group_name: "play", post_title: "Test victim" },
      { group_name: "play", post_title: "Test victim 2" },
    ])
    const playAction = actions.find((a) => a.group.toLowerCase().includes("play"))
    assert.ok(playAction, "expected play action")
    assert.ok(
      playAction.modules.some((m) => m.includes("raas") || m.includes("postex") || m.includes("esxi")),
    )
  })

  test("LockBit status is disrupted", () => {
    const groups = JSON.parse(fs.readFileSync(path.join(INTEL, "ransomware_groups.json"), "utf8"))
    const lb = groups.find((g) => g.id === "lockbit")
    assert.ok(lb)
    assert.equal(lb.status, "disrupted")
  })
})
