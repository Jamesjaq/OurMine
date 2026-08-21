const test = require("node:test")
const assert = require("node:assert")
const { auditHardwareRootOfTrust } = require("../src/ares/hardware_probe.ts")

test("ARES v5.0 Hardware Probe Validation", () => {
  const hrot = auditHardwareRootOfTrust()
  assert.ok(hrot, "Hardware Root of Trust audit executed successfully")
})
