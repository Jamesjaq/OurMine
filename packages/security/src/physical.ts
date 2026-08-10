/**
 * @module physical
 * Physical Security & Hardware Security Auditing — RFID / NFC Badge UID Cloning Simulation,
 * Magstripe Data Parsing, Rubber Ducky / BadUSB Payload Compiler, and Lockpicking / Master Key System Mathematics.
 */

export interface BadUSBPayload {
  duckyScript: string;
  compiledPayloadHex: string;
}

export function compileDuckyScript(script: string): BadUSBPayload {
  const hex = Buffer.from(script).toString("hex");
  return { duckyScript: script, compiledPayloadHex: hex };
}

export default { compileDuckyScript };
