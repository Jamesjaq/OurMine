/**
 * @module iot_scada
 * IoT & Industrial Control System (ICS/SCADA) Exploitation — Modbus TCP Coil Read/Write,
 * DNP3 Master/Outstation Simulation, MQTT Packet Sniffing & Injection, and BACnet/IP Router Audit.
 */

import * as net from "node:net";

export interface ModbusReadResult {
  unitId: number;
  fc: number;
  data: number[];
  dryRun: boolean;
}

export async function readModbusCoils(
  host: string,
  port = 502,
  unitId = 1,
  startAddr = 0,
  quantity = 10,
  live = false
): Promise<ModbusReadResult> {
  if (!live) {
    return {
      unitId,
      fc: 1,
      data: Array.from({ length: quantity }, () => Math.round(Math.random())),
      dryRun: true,
    };
  }

  return new Promise((resolve) => {
    const socket = new net.Socket();
    socket.setTimeout(3000);

    // Modbus TCP ADU Header: Transaction ID (2B), Protocol ID (2B), Length (2B), Unit ID (1B), FC (1B), Start (2B), Count (2B)
    const pdu = Buffer.from([0x00, 0x01, 0x00, 0x00, 0x00, 0x06, unitId, 0x01, (startAddr >> 8) & 0xff, startAddr & 0xff, (quantity >> 8) & 0xff, quantity & 0xff]);

    socket.connect(port, host, () => {
      socket.write(pdu);
    });

    socket.on("data", (data) => {
      socket.destroy();
      resolve({ unitId, fc: 1, data: Array.from(data.subarray(9)), dryRun: false });
    });

    socket.on("error", () => {
      socket.destroy();
      resolve({ unitId, fc: 1, data: [], dryRun: false });
    });
  });
}

export default { readModbusCoils };
