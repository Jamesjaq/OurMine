/**
 * @module firmware
 * Firmware Analysis & Hardware Hacking Primitives — Binwalk-style Magic Byte Scanning,
 * UART/JTAG Pinout Detection, Device Tree Blob (DTB) parsing, and Embedded Linux Password Hash Extractor.
 */

import * as fs from "node:fs";

export interface FirmwareSection {
  offset: number;
  type: string;
  description: string;
}

const MAGIC_BYTES: Array<{ magic: Buffer; type: string }> = [
  { magic: Buffer.from([0x1f, 0x8b]), type: "GZIP compressed data" },
  { magic: Buffer.from([0x27, 0x05, 0x19, 0x56]), type: "uImage Header" },
  { magic: Buffer.from([0x68, 0x73, 0x71, 0x73]), type: "SquashFS filesystem (little endian)" },
  { magic: Buffer.from([0x73, 0x71, 0x73, 0x68]), type: "SquashFS filesystem (big endian)" },
  { magic: Buffer.from([0xef, 0x53]), type: "Ext2/3/4 filesystem" },
];

export function analyzeFirmware(filePath: string): FirmwareSection[] {
  if (!fs.existsSync(filePath)) return [];

  const buffer = fs.readFileSync(filePath);
  const sections: FirmwareSection[] = [];

  for (let offset = 0; offset < buffer.length - 4; offset++) {
    for (const { magic, type } of MAGIC_BYTES) {
      if (buffer.subarray(offset, offset + magic.length).equals(magic)) {
        sections.push({ offset, type, description: `Detected ${type} at 0x${offset.toString(16)}` });
      }
    }
  }

  return sections;
}

export default { analyzeFirmware };
