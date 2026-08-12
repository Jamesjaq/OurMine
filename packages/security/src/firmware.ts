/**
 * @module firmware
 * Firmware Analysis & Hardware Hacking Primitives — Binwalk-style Magic Byte Scanning,
 * UART/JTAG Pinout Detection, Device Tree Blob (DTB) parsing, and Embedded Linux Password Hash Extractor.
 */

import * as fs from "node:fs";
import { resolveLiveMode } from "./exec_options.ts";
import { shannonEntropy } from "./polymorphic.ts";

export interface FirmwareSection {
  offset: number;
  type: string;
  description: string;
}

export interface EntropyWindow {
  offset: number;
  entropy: number;
  size: number;
}

export interface FirmwareCredentialHit {
  offset: number;
  kind: string;
  preview: string;
}

export interface UartHint {
  offset: number;
  kind: string;
  value: string;
}

export interface PatchCandidate {
  offset: number;
  kind: string;
  preview: string;
  note: string;
}

const MAGIC_BYTES: Array<{ magic: Buffer; type: string }> = [
  { magic: Buffer.from([0x1f, 0x8b]), type: "GZIP compressed data" },
  { magic: Buffer.from([0x27, 0x05, 0x19, 0x56]), type: "uImage Header" },
  { magic: Buffer.from([0x68, 0x73, 0x71, 0x73]), type: "SquashFS filesystem (little endian)" },
  { magic: Buffer.from([0x73, 0x71, 0x73, 0x68]), type: "SquashFS filesystem (big endian)" },
  { magic: Buffer.from([0xef, 0x53]), type: "Ext2/3/4 filesystem" },
  { magic: Buffer.from([0xd0, 0x0d, 0xfe, 0xed]), type: "Device Tree Blob (DTB)" },
];

const CREDENTIAL_PATTERNS: Array<{ kind: string; re: RegExp }> = [
  { kind: "shadow_entry", re: /(?:root|[a-z_][a-z0-9_-]{0,31}):\$[156]\$[^\s:]{1,120}/gi },
  { kind: "bcrypt_hash", re: /\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}/g },
  { kind: "md5_crypt", re: /\$1\$[./A-Za-z0-9]{1,8}\$[./A-Za-z0-9]{22}/g },
  { kind: "password_kv", re: /(?:password|passwd|pwd)\s*[=:]\s*[^\s\x00]{3,64}/gi },
  { kind: "api_secret", re: /(?:api[_-]?key|secret|token|auth)\s*[=:]\s*[^\s\x00]{8,128}/gi },
  { kind: "basic_auth", re: /Basic\s+[A-Za-z0-9+/=]{8,}/g },
];

const UART_PATTERNS: Array<{ kind: string; re: RegExp }> = [
  { kind: "console_tty", re: /console\s*=\s*tty[A-Za-z0-9]+(?:,\d+)?/gi },
  { kind: "tty_device", re: /tty(?:S|AMA|USB|O)\d+/g },
  { kind: "baud_rate", re: /\b(?:115200|57600|38400|19200|9600)\b/g },
  { kind: "uart_label", re: /\b(?:UART|JTAG|SWD|serial console|debug port)\b/gi },
  { kind: "pinout_hint", re: /\b(?:TX|RX|GND|VCC)\s*[:=]?\s*(?:pin\s*)?\d+/gi },
];

const PATCH_PATTERNS: Array<{ kind: string; re: RegExp; note: string }> = [
  { kind: "auth_check", re: /(?:authentication|login|verify_password|check_auth)/gi, note: "Auth gate — candidate for branch patch" },
  { kind: "license_check", re: /(?:license|trial|expired|registration)/gi, note: "License gate — candidate for NOP/return patch" },
  { kind: "debug_disabled", re: /(?:debug\s*=\s*0|DEBUG_DISABLED|NO_DEBUG)/gi, note: "Debug flag — candidate for enable patch" },
];

function readFirmwareBuffer(filePath: string, live = true): Buffer | null {
  if (!live) return null;
  if (!fs.existsSync(filePath)) return null;
  return fs.readFileSync(filePath);
}

export function analyzeFirmware(filePath: string, live = true): FirmwareSection[] {
  const buffer = readFirmwareBuffer(filePath, live);
  if (!buffer) return [];

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

export function firmwareEntropy(filePath: string, windowSize = 256, live = true): {
  globalEntropy: number;
  size: number;
  highEntropyWindows: EntropyWindow[];
} {
  const buffer = readFirmwareBuffer(filePath, live);
  if (!buffer) return { globalEntropy: 0, size: 0, highEntropyWindows: [] };

  const globalEntropy = shannonEntropy(buffer);
  const highEntropyWindows: EntropyWindow[] = [];
  const step = Math.max(64, Math.floor(windowSize / 2));

  for (let offset = 0; offset + windowSize <= buffer.length; offset += step) {
    const window = buffer.subarray(offset, offset + windowSize);
    const entropy = shannonEntropy(window);
    if (entropy >= 7.2) {
      highEntropyWindows.push({ offset, entropy, size: windowSize });
    }
  }

  return {
    globalEntropy,
    size: buffer.length,
    highEntropyWindows: highEntropyWindows.slice(0, 20),
  };
}

export function firmwareStrings(filePath: string, minLen = 4, limit = 100, live = true): string[] {
  const buffer = readFirmwareBuffer(filePath, live);
  if (!buffer) return [];

  const strings: string[] = [];
  let current = "";

  for (let i = 0; i < buffer.length; i++) {
    const byte = buffer[i]!;
    if (byte >= 0x20 && byte <= 0x7e) {
      current += String.fromCharCode(byte);
    } else if (current.length >= minLen) {
      strings.push(current);
      current = "";
      if (strings.length >= limit) break;
    } else {
      current = "";
    }
  }
  if (current.length >= minLen && strings.length < limit) strings.push(current);

  return strings;
}

export function firmwareCredentials(filePath: string, limit = 50, live = true): FirmwareCredentialHit[] {
  const buffer = readFirmwareBuffer(filePath, live);
  if (!buffer) return [];

  const text = buffer.toString("latin1");
  const hits: FirmwareCredentialHit[] = [];
  const seen = new Set<string>();

  for (const { kind, re } of CREDENTIAL_PATTERNS) {
    re.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = re.exec(text)) !== null && hits.length < limit) {
      const preview = match[0].slice(0, 80);
      const key = `${kind}:${match.index}:${preview}`;
      if (seen.has(key)) continue;
      seen.add(key);
      hits.push({ offset: match.index, kind, preview });
    }
  }

  return hits;
}

export function firmwareUartDetect(filePath: string, limit = 50, live = true): UartHint[] {
  const buffer = readFirmwareBuffer(filePath, live);
  if (!buffer) return [];

  const text = buffer.toString("latin1");
  const hints: UartHint[] = [];
  const seen = new Set<string>();

  for (const { kind, re } of UART_PATTERNS) {
    re.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = re.exec(text)) !== null && hints.length < limit) {
      const value = match[0].slice(0, 80);
      const key = `${kind}:${match.index}:${value}`;
      if (seen.has(key)) continue;
      seen.add(key);
      hints.push({ offset: match.index, kind, value });
    }
  }

  const dtbSections = analyzeFirmware(filePath, live).filter((s) => s.type.includes("Device Tree"));
  for (const dtb of dtbSections) {
    hints.push({
      offset: dtb.offset,
      kind: "dtb_header",
      value: `DTB at 0x${dtb.offset.toString(16)} — inspect for serial/console nodes`,
    });
  }

  return hints.slice(0, limit);
}

/** Read-only patch analysis — never writes to disk (dry-run safe). */
export function firmwarePatchPlan(filePath: string, limit = 30, live = true): PatchCandidate[] {
  const buffer = readFirmwareBuffer(filePath, live);
  if (!buffer) return [];

  const text = buffer.toString("latin1");
  const candidates: PatchCandidate[] = [];
  const seen = new Set<string>();

  for (const { kind, re, note } of PATCH_PATTERNS) {
    re.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = re.exec(text)) !== null && candidates.length < limit) {
      const preview = match[0].slice(0, 64);
      const key = `${kind}:${match.index}`;
      if (seen.has(key)) continue;
      seen.add(key);
      candidates.push({ offset: match.index, kind, preview, note });
    }
  }

  return candidates;
}

export type FirmwareAction =
  | "extract"
  | "entropy"
  | "strings"
  | "credentials"
  | "patch"
  | "uart_detect";

export const FIRMWARE_ACTIONS: FirmwareAction[] = [
  "extract",
  "entropy",
  "strings",
  "credentials",
  "patch",
  "uart_detect",
];

export function executeFirmwareAction(
  filePath: string,
  action: string,
  opts: { live?: boolean } = {},
): { action: string; error?: string; [key: string]: unknown } {
  if (!filePath) return { action, error: "path required" };

  const live = opts.live ?? resolveLiveMode();
  if (!live) {
    return { action, error: "live required — set OURMINE_LIVE=1 or pass live:true" };
  }
  if (!fs.existsSync(filePath)) return { action, error: `file not found: ${filePath}` };

  const act = action.toLowerCase() as FirmwareAction;

  switch (act) {
    case "extract": {
      const sections = analyzeFirmware(filePath, live);
      return {
        action: act,
        path: filePath,
        sections: sections.length,
        sample: sections.slice(0, 10),
      };
    }
    case "entropy": {
      const entropy = firmwareEntropy(filePath, 256, live);
      return { action: act, path: filePath, ...entropy };
    }
    case "strings": {
      const strings = firmwareStrings(filePath, 4, 100, live);
      return {
        action: act,
        path: filePath,
        count: strings.length,
        sample: strings.slice(0, 20),
      };
    }
    case "credentials": {
      const hits = firmwareCredentials(filePath, 50, live);
      return {
        action: act,
        path: filePath,
        count: hits.length,
        hits: hits.slice(0, 20),
      };
    }
    case "patch": {
      const candidates = firmwarePatchPlan(filePath, 30, live);
      return {
        action: act,
        path: filePath,
        dryRunOnly: true,
        count: candidates.length,
        candidates: candidates.slice(0, 15),
        note: "Analysis only — no bytes written",
      };
    }
    case "uart_detect": {
      const hints = firmwareUartDetect(filePath, 50, live);
      return {
        action: act,
        path: filePath,
        count: hints.length,
        hints: hints.slice(0, 20),
      };
    }
    default:
      return { action, error: `Unknown firmware action: ${action}` };
  }
}

export default {
  analyzeFirmware,
  firmwareEntropy,
  firmwareStrings,
  firmwareCredentials,
  firmwareUartDetect,
  firmwarePatchPlan,
  executeFirmwareAction,
  FIRMWARE_ACTIONS,
};
