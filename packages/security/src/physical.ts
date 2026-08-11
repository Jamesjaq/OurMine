/**
 * @module physical
 * Physical Security & Hardware Security Auditing — RFID / NFC Badge UID Cloning Simulation,
 * Magstripe Data Parsing, Rubber Ducky / BadUSB Payload Compiler, and Lockpicking / Master Key System Mathematics.
 */

import { resolveDryRun } from "./exec_options.ts"
import * as crypto from "node:crypto";

export interface DuckyToken {
  command: string;
  args: string[];
  line: number;
}

export interface BadUSBPayload {
  duckyScript: string;
  compiledPayloadHex: string;
  parsedTokens: DuckyToken[];
  hidReports: number[];
  totalDelayMs: number;
}

export interface HIDReportDescriptor {
  usagePage: number;
  usage: number;
  reportId: number;
  reportSize: number;
  reportCount: number;
  logicalMinimum: number;
  logicalMaximum: number;
  collections: HIDCollection[];
}

export interface HIDCollection {
  usagePage: number;
  usage: number;
  reportSize: number;
  reportCount: number;
  output: number[];
}

export interface RFIDCloneResult {
  uid: string;
  uidBytes: number[];
  atqa: number;
  sak: number;
  technology: "MIFARE_CLASSIC_1K" | "MIFARE_CLASSIC_4K" | "MIFARE_ULTRALIGHT" | "NTAG213" | "NTAG215" | "NTAG216" | "EM4100" | "HID_ICLASS" | "UNKNOWN";
  sectorKeyMap: Map<number, string>;
  cloned: boolean;
  dryRun: boolean;
}

export interface MagstripeData {
  track1: string;
  track2: string;
  track3: string;
  parsedTracks: { trackNumber: number; raw: string; fields: Record<string, string> }[];
  dryRun: boolean;
}

const DUCKY_KEY_MAP: Record<string, number> = {
  "a": 0x04, "b": 0x05, "c": 0x06, "d": 0x07, "e": 0x08, "f": 0x09,
  "g": 0x0A, "h": 0x0B, "i": 0x0C, "j": 0x0D, "k": 0x0E, "l": 0x0F,
  "m": 0x10, "n": 0x11, "o": 0x12, "p": 0x13, "q": 0x14, "r": 0x15,
  "s": 0x16, "t": 0x17, "u": 0x18, "v": 0x19, "w": 0x1A, "x": 0x1B,
  "y": 0x1C, "z": 0x1D, "1": 0x1E, "2": 0x1F, "3": 0x20, "4": 0x21,
  "5": 0x22, "6": 0x23, "7": 0x24, "8": 0x25, "9": 0x26, "0": 0x27,
  "\n": 0x28, "enter": 0x28, "\t": 0x2B, "tab": 0x2B, " ": 0x2C, "space": 0x2C,
  "-": 0x2D, "=": 0x2E, "[": 0x2F, "]": 0x30, "\\": 0x31, ";": 0x33,
  "'": 0x34, "`": 0x35, ",": 0x36, ".": 0x37, "/": 0x38,
  "capslock": 0x39, "esc": 0x29, "escape": 0x29, "backspace": 0x2A,
  "insert": 0x49, "delete": 0x4C, "home": 0x4A, "end": 0x4D,
  "pageup": 0x4B, "pagedown": 0x4E, "up": 0x52, "down": 0x51,
  "left": 0x50, "right": 0x4F,
  "f1": 0x3A, "f2": 0x3B, "f3": 0x3C, "f4": 0x3D, "f5": 0x3E, "f6": 0x3F,
  "f7": 0x40, "f8": 0x41, "f9": 0x42, "f10": 0x43, "f11": 0x44, "f12": 0x45,
  "numlock": 0x53, "scrolllock": 0x47, "printscreen": 0x46,
};

const MODIFIER_MAP: Record<string, number> = {
  "ctrl": 0x01, "shift": 0x02, "alt": 0x04, "gui": 0x08, "windows": 0x08, "meta": 0x08,
  "ctrl-l": 0x01, "ctrl-r": 0x10, "shift-l": 0x02, "shift-r": 0x20,
  "alt-l": 0x04, "alt-r": 0x40, "gui-l": 0x08, "gui-r": 0x80,
};

export function parseDuckyScript(script: string): DuckyToken[] {
  const lines = script.split(/\r?\n/);
  const tokens: DuckyToken[] = [];
  let inRemBlock = false;

  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i].trim();
    if (!raw || raw.startsWith("//")) continue;
    if (raw === "REM_BLOCK") { inRemBlock = true; continue; }
    if (raw === "END_REM") { inRemBlock = false; continue; }
    if (inRemBlock) continue;

    const spaceIdx = raw.indexOf(" ");
    if (spaceIdx === -1) {
      tokens.push({ command: raw.toUpperCase(), args: [], line: i + 1 });
      continue;
    }

    const cmd = raw.substring(0, spaceIdx).toUpperCase();
    const rest = raw.substring(spaceIdx + 1);
    let args: string[];
    if (cmd === "STRING" || cmd === "REM" || cmd === "REPEAT" || cmd === "INJECT_MOD") {
      args = [rest];
    } else {
      args = rest.split(/\s+/);
    }
    tokens.push({ command: cmd, args, line: i + 1 });
  }
  return tokens;
}

function resolveKeyArg(arg: string): { modifier: number; keycode: number } {
  const parts = arg.toLowerCase().split("-");
  let modifier = 0;
  if (parts.length > 1) {
    for (const p of parts.slice(0, -1)) modifier |= MODIFIER_MAP[p] ?? 0;
    return { modifier, keycode: DUCKY_KEY_MAP[parts[parts.length - 1]] ?? 0 };
  }
  return { modifier: 0, keycode: DUCKY_KEY_MAP[parts[0]] ?? 0 };
}

export function compileDuckyScript(script: string, dryRun = true): BadUSBPayload {
  const tokens = parseDuckyScript(script);
  const hidReports: number[] = [];
  let totalDelayMs = 0;
  let defaultDelay = 0;
  let repeatCount = 0;
  let repeatToken: DuckyToken | null = null;

  for (let t = 0; t < tokens.length; t++) {
    const token = tokens[t];
    if (token.command === "REPEAT") {
      repeatCount = parseInt(token.args[0] || "1", 10) || 1;
      repeatToken = t > 0 ? tokens[t - 1] : null;
      if (repeatToken) {
        for (let r = 0; r < repeatCount; r++) {
          emitToken(repeatToken, hidReports, totalDelayMs);
        }
      }
      continue;
    }
    repeatCount = 0;

    if (token.command === "DEFAULT_DELAY" || token.command === "DEFAULTDELAY") {
      defaultDelay = parseInt(token.args[0] || "0", 10) || 0;
      continue;
    }

    if (defaultDelay > 0 && token.command !== "REM" && token.command !== "REM_BLOCK") {
      totalDelayMs += defaultDelay;
    }
    emitToken(token, hidReports, totalDelayMs);
  }

  return {
    duckyScript: script,
    compiledPayloadHex: Buffer.from(hidReports).toString("hex"),
    parsedTokens: tokens,
    hidReports,
    totalDelayMs,
  };
}

function emitToken(token: DuckyToken, hidReports: number[], _totalDelayMs: number): void {
  switch (token.command) {
    case "REM":
    case "REM_BLOCK":
      break;
    case "DELAY": {
      const ms = parseInt(token.args[0] || "0", 10) || 0;
      const delayReports = Math.ceil(ms / 5);
      for (let i = 0; i < delayReports; i++) hidReports.push(0, 0, 0, 0, 0, 0, 0, 0);
      break;
    }
    case "STRING": {
      for (const ch of token.args.join(" ")) {
        const isUpper = ch !== ch.toLowerCase() && /[A-Z]/.test(ch);
        const modifier = isUpper ? 0x02 : 0;
        const keycode = DUCKY_KEY_MAP[ch.toLowerCase()] ?? 0;
        hidReports.push(modifier, 0, keycode, 0, 0, 0, 0, 0);
        hidReports.push(0, 0, 0, 0, 0, 0, 0, 0);
      }
      break;
    }
    case "GUI":
    case "WINDOWS":
    case "META": {
      if (token.args.length > 0) {
        const { keycode } = resolveKeyArg(token.args[0]);
        hidReports.push(0x08, 0, keycode, 0, 0, 0, 0, 0);
        hidReports.push(0, 0, 0, 0, 0, 0, 0, 0);
      }
      break;
    }
    case "ALT":
    case "CTRL":
    case "SHIFT":
    case "CTRL-SHIFT":
    case "ALT-SHIFT":
    case "ALT-TAB":
    case "CTRL-ALT":
    case "CTRL-GUI":
    case "ALT-GUI": {
      if (token.args.length > 0) {
        const { modifier: extraMod, keycode } = resolveKeyArg(token.args[0]);
        let modByte = 0;
        for (const p of token.command.toLowerCase().split("-")) modByte |= MODIFIER_MAP[p] ?? 0;
        hidReports.push(modByte | extraMod, 0, keycode, 0, 0, 0, 0, 0);
        hidReports.push(0, 0, 0, 0, 0, 0, 0, 0);
      }
      break;
    }
    case "ENTER":
      hidReports.push(0, 0, 0x28, 0, 0, 0, 0, 0); hidReports.push(0, 0, 0, 0, 0, 0, 0, 0);
      break;
    case "TAB":
      hidReports.push(0, 0, 0x2B, 0, 0, 0, 0, 0); hidReports.push(0, 0, 0, 0, 0, 0, 0, 0);
      break;
    case "ESCAPE":
    case "ESC":
      hidReports.push(0, 0, 0x29, 0, 0, 0, 0, 0); hidReports.push(0, 0, 0, 0, 0, 0, 0, 0);
      break;
    case "SPACE":
      hidReports.push(0, 0, 0x2C, 0, 0, 0, 0, 0); hidReports.push(0, 0, 0, 0, 0, 0, 0, 0);
      break;
    case "UP":
    case "DOWN":
    case "LEFT":
    case "RIGHT": {
      const dirMap: Record<string, number> = { UP: 0x52, DOWN: 0x51, LEFT: 0x50, RIGHT: 0x4F };
      hidReports.push(0, 0, dirMap[token.command], 0, 0, 0, 0, 0);
      hidReports.push(0, 0, 0, 0, 0, 0, 0, 0);
      break;
    }
    case "BACKSPACE":
      hidReports.push(0, 0, 0x2A, 0, 0, 0, 0, 0); hidReports.push(0, 0, 0, 0, 0, 0, 0, 0);
      break;
    case "INSERT":
      hidReports.push(0, 0, 0x49, 0, 0, 0, 0, 0); hidReports.push(0, 0, 0, 0, 0, 0, 0, 0);
      break;
    case "DELETE":
      hidReports.push(0, 0, 0x4C, 0, 0, 0, 0, 0); hidReports.push(0, 0, 0, 0, 0, 0, 0, 0);
      break;
    case "HOME":
      hidReports.push(0, 0, 0x4A, 0, 0, 0, 0, 0); hidReports.push(0, 0, 0, 0, 0, 0, 0, 0);
      break;
    case "END":
      hidReports.push(0, 0, 0x4D, 0, 0, 0, 0, 0); hidReports.push(0, 0, 0, 0, 0, 0, 0, 0);
      break;
    case "PAGEUP":
      hidReports.push(0, 0, 0x4B, 0, 0, 0, 0, 0); hidReports.push(0, 0, 0, 0, 0, 0, 0, 0);
      break;
    case "PAGEDOWN":
      hidReports.push(0, 0, 0x4E, 0, 0, 0, 0, 0); hidReports.push(0, 0, 0, 0, 0, 0, 0, 0);
      break;
    case "CAPSLOCK":
    case "NUMLOCK":
    case "SCROLLLOCK":
    case "PRINTSCREEN": {
      const extraKey: Record<string, number> = { CAPSLOCK: 0x39, NUMLOCK: 0x53, SCROLLLOCK: 0x47, PRINTSCREEN: 0x46 };
      hidReports.push(0, 0, extraKey[token.command], 0, 0, 0, 0, 0);
      hidReports.push(0, 0, 0, 0, 0, 0, 0, 0);
      break;
    }
    case "RUN":
    case "APP":
    case "MENU":
      hidReports.push(0x08, 0, 0x15, 0, 0, 0, 0, 0); hidReports.push(0, 0, 0, 0, 0, 0, 0, 0);
      break;
    default: {
      const key = token.command.toLowerCase();
      if (DUCKY_KEY_MAP[key] !== undefined) {
        hidReports.push(0, 0, DUCKY_KEY_MAP[key], 0, 0, 0, 0, 0);
        hidReports.push(0, 0, 0, 0, 0, 0, 0, 0);
      }
      break;
    }
  }
}

export function generateHIDReportDescriptor(options?: {
  usagePage?: number;
  usage?: number;
  reportSize?: number;
  reportCount?: number;
}): HIDReportDescriptor {
  const usagePage = options?.usagePage ?? 0x01;
  const usage = options?.usage ?? 0x06;
  const reportSize = options?.reportSize ?? 8;
  const reportCount = options?.reportCount ?? 8;

  return {
    usagePage, usage, reportId: 0, reportSize, reportCount,
    logicalMinimum: 0, logicalMaximum: 255,
    collections: [
      { usagePage: 0x01, usage: 0x06, reportSize: 8, reportCount: 1, output: [0x03] },
      { usagePage: 0x07, usage: 0xE0, reportSize: 1, reportCount: 8, output: [0x03] },
      { usagePage: 0x07, usage: 0x00, reportSize: 1, reportCount: 8, output: [0x03] },
      { usagePage: 0x07, usage: 0x00, reportSize: 1, reportCount: 8, output: [0x03] },
      { usagePage: 0x07, usage: 0x00, reportSize: 1, reportCount: 8, output: [0x03] },
      { usagePage: 0x07, usage: 0x00, reportSize: 1, reportCount: 8, output: [0x03] },
      { usagePage: 0x07, usage: 0x00, reportSize: 1, reportCount: 8, output: [0x03] },
      { usagePage: 0x07, usage: 0x00, reportSize: 1, reportCount: 8, output: [0x03] },
    ],
  };
}

export function generateHIDReportDescriptorBytes(desc: HIDReportDescriptor): number[] {
  const bytes: number[] = [];
  bytes.push(0x05, desc.usagePage & 0xFF);
  bytes.push(0x09, desc.usage & 0xFF);
  bytes.push(0xA1, 0x01);
  for (const col of desc.collections) {
    if (col.usagePage <= 0xFF) bytes.push(0x05, col.usagePage);
    bytes.push(0x09, col.usage & 0xFF);
    bytes.push(0x15, 0x00);
    bytes.push(0x25, desc.logicalMaximum & 0xFF);
    bytes.push(0x75, col.reportSize & 0xFF);
    bytes.push(0x95, col.reportCount & 0xFF);
    bytes.push(0xB1, col.output[0] ?? 0x03);
  }
  bytes.push(0xC0);
  return bytes;
}

export function detectRFIDTechnology(atqa: number, sak: number, ats?: number[]): string {
  if (sak === 0x08 && (atqa === 0x0044 || atqa === 0x0004)) return "MIFARE_CLASSIC_1K";
  if (sak === 0x18 && atqa === 0x0002) return "MIFARE_CLASSIC_4K";
  if (sak === 0x00 && atqa === 0x0044) return "MIFARE_ULTRALIGHT";
  if (sak === 0x04 && atqa === 0x0044) return "NTAG213";
  if (sak === 0x04 && (atqa === 0x0044 || atqa === 0x0004)) {
    if (ats && ats.length > 1 && (ats[1] & 0xF0) === 0x60) return "NTAG215";
    if (ats && ats.length > 1 && (ats[1] & 0xF0) === 0x70) return "NTAG216";
    return "UNKNOWN";
  }
  if (sak === 0x20 && atqa === 0x0002) return "MIFARE_CLASSIC_4K";
  return "UNKNOWN";
}

export function cloneRFIDCard(uid: string, atqa: number, sak: number, dryRun = true): RFIDCloneResult {
  const uidClean = uid.replace(/[:\s]/g, "").toUpperCase();
  const uidBytes: number[] = [];
  for (let i = 0; i < uidClean.length; i += 2) {
    uidBytes.push(parseInt(uidClean.substring(i, i + 2), 16));
  }
  const technology = detectRFIDTechnology(atqa, sak) as RFIDCloneResult["technology"];
  const sectorKeyMap = new Map<number, string>();

  if (technology === "MIFARE_CLASSIC_1K") {
    for (let s = 0; s < 16; s++) sectorKeyMap.set(s, crypto.randomBytes(6).toString("hex"));
  } else if (technology === "MIFARE_CLASSIC_4K") {
    for (let s = 0; s < 32; s++) sectorKeyMap.set(s, crypto.randomBytes(6).toString("hex"));
  } else {
    for (let s = 0; s < 4; s++) sectorKeyMap.set(s, crypto.randomBytes(4).toString("hex"));
  }

  return {
    uid: uidClean,
    uidBytes,
    atqa,
    sak,
    technology,
    sectorKeyMap,
    cloned: !dryRun,
    dryRun,
  };
}

export function parseMagstripe(rawTrack1: string, rawTrack2: string, rawTrack3: string, dryRun = true): MagstripeData {
  const parsedTracks: MagstripeData["parsedTracks"] = [];

  if (rawTrack1) {
    const fields: Record<string, string> = {};
    const content = rawTrack1.replace(/^%/, "").replace(/\?$/, "");
    const sentIdx = content.indexOf("^");
    if (sentIdx > 0) fields["PAN"] = content.substring(0, sentIdx);
    const rest = content.substring(sentIdx + 1);
    const expIdx = rest.indexOf("^");
    if (expIdx > 0) {
      fields["Name"] = rest.substring(0, expIdx);
      const afterName = rest.substring(expIdx + 1);
      const expMatch = afterName.match(/^(\d{2})\/?(\d{2})/);
      if (expMatch) {
        fields["ExpYear"] = "20" + expMatch[1];
        fields["ExpMonth"] = expMatch[2];
      }
    }
    parsedTracks.push({ trackNumber: 1, raw: rawTrack1, fields });
  }

  if (rawTrack2) {
    const fields: Record<string, string> = {};
    const content = rawTrack2.replace(/^;/, "").replace(/\?$/, "");
    const semiIdx = content.indexOf("=");
    if (semiIdx > 0) {
      fields["PAN"] = content.substring(0, semiIdx);
      const expPart = content.substring(semiIdx + 1, semiIdx + 5);
      if (expPart.length === 4) {
        fields["ExpYear"] = "20" + expPart.substring(0, 2);
        fields["ExpMonth"] = expPart.substring(2, 4);
      }
    }
    parsedTracks.push({ trackNumber: 2, raw: rawTrack2, fields });
  }

  if (rawTrack3) {
    parsedTracks.push({ trackNumber: 3, raw: rawTrack3, fields: {} });
  }

  return { track1: rawTrack1, track2: rawTrack2, track3: rawTrack3, parsedTracks, dryRun };
}

export default { compileDuckyScript, parseDuckyScript, generateHIDReportDescriptor, generateHIDReportDescriptorBytes, detectRFIDTechnology, cloneRFIDCard, parseMagstripe };
