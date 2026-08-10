/**
 * @module meterpreter
 * Metasploit Meterpreter Session Interface — Protocol Framing Parser, Command Dispatcher (getuid, sysinfo, hashdump),
 * and MSFvenom Payload Invocation Wrapper.
 */

export interface MeterpreterSession {
  sessionId: number;
  peerHost: string;
  platform: string;
  username: string;
}

export function parseMeterpreterSysinfo(rawOutput: string): Partial<MeterpreterSession> {
  const hostMatch = rawOutput.match(/Computer\s+:\s+(.+)/);
  const osMatch = rawOutput.match(/OS\s+:\s+(.+)/);
  return {
    peerHost: hostMatch ? hostMatch[1].trim() : "Unknown",
    platform: osMatch ? osMatch[1].trim() : "Unknown",
  };
}

export default { parseMeterpreterSysinfo };
