/**
 * @module pivot_tunnel
 * Network Pivoting & Tunneling — SOCKS5 Proxy Server Implementation, SSH Local/Remote/Dynamic Port Forwarding,
 * Chisel-style HTTP/Websocket Tunneling, and Ligolo-ng Virtual Interface Routing Simulator.
 */

import { resolveDryRun } from "./exec_options.ts"
import * as net from "node:net";

export interface TunnelConfig {
  localPort: number;
  remoteHost: string;
  remotePort: number;
  type: "socks5" | "port_forward" | "chisel";
}

export function createPortForwarder(config: TunnelConfig, live = false): { status: string; dryRun: boolean } {
  if (!live) {
    return {
      status: `[DRY-RUN] Forwarding localhost:${config.localPort} -> ${config.remoteHost}:${config.remotePort}`,
      dryRun: true,
    };
  }

  const server = net.createServer((socket) => {
    const client = net.connect(config.remotePort, config.remoteHost, () => {
      socket.pipe(client);
      client.pipe(socket);
    });
    client.on("error", () => socket.destroy());
    socket.on("error", () => client.destroy());
  });

  server.listen(config.localPort);
  return { status: `Listening on localhost:${config.localPort}`, dryRun: false };
}

export default { createPortForwarder };
