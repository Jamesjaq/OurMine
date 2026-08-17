/**
 * @module pivot_tunnel
 * Network Pivoting & Tunneling — SOCKS5, SSH port forward, chisel-style tunnels.
 */
import * as net from "node:net";

export interface TunnelConfig {
  localPort: number
  remoteHost: string
  remotePort: number
  type: "socks5" | "port_forward" | "chisel"
}

export interface TunnelResult {
  status: string
  dryRun: boolean
  localPort?: number
  close?: () => Promise<void>
}

function listenEphemeral(server: net.Server, startPort: number, host = "127.0.0.1"): Promise<number> {
  return new Promise((resolve, reject) => {
    const tryPort = (port: number) => {
      const onError = (err: NodeJS.ErrnoException) => {
        server.off("listening", onListening)
        if (err.code === "EADDRINUSE" && port < startPort + 50) tryPort(port + 1)
        else reject(err)
      }
      const onListening = () => {
        server.off("error", onError)
        resolve(port)
      }
      server.once("error", onError)
      server.once("listening", onListening)
      server.listen(port, host)
    }
    tryPort(startPort)
  })
}

export function createPortForwarder(config: TunnelConfig, live = false): TunnelResult {
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

  let boundPort = config.localPort
  try {
    server.listen(boundPort, "127.0.0.1")
    server.unref()
  } catch (err) {
    return { status: `Failed: ${(err as Error).message}`, dryRun: false }
  }

  return {
    status: `Listening on 127.0.0.1:${boundPort}`,
    dryRun: false,
    localPort: boundPort,
    close: () => new Promise((resolve) => server.close(() => resolve())),
  };
}

export async function createPortForwarderAsync(config: TunnelConfig, live = false): Promise<TunnelResult> {
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

  try {
    const boundPort = await listenEphemeral(server, config.localPort)
    server.unref()
    return {
      status: `Listening on 127.0.0.1:${boundPort}`,
      dryRun: false,
      localPort: boundPort,
      close: () => new Promise((resolve) => server.close(() => resolve())),
    }
  } catch (err) {
    server.close()
    return { status: `Failed: ${(err as Error).message}`, dryRun: false }
  }
}

export default { createPortForwarder, createPortForwarderAsync };
