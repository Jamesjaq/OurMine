/**
 * @module strix_engine
 * Strix offensive browser engine — CDP automation, Caido proxy GraphQL client,
 * XSS/CSRF/injection automation, and the Strix coordinator.
 *
 * Based on usestrix/strix (MIT).
 */

import { resolveDryRun } from "./exec_options.ts"
import * as crypto from "node:crypto";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface PageResult {
  url: string;
  finalUrl: string;
  status: number;
  headers: Record<string, string>;
  body: string;
  title: string;
  cookies: Record<string, string>;
}

export interface Form {
  action: string;
  method: string;
  fields: string[];
}

export interface ReflectionResult {
  url: string;
  reflected: boolean;
  status: number;
  snippet: string;
}

export interface StrixOptions {
  live?: boolean;
  userAgent?: string;
  timeout?: number;
  cdpUrl?: string;
  followRedirects?: boolean;
}

// ─── BrowserSession ───────────────────────────────────────────────────────────

const DEFAULT_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36 ARES2/0.1";

export class BrowserSession {
  private userAgent: string;
  private timeout: number;
  private cdpUrl: string;
  private cookies: Record<string, string> = {};
  private live: boolean;

  constructor(opts: StrixOptions = {}) {
    this.userAgent = opts.userAgent ?? DEFAULT_UA;
    this.timeout = opts.timeout ?? 15_000;
    this.cdpUrl = opts.cdpUrl ?? process.env["ARES2_CDP_URL"] ?? "http://127.0.0.1:9222";
    this.live = opts.live ?? false;
  }

  /** Restore cookies from persisted session. */
  loadCookies(cookies: Record<string, string>): void {
    this.cookies = { ...this.cookies, ...cookies }
  }

  getCookies(): Record<string, string> {
    return { ...this.cookies }
  }

  /** Fetch a page. Uses CDP when available, else plain HTTP fetch. */
  async navigate(url: string): Promise<PageResult> {
    if (!this.live) {
      return {
        url,
        finalUrl: url,
        status: 0,
        headers: {},
        body: "",
        title: "",
        cookies: {},
      }
    }

    if (await this._cdpAvailable()) {
      return this._navigateCDP(url);
    }
    return this._navigateHTTP(url);
  }

  private async _navigateHTTP(url: string): Promise<PageResult> {
    const resp = await fetch(url, {
      headers: { "User-Agent": this.userAgent, Cookie: this._cookieHeader() },
      signal: AbortSignal.timeout(this.timeout),
      redirect: "follow",
    });

    const body = await resp.text();
    const title = this._extractTitle(body);
    const setCookies = resp.headers.getSetCookie?.() ?? [];
    for (const c of setCookies) {
      const [pair] = c.split(";");
      const [k, v] = pair.split("=");
      if (k) this.cookies[k.trim()] = v?.trim() ?? "";
    }

    return {
      url,
      finalUrl: resp.url,
      status: resp.status,
      headers: Object.fromEntries(resp.headers.entries()),
      body,
      title,
      cookies: { ...this.cookies },
    };
  }

  private async _cdpAvailable(): Promise<boolean> {
    try {
      const r = await fetch(`${this.cdpUrl}/json/version`, { signal: AbortSignal.timeout(1000) });
      return r.ok;
    } catch { return false; }
  }

  private async _navigateCDP(url: string): Promise<PageResult> {
    const { CdpClient } = await import("./cdp_client.ts")
    const cdp = new CdpClient({ cdpUrl: this.cdpUrl, timeout: this.timeout, userAgent: this.userAgent })
    try {
      const page = await cdp.navigate(url, this.cookies)
      this.cookies = { ...this.cookies, ...page.cookies }
      return page
    } finally {
      await cdp.disconnect()
    }
  }

  /** Submit a form via POST. */
  async postForm(
    url: string,
    data: Record<string, string>,
    headers: Record<string, string> = {}
  ): Promise<PageResult> {
    if (!this.live) {
      return {
        url,
        finalUrl: url,
        status: 0,
        headers: {},
        body: "",
        title: "",
        cookies: {},
      };
    }
    const body = new URLSearchParams(data).toString();
    const resp = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", "User-Agent": this.userAgent, ...headers },
      body,
      signal: AbortSignal.timeout(this.timeout),
    });
    return {
      url,
      finalUrl: resp.url,
      status: resp.status,
      headers: Object.fromEntries(resp.headers.entries()),
      body: await resp.text(),
      title: "",
      cookies: { ...this.cookies },
    };
  }

  /** Extract HTML forms from a page result. */
  extractForms(page: PageResult): Form[] {
    const forms: Form[] = [];
    const formMatches = page.body.matchAll(/<form[^>]*>(.*?)<\/form>/gis);
    for (const match of formMatches) {
      const tag = match[0];
      const action = tag.match(/action=["']([^"']*)["']/i)?.[1] ?? "";
      const method = (tag.match(/method=["']([^"']*)["']/i)?.[1] ?? "get").toLowerCase();
      const fields = [...match[1].matchAll(/name=["']([^"']*)["']/gi)].map((m) => m[1]);
      forms.push({ action, method, fields });
    }
    return forms;
  }

  /** Test whether a parameter is reflected back in the response (XSS primitive). */
  async checkReflection(url: string, probe = "ARES2REFLECT123"): Promise<ReflectionResult> {
    const sep = url.includes("?") ? "&" : "?";
    const target = `${url}${sep}q=${encodeURIComponent(probe)}`;
    const page = await this.navigate(target);
    const reflected = page.body.includes(probe);
    const idx = page.body.indexOf(probe);
    return {
      url: target,
      reflected,
      status: page.status,
      snippet: reflected ? page.body.slice(Math.max(0, idx - 80), idx + 80) : "",
    };
  }

  private _cookieHeader(): string {
    return Object.entries(this.cookies).map(([k, v]) => `${k}=${v}`).join("; ");
  }

  private _extractTitle(html: string): string {
    const m = html.match(/<title[^>]*>(.*?)<\/title>/is);
    return m?.[1]?.trim() ?? "";
  }
}

// ─── CaidoClient ─────────────────────────────────────────────────────────────

export class CaidoClient {
  private baseUrl: string;
  private apiToken: string;
  private live: boolean;

  constructor(opts: { baseUrl?: string; apiToken?: string; live?: boolean } = {}) {
    this.baseUrl = (opts.baseUrl ?? process.env["CAIDO_URL"] ?? "http://127.0.0.1:8080/api").replace(/\/$/, "");
    this.apiToken = opts.apiToken ?? process.env["CAIDO_API_TOKEN"] ?? "";
    this.live = opts.live ?? false;
  }

  async isAvailable(): Promise<boolean> {
    if (!this.live) return false;
    try {
      const r = await fetch(`${this.baseUrl}/health`, { signal: AbortSignal.timeout(2000) });
      return r.ok;
    } catch { return false; }
  }

  async graphql(query: string, variables: Record<string, unknown> = {}): Promise<Record<string, unknown>> {
    if (!this.live) return { _dryRun: true };
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (this.apiToken) headers["Authorization"] = `Bearer ${this.apiToken}`;
    const resp = await fetch(`${this.baseUrl}/graphql`, {
      method: "POST",
      headers,
      body: JSON.stringify({ query, variables }),
      signal: AbortSignal.timeout(10_000),
    });
    resp.body; // consume
    const data = await resp.json() as { data?: Record<string, unknown>; errors?: unknown[] };
    if (data.errors) throw new Error(`Caido GraphQL error: ${JSON.stringify(data.errors)}`);
    return data.data ?? {};
  }

  async recentRequests(limit = 20): Promise<Array<Record<string, unknown>>> {
    const query = `query($limit: Int!) {
      requests(first: $limit) { edges { node { id method host path statusCode requestTime } } }
    }`;
    const data = await this.graphql(query, { limit });
    const reqs = (data["requests"] as any)?.edges ?? [];
    return reqs.map((e: any) => e.node);
  }

  async replay(requestId: string): Promise<Record<string, unknown>> {
    const query = `mutation($id: ID!) { replayRequest(id: $id) { id statusCode body } }`;
    return this.graphql(query, { id: requestId });
  }
}

// ─── StrixCoordinator ─────────────────────────────────────────────────────────

export interface AttackJob {
  id: string;
  target: string;
  type: "xss_reflection" | "csrf_test" | "sqli_probe" | "form_fuzz" | "auth_bypass";
  status: "pending" | "running" | "done" | "failed";
  result?: unknown;
}

/**
 * Coordinates multi-step offensive browser automation using BrowserSession + Caido.
 */
export class StrixCoordinator {
  private browser: BrowserSession;
  private caido: CaidoClient;
  private jobs: Map<string, AttackJob> = new Map();
  private live: boolean;

  constructor(opts: StrixOptions = {}) {
    this.live = opts.live ?? false;
    this.browser = new BrowserSession(opts);
    this.caido = new CaidoClient({ live: opts.live });
  }

  /** Queue an attack job. */
  queue(target: string, type: AttackJob["type"]): AttackJob {
    const job: AttackJob = { id: crypto.randomUUID(), target, type, status: "pending" };
    this.jobs.set(job.id, job);
    return job;
  }

  /** Execute all pending jobs. */
  async runAll(): Promise<AttackJob[]> {
    const results: AttackJob[] = [];
    for (const job of this.jobs.values()) {
      if (job.status !== "pending") continue;
      job.status = "running";
      try {
        job.result = await this._runJob(job);
        job.status = "done";
      } catch (e) {
        job.result = String(e);
        job.status = "failed";
      }
      results.push(job);
    }
    return results;
  }

  private async _runJob(job: AttackJob): Promise<unknown> {
    switch (job.type) {
      case "xss_reflection":
        return this.browser.checkReflection(job.target);
      case "csrf_test": {
        const page = await this.browser.navigate(job.target);
        const forms = this.browser.extractForms(page);
        let caidoRequests: unknown[] = []
        if (await this.caido.isAvailable()) {
          try {
            caidoRequests = await this.caido.recentRequests(10)
          } catch { /* caido optional */ }
        }
        return { forms, csrf_tokens: forms.flatMap((f) => f.fields.filter((f2) => /csrf|token/i.test(f2))), caidoRequests };
      }
      case "sqli_probe": {
        const probes = ["'", "1' OR '1'='1", "1; SELECT 1--"];
        const results = []
        for (const p of probes) {
          const sep = job.target.includes("?") ? "&" : "?"
          const page = await this.browser.navigate(`${job.target}${sep}id=${encodeURIComponent(p)}`)
          results.push({ probe: p, status: page.status, error: /sql|syntax|mysql|postgres|oracle/i.test(page.body.slice(0, 1000)) })
        }
        return results
      }
      case "auth_bypass": {
        const { AuthenticatedBrowser } = await import("./strix_session.ts")
        const auth = new AuthenticatedBrowser({ live: this.live, sessionId: `job_${job.id}` })
        const crawl = await auth.authenticatedCrawl(job.target, { maxDepth: 1, maxPages: 5 })
        return { pages: crawl.length, authenticated: crawl.some((c) => c.authenticated) }
      }
      case "form_fuzz": {
        const page = await this.browser.navigate(job.target);
        return this.browser.extractForms(page);
      }
      default:
        return { note: `unsupported job type ${job.type}` };
    }
  }

  /** Authenticated crawl with session persistence. */
  async authenticatedCrawl(
    startUrl: string,
    opts: { username?: string; password?: string; loginUrl?: string; maxDepth?: number } = {},
  ): Promise<unknown> {
    const { AuthenticatedBrowser } = await import("./strix_session.ts")
    const auth = new AuthenticatedBrowser({ live: this.live })
    if (opts.username && opts.password && opts.loginUrl) {
      await auth.login(opts.loginUrl, { username: opts.username, password: opts.password })
    }
    return auth.authenticatedCrawl(startUrl, { maxDepth: opts.maxDepth ?? 2 })
  }

  getJobs(): AttackJob[] { return [...this.jobs.values()]; }
}

export default { BrowserSession, CaidoClient, StrixCoordinator };
