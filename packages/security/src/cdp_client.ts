/**
 * @module cdp_client
 * Minimal Chrome DevTools Protocol client over WebSocket (Node 18+ global WebSocket).
 */
import type { PageResult } from "./strix_engine.ts"

export interface CdpSessionOptions {
  cdpUrl?: string
  timeout?: number
  userAgent?: string
}

interface CdpTarget {
  id?: string
  webSocketDebuggerUrl?: string
  url?: string
}

export class CdpClient {
  private cdpUrl: string
  private timeout: number
  private userAgent: string
  private ws: WebSocket | null = null
  private msgId = 0
  private pending = new Map<number, { resolve: (v: unknown) => void; reject: (e: Error) => void }>()

  constructor(opts: CdpSessionOptions = {}) {
    this.cdpUrl = (opts.cdpUrl ?? process.env["ARES2_CDP_URL"] ?? "http://127.0.0.1:9222").replace(/\/$/, "")
    this.timeout = opts.timeout ?? 15_000
    this.userAgent = opts.userAgent ?? "Mozilla/5.0 (X11; Linux x86_64) Chrome/126.0 ARES2/0.1"
  }

  static async isAvailable(cdpUrl?: string): Promise<boolean> {
    const base = (cdpUrl ?? process.env["ARES2_CDP_URL"] ?? "http://127.0.0.1:9222").replace(/\/$/, "")
    try {
      const r = await fetch(`${base}/json/version`, { signal: AbortSignal.timeout(1500) })
      return r.ok
    } catch {
      return false
    }
  }

  async connect(existingWsUrl?: string): Promise<void> {
    if (this.ws?.readyState === WebSocket.OPEN) return

    let wsUrl = existingWsUrl
    if (!wsUrl) {
      const listRes = await fetch(`${this.cdpUrl}/json/list`, { signal: AbortSignal.timeout(3000) })
      if (!listRes.ok) throw new Error("CDP /json/list failed")
      const targets = (await listRes.json()) as CdpTarget[]
      const page = targets.find((t) => t.webSocketDebuggerUrl && (t.url === "about:blank" || !t.url?.startsWith("devtools://")))
        ?? targets.find((t) => t.webSocketDebuggerUrl)
      if (!page?.webSocketDebuggerUrl) {
        const newRes = await fetch(`${this.cdpUrl}/json/new?about:blank`, { signal: AbortSignal.timeout(3000) })
        const created = (await newRes.json()) as CdpTarget
        wsUrl = created.webSocketDebuggerUrl
      } else {
        wsUrl = page.webSocketDebuggerUrl
      }
    }
    if (!wsUrl) throw new Error("No CDP WebSocket URL")

    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("CDP WebSocket connect timeout")), this.timeout)
      this.ws = new WebSocket(wsUrl!)
      this.ws.onopen = () => { clearTimeout(timer); resolve() }
      this.ws.onerror = () => { clearTimeout(timer); reject(new Error("CDP WebSocket error")) }
      this.ws.onmessage = (ev) => this._onMessage(String(ev.data))
      this.ws.onclose = () => { this.ws = null }
    })

    await this.send("Page.enable")
    await this.send("Network.enable")
    await this.send("Runtime.enable")
    await this.send("Network.setUserAgentOverride", { userAgent: this.userAgent })
  }

  async disconnect(): Promise<void> {
    if (this.ws) {
      this.ws.close()
      this.ws = null
    }
  }

  async navigate(url: string, cookies: Record<string, string> = {}): Promise<PageResult> {
    await this.connect()
    const origin = new URL(url).origin

    if (Object.keys(cookies).length > 0) {
      await this.send("Network.setCookies", {
        cookies: Object.entries(cookies).map(([name, value]) => ({
          name,
          value,
          url: origin,
        })),
      })
    }

    const nav = await this.send("Page.navigate", { url }) as { frameId?: string; errorText?: string }
    if (nav.errorText) throw new Error(nav.errorText)

    for (let i = 0; i < 40; i++) {
      await new Promise((r) => setTimeout(r, 150))
      const state = await this.send("Runtime.evaluate", {
        expression: "document.readyState",
        returnByValue: true,
      }) as { result?: { value?: string } }
      if (state.result?.value === "complete" || state.result?.value === "interactive") break
    }

    const evalResult = await this.send("Runtime.evaluate", {
      expression: `({
        title: document.title || "",
        html: document.documentElement ? document.documentElement.outerHTML : "",
        url: location.href
      })`,
      returnByValue: true,
    }) as { result?: { value?: { title?: string; html?: string; url?: string } } }

    const pageData = evalResult.result?.value ?? { title: "", html: "", url }

    const cookieResult = await this.send("Network.getCookies", { urls: [pageData.url ?? url] }) as {
      cookies?: Array<{ name: string; value: string }>
    }
    const outCookies: Record<string, string> = { ...cookies }
    for (const c of cookieResult.cookies ?? []) {
      outCookies[c.name] = c.value
    }

    return {
      url,
      finalUrl: pageData.url ?? url,
      status: 200,
      headers: { "content-type": "text/html" },
      body: pageData.html ?? "",
      title: pageData.title ?? "",
      cookies: outCookies,
    }
  }

  private _onMessage(raw: string): void {
    try {
      const msg = JSON.parse(raw) as { id?: number; result?: unknown; error?: { message?: string } }
      if (msg.id && this.pending.has(msg.id)) {
        const p = this.pending.get(msg.id)!
        this.pending.delete(msg.id)
        if (msg.error) p.reject(new Error(msg.error.message ?? "CDP error"))
        else p.resolve(msg.result)
      }
    } catch { /* ignore parse errors */ }
  }

  private send(method: string, params: Record<string, unknown> = {}): Promise<unknown> {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      return Promise.reject(new Error("CDP not connected"))
    }
    const id = ++this.msgId
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id)
        reject(new Error(`CDP timeout: ${method}`))
      }, this.timeout)
      this.pending.set(id, {
        resolve: (v) => { clearTimeout(timer); resolve(v) },
        reject: (e) => { clearTimeout(timer); reject(e) },
      })
      this.ws!.send(JSON.stringify({ id, method, params }))
    })
  }
}

export default { CdpClient }
