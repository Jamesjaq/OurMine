/**
 * @module strix_session
 * CDP session persistence + authenticated crawl for Strix engine.
 */
import * as fs from "node:fs"
import * as path from "node:path"
import { BrowserSession, type PageResult, type Form } from "./strix_engine.ts"

export interface AuthSession {
  id: string
  target: string
  cookies: Record<string, string>
  headers: Record<string, string>
  loginUrl?: string
  authenticated: boolean
  savedAt: string
}

export interface CrawlResult {
  url: string
  status: number
  title: string
  links: string[]
  forms: Form[]
  authenticated: boolean
}

const SESSION_DIR = path.join(process.cwd(), ".ourmine", "sessions")

function sessionPath(id: string): string {
  return path.join(SESSION_DIR, `${id.replace(/[^a-zA-Z0-9_-]/g, "_")}.json`)
}

export class StrixSessionStore {
  save(session: AuthSession): string {
    fs.mkdirSync(SESSION_DIR, { recursive: true })
    fs.writeFileSync(sessionPath(session.id), JSON.stringify(session, null, 2))
    return sessionPath(session.id)
  }

  load(id: string): AuthSession | null {
    try {
      return JSON.parse(fs.readFileSync(sessionPath(id), "utf8")) as AuthSession
    } catch {
      return null
    }
  }

  list(): string[] {
    try {
      return fs.readdirSync(SESSION_DIR).filter((f) => f.endsWith(".json")).map((f) => f.replace(/\.json$/, ""))
    } catch {
      return []
    }
  }
}

export class AuthenticatedBrowser extends BrowserSession {
  private sessionStore = new StrixSessionStore()
  private sessionId: string
  private extraHeaders: Record<string, string> = {}

  constructor(opts: { live?: boolean; sessionId?: string; cdpUrl?: string } = {}) {
    super(opts)
    this.sessionId = opts.sessionId ?? `strix_${Date.now()}`
    const existing = this.sessionStore.load(this.sessionId)
    if (existing) {
      this.importSession(existing)
    }
  }

  importSession(session: AuthSession): void {
    this.loadCookies(session.cookies)
    this.extraHeaders = { ...session.headers }
  }

  async login(
    loginUrl: string,
    credentials: { username: string; password: string; userField?: string; passField?: string },
  ): Promise<{ success: boolean; session: AuthSession }> {
    const page = await this.navigate(loginUrl)
    const forms = this.extractForms(page)
    const form = forms.find((f) => f.fields.some((x) => /user|email|login/i.test(x))) ?? forms[0]
    if (!form) {
      return { success: false, session: this.exportSession(loginUrl, false) }
    }

    const action = form.action.startsWith("http") ? form.action : new URL(form.action || loginUrl, loginUrl).href
    const userField = credentials.userField ?? form.fields.find((f) => /user|email|login/i.test(f)) ?? "username"
    const passField = credentials.passField ?? form.fields.find((f) => /pass/i.test(f)) ?? "password"

    const postPage = await this.postForm(action, {
      [userField]: credentials.username,
      [passField]: credentials.password,
    }, this.extraHeaders)

    const authenticated = postPage.status < 400 && !/login|sign.?in|invalid|error/i.test(postPage.body.slice(0, 2000))
    const session = this.exportSession(loginUrl, authenticated)
    this.sessionStore.save(session)
    return { success: authenticated, session }
  }

  exportSession(target: string, authenticated: boolean): AuthSession {
    return {
      id: this.sessionId,
      target,
      cookies: this.getCookies(),
      headers: { ...this.extraHeaders },
      loginUrl: target,
      authenticated,
      savedAt: new Date().toISOString(),
    }
  }

  /** Crawl authenticated pages — follows same-origin links up to maxDepth. */
  async authenticatedCrawl(startUrl: string, opts: { maxDepth?: number; maxPages?: number } = {}): Promise<CrawlResult[]> {
    const maxDepth = opts.maxDepth ?? 2
    const maxPages = opts.maxPages ?? 20
    const visited = new Set<string>()
    const queue: Array<{ url: string; depth: number }> = [{ url: startUrl, depth: 0 }]
    const results: CrawlResult[] = []
    const origin = new URL(startUrl).origin

    while (queue.length > 0 && results.length < maxPages) {
      const { url, depth } = queue.shift()!
      if (visited.has(url) || depth > maxDepth) continue
      visited.add(url)

      const page = await this.navigate(url)
      const forms = this.extractForms(page)
      const links = this.extractLinks(page.body, origin)

      results.push({
        url,
        status: page.status,
        title: page.title,
        links,
        forms,
        authenticated: page.status === 200 && !/login|sign.?in/i.test(page.title),
      })

      for (const link of links.slice(0, 10)) {
        if (!visited.has(link)) queue.push({ url: link, depth: depth + 1 })
      }
    }

    return results
  }

  private extractLinks(html: string, origin: string): string[] {
    const links: string[] = []
    for (const m of html.matchAll(/href=["']([^"'#]+)["']/gi)) {
      try {
        const href = m[1]!
        const abs = href.startsWith("http") ? href : new URL(href, origin).href
        if (abs.startsWith(origin)) links.push(abs)
      } catch { /* invalid url */ }
    }
    return [...new Set(links)]
  }
}

export default { StrixSessionStore, AuthenticatedBrowser }
