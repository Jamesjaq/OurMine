/**
 * Authentication & session-testing primitives (port of `modules.auth_primitives`).
 *
 * Session-handling analysis (cookie security flags, session-cookie detection,
 * CSRF token heuristics) + SAML message/response testing (base64/zlib decode,
 * signature-presence, recipient and replay-risk checks). Pure — no network.
 */

import { inflateSync } from "node:zlib";

// Cookie attributes that indicate secure session handling.
export const SECURE_FLAGS = ["HttpOnly", "Secure", "SameSite"] as const;

export interface SessionAnalysis {
  cookies: Array<Record<string, unknown>>;
  issues: string[];
  vulnerable: boolean;
}

function parseCookieHeader(header: string): Record<string, unknown> | null {
  const parts = header
    .split(";")
    .map((p) => p.trim())
    .filter((p) => p.length > 0);
  if (!parts.length) return null;
  const nameValue = parts[0]!;
  const eq = nameValue.indexOf("=");
  const name = eq === -1 ? nameValue : nameValue.slice(0, eq);
  const value = eq === -1 ? "" : nameValue.slice(eq + 1);
  const attrs: Record<string, string> = {};
  for (const p of parts.slice(1)) {
    const inner = p.indexOf("=");
    attrs[inner === -1 ? p : p.slice(0, inner).trim()] = inner === -1 ? "" : p.slice(inner + 1);
  }
  return { name: name.trim(), value, flags: attrs };
}

/** Audit Set-Cookie headers for session-handling weaknesses. */
export function analyzeCookies(setCookieHeaders: string[]): SessionAnalysis {
  const analysis: SessionAnalysis = { cookies: [], issues: [], vulnerable: false };
  for (const header of setCookieHeaders) {
    const cookie = parseCookieHeader(header);
    if (!cookie) continue;
    const flags = cookie["flags"] as Record<string, string>;
    const lowered: Record<string, string> = {};
    for (const [k, v] of Object.entries(flags)) lowered[k.toLowerCase()] = v;
    analysis.cookies.push(cookie);
    const name = String(cookie["name"]);
    for (const attr of SECURE_FLAGS) {
      if (!(attr.toLowerCase() in lowered)) {
        analysis.issues.push(`cookie '${name}' missing ${attr}`);
      }
    }
    if (!("expires" in lowered) && !("max-age" in lowered)) {
      analysis.issues.push(`cookie '${name}' is a session cookie (no expiry)`);
    }
  }
  analysis.vulnerable = analysis.issues.length > 0;
  return analysis;
}

/** Heuristic: does the page include a CSRF token in forms/JS? */
export function checkCsrfToken(html: string): boolean {
  const patterns = [
    /name=["']?(csrf|_token|authenticity_token|__RequestVerificationToken)["']?/i,
    /X-CSRF[-_]?Token/i,
  ];
  return patterns.some((re) => re.test(html));
}

// ------------------------------------------------------------------------- //
// SAML
// ------------------------------------------------------------------------- //

export const SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion";

export class SamlPrimitives {
  findings: string[] = [];

  /** Decode a SAML message: base64 (optionally deflate-compressed) or raw XML. */
  static decode(message: string): string {
    const candidate = message.trim();
    if (candidate.startsWith("<")) return candidate;
    // Node's Buffer.from(base64) is lenient — validate the alphabet first so
    // garbage is returned as-is (Python's b64decode raises instead).
    if (!/^[A-Za-z0-9+/=\s]+$/.test(candidate)) return candidate;
    let raw = Buffer.from(candidate.replace(/\s/g, ""), "base64");
    if (raw.length >= 2 && raw[0] === 0x78 && raw[1] === 0x9c) {
      // zlib magic — inflate the DEFLATE body.
      try {
        raw = inflateSync(raw);
      } catch {
        /* fall through with the raw bytes */
      }
    }
    return raw.toString("utf-8");
  }

  /** Inspect a SAML message for signature, recipient and replay basics. */
  inspect(message: string): Record<string, unknown> {
    const xmlText = SamlPrimitives.decode(message);
    // Regex-level element/attribute extraction (Node has no XML parser built in;
    // the checks only need signature presence + SubjectConfirmationData attrs).
    const hasSignature =
      /<[a-zA-Z0-9_-]*:?Signature[\s/>]|<\/[a-zA-Z0-9_-]*:?Signature>/.test(xmlText);
    const scd = xmlText.match(/<[a-zA-Z0-9_-]*:?SubjectConfirmationData([^>]*)>/);
    const attrs = parseTagAttrs(scd?.[1] ?? "");
    const recipient = attrs["Recipient"] ?? "";
    const notOnOrAfter = attrs["NotOnOrAfter"] ?? "";

    if (!hasSignature) this.findings.push("SAML message is unsigned");
    if (recipient && recipient !== "https://sp.example.com/acs") {
      this.findings.push(`unexpected Recipient: ${recipient}`);
    }
    if (!notOnOrAfter) {
      this.findings.push("SubjectConfirmationData missing NotOnOrAfter (replay risk)");
    }

    return {
      signed: hasSignature,
      recipient,
      not_on_or_after: notOnOrAfter,
      findings: [...this.findings],
      xml: xmlText.slice(0, 2000),
    };
  }

  isSamlRequest(message: string): boolean {
    const decoded = SamlPrimitives.decode(message);
    return decoded.includes("samlp:AuthnRequest") || decoded.includes("AuthnRequest");
  }
}

function parseTagAttrs(inner: string): Record<string, string> {
  const out: Record<string, string> = {};
  // Both double- and single-quoted attribute values (real XML allows either).
  const re = /([A-Za-z_:][A-Za-z0-9_.:-]*)\s*=\s*("([^"]*)"|'([^']*)')/g;
  for (const m of inner.matchAll(re)) {
    out[m[1]!] = m[3] ?? m[4] ?? "";
  }
  return out;
}
