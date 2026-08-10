/**
 * @module oauth_chain
 * OAuth 2.0 & OpenID Connect Attack Chains — Redirect URI Wildcard Bypass, PKCE Downgrade,
 * Cross-Site Request Forgery in OAuth Authorization, and Device Code Flow Phishing.
 */

export interface OAuthVulnerability {
  vector: string;
  severity: "critical" | "high" | "medium";
  description: string;
  pocUrl?: string;
}

export function checkOAuthRedirectBypass(clientRedirectUri: string): OAuthVulnerability | null {
  if (clientRedirectUri.includes("*") || clientRedirectUri.includes("localhost")) {
    return {
      vector: "Redirect URI Wildcard/Localhost Abuse",
      severity: "high",
      description: "The OAuth authorization server allows overly permissive redirect URI matching.",
      pocUrl: `https://auth.target.com/oauth/authorize?client_id=xxx&redirect_uri=${encodeURIComponent(clientRedirectUri)}`,
    };
  }
  return null;
}

export default { checkOAuthRedirectBypass };
