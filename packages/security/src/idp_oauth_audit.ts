/**
 * @module security/idp_oauth_audit
 * Identity Provider (IdP) & OAuth App Security Audit Engine
 *
 * Scans OAuth application registrations, multi-tenant consent, API permissions,
 * FIDO2 fallback policies, token binding enforcement, stale app registrations,
 * and exposed client secrets via Microsoft Graph API.
 *
 * All operations default to DRY-RUN mode. Pass `dryRun: false` only in authorised
 * red-team environments with a valid Microsoft Graph Bearer token.
 */

import { resolveDryRun } from "./exec_options.ts"
import { isToolAvailable } from "./tool_detection.ts"

// ─── Types ────────────────────────────────────────────────────────────────────

export interface IdPConfig {
  tenantId?: string
  domain: string
}

export interface IdPFinding {
  id: string
  category: "OAUTH_CONSENT" | "MFA_POLICY" | "TOKEN_BINDING" | "SECRET_EXPOSURE" | "APP_HYGIENE"
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
  title: string
  description: string
  remediation: string
  evidence?: string
}

export interface OAuthAppRegistration {
  appId: string
  displayName: string
  createdDateTime: string
  lastSignInDateTime: string | null
  signInAudience: string
  servicePrincipalType: string
  appRoles: string[]
  delegatedPermissionScopes: string[]
  apiPermissionScopes: string[]
  hasClientSecret: boolean
  secretExpiry: string | null
  passwordCredentialCount: number
  keyCredentialCount: number
  identifierUris: string[]
  redirectUris: string[]
}

export interface FIDO2PolicyStatus {
  isFIDO2Enabled: boolean
  allowSelfServiceRegistration: boolean
  enforceAttestation: boolean
  isEnforced: boolean
  combinedFIDO2Setting: string
}

export interface AuthenticationMethodPolicy {
  fido2: FIDO2PolicyStatus
  smsEnabled: boolean
  voiceEnabled: boolean
  totpEnabled: boolean
  emailOtpEnabled: boolean
  softwareOathEnabled: boolean
  hardwareOathEnabled: boolean
  temporaryAccessPassEnabled: boolean
}

export interface TokenBindingPolicy {
  includeTokenBinding: boolean
  tokenBindingType: string | null
  excludeNonTransferableTokens: boolean
}

export interface IdPAuditResult {
  domain: string
  tenantId: string | null
  highRiskOAuthApps: number
  totalOAuthApps: number
  fido2FallbackAllowed: boolean
  tokenBindingEnforced: boolean
  staleAppsCount: number
  exposedSecretsCount: number
  authMethodPolicy: AuthenticationMethodPolicy
  tokenBindingPolicy: TokenBindingPolicy
  oauthApps: OAuthAppRegistration[]
  findings: IdPFinding[]
  isDryRun: boolean
}

export interface IdPAuditOptions {
  dryRun?: boolean
  tenantId?: string
  domain: string
  accessToken?: string
}

// ─── Constants ────────────────────────────────────────────────────────────────

const STALE_APP_THRESHOLD_DAYS = 90
const SECRET_EXPIRY_WARNING_DAYS = 30

const HIGH_RISK_PERMISSIONS = new Set([
  "Directory.ReadWrite.All",
  "Directory.Read.All",
  "Application.ReadWrite.All",
  "AppRoleAssignment.ReadWrite.All",
  "RoleManagement.ReadWrite.Directory",
  "Group.ReadWrite.All",
  "User.ReadWrite.All",
  "Mail.ReadWrite",
  "Mail.Send",
  "Files.ReadWrite.All",
  "Sites.ReadWrite.All",
  "Calendars.ReadWrite",
  "Contacts.ReadWrite",
  "Notes.ReadWrite.All",
  "Ews.AccessAsUser.All",
  "full_access_as_app",
  "Exchange.ManageAsApp",
  "GroupMember.ReadWrite.All",
  "Policy.ReadWrite.ConditionalAccess",
  "RoleManagement.ReadWrite.CloudPC",
  "SecurityEvents.Read.All",
  "IdentityRiskEvent.Read.All",
  "AuditLog.Read.All",
  "Organization.ReadWrite.All",
  "Organization.Read.All",
  "Domain.Read.All",
])

const CRITICAL_PERMISSIONS = new Set([
  "Directory.ReadWrite.All",
  "Application.ReadWrite.All",
  "AppRoleAssignment.ReadWrite.All",
  "RoleManagement.ReadWrite.Directory",
  "Organization.ReadWrite.All",
  "full_access_as_app",
  "Exchange.ManageAsApp",
])

// ─── Helpers ──────────────────────────────────────────────────────────────────

let findingCounter = 0

function makeId(): string {
  findingCounter++
  return `IDP-${String(findingCounter).padStart(2, "0")}`
}

function resetFindings(): void {
  findingCounter = 0
}

async function graphApiGet(
  endpoint: string,
  accessToken: string,
  timeoutMs = 15000,
): Promise<Record<string, unknown> | null> {
  try {
    const resp = await fetch(`https://graph.microsoft.com/v1.0${endpoint}`, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": "application/json",
      },
      signal: AbortSignal.timeout(timeoutMs),
    })
    if (!resp.ok) return null
    return (await resp.json()) as Record<string, unknown>
  } catch {
    return null
  }
}

async function graphApiGetAll(
  endpoint: string,
  accessToken: string,
  timeoutMs = 30000,
): Promise<Record<string, unknown>[]> {
  const results: Record<string, unknown>[] = []
  let url: string | null = `https://graph.microsoft.com/v1.0${endpoint}`
  const headers = {
    Authorization: `Bearer ${accessToken}`,
    "Content-Type": "application/json",
  }

  while (url) {
    try {
      const resp = await fetch(url, { headers, signal: AbortSignal.timeout(timeoutMs) })
      if (!resp.ok) break
      const data = (await resp.json()) as Record<string, unknown>
      if (Array.isArray(data.value)) results.push(...data.value)
      url = (data["@odata.nextLink"] as string) || null
    } catch {
      break
    }
  }

  return results
}

function isMultiTenant(app: Record<string, unknown>): boolean {
  return String(app.signInAudience || "").includes("MultipleOrgs") || String(app.signInAudience || "").includes("AzureADMultipleOrgs")
}

function extractPermissionNames(scopes: unknown): string[] {
  if (!Array.isArray(scopes)) return []
  return scopes.map((s: Record<string, unknown>) => String(s.adminDisplayName || s.displayName || s.id || "")).filter(Boolean)
}

// ─── Empty policy defaults (error paths — no fabricated tenant data) ─────────

const EMPTY_AUTH_METHOD: AuthenticationMethodPolicy = {
  fido2: {
    isFIDO2Enabled: false,
    allowSelfServiceRegistration: false,
    enforceAttestation: false,
    isEnforced: false,
    combinedFIDO2Setting: "disabled",
  },
  smsEnabled: false,
  voiceEnabled: false,
  totpEnabled: false,
  emailOtpEnabled: false,
  softwareOathEnabled: false,
  hardwareOathEnabled: false,
  temporaryAccessPassEnabled: false,
}

const EMPTY_TOKEN_BINDING: TokenBindingPolicy = {
  includeTokenBinding: false,
  tokenBindingType: null,
  excludeNonTransferableTokens: false,
}

// ─── Live Implementation ──────────────────────────────────────────────────────

async function fetchOAuthAppsLive(
  accessToken: string,
  tenantId: string | undefined,
): Promise<OAuthAppRegistration[]> {
  const apps: OAuthAppRegistration[] = []
  const rawApps = await graphApiGetAll("/applications?$top=100", accessToken, 30000)

  for (const raw of rawApps) {
    const appId = String(raw.appId || "")
    const displayName = String(raw.displayName || "")
    const createdDateTime = String(raw.createdDateTime || "")
    const signInAudience = String(raw.signInAudience || "")
    const servicePrincipalType = raw.servicePrincipal ? "Application" : String(raw.servicePrincipalType || "Application")

    const appRoles = Array.isArray(raw.appRoles)
      ? (raw.appRoles as Record<string, unknown>[]).map(r => String(r.displayName || r.value || ""))
      : []

    const requiredResourceScopes = raw.requiredResourceAccess as Record<string, unknown>[] | undefined
    const apiPermissionScopes: string[] = []
    const delegatedPermissionScopes: string[] = []
    if (Array.isArray(requiredResourceScopes)) {
      for (const resource of requiredResourceScopes) {
        const delegated = resource.delegatedPermissionScopes as Record<string, unknown>[] | undefined
        const appPerms = resource.resourceAppId as Record<string, unknown>[] | undefined
        if (Array.isArray(delegated)) {
          delegatedPermissionScopes.push(...extractPermissionNames(delegated))
        }
      }
    }

    const passwordCredentials = raw.passwordCredentials as Record<string, unknown>[] | undefined
    const keyCredentials = raw.keyCredentials as Record<string, unknown>[] | undefined
    const passwordCredentialCount = Array.isArray(passwordCredentials) ? passwordCredentials.length : 0
    const keyCredentialCount = Array.isArray(keyCredentials) ? keyCredentials.length : 0
    const hasClientSecret = passwordCredentialCount > 0

    let secretExpiry: string | null = null
    if (Array.isArray(passwordCredentials) && passwordCredentials.length > 0) {
      const expires = passwordCredentials[0].endDateTime
      if (expires) secretExpiry = String(expires)
    }

    const identifierUris = Array.isArray(raw.identifierUris)
      ? raw.identifierUris.map(String)
      : typeof raw.identifierUris === "string" ? [raw.identifierUris] : []

    const redirectUris = Array.isArray(raw.web?.redirectUris)
      ? (raw.web as Record<string, unknown>).redirectUris as string[]
      : Array.isArray(raw.spa?.redirectUris)
        ? (raw.spa as Record<string, unknown>).redirectUris as string[]
        : []

    let lastSignInDateTime: string | null = null
    const spData = await graphApiGet(`/servicePrincipals?$filter=appId eq '${appId}'&$select=preferredSingleSignOnMode`, accessToken)
    const spList = spData?.value as Record<string, unknown>[] | undefined
    if (Array.isArray(spList) && spList.length > 0) {
      const signIns = await graphApiGetAll(
        `/auditLogs/signIns?$filter=appId eq '${appId}'&$top=1&$orderby=createdDateTime desc&$select=createdDateTime`,
        accessToken,
        10000,
      )
      if (signIns.length > 0) {
        lastSignInDateTime = String(signIns[0].createdDateTime || "")
      }
    }

    apps.push({
      appId,
      displayName,
      createdDateTime,
      lastSignInDateTime,
      signInAudience,
      servicePrincipalType,
      appRoles,
      delegatedPermissionScopes,
      apiPermissionScopes,
      hasClientSecret,
      secretExpiry,
      passwordCredentialCount,
      keyCredentialCount,
      identifierUris,
      redirectUris,
    })
  }

  return apps
}

async function fetchAuthMethodPolicyLive(
  accessToken: string,
): Promise<AuthenticationMethodPolicy> {
  const policy = await graphApiGet("/policies/authenticationMethodsPolicy", accessToken)
  const methods = await graphApiGetAll("/policies/authenticationMethodsPolicy/authenticationMethodConfigurations", accessToken)

  const fido2Method = methods.find(m => String(m.id || "").toLowerCase() === "fido2")
  const fido2: FIDO2PolicyStatus = {
    isFIDO2Enabled: false,
    allowSelfServiceRegistration: false,
    enforceAttestation: false,
    isEnforced: false,
    combinedFIDO2Setting: "disabled",
  }

  if (fido2Method) {
    const state = String(fido2Method.state || "").toLowerCase()
    fido2.isFIDO2Enabled = state === "enabled"
    fido2.isEnforced = state === "enabled"
    fido2.combinedFIDO2Setting = state
    const settings = fido2Method.settings as Record<string, unknown> | undefined
    if (settings) {
      fido2.allowSelfServiceRegistration = Boolean(settings.allowSelfServiceRegistration)
      fido2.enforceAttestation = Boolean(settings.enforceAttestation)
    }
  }

  const smsMethod = methods.find(m => String(m.id || "").toLowerCase() === "sms")
  const voiceMethod = methods.find(m => String(m.id || "").toLowerCase() === "voice")
  const totpMethod = methods.find(m => String(m.id || "").toLowerCase() === "softwareoath")
  const emailMethod = methods.find(m => String(m.id || "").toLowerCase() === "email")
  const hwOathMethod = methods.find(m => String(m.id || "").toLowerCase() === "hardwareoath")
  const tempPassMethod = methods.find(m => String(m.id || "").toLowerCase() === "temporaryaccesspass")

  function isMethodEnabled(method: Record<string, unknown> | undefined): boolean {
    if (!method) return false
    return String(method.state || "").toLowerCase() === "enabled"
  }

  return {
    fido2,
    smsEnabled: isMethodEnabled(smsMethod),
    voiceEnabled: isMethodEnabled(voiceMethod),
    totpEnabled: isMethodEnabled(totpMethod),
    emailOtpEnabled: isMethodEnabled(emailMethod),
    softwareOathEnabled: isMethodEnabled(totpMethod),
    hardwareOathEnabled: isMethodEnabled(hwOathMethod),
    temporaryAccessPassEnabled: isMethodEnabled(tempPassMethod),
  }
}

async function fetchTokenBindingPolicyLive(
  accessToken: string,
): Promise<TokenBindingPolicy> {
  const resp = await graphApiGet("/policies/authenticationMethodsPolicy", accessToken)
  if (!resp) {
    return { includeTokenBinding: false, tokenBindingType: null, excludeNonTransferableTokens: false }
  }

  const tokenBinding = resp.tokenBinding as Record<string, unknown> | undefined
  return {
    includeTokenBinding: Boolean(tokenBinding?.includeTokenBinding),
    tokenBindingType: tokenBinding?.tokenBindingType ? String(tokenBinding.tokenBindingType) : null,
    excludeNonTransferableTokens: Boolean(tokenBinding?.excludeNonTransferableTokens),
  }
}

// ─── Finding Generation ───────────────────────────────────────────────────────

function generateLiveFindings(
  apps: OAuthAppRegistration[],
  authMethod: AuthenticationMethodPolicy,
  tokenBinding: TokenBindingPolicy,
): IdPFinding[] {
  const findings: IdPFinding[] = []
  const now = Date.now()

  for (const app of apps) {
    if (isMultiTenant({ signInAudience: app.signInAudience })) {
      const highRiskPerms = app.apiPermissionScopes.filter(p => HIGH_RISK_PERMISSIONS.has(p))
      const criticalPerms = app.apiPermissionScopes.filter(p => CRITICAL_PERMISSIONS.has(p))
      if (highRiskPerms.length > 0) {
        findings.push({
          id: makeId(),
          category: "OAUTH_CONSENT",
          severity: criticalPerms.length > 0 ? "CRITICAL" : "HIGH",
          title: `Multi-Tenant App with High-Privilege API Permissions: ${app.displayName}`,
          description: `App "${app.displayName}" (${app.appId}) is registered as multi-tenant with elevated permissions: [${highRiskPerms.join(", ")}]. Any tenant can consent to these permissions.`,
          remediation: "Scope down permissions to least privilege. Require admin consent for multi-tenant apps. Consider switching to single-tenant if cross-tenant access is not needed.",
          evidence: `appId=${app.appId}, signInAudience=${app.signInAudience}, permissions=[${highRiskPerms.join(", ")}]`,
        })
      }
    }

    if (app.lastSignInDateTime === null) {
      const created = new Date(app.createdDateTime).getTime()
      const ageDays = (now - created) / 86400000
      if (ageDays > STALE_APP_THRESHOLD_DAYS) {
        findings.push({
          id: makeId(),
          category: "APP_HYGIENE",
          severity: "MEDIUM",
          title: `Stale/Unused App Registration: ${app.displayName}`,
          description: `App "${app.displayName}" (${app.appId}) was created ${Math.floor(ageDays)} days ago and has never recorded a sign-in. This is a dormant attack surface.`,
          remediation: "Review and delete unused app registrations. Implement lifecycle management policies.",
          evidence: `appId=${app.appId}, created=${app.createdDateTime}, lastSignIn=null, ageDays=${Math.floor(ageDays)}`,
        })
      }
    }

    if (app.secretExpiry) {
      const expiryTime = new Date(app.secretExpiry).getTime()
      const daysUntilExpiry = (expiryTime - now) / 86400000
      if (daysUntilExpiry < 0) {
        findings.push({
          id: makeId(),
          category: "SECRET_EXPOSURE",
          severity: "HIGH",
          title: `Expired Client Secret: ${app.displayName}`,
          description: `App "${app.displayName}" (${app.appId}) has a client secret that expired ${Math.abs(Math.floor(daysUntilExpiry))} days ago. Expired secrets may linger in logs and configuration files.`,
          remediation: "Rotate expired secrets immediately. Migrate to certificate-based authentication or managed identities.",
          evidence: `appId=${app.appId}, secretExpiry=${app.secretExpiry}`,
        })
      } else if (daysUntilExpiry < SECRET_EXPIRY_WARNING_DAYS) {
        findings.push({
          id: makeId(),
          category: "SECRET_EXPOSURE",
          severity: "MEDIUM",
          title: `Client Secret Expiring Soon: ${app.displayName}`,
          description: `App "${app.displayName}" (${app.appId}) has a client secret expiring in ${Math.floor(daysUntilExpiry)} days.`,
          remediation: "Rotate the secret before expiration. Automate secret rotation.",
          evidence: `appId=${app.appId}, secretExpiry=${app.secretExpiry}, daysRemaining=${Math.floor(daysUntilExpiry)}`,
        })
      }
    }

    if (app.appRoles.length > 0) {
      const privilegedRoles = app.appRoles.filter(r =>
        /global|admin|owner|writer|contributor/i.test(r),
      )
      if (privilegedRoles.length > 0) {
        findings.push({
          id: makeId(),
          category: "OAUTH_CONSENT",
          severity: "HIGH",
          title: `App with Privileged Roles Assigned: ${app.displayName}`,
          description: `App "${app.displayName}" (${app.appId}) has privileged app roles: [${privilegedRoles.join(", ")}]. Compromise of this app grants elevated directory access.`,
          remediation: "Audit app role assignments. Remove unnecessary administrative roles. Implement just-in-time role activation.",
          evidence: `appId=${app.appId}, privilegedRoles=[${privilegedRoles.join(", ")}]`,
        })
      }
    }

    for (const uri of app.redirectUris) {
      if (uri.startsWith("http://") && !uri.includes("localhost")) {
        findings.push({
          id: makeId(),
          category: "OAUTH_CONSENT",
          severity: "CRITICAL",
          title: `Plaintext HTTP Redirect URI: ${app.displayName}`,
          description: `App "${app.displayName}" (${app.appId}) uses an insecure HTTP redirect URI: ${uri}. Authorization codes and tokens can be intercepted in transit.`,
          remediation: "Enforce HTTPS-only redirect URIs. Block insecure redirect URIs in tenant policy.",
          evidence: `appId=${app.appId}, redirectUri=${uri}`,
        })
      }
    }
  }

  const fido2FallbackMethods = [
    authMethod.smsEnabled && "SMS",
    authMethod.voiceEnabled && "Voice",
    authMethod.totpEnabled && "TOTP",
    authMethod.emailOtpEnabled && "Email OTP",
  ].filter(Boolean)

  if (authMethod.fido2.isFIDO2Enabled && fido2FallbackMethods.length > 0) {
    findings.push({
      id: makeId(),
      category: "MFA_POLICY",
      severity: "HIGH",
      title: "FIDO2 / WebAuthn MFA Fallback Enabled",
      description: `MFA policy permits downgrade from FIDO2 hardware security keys to weaker methods: [${fido2FallbackMethods.join(", ")}]. This enables phishing and SIM swap attacks.`,
      remediation: "Enforce FIDO2-only for administrative roles using Conditional Access. Disable SMS and voice MFA. Require phishing-resistant authentication.",
      evidence: `fido2.isEnforced=${authMethod.fido2.isEnforced}, fallbackMethods=[${fido2FallbackMethods.join(", ")}], selfServiceRegistration=${authMethod.fido2.allowSelfServiceRegistration}`,
    })
  }

  if (authMethod.fido2.allowSelfServiceRegistration) {
    findings.push({
      id: makeId(),
      category: "MFA_POLICY",
      severity: "MEDIUM",
      title: "FIDO2 Self-Service Registration Enabled",
      description: "Users can register FIDO2 security keys without administrator approval. Unvetted keys may not meet security requirements.",
      remediation: "Restrict FIDO2 key registration to administrator-approved keys. Enforce attestation requirements.",
      evidence: "fido2.allowSelfServiceRegistration=true, fido2.enforceAttestation=" + String(authMethod.fido2.enforceAttestation),
    })
  }

  if (authMethod.temporaryAccessPassEnabled) {
    findings.push({
      id: makeId(),
      category: "MFA_POLICY",
      severity: "MEDIUM",
      title: "Temporary Access Pass (TAP) Enabled",
      description: "Temporary Access Pass is enabled, allowing time-limited bypass codes. If not properly scoped, this can be abused for initial access.",
      remediation: "Restrict TAP creation to break-glass scenarios. Require admin approval for TAP issuance. Monitor TAP usage via audit logs.",
      evidence: "temporaryAccessPassEnabled=true",
    })
  }

  if (!tokenBinding.includeTokenBinding) {
    findings.push({
      id: makeId(),
      category: "TOKEN_BINDING",
      severity: "MEDIUM",
      title: "Token Binding Not Enforced",
      description: "Token binding is disabled. Access tokens are not bound to the requesting device, enabling token replay attacks if a token is exfiltrated.",
      remediation: "Enable token binding in the authentication methods policy. Configure Conditional Access policies to require token-bound tokens.",
      evidence: `tokenBinding.includeTokenBinding=${tokenBinding.includeTokenBinding}, tokenBindingType=${tokenBinding.tokenBindingType}`,
    })
  }

  return findings
}

// ─── Main Audit Function ──────────────────────────────────────────────────────

/**
 * Perform a full IdP & OAuth application security audit.
 *
 * DRY-RUN (default): returns simulated results with realistic findings.
 * LIVE (dryRun=false): queries Microsoft Graph API for real tenant data.
 *
 * @param config - IdP configuration with domain and optional tenantId
 * @param options - Audit options including dryRun flag and accessToken for live mode
 * @returns Audit result with findings, app registrations, and policy statuses
 */
export async function auditIdPAndOAuth(
  config: IdPConfig,
  options: IdPAuditOptions = { dryRun: true, domain: "" },
): Promise<IdPAuditResult> {
  resetFindings()

  const { dryRun = true, tenantId, accessToken } = options
  const domain = config.domain || options.domain

  if (dryRun) {
    return {
      domain,
      tenantId: tenantId || config.tenantId || null,
      highRiskOAuthApps: 0,
      totalOAuthApps: 0,
      fido2FallbackAllowed: false,
      tokenBindingEnforced: false,
      staleAppsCount: 0,
      exposedSecretsCount: 0,
      authMethodPolicy: null,
      tokenBindingPolicy: null,
      oauthApps: [],
      findings: [],
      isDryRun: true,
    }
  }

  // ── Live Mode ──────────────────────────────────────────────────────────────

  if (!accessToken) {
    return {
      domain,
      tenantId: tenantId || config.tenantId || null,
      highRiskOAuthApps: 0,
      totalOAuthApps: 0,
      fido2FallbackAllowed: false,
      tokenBindingEnforced: false,
      staleAppsCount: 0,
      exposedSecretsCount: 0,
      authMethodPolicy: EMPTY_AUTH_METHOD,
      tokenBindingPolicy: EMPTY_TOKEN_BINDING,
      oauthApps: [],
      findings: [{
        id: makeId(),
        category: "OAUTH_CONSENT",
        severity: "CRITICAL",
        title: "No Access Token Provided",
        description: "Live audit requires a Microsoft Graph API access token. No token was supplied in options.accessToken.",
        remediation: "Obtain a valid OAuth 2.0 access token with Application.Read.All, AuditLog.Read.All, and Policy.Read.* scopes. Pass it as options.accessToken.",
      }],
      isDryRun: false,
    }
  }

  if (!isToolAvailable("curl") && !globalThis.fetch) {
    return {
      domain,
      tenantId: tenantId || config.tenantId || null,
      highRiskOAuthApps: 0,
      totalOAuthApps: 0,
      fido2FallbackAllowed: false,
      tokenBindingEnforced: false,
      staleAppsCount: 0,
      exposedSecretsCount: 0,
      authMethodPolicy: EMPTY_AUTH_METHOD,
      tokenBindingPolicy: EMPTY_TOKEN_BINDING,
      oauthApps: [],
      findings: [{
        id: makeId(),
        category: "OAUTH_CONSENT",
        severity: "HIGH",
        title: "No HTTP Client Available",
        description: "Neither curl nor fetch() is available for Microsoft Graph API requests.",
        remediation: "Install curl or use a Node.js runtime with fetch() support.",
      }],
      isDryRun: false,
    }
  }

  try {
    const apps = await fetchOAuthAppsLive(accessToken, tenantId || config.tenantId)
    const authMethod = await fetchAuthMethodPolicyLive(accessToken)
    const tokenBinding = await fetchTokenBindingPolicyLive(accessToken)
    const findings = generateLiveFindings(apps, authMethod, tokenBinding)

    const highRiskOAuthApps = apps.filter(a =>
      a.apiPermissionScopes.some(p => HIGH_RISK_PERMISSIONS.has(p)),
    ).length

    return {
      domain,
      tenantId: tenantId || config.tenantId || null,
      highRiskOAuthApps,
      totalOAuthApps: apps.length,
      fido2FallbackAllowed: authMethod.smsEnabled || authMethod.voiceEnabled,
      tokenBindingEnforced: tokenBinding.includeTokenBinding,
      staleAppsCount: apps.filter(a => a.lastSignInDateTime === null).length,
      exposedSecretsCount: apps.filter(a => a.secretExpiry && new Date(a.secretExpiry).getTime() < Date.now()).length,
      authMethodPolicy: authMethod,
      tokenBindingPolicy: tokenBinding,
      oauthApps: apps,
      findings,
      isDryRun: false,
    }
  } catch (err) {
    return {
      domain,
      tenantId: tenantId || config.tenantId || null,
      highRiskOAuthApps: 0,
      totalOAuthApps: 0,
      fido2FallbackAllowed: false,
      tokenBindingEnforced: false,
      staleAppsCount: 0,
      exposedSecretsCount: 0,
      authMethodPolicy: EMPTY_AUTH_METHOD,
      tokenBindingPolicy: EMPTY_TOKEN_BINDING,
      oauthApps: [],
      findings: [{
        id: makeId(),
        category: "OAUTH_CONSENT",
        severity: "HIGH",
        title: "Live Audit Execution Error",
        description: `Microsoft Graph API query failed: ${err instanceof Error ? err.message : String(err)}`,
        remediation: "Verify the access token is valid, not expired, and has sufficient Graph API permissions. Check network connectivity.",
      }],
      isDryRun: false,
    }
  }
}

export default { auditIdPAndOAuth }
