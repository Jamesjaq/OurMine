/**
 * @module browser_ext
 * Malicious Browser Extension & Web Injection Suite — Extension Manifest V3 Keylogger,
 * Session Cookie Exfiltrator, Tab Hijacking Simulator, and DOM Credential Harvester.
 */

export interface ExtensionManifest {
  name: string;
  version: string;
  manifest_version: number;
  permissions: string[];
}

export function buildMaliciousExtensionManifest(name = "Chrome Security Extension"): ExtensionManifest {
  return {
    name,
    version: "1.0.0",
    manifest_version: 3,
    permissions: ["cookies", "tabs", "webRequest", "<all_urls>"],
  };
}

export default { buildMaliciousExtensionManifest };
