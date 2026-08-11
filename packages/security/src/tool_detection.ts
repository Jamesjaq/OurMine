/**
 * Tool Detection Utility
 *
 * Checks if security tools are available on PATH, provides version info,
 * and offers graceful fallbacks when tools are missing.
 */

import { execFileSync } from "node:child_process"
import { which } from "./which.ts"

export interface ToolInfo {
  name: string
  available: boolean
  path: string | null
  version: string | null
  required: boolean
  installHint: string
}

const TOOL_DATABASE: Record<string, { installHint: string; required: boolean }> = {
  nmap: { installHint: "apt install nmap / brew install nmap", required: false },
  gobuster: { installHint: "go install github.com/OJ/gobuster/v3@latest", required: false },
  nuclei: { installHint: "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", required: false },
  masscan: { installHint: "apt install masscan / brew install masscan", required: false },
  ffuf: { installHint: "go install github.com/ffuf/ffuf/v2@latest", required: false },
  nikto: { installHint: "apt install nikto / brew install nikto", required: false },
  sqlmap: { installHint: "apt install sqlmap / pip install sqlmap", required: false },
  hydra: { installHint: "apt install hydra / brew install hydra", required: false },
  john: { installHint: "apt install john / brew install john", required: false },
  hashcat: { installHint: "apt install hashcat / brew install hashcat", required: false },
  smbclient: { installHint: "apt install smbclient / brew install samba", required: false },
  enum4linux: { installHint: "apt install enum4linux / pip install enum4linux-ng", required: false },
  snmpwalk: { installHint: "apt install snmp / brew install net-snmp", required: false },
  searchsploit: { installHint: "git clone https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb", required: false },
  msfvenom: { installHint: "apt install metasploit-framework / brew install metasploit", required: false },
  "impacket-secretsdump": { installHint: "pip install impacket", required: false },
  "impacket-wmiexec": { installHint: "pip install impacket", required: false },
  "impacket-ticketer": { installHint: "pip install impacket", required: false },
  "impacket-getTGT": { installHint: "pip install impacket", required: false },
  "evil-winrm": { installHint: "gem install evil-winrm", required: false },
  "bloodhound-python": { installHint: "pip install bloodhound", required: false },
  openssl: { installHint: "apt install openssl / brew install openssl", required: false },
  ssh: { installHint: "apt install openssh-client / brew install openssh", required: false },
  ncat: { installHint: "apt install nmap / brew install nmap", required: false },
  netcat: { installHint: "apt install netcat / brew install netcat", required: false },
  socat: { installHint: "apt install socat / brew install socat", required: false },
  ftp: { installHint: "apt install ftp / brew install ftp", required: false },
  curl: { installHint: "apt install curl / brew install curl", required: true },
  wget: { installHint: "apt install wget / brew install wget", required: false },
  dig: { installHint: "apt install dnsutils / brew install bind", required: false },
  host: { installHint: "apt install dnsutils / brew install bind", required: false },
  whois: { installHint: "apt install whois / brew install whois", required: false },
  ping: { installHint: "built-in on most systems", required: false },
  traceroute: { installHint: "apt install traceroute / brew install traceroute", required: false },
  git: { installHint: "apt install git / brew install git", required: false },
  python3: { installHint: "apt install python3 / brew install python3", required: false },
  theHarvester: { installHint: "git clone https://github.com/laramies/theHarvester.git", required: false },
  subfinder: { installHint: "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", required: false },
  amass: { installHint: "go install github.com/owasp-amass/amass/v4/...@master", required: false },
  whatweb: { installHint: "apt install whatweb / git clone https://github.com/urbanadventurer/WhatWeb.git", required: false },
  wpscan: { installHint: "gem install wpscan", required: false },
  droopescan: { installHint: "pip install droopescan", required: false },
  cmsmap: { installHint: "pip install cmsmap", required: false },
  dirb: { installHint: "apt install dirb", required: false },
  wfuzz: { installHint: "pip install wfuzz", required: false },
  "bpftool": { installHint: "apt install linux-tools-common / bpftool", required: false },
  kubectl: { installHint: "https://kubernetes.io/docs/tasks/tools/", required: false },
  docker: { installHint: "https://docs.docker.com/get-docker/", required: false },
  gh: { installHint: "apt install gh / brew install gh", required: false },
  adb: { installHint: "apt install adb / brew install android-platform-tools", required: false },
  msfconsole: { installHint: "apt install metasploit-framework / brew install metasploit", required: false },
  rpcclient: { installHint: "apt install samba / brew install samba", required: false },
  ldapsearch: { installHint: "apt install ldap-utils / brew install openldap", required: false },
  "impacket-GetUserSPNs": { installHint: "pip install impacket", required: false },
  "impacket-GetNPUsers": { installHint: "pip install impacket", required: false },
  "impacket-smbexec": { installHint: "pip install impacket", required: false },
  "impacket-psexec": { installHint: "pip install impacket", required: false },
  certipy: { installHint: "pip install certipy-ad", required: false },
  crackmapexec: { installHint: "pip install crackmapexec / apt install crackmapexec", required: false },
  netexec: { installHint: "pip install netexec", required: false },
  responder: { installHint: "apt install responder", required: false },
  feroxbuster: { installHint: "cargo install feroxbuster / apt install feroxbuster", required: false },
  rustscan: { installHint: "cargo install rustscan", required: false },
  tcpdump: { installHint: "apt install tcpdump", required: false },
  tshark: { installHint: "apt install tshark", required: false },
  evilginx: { installHint: "go install github.com/kgretzky/evilginx2@latest", required: false },
  evilginx2: { installHint: "go install github.com/kgretzky/evilginx2@latest", required: false },
  tor: { installHint: "apt install tor / brew install tor", required: false },
  "bitcoin-cli": { installHint: "apt install bitcoin-cli / brew install bitcoin", required: false },
  "monero-wallet-cli": { installHint: "apt install monero-wallet-cli", required: false },
  monerod: { installHint: "apt install monerod", required: false },
  electrum: { installHint: "apt install electrum / pip install electrum", required: false },
}

/** GUI or interactive tools — PATH check only, never spawn (avoids OWASP DirBuster GUI, msfconsole, etc.) */
const NO_EXEC_PROBE = new Set([
  "dirbuster",
  "msfconsole",
  "enum4linux",
  "searchsploit",
])

function shouldSkipVersionProbe(name: string): boolean {
  if (NO_EXEC_PROBE.has(name)) return true
  if (name.startsWith("impacket-")) return true
  return false
}

const toolCache = new Map<string, ToolInfo>()

function detectTool(name: string): ToolInfo {
  if (toolCache.has(name)) return toolCache.get(name)!

  const meta = TOOL_DATABASE[name] || { installHint: `Install ${name} manually`, required: false }

  try {
    const path = which(name)
    let version: string | null = null

    if (!shouldSkipVersionProbe(name)) {
      try {
        if (name === "nmap") {
          version = execFileSync(name, ["--version"], { timeout: 5000, encoding: "utf-8" }).match(/Nmap version (\S+)/)?.[1] || null
        } else if (name === "gobuster") {
          version = execFileSync(name, ["version"], { timeout: 5000, encoding: "utf-8" }).match(/v(\S+)/)?.[1] || null
        } else if (name === "nuclei") {
          version = execFileSync(name, ["-version"], { timeout: 5000, encoding: "utf-8" }).match(/current version (\S+)/)?.[1] || null
        } else if (name === "masscan") {
          version = execFileSync(name, ["--version"], { timeout: 5000, encoding: "utf-8" }).match(/version (\S+)/)?.[1] || null
        } else if (name === "sqlmap") {
          version = execFileSync(name, ["--version"], { timeout: 5000, encoding: "utf-8" }).trim() || null
        } else if (name === "curl") {
          version = execFileSync(name, ["--version"], { timeout: 5000, encoding: "utf-8" }).match(/curl (\S+)/)?.[1] || null
        } else if (name === "python3") {
          version = execFileSync(name, ["--version"], { timeout: 5000, encoding: "utf-8" }).match(/Python (\S+)/)?.[1] || null
        } else if (name === "theHarvester") {
          version = execFileSync(name, ["-h"], { timeout: 5000, encoding: "utf-8" }).match(/Current Version:\s*(\S+)/)?.[1] || null
        } else if (name === "hydra") {
          version = execFileSync(name, ["-h"], { timeout: 5000, encoding: "utf-8" }).match(/v(\d+\.\d+[^\s]*)/)?.[1] || null
        } else {
          version = execFileSync(name, ["--version"], { timeout: 5000, encoding: "utf-8" }).match(/\d+\.\d+(\.\d+)?/)?.[0] || null
        }
      } catch {
        version = null
      }
    }

    const info: ToolInfo = { name, available: true, path, version, required: meta.required, installHint: meta.installHint }
    toolCache.set(name, info)
    return info
  } catch {
    const info: ToolInfo = { name, available: false, path: null, version: null, required: meta.required, installHint: meta.installHint }
    toolCache.set(name, info)
    return info
  }
}

export function checkTools(...names: string[]): ToolInfo[] {
  return names.map(detectTool)
}

export function requireTools(...names: string[]): { ok: boolean; missing: ToolInfo[]; available: ToolInfo[] } {
  const results = checkTools(...names)
  const missing = results.filter(t => !t.available)
  const available = results.filter(t => t.available)
  return { ok: missing.length === 0, missing, available }
}

export function getToolPath(name: string): string | null {
  return detectTool(name).path
}

export function isToolAvailable(name: string): boolean {
  return detectTool(name).available
}

export function toolSummary(): string {
  const tools = Object.keys(TOOL_DATABASE).map(detectTool)
  const available = tools.filter(t => t.available)
  const missing = tools.filter(t => !t.available)

  const lines = [`Available: ${available.length}/${tools.length}`]
  for (const t of available) {
    lines.push(`  ✓ ${t.name}${t.version ? ` v${t.version}` : ""}`)
  }
  if (missing.length > 0) {
    lines.push(`Missing: ${missing.length}`)
    for (const t of missing) {
      lines.push(`  ✗ ${t.name} — ${t.installHint}`)
    }
  }
  return lines.join("\n")
}
