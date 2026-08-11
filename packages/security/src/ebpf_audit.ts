/**
 * @module security/ebpf_audit
 * Stealth Kernel Persistence & Probe Detection Engine (eBPF & Rootkits)
 * Audits system tracepoints, active eBPF programs/maps, and user-land LD_PRELOAD hooks.
 */

import { resolveDryRun } from "./exec_options.ts"
import * as fs from "node:fs"
import { execFileSync } from "node:child_process"
import { isToolAvailable } from "./tool_detection.ts"

export interface EBPFProgram {
  id: number
  type: string
  name: string
  loadedAt: string
  tag?: string
  uid?: number
  jited?: boolean
}

export interface EBPFMap {
  id: number
  type: string
  name: string
  keySize: number
  valueSize: number
  maxEntries: number
}

export interface LDPreloadEntry {
  path: string
  owner: string
  suspicious: boolean
  description: string
}

export interface EBPFAuditResult {
  ebpfSupported: boolean
  bpftoolAvailable: boolean
  bpfJitEnabled: boolean
  activeEBPFPrograms: EBPFProgram[]
  activeEBPFMaps: EBPFMap[]
  ldPreloadHooks: LDPreloadEntry[]
  ldPreloadEnvVar: string | null
  kernelTracepointsAudited: number
  tracepointCategories: string[]
  suspiciousPrograms: Array<{
    id: number
    name: string
    type: string
    reason: string
  }>
  findings: Array<{
    severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    title: string
    description: string
  }>
  isDryRun: boolean
}

function execCmd(cmd: string, args: string[]): string {
  try {
    return execFileSync(cmd, args, { timeout: 15000, encoding: "utf-8", stdio: ["pipe", "pipe", "pipe"] }).trim()
  } catch {
    return ""
  }
}

function readSysfsFile(path: string): string {
  try {
    if (fs.existsSync(path)) {
      return fs.readFileSync(path, "utf8").trim()
    }
  } catch {}
  return ""
}

function parseBpftoolProgList(output: string): EBPFProgram[] {
  const programs: EBPFProgram[] = []
  if (!output) return programs

  const lines = output.split("\n")
  let current: Partial<EBPFProgram> = {}

  for (const line of lines) {
    const trimmed = line.trim()
    if (trimmed.startsWith("#")) continue

    const idMatch = trimmed.match(/^(\d+):\s+(.+?)\s+name\s+(\S+)/)
    if (idMatch) {
      if (current.id !== undefined) {
        programs.push(current as EBPFProgram)
      }
      current = {
        id: parseInt(idMatch[1]),
        type: idMatch[2].trim(),
        name: idMatch[3],
        loadedAt: new Date().toISOString(),
      }
      continue
    }

    const tagMatch = trimmed.match(/tag\s+([a-f0-9]+)/)
    if (tagMatch && current) {
      current.tag = tagMatch[1]
    }

    const uidMatch = trimmed.match(/uid\s+(\d+)/)
    if (uidMatch && current) {
      current.uid = parseInt(uidMatch[1])
    }

    if (trimmed.includes("jited")) {
      current.jited = true
    }
  }

  if (current.id !== undefined) {
    programs.push(current as EBPFProgram)
  }

  return programs
}

function parseBpftoolMapList(output: string): EBPFMap[] {
  const maps: EBPFMap[] = []
  if (!output) return maps

  const lines = output.split("\n")
  let current: Partial<EBPFMap> = {}

  for (const line of lines) {
    const trimmed = line.trim()
    if (trimmed.startsWith("#")) continue

    const idMatch = trimmed.match(/^(\d+):\s+(.+?)\s+name\s+(\S+)/)
    if (idMatch) {
      if (current.id !== undefined) {
        maps.push(current as EBPFMap)
      }
      current = {
        id: parseInt(idMatch[1]),
        type: idMatch[2].trim(),
        name: idMatch[3],
        keySize: 0,
        valueSize: 0,
        maxEntries: 0,
      }
      continue
    }

    const keyMatch = trimmed.match(/key\s+(\d+)\s+bval/)
    if (keyMatch && current) {
      current.keySize = parseInt(keyMatch[1])
    }

    const valMatch = trimmed.match(/value\s+(\d+)\s+bval/)
    if (valMatch && current) {
      current.valueSize = parseInt(valMatch[1])
    }

    const maxMatch = trimmed.match(/max_entries\s+(\d+)/)
    if (maxMatch && current) {
      current.maxEntries = parseInt(maxMatch[1])
    }
  }

  if (current.id !== undefined) {
    maps.push(current as EBPFMap)
  }

  return maps
}

function parseTracepoints(output: string): { count: number; categories: string[] } {
  if (!output) return { count: 0, categories: [] }

  const categories = new Set<string>()
  const lines = output.split("\n").filter(l => l.trim() && !l.startsWith("#"))

  for (const line of lines) {
    const parts = line.trim().split(":")
    if (parts.length >= 2) {
      categories.add(parts[0].trim())
    }
  }

  return { count: lines.length, categories: Array.from(categories).sort() }
}

const SUSPICIOUS_PROG_TYPES = [
  "BPF_PROG_TYPE_XDP",
  "BPF_PROG_TYPE_TRACEPOINT",
  "BPF_PROG_TYPE_KPROBE",
  "BPF_PROG_TYPE_KRETPROBE",
  "BPF_PROG_TYPE_RAW_TRACEPOINT",
  "BPF_PROG_TYPE_LSM",
]

const SUSPICIOUS_MAP_TYPES = [
  "BPF_MAP_TYPE_RINGBUF",
  "BPF_MAP_TYPE_PERF_EVENT_ARRAY",
]

const KNOWN_ROOTKIT_NAMES = [
  "processhide", "diamorphine", "reptile", "adore", "kovid",
  "kmemleak", "heroin", "morphine", "suckit", "hide-and-seek",
]

function classifySuspicious(programs: EBPFProgram[]): Array<{ id: number; name: string; type: string; reason: string }> {
  const suspicious: Array<{ id: number; name: string; type: string; reason: string }> = []

  for (const prog of programs) {
    const reasons: string[] = []

    if (SUSPICIOUS_PROG_TYPES.includes(prog.type)) {
      reasons.push(`High-risk program type: ${prog.type}`)
    }

    if (prog.name && KNOWN_ROOTKIT_NAMES.some(r => prog.name.toLowerCase().includes(r))) {
      reasons.push(`Name matches known rootkit pattern: ${prog.name}`)
    }

    if (prog.uid === 0 && (prog.type.includes("KPROBE") || prog.type.includes("TRACEPOINT"))) {
      reasons.push("Root-owned kprobe/tracepoint program (possible syscall hooking)")
    }

    if (reasons.length > 0) {
      suspicious.push({
        id: prog.id,
        name: prog.name,
        type: prog.type,
        reason: reasons.join("; "),
      })
    }
  }

  return suspicious
}

function generateDryRunResult(): EBPFAuditResult {
  const fakePrograms: EBPFProgram[] = [
    {
      id: 42,
      type: "BPF_PROG_TYPE_XDP",
      name: "anti_forensics_xdp",
      loadedAt: new Date(Date.now() - 3600000).toISOString(),
      tag: "a1b2c3d4e5f6a7b8",
      uid: 0,
      jited: true,
    },
    {
      id: 78,
      type: "BPF_PROG_TYPE_KPROBE",
      name: "syscall_monitor",
      loadedAt: new Date(Date.now() - 7200000).toISOString(),
      tag: "f0e1d2c3b4a59687",
      uid: 0,
      jited: true,
    },
    {
      id: 103,
      type: "BPF_PROG_TYPE_TRACEPOINT",
      name: "hidden_process_filter",
      loadedAt: new Date(Date.now() - 1800000).toISOString(),
      tag: "1122334455667788",
      uid: 0,
      jited: false,
    },
    {
      id: 156,
      type: "BPF_PROG_TYPE_SOCKET_FILTER",
      name: "packet_capturer",
      loadedAt: new Date(Date.now() - 900000).toISOString(),
      tag: "deadbeefcafebabe",
      uid: 1000,
      jited: true,
    },
  ]

  const fakeMaps: EBPFMap[] = [
    {
      id: 10,
      type: "BPF_MAP_TYPE_HASH",
      name: "process_whitelist",
      keySize: 4,
      valueSize: 8,
      maxEntries: 256,
    },
    {
      id: 25,
      type: "BPF_MAP_TYPE_RINGBUF",
      name: "exfil_buffer",
      keySize: 0,
      valueSize: 0,
      maxEntries: 262144,
    },
  ]

  return {
    ebpfSupported: true,
    bpftoolAvailable: true,
    bpfJitEnabled: true,
    activeEBPFPrograms: fakePrograms,
    activeEBPFMaps: fakeMaps,
    ldPreloadHooks: [
      {
        path: "/etc/ld.so.preload",
        owner: "root",
        suspicious: true,
        description: "LD_PRELOAD entry pointing to untracked library '/lib/x86_64-linux-gnu/libprocesshide.so'",
      },
    ],
    ldPreloadEnvVar: "/usr/lib/libexec_wrapper.so",
    kernelTracepointsAudited: 1847,
    tracepointCategories: [
      "block", "bpf", "cgroup", "compaction", "enablement",
      "exceptions", "filemap", "hrtimer", "irq", "kmem",
      "migrate", "module", "nmi", "oom", "power",
      "raw_syscalls", "rcu", "sched", "signal", "skb",
      "sunrpc", "timer", "udp", "vfs", "writeback",
    ],
    suspiciousPrograms: [
      {
        id: 42,
        name: "anti_forensics_xdp",
        type: "BPF_PROG_TYPE_XDP",
        reason: "High-risk program type: BPF_PROG_TYPE_XDP; Root-owned kprobe/tracepoint program (possible syscall hooking)",
      },
      {
        id: 103,
        name: "hidden_process_filter",
        type: "BPF_PROG_TYPE_TRACEPOINT",
        reason: "High-risk program type: BPF_PROG_TYPE_TRACEPOINT; Root-owned kprobe/tracepoint program (possible syscall hooking)",
      },
    ],
    findings: [
      {
        severity: "CRITICAL",
        title: "User-land Rootkit Hook (LD_PRELOAD) Detected",
        description: "/etc/ld.so.preload contains active library hooks: /lib/x86_64-linux-gnu/libprocesshide.so — likely hiding processes from ps/top",
      },
      {
        severity: "CRITICAL",
        title: "Suspicious XDP Program Loaded",
        description: "Root-owned XDP program 'anti_forensics_xdp' (id=42) active on network interface. May perform packet interception or evasion.",
      },
      {
        severity: "HIGH",
        title: "Suspicious Tracepoint Program Detected",
        description: "Tracepoint program 'hidden_process_filter' (id=103) is root-owned and may be intercepting syscall results to hide artifacts.",
      },
      {
        severity: "HIGH",
        title: "LD_PRELOAD Environment Variable Set",
        description: "LD_PRELOAD environment variable is set to '/usr/lib/libexec_wrapper.so', enabling user-land library preloading.",
      },
      {
        severity: "MEDIUM",
        title: "Ring Buffer Map Used for Data Exfiltration",
        description: "eBPF map 'exfil_buffer' (id=25) of type RINGBUF with 256KB capacity may be used for covert data channel.",
      },
      {
        severity: "LOW",
        title: "BPF JIT Compilation Enabled",
        description: "BPF JIT compiler is enabled (bpf_jit_enable=1). Normal for systems running eBPF tooling but increases attack surface.",
      },
    ],
    isDryRun: true,
  }
}

export function auditEBPFAndPersistence(options: { dryRun?: boolean } = {}): EBPFAuditResult {
  const dryRun = options.dryRun !== false

  if (dryRun) {
    return generateDryRunResult()
  }

  const findings: EBPFAuditResult["findings"] = []
  const bpftoolAvail = isToolAvailable("bpftool")

  const ebpfSupported = fs.existsSync("/sys/fs/bpf") || fs.existsSync("/proc/sys/net/core/bpf_jit_enable")

  const jitRaw = readSysfsFile("/proc/sys/net/core/bpf_jit_enable")
  const bpfJitEnabled = jitRaw === "1"

  let programs: EBPFProgram[] = []
  if (bpftoolAvail) {
    const progOutput = execCmd("bpftool", ["prog", "list", "-j"])
    if (progOutput) {
      try {
        const parsed = JSON.parse(progOutput)
        if (Array.isArray(parsed)) {
          programs = parsed.map((p: any) => ({
            id: p.id ?? 0,
            type: p.type ?? "unknown",
            name: p.name ?? "unnamed",
            loadedAt: p.loaded_at ?? new Date().toISOString(),
            tag: p.tag,
            uid: p.uid,
            jited: p.jited ?? false,
          }))
        }
      } catch {
        const rawProg = execCmd("bpftool", ["prog", "list"])
        programs = parseBpftoolProgList(rawProg)
      }
    }
  }

  let maps: EBPFMap[] = []
  if (bpftoolAvail) {
    const mapOutput = execCmd("bpftool", ["map", "list", "-j"])
    if (mapOutput) {
      try {
        const parsed = JSON.parse(mapOutput)
        if (Array.isArray(parsed)) {
          maps = parsed.map((m: any) => ({
            id: m.id ?? 0,
            type: m.type ?? "unknown",
            name: m.name ?? "unnamed",
            keySize: m.key_size ?? 0,
            valueSize: m.value_size ?? 0,
            maxEntries: m.max_entries ?? 0,
          }))
        }
      } catch {
        const rawMap = execCmd("bpftool", ["map", "list"])
        maps = parseBpftoolMapList(rawMap)
      }
    }
  }

  let tracepointCount = 0
  let tracepointCategories: string[] = []
  const tracingPath = "/sys/kernel/debug/tracing/available_events"
  if (fs.existsSync(tracingPath)) {
    const tracingContent = readSysfsFile(tracingPath)
    const tp = parseTracepoints(tracingContent)
    tracepointCount = tp.count
    tracepointCategories = tp.categories
  }

  const ldHooks: LDPreloadEntry[] = []
  try {
    if (fs.existsSync("/etc/ld.so.preload")) {
      const content = fs.readFileSync("/etc/ld.so.preload", "utf8").trim()
      if (content) {
        const entries = content.split("\n").filter(l => l.trim())
        for (const entry of entries) {
          const trimmed = entry.trim()
          if (!trimmed.startsWith("#") && trimmed.length > 0) {
            const isSuspicious = !trimmed.startsWith("/") || KNOWN_ROOTKIT_NAMES.some(r => trimmed.toLowerCase().includes(r))
            ldHooks.push({
              path: "/etc/ld.so.preload",
              owner: "root",
              suspicious: isSuspicious,
              description: `Active preload library: ${trimmed}`,
            })
          }
        }
      }
    }
  } catch {}

  const ldEnvVar = process.env.LD_PRELOAD || null
  if (ldEnvVar) {
    findings.push({
      severity: "HIGH",
      title: "LD_PRELOAD Environment Variable Set",
      description: `LD_PRELOAD environment variable is set to '${ldEnvVar}', enabling user-land library preloading.`,
    })
  }

  const suspiciousPrograms = classifySuspicious(programs)

  for (const hook of ldHooks) {
    if (hook.suspicious) {
      findings.push({
        severity: "CRITICAL",
        title: "User-land Rootkit Hook (LD_PRELOAD) Detected",
        description: hook.description,
      })
    }
  }

  for (const sp of suspiciousPrograms) {
    const severity = sp.type.includes("XDP") ? "CRITICAL" : "HIGH"
    findings.push({
      severity,
      title: `Suspicious eBPF Program: ${sp.name}`,
      description: `Program id=${sp.id} type=${sp.type}. ${sp.reason}`,
    })
  }

  const suspiciousMaps = maps.filter(m => SUSPICIOUS_MAP_TYPES.includes(m.type))
  for (const sm of suspiciousMaps) {
    findings.push({
      severity: "MEDIUM",
      title: `Suspicious eBPF Map Type: ${sm.type}`,
      description: `Map '${sm.name}' (id=${sm.id}) uses type ${sm.type} which can be abused for covert data channels.`,
    })
  }

  if (bpfJitEnabled) {
    findings.push({
      severity: "LOW",
      title: "BPF JIT Compilation Enabled",
      description: "BPF JIT compiler is enabled (bpf_jit_enable=1). Normal for systems running eBPF tooling but increases attack surface.",
    })
  }

  if (!ebpfSupported) {
    findings.push({
      severity: "LOW",
      title: "eBPF Subsystem Not Detected",
      description: "/sys/fs/bpf and /proc/sys/net/core/bpf_jit_enable not found. System may not support eBPF or is running in a container.",
    })
  }

  if (!bpftoolAvail) {
    findings.push({
      severity: "MEDIUM",
      title: "bpftool Not Available",
      description: "bpftool is not installed. Cannot enumerate eBPF programs/maps. Install with: apt install linux-tools-common",
    })
  }

  return {
    ebpfSupported,
    bpftoolAvailable: bpftoolAvail,
    bpfJitEnabled,
    activeEBPFPrograms: programs,
    activeEBPFMaps: maps,
    ldPreloadHooks: ldHooks,
    ldPreloadEnvVar: ldEnvVar,
    kernelTracepointsAudited: tracepointCount,
    tracepointCategories,
    suspiciousPrograms,
    findings,
    isDryRun: false,
  }
}

export default { auditEBPFAndPersistence }
