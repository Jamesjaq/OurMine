/**
 * Builtin YARA detection rule catalog (port of `modules/yara.rules`).
 *
 * The catalog encodes the *detection shapes* blue teams actually hunt for
 * across the techniques VANTA emulates — the same signatures an operator's
 * payload would trip in a real environment. Scanning generated payloads
 * against these before deployment is the OPSEC self-check.
 */

export const BUILTIN_RULES: readonly string[] = [
  // AMSI bypass — reflection patch (Matt Graeber style)
  `rule detect_amsi_reflection {
    meta:
        description = "AMSI bypass via reflection (amsiInitFailed)"
        author = "VANTA builtin"
        attack_id = "T1562.001"
        attack_name = "Impair Defenses"
    strings:
        $a = "amsiInitFailed" ascii wide nocase
        $b = "AmsiUtils" ascii wide nocase
    condition:
        any of them
}
`,
  // AMSI bypass — memory patch byte sequence (mov eax, 0x80070057; ret)
  `rule detect_amsi_memory_patch {
    meta:
        description = "AMSI bypass via in-process memory patch"
        author = "VANTA builtin"
        attack_id = "T1562.001"
    strings:
        $a = { B8 57 00 07 80 C3 }            // mov eax,0x80070057; ret
        $b = "AmsiContext" ascii wide nocase
        $c = "WriteByte" ascii wide nocase
    condition:
        any of them
}
`,
  // In-memory PowerShell download-and-execute
  `rule detect_ps_download_cradle {
    meta:
        description = "PowerShell download cradle (IEX + DownloadString)"
        author = "VANTA builtin"
        attack_id = "T1059.001"
    strings:
        $a = "DownloadString" ascii wide nocase
        $b = "IEX (New-Object" ascii wide nocase
        $c = "Invoke-Expression" ascii wide nocase
        $d = "-enc" ascii wide nocase
    condition:
        any of them
}
`,
  // certutil download/decode (LotL downloader)
  `rule detect_certutil_download {
    meta:
        description = "certutil used as downloader/decoder"
        author = "VANTA builtin"
        attack_id = "T1105"
    strings:
        $a = "certutil" ascii wide nocase
        $b = "-urlcache" ascii wide nocase
        $c = "-decode" ascii wide nocase
    condition:
        $a and ($b or $c)
}
`,
  // mshta remote scriptlet execution
  `rule detect_mshta_scriptlet {
    meta:
        description = "mshta executing remote scriptlet"
        author = "VANTA builtin"
        attack_id = "T1218.005"
    strings:
        $a = "mshta" ascii wide nocase
        $b = "script:" ascii wide nocase
        $c = "GetObject" ascii wide nocase
    condition:
        $a and $b and $c
}
`,
  // regsvr32 squiblydoo
  `rule detect_regsvr32_squiblydoo {
    meta:
        description = "regsvr32 scrobj.dll scriptlet execution"
        author = "VANTA builtin"
        attack_id = "T1218.010"
    strings:
        $a = "regsvr32" ascii wide nocase
        $b = "scrobj.dll" ascii wide nocase
        $c = "/i:" ascii wide nocase
    condition:
        $a and $b and $c
}
`,
  // Log clearing
  `rule detect_log_clearing {
    meta:
        description = "Windows event log clearing"
        author = "VANTA builtin"
        attack_id = "T1070.004"
    strings:
        $a = "wevtutil" ascii wide nocase
        $b = "cl Security" ascii wide nocase
        $c = "cl System" ascii wide nocase
    condition:
        $a and any of them
}
`,
  // NTDS dump
  `rule detect_ntds_dump {
    meta:
        description = "NTDS.dit capture via ntdsutil"
        author = "VANTA builtin"
        attack_id = "T1003.003"
    strings:
        $a = "ntdsutil" ascii wide nocase
        $b = "create full" ascii wide nocase
    condition:
        $a and $b
}
`,
  // Encoded PowerShell (-enc / -encodedcommand)
  `rule detect_encoded_ps {
    meta:
        description = "PowerShell -enc base64 execution"
        author = "VANTA builtin"
        attack_id = "T1059.001"
    strings:
        $a = "-enc" ascii wide nocase
        $b = "-encodedcommand" ascii wide nocase
    condition:
        any of them
}
`,
  // ─── vx-derived detection shapes (metadata only, no payloads) ───
  `rule detect_stealer_prynt {
    meta:
        description = "PryntStealer / infostealer string artifacts"
        author = "OurMine vx-index"
        ruleset = "stealer"
        attack_id = "T1555"
    strings:
        $a = "PryntStealer" ascii wide nocase
        $b = "BrowserPasswords" ascii wide nocase
        $c = "DiscordToken" ascii wide nocase
    condition:
        2 of them
}
`,
  `rule detect_botnet_mirai {
    meta:
        description = "Mirai botnet family strings"
        author = "OurMine vx-index"
        ruleset = "botnet"
        attack_id = "T1584.005"
    strings:
        $a = "/bin/busybox" ascii
        $b = "mirai" ascii nocase
        $c = "POST /cdn-cgi/" ascii
    condition:
        2 of them
}
`,
  `rule detect_rootkit_bpfdoor {
    meta:
        description = "BPFDoor passive rootkit markers"
        author = "OurMine vx-index"
        ruleset = "rootkit"
        attack_id = "T1014"
    strings:
        $a = "BPFDoor" ascii nocase
        $b = "libpcap" ascii nocase
        $c = "magic packet" ascii nocase
    condition:
        any of them
}
`,
  `rule detect_agentic_llm_keys {
    meta:
        description = "LLM API key strings in scripts/logs (agentic abuse)"
        author = "OurMine vx-index"
        ruleset = "agentic"
        attack_id = "T1552.001"
    strings:
        $a = "sk-ant-" ascii
        $b = "sk-proj-" ascii
        $c = "OPENAI_API_KEY" ascii nocase
        $d = "anthropic.com" ascii nocase
    condition:
        any of them
}
`,
  `rule detect_sorry_ransomware {
    meta:
        description = "Sorry ransomware .sorry extension / header markers"
        author = "OurMine vx-index"
        ruleset = "ransomware"
        attack_id = "T1486"
    strings:
        $a = ".sorry" ascii nocase
        $b = "SORRY" ascii wide nocase
        $c = { 00 00 08 09 }
    condition:
        any of them
}
`,
  `rule detect_encforge_ml_ext {
    meta:
        description = "ENCFORGE ML model extension sweep"
        author = "OurMine vx-index"
        ruleset = "ransomware"
        attack_id = "T1486"
    strings:
        $a = ".safetensors" ascii nocase
        $b = ".gguf" ascii nocase
        $c = ".ckpt" ascii nocase
    condition:
        any of them
}
`,
];

/** Rules grouped by vx-underground family category for selective OPSEC scans. */
export const RULESETS: Record<string, string[]> = {
  stealer: ["detect_stealer_prynt"],
  botnet: ["detect_botnet_mirai"],
  rootkit: ["detect_rootkit_bpfdoor"],
  agentic: ["detect_agentic_llm_keys"],
  ransomware: ["detect_sorry_ransomware", "detect_encforge_ml_ext"],
};

function extractRuleNameFromSource(source: string): string {
  for (const raw of source.split("\n")) {
    const line = raw.trim()
    if (line.startsWith("rule ")) {
      return line.split(/\s+/)[1]?.replace(/\{$/, "") ?? ""
    }
  }
  return ""
}

export function rulesForRuleset(name: string): string[] {
  if (name === "default") return [...BUILTIN_RULES]
  const names = new Set(RULESETS[name] ?? [])
  return BUILTIN_RULES.filter((r) => names.has(extractRuleNameFromSource(r)))
}

// ------------------------------------------------------------------------- //
// Rule generation from findings
// ------------------------------------------------------------------------- //

export function sanitizeRuleName(name: string): string {
  let safe = name.replace(/[^a-zA-Z0-9_]/g, "_").replace(/^_+|_+$/g, "").toLowerCase();
  if (!safe) safe = "detected";
  if (/^\d/.test(safe)) safe = `d_${safe}`;
  return safe.slice(0, 120);
}

export function escapeString(value: string): string {
  return value
    .replace(/\\/g, "\\\\")
    .replace(/"/g, '\\"')
    .replace(/\n/g, "\\n")
    .replace(/\r/g, "\\r")
    .replace(/\t/g, "\\t");
}

export function ruleFromStrings(
  name: string,
  strings: string[],
  opts: {
    description?: string;
    attackId?: string;
    condition?: string;
    author?: string;
  } = {},
): string {
  const { description = "", attackId = "", condition = "any of them", author = "VANTA" } = opts;
  const cleaned = Array.from(new Set(strings.filter((s) => s && s.length >= 4))).sort();
  if (!cleaned.length) {
    throw new Error("rule_from_strings: no usable strings (need >=4 chars each)");
  }
  const entries = cleaned
    .map((s, i) => `        $s${i} = "${escapeString(s)}" ascii wide nocase`)
    .join("\n");
  const meta = [
    `        description = "${escapeString(description.slice(0, 200))}"`,
    `        author = "${escapeString(author)}"`,
  ];
  if (attackId) meta.push(`        attack_id = "${escapeString(attackId)}"`);
  return (
    `rule ${sanitizeRuleName(name)} {\n` +
    "    meta:\n" +
    meta.join("\n") +
    "\n" +
    "    strings:\n" +
    entries +
    "\n" +
    `    condition:\n        ${condition}\n` +
    "}\n"
  );
}

export function generateRuleFromFinding(finding: Record<string, unknown>): string {
  const name = String(finding.title ?? finding.name ?? "finding");
  const techniqueId = String(finding.technique_id ?? "");
  const evidence: string[] = [];
  for (const field of ["payload", "command", "evidence", "stdout", "stager"]) {
    const value = finding[field];
    if (typeof value === "string" && value.trim()) evidence.push(value);
  }
  return ruleFromStrings(sanitizeRuleName(name), evidence, {
    description: String(finding.description ?? name),
    attackId: techniqueId,
  });
}
