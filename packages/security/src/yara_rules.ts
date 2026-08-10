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
];

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
  const cleaned = [...new Set(strings.filter((s) => s && s.length >= 4))].sort();
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
