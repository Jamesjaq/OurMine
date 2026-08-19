/**
 * YARA scan engine — TypeScript port of `modules/yara`.
 *
 * The Python original uses `yara-python` when available and falls back to a
 * documented pure-Python substring matcher over the rules' plain strings.
 * Node has no native YARA binding here, so this port ships the fallback
 * matcher (clearly flagged via `engine: "fallback"`), keeping the exact
 * same public shape: compile a rule set, scan text, extract matched strings.
 *
 * All scanning is read-only: it never executes payloads.
 */

import { readFile } from "node:fs/promises";

import { BUILTIN_RULES } from "./yara_rules.ts";

export interface YaraMatch {
  rule: string;
  description: string;
  attackId: string;
  strings: string[];
  /** "yara" | "fallback" — fallback means a degraded substring match. */
  engine: "yara" | "fallback";
}

/** Native yara-python is not available in the Node runtime. */
export function engineAvailable(): boolean {
  return false;
}

// ------------------------------------------------------------------------- //
// Fallback rule-source helpers
// ------------------------------------------------------------------------- //

export function extractRuleName(source: string): string {
  for (const raw of source.split("\n")) {
    const line = raw.trim();
    if (line.startsWith("rule ")) {
      const parts = line.split(/\s+/);
      const name = parts[1] ?? "";
      return name.replace(/\{$/, "").trim();
    }
  }
  return "unknown";
}

export function extractMeta(source: string, key: string): string {
  for (const raw of source.split("\n")) {
    const line = raw.trim();
    if (line.startsWith(`${key} =`)) {
      return line.split("=", 2)[1]?.trim().replace(/^"|"$/g, "") ?? "";
    }
  }
  return "";
}

export function extractLiterals(source: string): string[] {
  const literals: string[] = [];
  for (const raw of source.split("\n")) {
    const line = raw.trim();
    if (!line.startsWith("$")) continue;
    if (!line.includes("=")) continue;
    const rhs = line.split("=", 2)[1]?.trim() ?? "";
    if (!rhs.startsWith('"')) continue;
    const end = rhs.indexOf('"', 1);
    if (end !== -1) literals.push(rhs.slice(1, end));
  }
  return literals;
}

// ------------------------------------------------------------------------- //
// Engine
// ------------------------------------------------------------------------- //

export class YaraEngine {
  rules: string[];
  private compiled: unknown = null;
  private fallback = false;
  errors: string[] = [];

  constructor(rules?: string[] | readonly string[]) {
    this.rules = rules ? [...rules] : [...BUILTIN_RULES];
    this.compile();
  }

  private compile(): void {
    if (engineAvailable()) {
      try {
        // Native path never triggers in Node; kept for parity with the port.
        this.compiled = { rules: this.rules };
        return;
      } catch (exc) {
        this.errors.push(`yara compile failed, using fallback: ${exc instanceof Error ? exc.message : String(exc)}`);
      }
    }
    this.fallback = true;
    this.compiled = null;
  }

  get usingNative(): boolean {
    return !this.fallback;
  }

  scanText(text: string, ruleName?: string): YaraMatch[] {
    if (!text) return [];
    if (this.compiled !== null) return this.scanNative(text, ruleName);
    return this.scanFallback(text, ruleName);
  }

  async scanFile(path: string, ruleName?: string): Promise<YaraMatch[]> {
    const content = await readFile(path, "utf-8");
    return this.scanText(content, ruleName);
  }

  private scanNative(_text: string, _ruleName?: string): YaraMatch[] {
    // Parity stub — unreachable in Node without a native binding.
    return [];
  }

  private scanFallback(text: string, ruleName?: string): YaraMatch[] {
    const matches: YaraMatch[] = [];
    const lowered = text.toLowerCase();
    for (const ruleSrc of this.rules) {
      const name = extractRuleName(ruleSrc);
      if (ruleName && name !== ruleName) continue;
      const literals = extractLiterals(ruleSrc);
      if (!literals.length) continue;
      const hit = literals.filter((lit) => lowered.includes(lit.toLowerCase()));
      if (hit.length) {
        matches.push({
          rule: name,
          description: extractMeta(ruleSrc, "description"),
          attackId: extractMeta(ruleSrc, "attack_id"),
          strings: [...new Set(hit)],
          engine: "fallback",
        });
      }
    }
    return matches;
  }

  /** Generate a new YARA rule for a specific technique or pattern. */
  static generateRule(name: string, description: string, attackId: string, patterns: string[]): string {
    const strings = patterns.map((p, i) => `    $s${i} = "${p}"`).join("\n");
    const condition = patterns.map((_, i) => `$s${i}`).join(" or ");
    
    return `rule ${name.replace(/[^a-zA-Z0-9_]/g, "_")} {
  meta:
    description = "${description.replace(/"/g, '\\"')}"
    attack_id = "${attackId}"
    author = "OurMine ARES Autonomous Generator"
  strings:
${strings}
  condition:
    ${condition}
}`;
  }
}

// ------------------------------------------------------------------------- //
// Convenience API
// ------------------------------------------------------------------------- //

let ENGINE: YaraEngine | null = null;

function defaultEngine(): YaraEngine {
  if (ENGINE === null) ENGINE = new YaraEngine();
  return ENGINE;
}

export function scanText(text: string, ruleName?: string): YaraMatch[] {
  return defaultEngine().scanText(text, ruleName);
}

export function scanPayload(payload: string): YaraMatch[] {
  return defaultEngine().scanText(payload);
}
