/**
 * @module caldera_ttp
 * MITRE Caldera TTP executor — loads adversary profiles (YAML/JSON), resolves
 * abilities, renders Caldera-style fact templates, and executes TTPs.
 */

import { resolveDryRun } from "./exec_options.ts"
import * as fs from "node:fs";
import * as path from "node:path";
import * as crypto from "node:crypto";
import { spawnSync } from "node:child_process";

// ─── Models ───────────────────────────────────────────────────────────────────

export interface Executor {
  name: string;         // "sh" | "psh" | "cmd" | "python"
  platform: string;    // "linux" | "windows" | "darwin"
  command: string;
  cleanup: string[];
  parsers: Array<{ module: string; relationships: Array<{ source: string; edge?: string; target?: string }> }>;
  timeout: number;
  payloads: string[];
  uploads: string[];
}

export interface Ability {
  ability_id: string;
  name: string;
  description: string;
  tactic: string;
  technique_id: string;
  technique_name: string;
  executors: Executor[];
  requirements: Array<{ module: string; relationship_match: Array<{ edge: string; target?: string; source?: string }> }>;
  privilege: string;
  repeatable: boolean;
  buckets: string[];
}

export interface Adversary {
  adversary_id: string;
  name: string;
  description: string;
  atomic_ordering: string[];   // ability IDs
  objective: string;
  tags: string[];
  abilities?: Map<string, Ability>;
}

export interface ExecutionResult {
  abilityId: string;
  executorName: string;
  command: string;
  output: string;
  exitCode: number;
  facts: Record<string, string>;
  dryRun: boolean;
  timestamp: string;
}

export interface CalderaOptions {
  live?: boolean;
  platform?: string;
  executor?: string;
  facts?: Record<string, string>;
  profilesDir?: string;
}

// ─── Template rendering ───────────────────────────────────────────────────────

/**
 * Render a Caldera `#{fact.key}` template with a facts dictionary.
 */
export function renderTemplate(template: string, facts: Record<string, string>): string {
  let rendered = template;
  for (const [key, value] of Object.entries(facts)) {
    rendered = rendered.replaceAll(`#{${key}}`, value);
  }
  // Strip unresolved facts
  return rendered.replace(/#\{[^}]+\}/g, "");
}

// ─── YAML-lite loader (no external dep) ──────────────────────────────────────

function parseSimpleYaml(text: string): Record<string, unknown> {
  // For Caldera profiles we only need top-level keys and string arrays.
  // Use JSON.parse fallback first; otherwise best-effort regex parse.
  try { return JSON.parse(text); } catch {/* not JSON */}

  const result: Record<string, unknown> = {};
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const match = lines[i].match(/^(\w[\w_-]*):\s*(.*)$/);
    if (match) {
      const [, key, val] = match;
      result[key] = val.trim().replace(/^["']|["']$/g, "");
    }
  }
  return result;
}

// ─── Profile loader ───────────────────────────────────────────────────────────

/**
 * Load an adversary profile from a YAML or JSON file.
 */
export function loadAdversary(filePath: string): Adversary {
  const text = fs.readFileSync(filePath, "utf8");
  const raw = parseSimpleYaml(text) as Record<string, unknown>;
  return {
    adversary_id: String(raw["adversary_id"] ?? raw["id"] ?? crypto.randomUUID()),
    name: String(raw["name"] ?? ""),
    description: String(raw["description"] ?? ""),
    atomic_ordering: (raw["atomic_ordering"] as string[]) ?? [],
    objective: String(raw["objective"] ?? ""),
    tags: (raw["tags"] as string[]) ?? [],
  };
}

/**
 * Load all abilities from a directory of YAML/JSON files.
 */
export function loadAbilities(dirPath: string): Map<string, Ability> {
  const abilities = new Map<string, Ability>();
  if (!fs.existsSync(dirPath)) return abilities;

  const files = fs.readdirSync(dirPath).filter((f) => f.endsWith(".yml") || f.endsWith(".yaml") || f.endsWith(".json"));
  for (const file of files) {
    try {
      const text = fs.readFileSync(path.join(dirPath, file), "utf8");
      const raw = parseSimpleYaml(text) as Record<string, unknown>;
      const ability: Ability = {
        ability_id: String(raw["ability_id"] ?? raw["id"] ?? file),
        name: String(raw["name"] ?? ""),
        description: String(raw["description"] ?? ""),
        tactic: String(raw["tactic"] ?? "").toLowerCase(),
        technique_id: String(raw["technique_id"] ?? ""),
        technique_name: String(raw["technique_name"] ?? ""),
        executors: (raw["executors"] as Executor[]) ?? [],
        requirements: (raw["requirements"] as Ability["requirements"]) ?? [],
        privilege: String(raw["privilege"] ?? ""),
        repeatable: Boolean(raw["repeatable"] ?? false),
        buckets: (raw["buckets"] as string[]) ?? [],
      };
      abilities.set(ability.ability_id, ability);
    } catch {/* skip malformed */}
  }
  return abilities;
}

// ─── TTP Executor ─────────────────────────────────────────────────────────────

/**
 * Execute a single Caldera ability (one TTP step).
 * DRY-RUN: renders the command and returns it without executing.
 * LIVE: spawns the appropriate shell.
 */
export async function executeAbility(
  ability: Ability,
  opts: CalderaOptions = {}
): Promise<ExecutionResult> {
  const {
    live = false,
    platform = process.platform === "win32" ? "windows" : process.platform === "darwin" ? "darwin" : "linux",
    executor: preferredExec = platform === "linux" ? "sh" : "psh",
    facts = {},
  } = opts;

  // Find matching executor
  const exec = ability.executors.find(
    (e) => e.platform === platform && (e.name === preferredExec || !preferredExec)
  ) ?? ability.executors[0];

  if (!exec) {
    return {
      abilityId: ability.ability_id,
      executorName: "",
      command: "",
      output: "No compatible executor found",
      exitCode: -1,
      facts,
      dryRun: !live,
      timestamp: new Date().toISOString(),
    };
  }

  const command = renderTemplate(exec.command, facts);

  if (!live) {
    return {
      abilityId: ability.ability_id,
      executorName: exec.name,
      command,
      output: `[DRY-RUN] would execute: ${command}`,
      exitCode: 0,
      facts,
      dryRun: true,
      timestamp: new Date().toISOString(),
    };
  }

  // Live execution
  const shell = exec.name === "psh" ? "powershell.exe"
    : exec.name === "cmd" ? "cmd.exe"
    : exec.name === "python" ? "python3"
    : "/bin/sh";

  const shellArg = exec.name === "cmd" ? "/c"
    : exec.name === "psh" ? "-Command"
    : "-c";

  const r = spawnSync(shell, [shellArg, command], {
    encoding: "utf8",
    timeout: (exec.timeout || 60) * 1000,
  });

  return {
    abilityId: ability.ability_id,
    executorName: exec.name,
    command,
    output: (r.stdout ?? "") + (r.stderr ?? ""),
    exitCode: r.status ?? -1,
    facts,
    dryRun: false,
    timestamp: new Date().toISOString(),
  };
}

/**
 * Execute a full adversary profile — run each ability in atomic order.
 */
export async function executeAdversary(
  adversary: Adversary,
  abilities: Map<string, Ability>,
  opts: CalderaOptions = {}
): Promise<ExecutionResult[]> {
  const results: ExecutionResult[] = [];
  const facts: Record<string, string> = { ...(opts.facts ?? {}) };

  for (const abilityId of adversary.atomic_ordering) {
    const ability = abilities.get(abilityId);
    if (!ability) continue;
    const result = await executeAbility(ability, { ...opts, facts });
    results.push(result);
    // Extract facts from output (simplified — full Caldera uses parser modules)
    if (result.output) {
      facts[`result.${ability.tactic}`] = result.output.trim().split("\n")[0] ?? "";
    }
  }

  return results;
}

export default { loadAdversary, loadAbilities, executeAbility, executeAdversary, renderTemplate };
