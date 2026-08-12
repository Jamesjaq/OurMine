# OurMine ⛏️

**Autonomous penetration testing platform on OpenCode**

OurMine ships the **ARES Security Suite** — an engagement engine with 119+ MCP tools, 2026-aligned threat intel, and a ValidationEngine that promotes findings to **CONFIRMED** only when evidence exists. Real execution on Kali when authorized; dry-run by default everywhere else.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/Jamesjaq/OurMine/main/install.sh | bash
```

Then run:

```bash
ourmine
```

OpenCode TUI launches with ARES wired automatically. Pick a model with `/model`, declare a target and scope, and start an engagement.

**Requires:** [Node.js](https://nodejs.org/) 20+, `git`, and [OpenCode](https://opencode.ai) (installed automatically if missing).

<details>
<summary>Manual install</summary>

```bash
git clone https://github.com/Jamesjaq/OurMine.git ~/.ourmine
cd ~/.ourmine && npm install && npm link --force
ourmine
```

</details>

## Uninstall

Remove the CLI and install directory:

```bash
curl -fsSL https://raw.githubusercontent.com/Jamesjaq/OurMine/main/uninstall.sh | bash
```

Also remove OurMine MCP, pentest agent, and TUI plugin from OpenCode config:

```bash
curl -fsSL https://raw.githubusercontent.com/Jamesjaq/OurMine/main/uninstall.sh | bash -s -- --purge-config
```

This does **not** uninstall OpenCode itself.

<details>
<summary>Manual uninstall</summary>

```bash
npm unlink -g ourmine 2>/dev/null || npm rm -g ourmine
rm -rf ~/.ourmine
# optional: delete ares MCP + pentest agent from ~/.config/opencode/
```

</details>

## Canonical engagement workflow

The default path is the **engagement engine**, not PentestGPT:

```
ares_threat_intel → ares_engagement_slice → ares_engagement_continue → ares_autopilot
```

| Tool | Role |
|------|------|
| `ares_engagement_slice` | Plan + intel prefetch + first phase + evidence graph (~400B compact response) |
| `ares_engagement_continue` | Next phase via `resumeToken` — no re-planning |
| `ares_autopilot` | Server-side slice → continue loop until stop conditions |
| `ares_artifact_get` | Full phase/batch detail when `artifactId` is returned |

`ares_pentest_run` (PentestGPT) remains available for ad-hoc LLM-steered tasks but is **not** the default — it costs ~40× more tokens per campaign. See [ORCHESTRATION.md](packages/security/docs/ORCHESTRATION.md).

### Example session

```
/model
Target corp.example.com, identity-first assessment, scope corp.example.com
```

The pentest agent calls `ares_engagement_slice`, reads `graphNextActions` and `blockers`, then continues or hands off to `ares_autopilot`.

On first launch, OurMine auto-wires:
- **ARES MCP server** (`ares`) — curated efficient tool surface
- **`pentest` agent** — engagement-engine-first workflow
- **Dry-run default** — simulation with evidence; live probes require RoE (below)
- **Credential graph + engagement memory** — chained pivots across turns

## Safety and ROE defaults

| Posture | Behavior |
|---------|----------|
| **Dry-run (default)** | All modules simulate; produces engagement-graph evidence without live probes |
| **Live execution** | Requires `OURMINE_ROE_SIGNED=1` after written scope authorization; Kali/`OURMINE_LIVE=1`/`--live` enable real probes |
| **Extortion-only (dry-run default)** | Ransomware impact simulates catalog/leak paths; encrypt/VSS wipe require `OURMINE_FORCE_LIVE=1` + RoE |
| **Scope enforcement** | Targets outside declared scope are blocked by `engagement_policy` |

Set `OURMINE_ALLOW_DRY_RUN=1` to force simulation even on Kali (CI/dev). See [LIVE_ENGAGEMENT.md](packages/security/LIVE_ENGAGEMENT.md) for env vars.

## Key capabilities (2026)

- **Threat intel** — APT profiles, CISA KEV, ransomwatch cache, MITRE technique mappings; prefetch via `intel_autonomous` with artifact indirection (no inline dumps)
- **IAB market tradecraft** — stealer-log → VPN/RDP access → RaaS affiliate handoff patterns
- **Device-code phishing** — Entra/Okta/Google device-code flow assessment in identity-first campaigns
- **Extortion-only mode** — realistic 2025+ ransomware simulation without destructive encrypt ops
- **OT paired-ops** — SYLVANITE/VOLTZITE hybrid IT/OT chains via `hybrid_pivot`, `ot_batch_scan`, `ics_impact_proof`
- **ValidationEngine** — the **only** path to CONFIRMED findings; evidence-backed promotion via `ValidationPlanner` → `ToolBroker`; LLM cannot bypass

## Token efficiency

ARES steers a compact engagement loop instead of exposing 119+ tools individually to the LLM:

| Mode | Typical cost |
|------|--------------|
| Slice + 2× continue | **~941B** over 3 turns |
| Hypothetical 20-tool OpenCode sprawl | **~37KB** over 20 turns |

Intel, phase output, and graph state go to disk artifacts (`.ourmine/ares/artifacts/`); MCP responses return compact fields + `artifactId`. Details: [TOKEN_EFFICIENCY.md](packages/security/docs/TOKEN_EFFICIENCY.md).

## Security CLI (headless)

| Command | Description |
|---------|-------------|
| `ourmine recon <domain>` | AI-driven OSINT + subdomain recon |
| `ourmine audit <target>` | Container / cloud security audit |
| `ourmine pentest <target>` | Legacy PentestGPT path (prefer engagement engine in TUI) |
| `ourmine agent <target>` | LLM-driven pentest agent (no TUI) |
| `ourmine yara <path>` | YARA rulepack scan |
| `ourmine toolcheck` | Security tool availability report |
| `ourmine serve` | Start ARES MCP server (stdio) |
| `ourmine modules` | List all module namespaces |

Flags: `--live` (real execution), `--dry-run` (force simulation), `--require-live` (fail if tools missing).

## Architecture

```
OpenCode TUI / Cursor MCP
         ↓
   mcp_server.ts (ARES MCP)
         ↓
   engagement_slice → engagement_policy → phase_runner → MODULE_BRIDGE (~119 tools)
         ↓                                      ↓
   engagement_autopilot              ValidationEngine (CONFIRMED only)
         ↓
   intel_autonomous ← data/intel/*.json (KEV, ransomwatch, APT playbooks)
```

| Component | Path | Description |
|-----------|------|-------------|
| OpenCode core | `packages/opencode/` | TUI, sessions, model browsing, agent loop |
| Security engine | `packages/security/src/` | 220+ ARES modules |
| MCP server | `packages/security/src/mcp_server.ts` | Exposes ARES tools to LLM agents |
| Engagement engine | `packages/security/src/engagement_slice.ts` | Canonical slice/continue/autopilot orchestration |
| Bootstrap | `packages/security/src/opencode_bootstrap.ts` | Auto-wires MCP + pentest agent on launch |
| CLI | `bin/ourmine.ts` | TUI launcher + headless security commands |

Config written on launch:
- Global: `~/.config/opencode/opencode.json` (MCP + default agent)
- Project: `.opencode/agent/pentest.md`, `.opencode/command/pentest.md`

## Development

```bash
npm run generate:index      # regenerate packages/security/src/index.ts
npm run test:fast           # 43 fast security tests (excludes live/lab suites)
npm test                    # full suite — 47 test files
npm run test:wiring         # namespace export integration tests
npm run intel:refresh       # refresh KEV + ransomwatch caches (data/intel/cache/)
npm run capability:benchmark  # lab benchmark (requires tools + port 8080 target)
```

**Test split:** `test:fast` skips `live_offensive`, `ares_modules`, `tier1_phases`, and `top_cut` (slow/live). Run `npm test` before release or when changing offensive modules.

### Documentation

- [ARES Upgrade Master Plan](packages/security/docs/ARES_UPGRADE_MASTER_PLAN.md) — 2025–2026 threat alignment roadmap
- [Orchestration](packages/security/docs/ORCHESTRATION.md) — slice vs continue vs autopilot vs PentestGPT
- [Token efficiency](packages/security/docs/TOKEN_EFFICIENCY.md) — compact MCP response design
- [Live engagement](packages/security/LIVE_ENGAGEMENT.md) — env vars, scope, OT safety

See [CONTRIBUTING.md](CONTRIBUTING.md) for module authoring conventions.

## License

MIT
