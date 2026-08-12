# OurMine ARES — Token Efficiency Design (2026)

## Research synthesis

Industry-leading autonomous pentest agents (XBOW, MAPTA-style open agents, PentestGPT/LangGraph stacks) converge on the same token economics:

| Pattern | Source | OurMine implementation |
|---------|--------|------------------------|
| Plans in vector/disk memory, not context | MAPTA / LangGraph agents | `.ourmine/ares/memory/` + `engagement_cache.ts` |
| Early stopping on tool/token budget | XBOW benchmark (~40 calls, −0.587 token correlation) | `ares_engagement_slice` + `resumeToken` multi-turn |
| Artifact indirection for large payloads | MCP best practice | `mcp_artifacts.ts` + `aid` in compact responses |
| Parallel independent probes | XBOW alloy agents | `PARALLEL_RECON_MODULES` + `Promise.all` in `phase_runner.ts` |
| Delta/stateful continue | LangGraph checkpointing | `semantic_compression.ts` + `compactEngagementContinueResponse` |
| Dense intel digests + action codes | 2026 IAB/extortion patterns | pipe-delimited `is` + `ac[]` + `im{}` keys |

## Architecture

```
LLM turn
  └─ ares_engagement_slice / continue
       ├─ engagement_cache     → persona playbook + phaseList (disk, load once)
       ├─ engagement_memory    → intel read dedup, decisions, slice snapshots
       ├─ intel_autonomous     → dense digest + actionCodes (full text in artifact)
       ├─ phase_runner         → speculative parallel recon batch
       └─ mcp_response         → ≤400B slice / ≤280B delta continue + artifact
            └─ .ourmine/ares/artifacts/  (full confirmed/candidates/steps/actions)
```

## 2026 compact response keys

| Key | Meaning | Example |
|-----|---------|---------|
| `is` | Pipe-delimited intel digest | `Volt\|ia\|citrix_audit,edge_audit\|kev:2` |
| `im.ib` | IAB stage code | `ia` = initial_access |
| `im.eo` | Extortion-only mode | `true` when `OURMINE_EXTORTION_ONLY=1` |
| `im.dc` | Device-code findings | `2h1` = 2 findings, 1 high |
| `im.st` | Intel staleness (days) | `9` or `!` when cache missing |
| `ac` | Recommended action codes | `["raas:ttp","kev:scan"]` |
| `na[].c` | Next-action code (not prose) | `dc:audit`, `iab:vpn`, `ext:only` |
| `aid` | Artifact id — fetch via `ares_artifact_get` | `engagement_abc123` |

Full labels, rationale, and module args live in the artifact only. The LLM resolves `c` codes via `INTEL_ACTION_CODES` in `intel_autonomous.ts`.

## Components

### 1. Engagement memory (`.ourmine/ares/memory/`)

Cross-turn persistence so the agent never re-fetches the same intel:

- `markIntelRead(artifactId)` / `hasReadIntel()` — skip `runIntelPrefetch` on continue
- `recordDecision(key, value)` — phase picks, persona, objective
- `saveSliceSnapshot(token, metrics)` — feeds delta-only continue responses
- `registerHostRef(host)` — stable `@hN` refs for repeated host strings

### 2. Speculative parallel recon (`phase_runner.ts`)

Independent recon modules run via `Promise.all`:

`intel_feed`, `recon`, `bountyhunter`, `vuln_research`, `ot_scan`, `telecom_audit`, proximity audits, `cloud_enum`, etc.

Dependent modules (AD chain, auto_chain) remain sequential.

### 3. Semantic compression (`semantic_compression.ts`)

- Host lists → `@h1`, `@h2` refs + `host_registry` artifact
- IAB stages → `ib:ia|sl|rh|vs|rd` (2-char codes)
- Extortion-only → `eo:true`
- Device-code findings → `dc:NhM` (count + high-severity)
- Intel staleness → `st:days` or `st:!`
- Continue responses emit `buildEngagementDelta()` — only changed `cf/cd/bk/ph/ok/nxp`

### 4. Persona playbook cache (`engagement_cache.ts`)

Precomputed per `persona + objective` under `.ourmine/ares/cache/`:

- `recommendedPhases`, `phaseList` (`r→i→e→p`), `workflow`, `techniqueIds`, `modulePriorities`
- `buildCachedActionablePlan()` overlays cache on target-specific plan — no per-turn PTT rebuild

### 5. MCP efficient surface (`mcp_efficiency.ts`)

Default allowlist includes engagement tools: `ares_engagement_slice`, `ares_engagement_continue`, `ares_engagement_watch`, `ares_autopilot`, `ares_artifact_get`.

Verbose standalone audits (`ares_lolbins_audit`, `ares_proof_export`, etc.) are on `EFFICIENT_TOOL_DENYLIST` — reach via `ares_dispatch` or `ares_tool_search`.

## Measured benchmark (corp.example.com)

Run: `node --experimental-strip-types --test packages/security/test/token_efficiency_benchmark.test.js`

Typical dry-run results:

| Mode | Turns | Bytes to LLM |
|------|-------|--------------|
| ARES slice + 2× continue | 3 | **~940B** compact |
| ARES full JSON (uncompressed) | 3 | ~9,100B (9.7× compression) |
| Hypothetical 20-tool OpenCode | 20 | ~37,800B (schemas + 1.4KB×20 results) |

**Savings vs 20-tool OpenCode: ~98%** with 17 fewer LLM turns.

Continue delta turn 2: **≤280B** (`intelFromMemory: true`, `d: true`). Parallel recon probes (turn 1): **6** modules via `Promise.all`.

## Agent workflow (minimal tokens)

1. `ares_engagement_slice(target)` — plan + first phase + dense `is|ac|im` (~400B)
2. `ares_engagement_continue(resumeToken)` — next phase; follow `na[].c` codes
3. `ares_artifact_get(aid)` — full evidence when compact body references `aid`
4. Resolve action codes: `dc:audit` → device_code_audit, `iab:vpn` → citrix_audit, `ext:only` → raas_leak_catalog

Never re-plan after slice: use `rt` and `na[].c`. Details in `.ourmine/ares/artifacts/`.
