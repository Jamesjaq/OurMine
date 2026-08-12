# OurMine ARES — Token Efficiency Design (Beyond Baseline)

## Research synthesis

Industry-leading autonomous pentest agents (XBOW, MAPTA-style open agents, PentestGPT/LangGraph stacks) converge on the same token economics:

| Pattern | Source | OurMine implementation |
|---------|--------|------------------------|
| Plans in vector/disk memory, not context | MAPTA / LangGraph agents | `.ourmine/ares/memory/` + `engagement_cache.ts` |
| Early stopping on tool/token budget | XBOW benchmark (~40 calls, −0.587 token correlation) | `ares_engagement_slice` + `resumeToken` multi-turn |
| Artifact indirection for large payloads | MCP best practice | `mcp_artifacts.ts` + `aid` in compact responses |
| Parallel independent probes | XBOW alloy agents | `PARALLEL_RECON_MODULES` + `Promise.all` in `phase_runner.ts` |
| Delta/stateful continue | LangGraph checkpointing | `semantic_compression.ts` + `compactEngagementContinueResponse` |

## Architecture

```
LLM turn
  └─ ares_engagement_slice / continue
       ├─ engagement_cache     → persona playbook (disk, load once)
       ├─ engagement_memory    → intel read dedup, decisions, slice snapshots
       ├─ phase_runner         → speculative parallel recon batch
       └─ mcp_response         → ≤400B slice / ≤280B delta continue + artifact
            └─ .ourmine/ares/artifacts/  (full confirmed/candidates/steps)
```

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
- Continue responses emit `buildEngagementDelta()` — only changed `cf/cd/bk/ph/ok/nxp`

### 4. Persona playbook cache (`engagement_cache.ts`)

Precomputed per `persona + objective` under `.ourmine/ares/cache/`:

- `recommendedPhases`, `workflow`, `techniqueIds`, `modulePriorities`
- `buildCachedActionablePlan()` overlays cache on target-specific plan

## Measured benchmark (corp.example.com)

Run: `node --experimental-strip-types --test packages/security/test/token_efficiency_benchmark.test.js`

Typical dry-run results (measured `token_efficiency_benchmark.test.js`):

| Mode | Turns | Bytes to LLM |
|------|-------|--------------|
| ARES slice + 2× continue | 3 | **941B** compact |
| ARES full JSON (uncompressed) | 3 | 9,144B (9.7× compression) |
| Hypothetical 20-tool OpenCode | 20 | ~37,800B (schemas + 1.4KB×20 results) |

**Savings vs 20-tool OpenCode: 36,859B (98%)** with 17 fewer LLM turns.

Continue delta turn 2: **280B** (`intelFromMemory: true`, `d: true`). Parallel recon probes (turn 1): **6** modules via `Promise.all`.
