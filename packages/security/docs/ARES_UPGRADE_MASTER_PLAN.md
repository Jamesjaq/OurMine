# OurMine/ARES Upgrade Master Plan (2025–2026 Threat Alignment)

**Repository:** `/home/spnxr/Documents/raven/OurMine`  
**Baseline (verified Aug 2026):** 44 APT profiles, 35 MITRE technique mappings, 500-entry ransomwatch cache frozen at 2021-09-09, ~100 bridged modules, 47 test files, `mcp_server.ts` 1446 LOC, `module_bridge.ts` 1051 LOC  
**North star:** Close the intel freshness + tradecraft fidelity gap while preserving the 9/10 token-efficiency engagement loop (`engagement_slice` → `continue` → `autopilot`).

---

## Executive Summary

The engagement engine is architecturally sound — slice/continue/autopilot, ValidationEngine evidence promotion, and semantic compression are differentiators. The threat intel layer is stale and incomplete: ransomwatch is 4+ years old, ransomware profiles are missing or aliased to LockBit, OT paired-ops actors are absent, MITRE coverage is ~5% of enterprise, and dual orchestration (PentestGPT vs engagement autopilot) creates ambiguity.

This plan sequences **7 phases over ~12 sprints**, prioritizing P0 intel freshness blockers first, then tradecraft playbooks, simulation fidelity, architecture hardening, CI depth, and advanced capabilities from pending research streams.

---

## Architecture Reference (Current State)

```
MCP Client (OpenCode/Cursor)
  └─ mcp_server.ts (1446 LOC, 50+ tools)
       ├─ mcp_dispatch.ts          → direct module handlers
       ├─ mcp_bridged_tools.ts     → bridge surface
       ├─ mcp_response.ts           → ≤400B slice / artifact indirection
       └─ engagement path ──────────┐
                                    ▼
  engagement_slice.ts ──► engagement_policy.ts ──► phase_runner.ts
       │                      │                        │
       ├─ intel_autonomous.ts │                        └─ MODULE_BRIDGE (~100 keys)
       ├─ engagement_cache.ts │                              └─ 215 src modules
       └─ engagement_graph.ts ▼
  engagement_autopilot.ts ──► pickAutopilotAction() ──► MODULE_BRIDGE

  PentestGPT path (parallel, LLM-steered):
  pentestgpt_agent.ts ──► agent_tools.ts ──► ValidationEngine (CONFIRMED only path)

  Intel layer:
  data/intel/*.json ──► intel_feeds.ts / apt_intel_feed.ts / intel_autonomous.ts
```

**Canonical orchestration decision (Phase 4):** `ares_engagement_slice` + `ares_autopilot` become the default campaign path; `ares_pentest_run` / PentestGPT reserved for ad-hoc LLM-steered engagements with explicit opt-in.

---

## Priority Matrix

| Item | Impact | Effort | Phase | Priority |
|------|--------|--------|-------|----------|
| Ransomwatch refresh + TTL | Critical | S | 0 | P0 |
| Ransomware profile expansion | Critical | M | 1 | P0 |
| ALPHV defunct + LockBit stale fix | High | S | 0 | P0 |
| IAB market schema | Critical | M | 1 | P0 |
| Device-code phishing playbook | Critical | M | 2 | P0 |
| MITRE expansion (37→200+) | High | L | 1 | P1 |
| OT paired-ops profiles | High | M | 1–2 | P1 |
| ChainDrop OIDC chain | High | M | 2 | P1 |
| Extortion-only mode | High | M | 3 | P1 |
| mcp_server split | Medium | L | 4 | P1 |
| Canonical orchestration | Medium | M | 4 | P1 |
| Per-module smoke tests | High | L | 5 | P1 |
| TAXII feed enablement | Medium | M | 1 | P2 |
| AiTM / nation-state (Phase 6) | Medium | L | 6 | P2 |

---

## PHASE 0: Foundation & Intel Freshness (P0 Blockers)

**Goal:** No engagement runs on 2020–2021 ransom intel. All offline paths return representative 2025–2026 data.

### 0.1 Intel Cache Refresh Pipeline

| Action | File | Change |
|--------|------|--------|
| Add refresh script | `packages/security/scripts/refresh-intel-cache.ts` | Fetch KEV, ransomwatch, optional TAXII; write to `data/intel/cache/` with `cachedAt` metadata |
| Add cache metadata schema | `packages/security/data/intel/cache/_meta.json` | `{ "kev": { "cachedAt", "count", "source" }, "ransomwatch": { ... } }` |
| Fix offline fallback | `packages/security/src/intel_feeds.ts` | `fetchRansomwatch(false)` reads `cache/ransomwatch.json` (not `ransomwatch_sample.json`); warn if `cachedAt` > 7 days stale |
| Add staleness gate | `packages/security/src/intel_autonomous.ts` | `intelStalenessWarning()` → append to `intelDigest` when cache age > TTL |
| npm script | `package.json` | `"intel:refresh": "node --experimental-strip-types packages/security/scripts/refresh-intel-cache.ts"` |

**Example `_meta.json`:**

```json
{
  "ransomwatch": {
    "cachedAt": "2026-08-12T15:00:00Z",
    "count": 2500,
    "latestDiscovered": "2026-08-10T12:00:00Z",
    "source": "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json",
    "ttlDays": 7
  },
  "kev": { "cachedAt": "2026-08-12T15:00:00Z", "count": 1665 }
}
```

**Module wiring:** `refresh-intel-cache.ts` → `intel_feeds.fetchKevCache(true)` + `fetchRansomwatch(true)` → writes cache → consumed by `intel_autonomous.runIntelPrefetch()` → `engagement_slice.ts` intel snippet.

**Test:** `packages/security/test/intel_cache_freshness.test.js`

- Assert `cache/ransomwatch.json` latest `discovered` > 2025-01-01 (after refresh)
- Assert offline `fetchRansomwatch(false)` returns > 100 records
- Assert staleness warning emitted when `_meta.json` age > TTL

**Effort:** S | **Blocks:** Phase 1, 2, 3  
**Success criteria:** `npm run intel:refresh` updates cache; dry-run engagement shows 2025+ ransom TTPs  
**Risk:** GitHub rate limits → **Mitigation:** CI weekly cron + commit refreshed cache; fallback to vendored snapshot

---

### 0.2 Ransomware Profile Lifecycle Corrections

| Action | File | Change |
|--------|------|--------|
| Mark ALPHV defunct | `packages/security/data/intel/apt_profiles.json` | Add `"status": "defunct"`, `"defunctDate": "2024-12"`, `"successor": "play"` to `alphv_blackcat` |
| Update LockBit | `apt_profiles.json`, `ransomware_groups.json` | Rename `lockbit5` → `lockbit`; add `"status": "disrupted"`, note 2025 takedown; map affiliates to `ransomhub`, `play` |
| Fix actor aliasing | `packages/security/src/intel_autonomous.ts` | Replace `play → lockbit5` mapping with distinct profile IDs |
| Update opsec profiles | `packages/security/src/opsec_gate.ts` | Remove/adjust `lockbit5: 40` throttle; add `play`, `ransomhub` entries |

**Example ransomware group entry:**

```json
{
  "id": "play",
  "name": "Play",
  "aliases": ["Play Ransomware"],
  "status": "active",
  "focus": ["healthcare", "manufacturing", "double_extortion"],
  "extortionOnly": false,
  "tools": ["postex_harvest", "raas_leak_catalog", "esxi_audit", "lolbins_audit"],
  "techniques": ["T1486", "T1490", "T1489"],
  "iabEntryVector": ["vpn_creds", "rdp_exposed"],
  "paymentRate2025": 0.28
}
```

**Test:** `packages/security/test/ransomware_lifecycle.test.js` — assert ALPHV status=defunct; Play resolves independently  
**Effort:** S | **Blocks:** Phase 1.2  
**Risk:** Stale affiliate mappings → **Mitigation:** Source from ransomwatch group_name frequency analysis in refresh script

---

### 0.3 Dual-Orchestration Clarity (Documentation + Guard)

| Action | File | Change |
|--------|------|--------|
| Orchestration doc | `packages/security/docs/ORCHESTRATION.md` | Decision tree: slice vs pentest_run vs autopilot |
| Deprecation notice | `packages/security/src/mcp_server.ts` | `ares_pentest_run` description: "Legacy LLM-steered path; prefer ares_engagement_slice" |
| Routing test | `packages/security/test/orchestration_canonical.test.js` | Assert engagement_slice is recommended entry for `identity_first`, `cloud_ransom`, `ot_ics` objectives |

**Effort:** S | **Success:** New operators know canonical path without reading 1446 LOC

---

## PHASE 1: Threat Intel Layer

**Goal:** Complete actor/ransomware/IAB/MITRE coverage aligned to 2025–2026 landscape.

### 1.1 Ransomware Profile Expansion

**Create/modify:**

| File | Profiles to Add |
|------|-----------------|
| `data/intel/ransomware_groups.json` | Play, RansomHub, Interlock, World Leaks, Ghost, Gunra, NightSpire, INC |
| `data/intel/apt_profiles.json` | Mirror as eCrime profiles where tradecraft differs (e.g., `storm_0501` already exists) |
| `data/intel/apt_playbook_modules.json` | Per-group module chains |

**Example `apt_playbook_modules.json` entry (RansomHub):**

```json
"ransomhub": {
  "objectiveHint": "ransomware_impact",
  "techniqueChain": ["T1078", "T1021", "T1486", "T1490"],
  "modules": ["edge_audit", "rmm_audit", "cred_access_auto", "raas_leak_catalog", "raas_campaign", "esxi_audit"],
  "intelSnippetTemplate": "{name}: IAB VPN creds → RMM → encrypt + leak; payment rate ~28%"
}
```

**Module wiring chain:**

```
intel_autonomous.actorModuleMap → engagement_policy.prioritizeAptModules
  → phase_runner (recon: edge_audit, rmm_audit)
  → exploit: cred_access_auto
  → post_ex/apt: raas_leak_catalog → raas_campaign → raas_esxi_encrypt
```

**Test:** `packages/security/test/ransomware_profiles.test.js` — all 8 new groups resolve; modules pass `findUnresolvedModules()`  
**Effort:** M | **Depends on:** 0.1, 0.2  
**Success:** `ares_threat_intel` query "RansomHub" returns playbook + KEV hits

---

### 1.2 IAB Market Schema

**Create:** `packages/security/data/intel/iab_market.json`

```json
{
  "schemaVersion": 1,
  "chainStages": [
    { "id": "stealer_log", "name": "Stealer Log Harvest", "priceRangeUsd": [5, 50], "sources": ["redline", "lumma", "vidar"], "artifacts": ["cookies", "passwords", "autofill"] },
    { "id": "initial_access", "name": "VPN/RDP/Citrix Access", "priceRangeUsd": [200, 250000], "indicators": ["fortinet_session", "citrix_aaacookie", "rdp_port3389"] },
    { "id": "raas_handoff", "name": "RaaS Affiliate Onboard", "indicators": ["anydesk_deploy", "rmm_install", "vss_delete"] }
  ],
  "stealerToAccessPatterns": [
    {
      "id": "cookie_vpn_pivot",
      "stealerArtifact": "session_cookie",
      "targetService": "vpn_portal",
      "techniques": ["T1539", "T1078"],
      "modules": ["citrix_audit", "edge_audit", "identity_playbooks", "cloud_token"]
    },
    {
      "id": "corp_cred_rdp",
      "stealerArtifact": "domain_password",
      "targetService": "rdp",
      "techniques": ["T1078", "T1021.001"],
      "modules": ["cred_spray", "cred_access_auto", "rmm_audit"]
    }
  ],
  "iabBrokers": [
    { "id": "sylvanite", "type": "ot_iab", "pairedActor": "voltzite", "focus": ["scada_mapping", "engineering_workstation"] }
  ]
}
```

**Create:** `packages/security/src/iab_intel.ts`

- `loadIabMarket()`, `matchStealerPattern(artifacts)`, `iabHandoffPlaybook(brokerId)`
- Wire into `intel_autonomous.ts` → `recommendedNextActions` when persona=`enterprise_ad` + objective=`identity_first`

**Test:** `packages/security/test/iab_market.test.js`  
**Effort:** M | **Depends on:** 0.1  
**Success:** Engagement with hint "stealer log vpn" prioritizes `citrix_audit` + `edge_audit`

---

### 1.3 OT Paired-Ops Profiles

**Modify:** `data/intel/apt_profiles.json` — add:

| ID | Name | Paired With | Modules |
|----|------|-------------|---------|
| `pipedream_chernovite` | PIPEDREAM/CHERNOVITE | — | `iot_scada`, `ics_impact_proof`, `profinet_l2`, `firmware_audit` |
| `sylvanite` | SYLVANITE (IAB) | `voltzite` | `ot_batch_scan`, `hybrid_pivot`, `edge_audit` |
| `voltzite` | VOLTZITE | `sylvanite` | `iot_scada`, `ot_segment_infer`, `ics_impact_proof` |
| `kamacite` | KAMACITE | — | `iot_scada`, `industrial_protocol_fuzz` |
| `cosmicenergy` | COSMICENERGY | — | `iot_scada`, `impact_assess`, `ics_impact_proof` |

**Modify:** `data/intel/apt_playbook_modules.json` — paired chain:

```json
"sylvanite_voltzite": {
  "objectiveHint": "hybrid_it_ot",
  "techniqueChain": ["T1078", "T0886", "T0855", "T0827"],
  "modules": ["edge_audit", "ot_batch_scan", "hybrid_pivot", "iot_scada", "ics_impact_proof"],
  "pairedOps": { "iab": "sylvanite", "ot_mapping": "voltzite" }
}
```

**Module wiring:** `engagement_policy.ts` hybrid_it_ot branch → `prioritizeModules.unshift("hybrid_pivot", "ot_batch_scan")` + APT hint `sylvanite`  
**Test:** extend `packages/security/test/ot_ics_flow.test.js` + `apt_tier1_gaps.test.js`  
**Effort:** M | **Depends on:** none (parallel with 1.1)

---

### 1.4 MITRE ATT&CK Expansion (35 → 200+)

**Strategy:** Tiered expansion — don't map all 700; map techniques referenced by 2025–2026 campaigns + existing modules.

**Create:** `packages/security/scripts/generate-mitre-map.ts`

- Input: MITRE STIX bundle (cached) + existing `module_registry.ts` keys
- Output: `data/intel/mitre_techniques.json` (target: 200 enterprise + 30 ICS)

**Priority technique batches:**

| Batch | Techniques | Key Modules |
|-------|-----------|-------------|
| Identity | T1550.*, T1528, T1606, T1621, T1556.* | `oauth_consent_audit`, `idp_audit`, `identity_playbooks`, `evilginx_lab` |
| Cloud-native | T1537, T1525, T1098.003, T1485 | `ares_cloud_native`, `cloud_token`, `hybrid_ad_audit` |
| LotL/malware-free | T1218.*, T1574.*, T1055 | `lolbins_audit`, `ebpf_audit`, `ares_evasion_engine` |
| Supply chain | T1195.*, T1554, T1553.005 | `cicd_audit`, `supply_chain_audit`, `lockfile_scan` |
| Ransom/extortion | T1486, T1490, T1489, T1657 | `raas_*`, `impact_assess` |

**Modify:** `apt_intel_feed.ts` — `lookupTechnique()` fallback currently creates stub refs; add validation that module exists via `isExecutableModule()`

**Test:** `packages/security/test/mitre_coverage.test.js` — count ≥ 200; every technique has ≥1 resolvable module  
**Effort:** L | **Depends on:** 0.1  
**Risk:** Module key drift → **Mitigation:** `system_completeness.test.js` gate in CI

---

### 1.5 TAXII Feed Enablement

**Modify:** `data/intel/taxii_feeds.json`

```json
[
  { "id": "mitre_enterprise", "baseUrl": "https://attack-taxii.mitre.org/api/v21", "collectionId": "95ecc380-afe9-11df-a3b3-001e4cfc1678", "enabled": true },
  { "id": "cisa_apt", "baseUrl": "https://taxii.mitre.org/api/v21", "collectionId": "...", "enabled": false, "apiKeyEnv": "OURMINE_TAXII_KEY" }
]
```

**Modify:** `intel_feeds.ts` — `pollStixFeeds()` already exists; add dry-run mode returning cached STIX summaries from `cache/stix_*.json`

**Wire:** `ares_stix_ingest` MCP tool → `engagement_memory` dedup  
**Test:** `packages/security/test/stix_ingest.test.js`  
**Effort:** M | **Depends on:** 0.1

---

## PHASE 2: Tradecraft Playbooks

**Goal:** Encode 2025–2026 attack chains as executable (dry-run default) playbooks.

### 2.1 Device-Code Phishing Playbook

**Create:** `packages/security/src/device_code_phish.ts`

```typescript
export interface DeviceCodePhishResult {
  target: string; dryRun: boolean;
  provider: "entra" | "okta" | "google";
  findings: Array<{ id: string; severity: string; title: string; mitre: string }>;
  userCodeSimulation?: { verificationUri: string; userCode: string; pollEndpoint: string };
  recommendations: string[];
}
export function auditDeviceCodeFlow(domain: string, opts: { dryRun?: boolean }): DeviceCodePhishResult
```

**Modify:**

- `module_bridge.ts` — add `device_code_audit` bridge
- `module_registry.ts` — `MODULE_ALIASES.device_code_phish → device_code_audit`
- `apt_playbook_modules.json` — add to `scattered_spider`, `apt29`, `storm_0501` chains
- `mitre_techniques.json` — T1528, T1550.001 with `device_code_audit`
- `mcp_server.ts` (later split: `mcp/tools/identity.ts`) — expose `ares_device_code_audit`

**Module chain:**

```
identity_first objective
  → oauth_consent_audit (consent policy)
  → device_code_audit (device code flow assessment)
  → idp_oauth_audit (live Graph when OURMINE_GRAPH_TOKEN set)
  → cloud_token (token abuse simulation)
```

**ROE gate:** Live polling of device-code endpoints requires `OURMINE_ROE_SIGNED=1` + scope includes IdP domain  
**Live vs dry-run:** Dry-run returns simulated user-code + policy findings; live probes OIDC device endpoint + tenant policy via Graph  
**Test:** `packages/security/test/device_code_phish.test.js`  
**Effort:** M

---

### 2.2 ChainDrop OIDC / CI Runner Supply Chain

**Create:** `packages/security/src/chaindrop_oidc.ts`

- Simulates OIDC token extraction from CI runner context (GitHub Actions, GitLab CI)
- Patterns: `ACTIONS_ID_TOKEN_REQUEST_URL`, `OIDC_TOKEN`, federated credential abuse

**Modify:**

- `apt_playbook_modules.json` — new profile `chaindrop` or extend `team_pcp`:

```json
"chaindrop": {
  "objectiveHint": "supply_chain",
  "techniqueChain": ["T1552.001", "T1078.004", "T1528", "T1195.002"],
  "modules": ["cicd_audit", "chaindrop_oidc", "cloud_token", "supply_chain_exec"]
}
```

- `engagement_policy.ts` — `SUPPLY_CHAIN_MODULES` += `chaindrop_oidc`
- `module_bridge.ts` — bridge entry

**Module chain:**

```
supply_chain objective
  → lockfile_scan → cicd_audit → chaindrop_oidc → cloud_token → supply_chain_exec
```

**Test:** `packages/security/test/chaindrop_oidc.test.js`  
**Effort:** M | **Depends on:** 1.4 (T1528)

---

### 2.3 Cloud-Native Ransom (Storm-0501) Playbook

**Modify:** `apt_playbook_modules.json` storm_0501 entry:

```json
"storm_0501": {
  "objectiveHint": "cloud_ransom",
  "techniqueChain": ["T1078.004", "T1098.003", "T1530", "T1485", "T1486"],
  "modules": ["hybrid_ad_audit", "ares_cloud_native", "cloud_token", "idp_audit", "raas_leak_catalog", "impact_assess"],
  "cloudNative": true,
  "endpointMalware": false
}
```

**Modify:** `engagement_policy.ts` — `cloud_ransom` objective skips endpoint-heavy modules (`lolbins_audit`, `cred_dump`) when `cloudNative: true` hint  
**Test:** extend `packages/security/test/institutional_flow.test.js`  
**Effort:** S

---

### 2.4 AiTM / Session Cookie Chain (Enhancement)

**Existing:** `evilginx_lab`, `citrix_audit`, `aitm_proxy` (external/HITL)  
**Create:** `packages/security/src/aitm_playbook.ts` — orchestrates assessment-only chain linking citrix + oauth + session cookie modules

**Modify:** `intel_autonomous.ts` — when stack signals include `citrix` or `vpn`, inject AiTM awareness  
**Test:** extend `packages/security/test/apt_tier1_gaps.test.js`  
**Effort:** S

---

### 2.5 BYOVD / LOLBin Malware-Free Chain

**Modify:** `lolbins_audit.ts` — add BYOVD driver blocklist awareness (RTCore64, DBUtil, etc.)  
**Modify:** `ebpf_audit.ts` — cross-reference BYOVD → EDR blind spots  
**Add to MITRE batch:** T1562.001, T1211  
**Test:** extend `packages/security/test/audit_gap_fixes.test.js`  
**Effort:** S

---

## PHASE 3: Simulation Fidelity

**Goal:** Realistic 2025–2026 campaign simulation without uncontrolled destructive ops.

### 3.1 Extortion-Only Mode

**Create:** `packages/security/src/extortion_mode.ts`

```typescript
export interface ExtortionModeConfig {
  enabled: boolean;
  skipEncrypt: boolean;       // no raas_esxi_encrypt, raas_vss_wipe
  catalogOnly: boolean;     // raas_leak_catalog only
  publishSimulation: boolean; // raas_tor_portal dry-run descriptor
}
export function applyExtortionMode(modules: string[], config: ExtortionModeConfig): string[]
```

**Modify:**

- `target_flow.ts` — add objective variant or flag `extortion_only` on `ransomware_impact`
- `engagement_policy.ts` — when `extortionOnly: true` on ransomware group or env `OURMINE_EXTORTION_ONLY=1`, filter destructive modules
- `raas_engine.ts` — respect `extortionOnly` flag; skip VSS/encrypt even in live
- `ransomware_groups.json` — `"extortionOnly": true` for World Leaks, Interlock

**Module chain (extortion-only):**

```
post_ex: collection_engine → raas_leak_catalog → raas_exfil_upload (dry-run) → raas_tor_portal (descriptor only)
SKIP: raas_vss_wipe, raas_esxi_encrypt, raas_smb_spread
```

**ROE:** Extortion-only is **default for dry-run**; live encrypt requires `OURMINE_FORCE_LIVE=1` + RoE (existing pattern in `raas_engine.ts`)  
**Test:** `packages/security/test/extortion_mode.test.js`  
**Effort:** M | **Depends on:** 1.1

---

### 3.2 IAB Handoff Simulation

**Create:** `packages/security/src/iab_handoff_sim.ts`

- Simulates stealer-log → VPN access → RaaS affiliate handoff as staged evidence in `CredentialGraph`
- Stages: `{ stage: "stealer_log", artifacts: [...] }` → `{ stage: "vpn_session", ... }` → `{ stage: "raas_deploy", ... }`

**Wire:**

```
iab_intel.matchStealerPattern() → iab_handoff_sim.runChain()
  → engagement_graph evidence items
  → engagement_report.ts section "IAB Chain Reconstruction"
```

**Test:** `packages/security/test/iab_handoff_sim.test.js`  
**Effort:** M | **Depends on:** 1.2

---

### 3.3 Stealer-Log → Access Chain Realism

**Modify:** `packages/security/src/credential_graph.ts` — add `source: "stealer_log" | "iab_market"` credential type  
**Modify:** `packages/security/src/browser_ext.ts` — link `cookie_stealer` findings to IAB patterns  
**Modify:** `engagement_graph.ts` — promote stealer-log credentials to pivot candidates when IAB pattern matches  

**Test:** extend `packages/security/test/cred_chain.test.js`  
**Effort:** M | **Depends on:** 1.2, 3.2

---

## PHASE 4: Architecture Hardening

**Goal:** Maintainable MCP surface; single canonical orchestration path.

### 4.1 mcp_server.ts Split (1446 → ~200 LOC bootstrap)

**Target structure:**

```
packages/security/src/mcp/
  ├── server.ts              # bootstrap, JSON-RPC, tool registry (~200 LOC)
  ├── tools/
  │   ├── shell.ts           # bash
  │   ├── recon.ts           # ares_recon, bountyhunter, scanner_parse
  │   ├── identity.ts        # ares_identity, oauth, idp, device_code
  │   ├── engagement.ts      # slice, continue, autopilot, plan
  │   ├── intel.ts           # threat_intel, intel_feed, stix, vx
  │   ├── offensive.ts       # ad_exploit, c2, payload, raas
  │   ├── audit.ts           # lolbins, ebpf, cicd, edge, etc.
  │   └── ot.ts              # iot_scada, firmware
  └── register_tools.ts      # aggregates McpTool[] from ./tools/*
```

**Migration steps:**

1. Extract tool definitions to domain files (no logic change)
2. `mcp_server.ts` re-exports from `mcp/server.ts` for backward compat
3. Update imports in tests if any direct-import `mcp_server.ts`
4. `mcp_bridged_tools.ts` unchanged initially

**Test:** existing `wiring.test.js`, `mcp_efficiency.test.js` must pass unchanged  
**Effort:** L | **Depends on:** Phase 2 complete (avoid merge conflicts)  
**Risk:** MCP tool name drift → **Mitigation:** snapshot test of tool name list

---

### 4.2 module_bridge.ts Domain Split (1051 → ~250 LOC per domain)

**Target structure:**

```
packages/security/src/bridges/
  ├── index.ts           # re-exports MODULE_BRIDGE merged object
  ├── recon_bridge.ts
  ├── identity_bridge.ts
  ├── ot_bridge.ts
  ├── raas_bridge.ts
  ├── c2_bridge.ts
  └── audit_bridge.ts
```

**Effort:** M | **Depends on:** 4.1 (parallel OK)

---

### 4.3 Canonical Orchestration Enforcement

**Modify:** `packages/security/src/opencode_tool_policy.ts`

- Default allowed tools for pentest agent: `ares_engagement_slice`, `ares_engagement_continue`, `ares_autopilot`, `ares_artifact_get`, `ares_threat_intel`
- `ares_pentest_run` requires explicit enable flag

**Modify:** `packages/security/src/engagement_autopilot.ts`

- Document stop conditions: scope violation, RoE block, human-intervention blockers (already partially implemented via `HUMAN_BLOCKER_PATTERNS`)

**Modify:** `packages/security/src/pentestgpt_agent.ts`

- Add header comment: "Secondary orchestrator — use for ad-hoc LLM-driven tasks only"
- Optional: delegate phase execution to `runEngagementSlice` internally (future refactor)

**Test:** `packages/security/test/orchestration_canonical.test.js`  
**Effort:** M

---

## PHASE 5: Validation & CI

**Goal:** 215 modules covered by smoke tests; fast/slow CI split enforced.

### 5.1 Per-Module Smoke Test Generator

**Create:** `packages/security/scripts/generate-module-smokes.ts`

- Input: `MODULE_BRIDGE` keys + `MCP_NATIVE_TOOLS`
- Output: `packages/security/test/generated/module_smoke.test.js`
- Each test: dry-run invoke, assert `{ success: true }` or `{ dryRun: true }`, max 2s timeout

**Create:** `packages/security/test/module_smoke_manifest.json` — exclude list (destructive live-only modules)

**Effort:** L

---

### 5.2 Fast/Slow CI Split Enhancement

**Modify:** `packages/security/scripts/run-fast-tests.ts`

- Add `generated/module_smoke.test.js` to fast suite
- Keep `live_offensive.test.js`, `ares_modules.test.js`, `tier1_phases.test.js` in slow

**Create:** `.github/workflows/security-fast.yml`

```yaml
on: [push, pull_request]
jobs:
  fast:
    runs-on: ubuntu-latest
    steps:
      - run: npm run test:fast
  slow:
    runs-on: ubuntu-latest
    if: github.event_name == 'schedule' || contains(github.event.pull_request.labels.*.name, 'full-ci')
    steps:
      - run: npm test
```

**Add:** weekly `intel:refresh` CI cron throughout.

**Test:** CI green on fast path < 120s  
**Effort:** M | **Depends on:** 5.1

---

### 5.3 ValidationEngine Extension

**Modify:** `validation_engine.ts` — add strategies for:

- OAuth consent misconfiguration (policy check, no token issuance)
- Device-code flow (endpoint reachable, not token acquisition)
- IAB credential validity (format check, not login)

**Modify:** `validation_planner.ts` — map new finding types  
**Test:** extend `packages/security/test/engagement_engine.test.js`  
**Effort:** M

---

### 5.4 System Completeness Gate

**Modify:** `packages/security/test/system_completeness.test.js`

- Assert playbook module count ≥ 80
- Assert ransomware groups ≥ 18
- Assert APT profiles ≥ 50
- Assert MITRE techniques ≥ 200
- Assert 0 unresolved modules (except EXTERNAL_MODULES_BY_DESIGN)

**Effort:** S — add to fast CI

---

## PHASE 6: Advanced Capabilities (Pending Research Streams 5–11)

**Goal:** Integrate findings from remaining research streams without bloating default MCP surface.

### 6.1 C2 Realism (Stream: C2)

**Existing:** `c2_autonomous`, `c2_dwell_ops`, `c2_rotation`, `LegitC2Server`  
**Enhance:**

- `packages/security/src/c2_platform.ts` — add DNS-over-HTTPS channel template
- `data/intel/apt_playbook_infra.json` — refresh C2 infra patterns
- Wire: `tier1_orchestrator` → `c2_dwell_scheduler` with OPSEC throttle

**ROE:** C2 live channels require env vars (`OURMINE_C2_HTTP_URL` etc.) + RoE  
**Effort:** M

---

### 6.2 Zero-Day / Fuzzing (Stream: Zero-day)

**Existing:** `ares_zero_day_fuzzer`, `exploit_synthesis`  
**Enhance:** Link KEV cache → fuzzer target prioritization in `intel_autonomous.ts`  
**Effort:** M

---

### 6.3 Nation-State Deep Profiles (Stream: Nation-state)

**Add:** APT profiles from streams 5–11 (e.g., Salt Typhoon enhancements, Volt Typhoon cloud dwell)  
**Effort:** M per actor batch

---

### 6.4 AiTM Full Chain (Stream: AiTM)

**Enhance:** `evilginx_lab` + `aitm_playbook.ts` + external `aitm_proxy` HITL documentation  
**Keep `aitm_proxy` in EXTERNAL_MODULES_BY_DESIGN** — never auto-execute  
**Effort:** M

---

### 6.5 AD / Entra Hybrid (Stream: AD)

**Existing:** `hybrid_ad_entra.ts`, `ares_kerberos_advanced`, `cred_access_auto`  
**Enhance:** Entra ID device-code + CA policy bypass assessment in `hybrid_ad_audit`  
**Effort:** M

---

### 6.6 Financial Sector (Stream: Financial)

**Modify:** `institutional_sectors.json` — SWIFT/ISO20022 awareness modules  
**Wire:** `institutional_hints.ts` → `simSwapAwareness()` (already in `intel_autonomous.ts`)  
**Effort:** S

---

## Token Efficiency Preservation (Cross-Cutting)

**Non-negotiable constraints for ALL phases:**

| Rule | Implementation |
|------|----------------|
| No full intel dumps in MCP responses | All new intel → `writeArtifact()` + `aid` in compact response |
| Engagement tools stay THROTTLE_EXEMPT | Add new meta tools to `THROTTLE_EXEMPT_TOOLS` in `mcp_response.ts` |
| New modules return ≤8KB JSON | Follow `module_bridge.result()` slice pattern |
| Intel prefetch dedup | Register in `engagement_memory.markIntelRead()` |
| New playbook data on disk | Never inline 200+ MITRE entries in LLM context — use `engagement_cache.ts` |
| Compact field names | New response fields use 2–3 char keys in `semantic_compression.ts` deltas |

**Anti-bloat checklist for each new module:**

1. Does it have a bridge entry returning truncated JSON?
2. Is it reachable via `ares_engagement_slice` policy, not only standalone MCP?
3. Does dry-run produce meaningful evidence for `engagement_graph`?

---

## Live vs Dry-Run Behavior Matrix (New Capabilities)

| Module | Dry-Run | Live | Live Gate |
|--------|---------|------|-----------|
| `device_code_audit` | Policy assessment + simulated user-code | OIDC endpoint probe + Graph policy | RoE + scope |
| `chaindrop_oidc` | CI env var pattern scan (local repo) | Live CI runner probe | RoE + `OURMINE_CICD_LIVE=1` |
| `iab_handoff_sim` | Full staged evidence chain | No live (simulation only) | N/A |
| `extortion_mode` | Catalog + portal descriptor | Upload to configured staging only | RoE + no encrypt |
| `refresh-intel-cache` | Read local cache | Network fetch | Network |
| `stix_ingest` | Cached STIX summary | TAXII poll | `enabled: true` in feeds |
| TAXII poll | — | Network | API key if required |
| `raas_esxi_encrypt` | Simulated marker file | Real encrypt | `OURMINE_FORCE_LIVE=1` + RoE + extortion mode OFF |

---

## ROE / Safety Gates (Per Capability)

| Capability | Gate | Env Vars |
|------------|------|----------|
| All live probes | RoE attestation | `OURMINE_ROE_SIGNED=1` |
| Destructive ransom ops | Force live + extortion mode off | `OURMINE_FORCE_LIVE=1` |
| Graph API IdP audit | Token scoped to audit perms | `OURMINE_GRAPH_TOKEN` |
| C2 live channels | Explicit endpoint config | `OURMINE_C2_*` |
| AiTM proxy | HITL only, never autopilot | Manual MCP invoke |
| OT write operations | ICS validation gate | `ics_validation.ts` + scope |
| Intel refresh | No target interaction | `OURMINE_INTEL_REFRESH=1` |
| Stealer-log simulation | Synthetic data only | No real creds in repo |

---

## Threat Model for This Plan

| Threat | Impact | Mitigation |
|--------|--------|------------|
| Stale intel reintroduced | Bad recommendations | `_meta.json` TTL + CI staleness test |
| Module key sprawl / unresolved refs | Runtime failures | `system_completeness.test.js` gate |
| MCP response bloat | Token cost explosion | Artifact indirection + benchmark regression test |
| Destructive op accidental live | Target damage | extortion-only default + `OURMINE_FORCE_LIVE` + RoE |
| Dual orchestration confusion | Operator error | Canonical path docs + tool policy |
| Supply chain in refresh script | Compromised intel | Pin URLs, verify JSON schema, signed commits |
| Over-mapping MITRE → false confidence | Bad reports | ValidationEngine evidence requirement unchanged |
| IAB simulation with real stealer logs | Legal/ethical issue | Synthetic fixtures only in repo |
| mcp_server split regression | Broken MCP clients | Tool name snapshot test |
| PentestGPT bypassing ValidationEngine | Unconfirmed findings | ValidationEngine remains only CONFIRMED path |

---

## Anti-Patterns to Avoid (Research-Backed)

1. **Monolithic intel dumps to LLM** — 79% malware-free ops mean technique selection matters more than payload gen; keep intel in artifacts.
2. **Encrypt-first ransomware simulation** — 28% payment rate; extortion/leak is the realistic 2025 path.
3. **Treating ALPHV as active** — defunct since late 2024; causes wrong TTP chains.
4. **Ignoring IAB market economics** — most enterprise intrusions start with $200 VPN creds, not zero-days.
5. **OT ops without paired IAB context** — SYLVANITE→VOLTZITE pattern requires hybrid_it_ot objective.
6. **Auto-running aitm_proxy** — session hijacking requires HITL; keep in EXTERNAL_MODULES_BY_DESIGN.
7. **Adding modules without bridge/registry wiring** — 215 modules already exist; wire before creating new.
8. **PentestGPT as default** — burns tokens (~37KB/20 tools vs 941B/3 turns for slice path).
9. **Live probes without RoE** — engagement_policy already blocks; don't bypass in new modules.
10. **Skipping dry-run evidence** — every module must produce engagement_graph evidence in dry-run.

---

## Timeline (12 Sprints, ~24 Weeks)

| Sprint | Phase | Deliverables |
|--------|-------|-------------|
| 1 | 0 | Intel refresh script, cache metadata, ALPHV/LockBit fixes, ransomwatch 2025+ cache |
| 2 | 0–1 | Orchestration doc, 8 ransomware profiles, IAB schema v1 |
| 3 | 1 | OT profiles (5), MITRE batch 1 (identity + cloud, +50 techniques) |
| 4 | 1 | MITRE batch 2 (LotL + supply chain + ransom, +115 techniques), TAXII dry-run |
| 5 | 2 | device_code_audit, chaindrop_oidc, Storm-0501 playbook |
| 6 | 2 | AiTM playbook, BYOVD/LOLBins enhancement, identity chain tests |
| 7 | 3 | extortion_mode, iab_handoff_sim, stealer-log credential graph |
| 8 | 3 | Simulation fidelity tests, engagement_report IAB section |
| 9 | 4 | mcp_server split (tools/*.ts), tool name snapshot test |
| 10 | 4 | module_bridge split, canonical orchestration enforcement |
| 11 | 5 | Module smoke generator, fast/slow CI, system_completeness gates |
| 12 | 5–6 | ValidationEngine extensions, Phase 6 priority items from research streams |

**Parallel track:** Weekly `intel:refresh` CI cron throughout.

---

## Dependency Graph

```
Phase 0 (intel freshness)
  ├─► Phase 1.1 (ransomware profiles)
  ├─► Phase 1.4 (MITRE expansion)
  └─► Phase 1.5 (TAXII)
Phase 1.2 (IAB schema)
  ├─► Phase 3.2 (IAB handoff sim)
  └─► Phase 3.3 (stealer-log chain)
Phase 1.1 + 1.2
  └─► Phase 3.1 (extortion-only mode)
Phase 2 (all playbooks)
  └─► Phase 4 (architecture split — avoid conflicts)
Phase 4
  └─► Phase 5 (CI smoke generator needs stable module surface)
Phase 5
  └─► Phase 6 (advanced capabilities on validated foundation)
```

---

## Success Criteria (Program Level)

| Metric | Current | Target |
|--------|---------|--------|
| Ransomwatch latest entry | 2021-09-09 | ≥ 2025-06-01 |
| Ransomware group profiles | 11 | ≥ 19 |
| APT profiles | 44 | ≥ 52 |
| MITRE technique mappings | 35 | ≥ 230 |
| Unresolved playbook modules | ~0–3 | 0 |
| Fast CI time | ~unknown | < 120s |
| Module smoke coverage | ~47 test files | 100% bridge keys |
| Engagement slice compact response | 941B/3 turns | ≤ 1000B/3 turns (no regression) |
| Offline intel quality | 2-entry sample fallback | Full cache fallback |

**Verification command suite (post-implementation):**

```bash
npm run intel:refresh
npm run test:fast
node --experimental-strip-types --test packages/security/test/system_completeness.test.js
node --experimental-strip-types --test packages/security/test/token_efficiency_benchmark.test.js
OURMINE_ALLOW_DRY_RUN=1 node --experimental-strip-types -e "
  import { runEngagementSlice } from './packages/security/src/engagement_slice.ts';
  const r = await runEngagementSlice({ target: 'corp.example.com', objective: 'identity_first', live: false });
  console.log(r.summary, r.intelDigest?.slice(0,200));
"
```

---

## File Creation Summary (Quick Reference)

### New Files

- `packages/security/scripts/refresh-intel-cache.ts`
- `packages/security/scripts/generate-mitre-map.ts`
- `packages/security/scripts/generate-module-smokes.ts`
- `packages/security/data/intel/iab_market.json`
- `packages/security/data/intel/cache/_meta.json`
- `packages/security/src/iab_intel.ts`
- `packages/security/src/device_code_phish.ts`
- `packages/security/src/chaindrop_oidc.ts`
- `packages/security/src/extortion_mode.ts`
- `packages/security/src/iab_handoff_sim.ts`
- `packages/security/src/aitm_playbook.ts`
- `packages/security/docs/ORCHESTRATION.md`
- `packages/security/src/mcp/server.ts` + `mcp/tools/*.ts`
- `packages/security/src/bridges/*.ts`
- `packages/security/test/intel_cache_freshness.test.js`
- `packages/security/test/ransomware_lifecycle.test.js`
- `packages/security/test/ransomware_profiles.test.js`
- `packages/security/test/iab_market.test.js`
- `packages/security/test/device_code_phish.test.js`
- `packages/security/test/chaindrop_oidc.test.js`
- `packages/security/test/extortion_mode.test.js`
- `packages/security/test/iab_handoff_sim.test.js`
- `packages/security/test/mitre_coverage.test.js`
- `packages/security/test/orchestration_canonical.test.js`
- `packages/security/test/stix_ingest.test.js`
- `packages/security/test/generated/module_smoke.test.js`

### Primary Modify Targets

- `packages/security/data/intel/apt_profiles.json`
- `packages/security/data/intel/ransomware_groups.json`
- `packages/security/data/intel/apt_playbook_modules.json`
- `packages/security/data/intel/mitre_techniques.json`
- `packages/security/data/intel/taxii_feeds.json`
- `packages/security/src/intel_feeds.ts`
- `packages/security/src/intel_autonomous.ts`
- `packages/security/src/apt_intel_feed.ts`
- `packages/security/src/engagement_policy.ts`
- `packages/security/src/target_flow.ts`
- `packages/security/src/module_registry.ts`
- `packages/security/src/module_bridge.ts`
- `packages/security/src/credential_graph.ts`
- `packages/security/src/engagement_graph.ts`
- `packages/security/src/mcp_server.ts`
- `packages/security/src/mcp_response.ts`
- `packages/security/src/opsec_gate.ts`
- `packages/security/src/raas_engine.ts`
- `packages/security/scripts/run-fast-tests.ts`
- `packages/security/test/system_completeness.test.js`
- `package.json`

---

## Appendix A: Pending Research Streams (5–11) Integration Slots

When remaining research streams complete, map findings to these slots:

| Stream | Expected Deliverable | Target Phase | Primary Files |
|--------|---------------------|--------------|---------------|
| 5 — C2 tradecraft | DoH/DNS C2, domain fronting refresh | 6.1 | `c2_platform.ts`, `apt_playbook_infra.json` |
| 6 — Zero-day / n-day | KEV-prioritized fuzz targets | 6.2 | `intel_autonomous.ts`, `ares_zero_day_fuzzer` |
| 7 — Nation-state | Salt/Volt Typhoon cloud dwell updates | 6.3 | `apt_profiles.json`, `apt_playbook_modules.json` |
| 8 — AiTM | Evilginx 3.x session patterns | 6.4 | `aitm_playbook.ts`, `evilginx_lab` bridge |
| 9 — AD/Entra | CA policy bypass, PRT abuse | 6.5 | `hybrid_ad_entra.ts`, `device_code_phish.ts` |
| 10 — Financial | SWIFT, wire fraud, SIM-swap chains | 6.6 | `institutional_sectors.json`, `helpdesk_social_auto.ts` |
| 11 — Full landscape synthesis | Priority re-rank matrix update | All | This document §Priority Matrix |

**Integration protocol for each stream:**

1. Add intel JSON entries (profiles, techniques, IAB patterns)
2. Wire modules via `apt_playbook_modules.json` + `module_bridge.ts`
3. Add dry-run test + `system_completeness` resolution check
4. Verify token efficiency benchmark unchanged
5. Document ROE gate in §Live vs Dry-Run matrix

---

## Appendix B: Sprint 1 Execution Checklist (Start Here)

Use this as the first actionable sprint without guessing:

- [ ] **0.1a** Create `scripts/refresh-intel-cache.ts` — fetch KEV + ransomwatch, write `_meta.json`
- [ ] **0.1b** Patch `intel_feeds.ts` line 133–136: offline path uses `cache/ransomwatch.json`
- [ ] **0.1c** Add `intelStalenessWarning()` to `intel_autonomous.ts`
- [ ] **0.1d** Run refresh, commit updated `cache/ransomwatch.json` + `_meta.json`
- [ ] **0.2a** Add `status: "defunct"` to `alphv_blackcat` in `apt_profiles.json`
- [ ] **0.2b** Fix `intel_autonomous.ts` `actorModuleMap` — decouple Play from LockBit
- [ ] **0.2c** Add Play profile to `ransomware_groups.json`
- [ ] **0.3a** Write `docs/ORCHESTRATION.md` decision tree
- [ ] **Tests** Add `intel_cache_freshness.test.js` + `ransomware_lifecycle.test.js`
- [ ] **Verify** `npm run test:fast` green; ransomwatch latest > 2025-01-01

---

*Document version: 1.0 — generated from codebase audit + 2025–2026 threat research (streams 1–4). Update Appendix A when streams 5–11 complete.*
