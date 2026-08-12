# ARES Orchestration Decision Tree

Canonical engagement path: **`ares_engagement_slice` → `ares_engagement_continue` → `ares_autopilot`**

Legacy LLM-steered path: **`ares_pentest_run`** (PentestGPT) — use only for ad-hoc tasks with explicit opt-in.

## When to use which entrypoint

```
                    ┌─────────────────────────┐
                    │   New engagement start   │
                    └───────────┬─────────────┘
                                │
              ┌─────────────────┼─────────────────┐
              ▼                 ▼                 ▼
     identity_first      cloud_ransom         ot_ics
     ransomware_impact    supply_chain      hybrid_it_ot
              │                 │                 │
              └─────────────────┼─────────────────┘
                                ▼
                  ares_engagement_slice  ◄── DEFAULT
                  (persona + objective + intel prefetch)
                                │
                                ▼
                  ares_engagement_continue
                  (phase execution via MODULE_BRIDGE)
                                │
                                ▼
                  ares_autopilot
                  (pickAutopilotAction loop)
```

## Decision matrix

| Scenario | Entry | Why |
|----------|-------|-----|
| Standard pentest campaign | `ares_engagement_slice` | Token-efficient (≤1KB/turn), intel prefetch, policy gates |
| Continue after slice | `ares_engagement_continue` | Executes next phase modules with RoE |
| Hands-off module picking | `ares_autopilot` | Server-side action selection, no LLM burn |
| Ad-hoc LLM tool steering | `ares_pentest_run` | Legacy — higher token cost, ValidationEngine path |
| Intel lookup only | `ares_threat_intel` | Compact digest + artifact indirection |
| Refresh stale caches | `npm run intel:refresh` | KEV + ransomwatch offline data |

## Objective routing

| Objective | Primary modules | APT hints |
|-----------|-----------------|-----------|
| `identity_first` | oauth_consent_audit, device_code_audit, idp_audit | scattered_spider, apt29 |
| `cloud_ransom` | hybrid_ad_audit, ares_cloud_native, cloud_token | storm_0501 |
| `supply_chain` | lockfile_scan, cicd_audit, chaindrop_oidc | team_pcp, chaindrop |
| `ot_ics` / `hybrid_it_ot` | ot_batch_scan, hybrid_pivot, iot_scada | sylvanite_voltzite |
| `ransomware_impact` | raas_leak_catalog, esxi_audit (extortion-only default) | play, ransomhub |

## Safety defaults

- **Dry-run** is default for all modules unless `OURMINE_ROE_SIGNED=1` + live gates pass
- **Extortion-only** default in dry-run — no VSS wipe / ESXi encrypt without `OURMINE_FORCE_LIVE=1`
- **Intel** never inlined in MCP — use `ares_artifact_get` with `aid` from prefetch

## Anti-patterns

1. Starting with `ares_pentest_run` for routine campaigns (37KB/20 tools vs ~941B/3 turns)
2. Inline ransomwatch/KEV dumps in LLM context
3. Treating ALPHV as active (defunct since 2024-12; use Play/RansomHub)
4. Auto-running `aitm_proxy` (HITL only, external-by-design)
