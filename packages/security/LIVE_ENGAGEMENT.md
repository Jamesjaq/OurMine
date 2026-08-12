# Live Engagement (ARES)

Operational guide for authorized targets — not lab fiction.

## Environment

| Variable | Effect |
|----------|--------|
| `OURMINE_LIVE=1` | Enable real probes (also auto on Kali, `--live`, `OURMINE_TIER1=1`, `OURMINE_LAB_AUTONOMOUS=1`) |
| `OURMINE_ALLOW_DRY_RUN=1` | Force dry-run even on Kali (CI/dev only) |
| `OURMINE_REQUIRE_LIVE=1` | Bootstrap/MCP treat live as mandatory |
| `OURMINE_MCP_EFFICIENT=1` | Curated MCP surface (default) — includes `ares_engagement_slice`, `ares_engagement_continue`, `ares_autopilot`, `ares_artifact_get`, `ares_threat_intel` |
| `OURMINE_OT_SCAN_MAX` | Max hosts per `ot_batch_scan` page (default 64) |
| `OURMINE_AD_DOMAIN` / `OURMINE_AD_USER` / `OURMINE_AD_PASS` | AD cred paths for identity phases |
| `OURMINE_INTEL_REFRESH=1` | Live pull KEV + ransomwatch on slice/threat_intel (default: cached `.ourmine/intel/`) |

Resolution chain: `resolveLiveMode()` → `resolveDryRun()` (= `!live`). MCP server uses `mcpLive()` → `resolveLiveMode()`.

## 3-turn workflow

1. **`ares_engagement_slice`(target, scope?)** — plan + first phase + graph evidence (`confirmed` / `candidates` / `blockers`). Returns `resumeToken`.
2. **`ares_engagement_continue`(resumeToken)** — next recommended phase without re-planning. Follow `graphNextActions`.
3. **`ares_artifact_get`(id)** — full payload when compact response includes `artifactId`.

Optional: **`ares_autopilot`(target, scope, maxPhases)** runs slice → continue loop server-side. **`ares_threat_intel`** for persona-aware APT tradecraft before turn 1.

## Scope rules

- Declare scope (comma-separated domains/CIDRs). Policy blocks live execution when target is outside scope.
- CIDR targets prioritize `ot_batch_scan` (paginated; use `resumeToken` for /16+).
- OT/PLC personas skip AD identity modules (`cred_access_auto`, `ares_auto_chain`).
- Dry-run adds blocker: `dry-run: live probes skipped — set OURMINE_LIVE=1 or pass --live`.

## OT safety

- **Read-only by default:** Modbus/DNP3/BACnet validation uses register read / who-is probes only (`ics_validation`, `iot_scada`).
- **No writes without live + explicit action:** SCADA `write`/`fuzz`/`exploit` require `live:true` and are gated by `engagement_policy`.
- **Impact proof:** `ics_impact_proof` runs only in live mode after OT hosts discovered in phase steps.
- **Batch scans:** `ot_batch_scan` completes successfully when hosts are scanned (`scanned > 0`), not only when OT is found.

## Wiring

- **Cursor:** `.cursor/mcp.json` → `ourmine-ares` with `OURMINE_LIVE=1`
- **OpenCode:** `opencode_bootstrap` writes `~/.config/opencode/opencode.json` with `mcp.ares` + pentest agent allowlist
