# OurMine Final Validation Report

Generated 2026-08-17. Scope was restricted to the disposable loopback laboratory under `127.0.0.1`; no external target was contacted by the proof harness.

## Executive result

The repaired repository now has a reproducible Bun installation path, a working localhost lab lifecycle, structured failure semantics at the central agent dispatcher, strict validation target parsing, real executable selection for scanner fallbacks, and deterministic tunnel cleanup. The proof matrix remains conservative: namespace-level capabilities are not promoted to `PROVEN` solely because their modules load or their unit tests pass.

| Area | Result | Evidence |
|---|---:|---|
| Bun workspace installation | Passed | `bun install --frozen-lockfile --ignore-scripts`, 4,615 packages installed |
| Lab setup and health | Passed | `validation/vm/setup.sh` starts the detached target and health checks succeed |
| Lab teardown | Passed | PID is stopped and teardown completes |
| Loopback HTTP state checks | Passed | `/` = 200, `/admin/` = 200, `/missing` = 404 |
| Live scanner fallback | Passed | `nmap_scan` selected `curl`, captured HTTP headers, ingested port 8080 |
| Optional scanner absence | Correct failure | `gobuster` and `nuclei` return `success: false` with installation errors |
| Dispatcher error handling | Passed | Unknown and live-gated tools return structured failed results |
| Validation safety boundary | Passed | Malformed and out-of-scope targets are rejected before command construction |
| Tunnel lifecycle | Passed | Loopback forward served lab state, then closed and became unreachable |
| Focused regression suite | Passed | 29 tests passed, 0 failed |
| Tier-1 live suite | Passed | 18 tests passed, 0 failed, process exits cleanly |
| Top-cut suite | Passed | 19 tests passed, 0 failed in direct 60-second run |
| Repository-wide typecheck | Blocked | Bounded command timed out before emitting diagnostics |

## Repairs completed

The lab startup path was repaired by making `validation/vm/setup.sh` invoke the valid detached JavaScript launcher and by removing TypeScript-only syntax from `validation/vm/start_target.js`. The workspace was repaired with Bun catalog and workspace metadata, and the unused nonexistent `@ourmine/core` dependency was removed from the security package.

The execution layer was repaired at several high-confidence boundaries. `runtime_capability.ts` now exports the named `probeCapabilities` function consumed by live scan code. `nmapScan` passes the selected executable to the broker, allowing the container-safe `curl` fallback to execute. Gobuster and Nuclei wrappers now pass their real binary names rather than logical registry names. The central `executeAgentTool` dispatcher catches capability exceptions and returns `success: false` with the error text, so live-only gates and missing dependencies cannot escape as uncaught orchestration failures.

Validation planning now applies strict `host:port` parsing, port-range checks, exact authorized-host matching, and command generation for HTTP state, L3, and L4 read-only plans. Tunnel creation returns a disposer and unrefs live listeners; the tier-1 test process now exits after teardown instead of hanging on leaked listeners.

## Loopback proof details

The HTTP proof runner starts the real detached target and independently verifies endpoint status changes. The live scan path uses the actual `curl` executable fallback and records the captured HTTP response in graph evidence. Optional tools are not simulated: when `gobuster` or `nuclei` are absent, their results are explicit failed/unavailable results.

The adversarial runner performed seven checks: dry-run denial, broker non-live denial, unknown-tool structured failure, malformed-target rejection, live tunnel binding, live forwarding to the lab endpoint, and post-close listener cleanup. All seven passed.

## Test evidence

The final per-file matrix contained 21 security test files. Twenty files passed in the final isolated run; the top-cut file had one transient failure in that aggregate run but passed independently immediately afterward with 19/19. The stable focused results are therefore reported from the direct rerun, not from the transient aggregate record. The tier-1 suite passed 18/18 after the tunnel lifecycle repair, and the expanded agent-plus-validation regression run passed 29/29.

## Remaining limitations

The repository still contains a broad static population of unconditional success markers across ARES orchestration, C2 and implant/scaffold modules, Modbus/SCADA helpers, and other namespaces. These are not silently reclassified. Each requires its own evidence contract and lab proof before being considered operational. Optional Kali tooling is not present in the current sandbox, so those capabilities are correctly recorded as unavailable rather than simulated.

The full repository typecheck remains unresolved because the root command produces no diagnostics before the bounded timeout. This is a toolchain or project-scale issue rather than evidence that the repaired security paths fail; it remains an explicit follow-up item.

## Files containing evidence

| File | Purpose |
|---|---|
| `audit/proof/http-lab-proof.json` | Loopback endpoint, scanner fallback, graph-ingestion, and optional-tool evidence |
| `audit/proof/adversarial-lab-checks.log` | Seven denial, forwarding, and cleanup checks |
| `audit/proof/security-test-file-run-final.log` | Isolated per-file test results |
| `audit/proof/top-cut-current.log` | Direct stable 19/19 top-cut rerun |
| `audit/proof/tier1-after-tunnel-lifecycle-fix.log` | Direct stable 18/18 tier-1 live run |
| `audit/proof/ninth-pass-regression.log` | Planner and graph regression evidence |
| `audit/proof/phase3-findings.md` | Static audit and repair chronology |
| `audit/proof/capability-proof.json` | Conservative namespace inventory; unproven until independent evidence exists |
