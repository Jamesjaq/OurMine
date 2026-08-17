# Phase 3 Findings — Stubs, False Success, and Execution Boundaries

## Scope reviewed

The inventory covers 203 security TypeScript source files, 56,903 security source lines, 176 exported security namespaces, 46 agent-dispatch tools, 58 MCP tool declarations, 38 package manifests, and 597 test/lab JavaScript or TypeScript files. Every namespace remains `UNPROVEN` in `capability-proof.json` until an independent lab proof exists.

## Confirmed issues

The lab lifecycle contained two concrete defects. `validation/vm/setup.sh` invoked `lab/start_target.ts`, which exports an in-process helper but has no command-line startup path, so setup returned without starting the target. The intended detached `validation/vm/start_target.js` launcher then failed because the `.js` file contained a TypeScript return-type annotation. Both defects were repaired. The localhost target now starts, passes health checks, exposes the expected real endpoint status codes, and cleans up its PID/process state.

The agent tool layer contained several unconditional success responses. The first repaired set covers reconnaissance, suspected-finding validation, identity and AD wrapper result classification, cloud metadata enumeration, container audit, YARA path validation, and the Evilginx lab wrapper. Dry-run, missing-input, configuration-only, and failed-result states are no longer reported as successful operations in those paths. The central dispatcher now converts thrown capability errors into structured failed results, and scanner wrappers invoke real binaries rather than logical registry names. The focused agent-plus-validation regression run now passes 29/29.

The broader static scan still identifies many unconditional `success: true` sites across ARES orchestration, phase runners, C2 channels, implant/scaffold modules, Modbus/SCADA helpers, and other modules. These are not promoted to proven status. They require individual inspection and either real execution-result derivation, an explicit unavailable/external-dependency result, or a redesign of the result contract.

The execution-boundary matrix shows inconsistent implementation paths. Some modules route through `ToolBroker` or `execLive`; others use direct `child_process`, shell-string interpolation, or direct network APIs. This is a confirmed architectural risk and is scheduled for consolidation after the lab and baseline workspace are repaired.

## Test evidence

The initial full security test run was bounded and terminated after the suite continued beyond the audit window; it recorded one failure caused by the old dry-run success expectation. After the implementation and test repair, the expanded focused suites `agent_apt.test.js` plus `ninth_pass.test.js` passed 29/29, the tier1 live suite passed 18/18 and now exits cleanly, and the top-cut suite passed 19/19 in a direct 60-second run. The repository-wide typecheck remains blocked by a command that produces no diagnostics before the bounded timeout; this is distinct from the passing Node test evidence and still requires separate toolchain remediation.

## Current status policy

No capability is marked `PROVEN` merely because a module loads, a command is generated, an internal function returns, or a unit test passes. The proof matrix remains conservative. A capability will be promoted only after real localhost/lab execution, independent target-state verification, captured evidence, cleanup, repeatability, and failure testing.
