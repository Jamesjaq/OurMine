# OurMine — End-to-End Repository Audit

**Repository:** `Jamesjaq/OurMine`
**Audited revision:** `e5ff3d6` — “Add token-efficient MCP mode with OpenCode tool globs and search layer.”
**Branch state:** `main`, clean relative to `origin/main` at clone time.
**Audit scope:** repository structure, runtime entrypoints, package boundaries, security/MCP execution paths, configuration, installation, tests, and reproducibility.

## Executive assessment

OurMine is a large TypeScript monorepo that combines a substantial OpenCode-derived developer platform with an ARES security-automation layer. The repository is not merely a passive scanner library. It exposes an interactive CLI, delegates non-security commands to an external `opencode` executable, and exposes security modules through a local MCP server. The security package contains both simulation/reporting logic and live command-execution paths, including reconnaissance, scanning, identity attacks, credential operations, lateral movement, post-exploitation, persistence, implant-oriented modules, and destructive-impact-themed modules.

The most important architectural fact is that **live execution is an explicit mode, but the defaulting rules are broad**. Live mode can be enabled by `--live`, environment variables, tier-1/autonomous lab variables, or detection of Kali Linux. The installer also writes persistent environment configuration on Kali. A safe deployment should therefore treat the application as a privileged offensive security toolkit, not as an ordinary documentation or developer assistant application.

The repository is ambitious and heavily instrumented, but its current engineering baseline is not release-ready. The documented npm installation path is incompatible with the workspace’s `catalog:` dependency protocol, while pnpm installs only the root development dependencies because the repository lacks the `pnpm-workspace.yaml` file that pnpm expects. The root typecheck fails with many errors, including missing package dependencies, missing Playwright types, unresolved extensionless imports, and strictness errors. The root test command did not complete within the bounded audit window. These are reproducibility and CI-gating problems rather than isolated defects.

| Area | Assessment | Confidence |
|---|---|---|
| Repository comprehension | Clear monorepo boundaries and identifiable runtime paths | High |
| CLI architecture | Understandable dispatcher with OpenCode delegation and ARES commands | High |
| Security execution model | Real live execution exists behind mode and policy gates | High |
| Installation reproducibility | Broken or ambiguous in a clean npm/pnpm environment | High |
| Type safety | Root typecheck currently fails substantially | High |
| Test confidence | Incomplete; root test run did not finish in the audit window | Medium |
| Security posture | High-risk by design; needs strict default-deny deployment controls | High |
| Release readiness | Not ready without dependency, workspace, and validation remediation | High |

## Repository shape and package architecture

The repository is organized as a workspace-style monorepo under `packages/`. It contains the OpenCode application ecosystem—core services, CLI, client, protocol/schema layers, TUI, UI, session UI, SDKs, server, desktop, web, stats, and integrations—alongside a distinct `packages/security` package. The root `package.json` names the project `ourmine`, declares workspaces using `packages/*`, provides the `ourmine` binary, and defines build, typecheck, test, lab, benchmark, and audit scripts. The root TypeScript configuration uses strict mode, NodeNext module resolution, path aliases for core and security, and explicitly excludes several large packages from the root compilation scope.

The repository contains a very large source surface, including thousands of TypeScript/TSX files plus extensive documentation, localization, UI assets, and test fixtures. This appears to be an OpenCode codebase extended with OurMine branding and security capabilities rather than a small greenfield application. The practical consequence is that changes to the security layer, launcher, configuration, or OpenCode integration must be evaluated against a broad set of shared types and runtime assumptions.

| Layer | Representative location | Responsibility |
|---|---|---|
| Launcher | `bin/ourmine.ts`, `bin/ourmine` | CLI parsing, security command routing, OpenCode delegation |
| Security API | `packages/security/src/index.ts` | Namespace exports for the ARES/security modules |
| Tool execution | `packages/security/src/agent_tools.ts`, `runtime_exec.ts`, `tool_broker.ts` | Tool dispatch, subprocess execution, dry-run display, output handling |
| Agent orchestration | `pentestgpt_agent.ts`, `apt_playbook.ts`, `ares/orchestrator.ts` | Task planning, phases, subagents, playbooks, automated execution |
| MCP exposure | `mcp_server.ts`, `mcp_dispatch.ts`, `mcp_bridged_tools.ts` | JSON-RPC stdio server and LLM-callable tool surface |
| OpenCode platform | `packages/opencode`, `packages/core`, `packages/app`, `packages/tui`, `packages/ui` | Developer-agent runtime, UI, server, configuration, MCP lifecycle |
| Lab/validation | `lab/`, `audit/` | Local target environment, benchmarks, capability reports, adversarial checks |
| Installation | `install.sh`, `uninstall.sh` | Clone/update, optional OpenCode installation, npm linking, Kali setup |

## End-to-end runtime flow

### CLI startup and command routing

The primary entrypoint is `bin/ourmine.ts`. It defines a set of OurMine-specific security commands such as `recon`, `audit`, `pentest`, `yara`, `c2`, `serve`, `agent`, `watch`, `retest`, `tier1`, and related aliases. Commands outside that set are passed to the external `opencode` binary. Bare `ourmine` and TUI-oriented invocations therefore do not run a separate OurMine UI implementation; they delegate to OpenCode with inherited stdio and environment variables including `OURMINE=1` and `OURMINE_BRAND=1`.

Security commands create an `ExecutionDisplay`, resolve live/dry-run behavior, and invoke functions from `packages/security/src/index.ts`. The index file re-exports a very broad set of namespaces. This gives the CLI and MCP layer a convenient aggregate API, but it also makes the public security surface difficult to reason about and increases the blast radius of accidental exports.

### Reconnaissance flow

`ourmine recon <target>` invokes AI reconnaissance and bounty-hunter reconnaissance, then emits subagent-style progress messages and findings. The code references passive OSINT sources such as certificate transparency, Shodan, Have I Been Pwned, and LinkedIn. The display layer is partly presentation-oriented: `runSubagent` in `runtime_exec.ts` loops over module names, waits briefly, and returns synthetic dry-run findings. This means the presence of an “agent” event in the terminal does not by itself prove that a real independent agent was executed.

### Audit flow

`ourmine audit <target>` checks local/container and cloud-related conditions, including Docker socket exposure, cgroup escape indicators, cloud metadata access, and counter-intelligence signals. The command is materially different from a pure target URL scanner because some checks inspect the host execution environment. In live mode, functions may access local system state or external metadata endpoints.

### Pentest and agent flow

`ourmine pentest <target>` builds a PentestGPT planning tree, iterates over several named subagents, and then runs `PentestAgent.runAutonomous()`. The subagent display path includes deterministic simulation behavior, while the agent path can dispatch into the registered security tool map. `ourmine agent <target>` constructs a `PentestAgent` with a configurable live/require-live mode and a maximum step count. LLM provider detection is based on environment variables, with deterministic fallback behavior when no provider key is present.

The planning model is phased: reconnaissance, scanning, exploitation, post-exploitation, reporting, and cleanup. APT tradecraft and playbook code adds preconditions, fallback chains, technique labels, timing/infra metadata, and phase ordering. These structures are useful for controlled lab automation, but their names and orchestration semantics show that the repository models multi-stage offensive operations rather than only vulnerability assessment.

### MCP flow

`ourmine serve` starts `packages/security/src/mcp_server.ts`, which implements a line-oriented JSON-RPC 2.0 server over stdin/stdout. It exposes security tools, bridged tools, a bash-like tool broker, and tool-search/efficiency helpers. The server determines live mode through the shared resolver, applies context wrapping to tool output, invokes an OPSEC gate, and dispatches permitted commands through `ToolBroker`.

The MCP design lets an LLM agent discover and call security functions natively. The server description explicitly includes recon, pentest, C2, malware analysis, YARA, and related capabilities. The repository’s latest commit adds token-efficient MCP filtering and a search layer, but this optimizes tool exposure; it does not replace authorization, tenant isolation, target authorization, or human approval controls.

### Shell and subprocess execution

`runtime_exec.ts` provides two important paths. In dry-run mode, `execShell` prints the requested command and returns a successful synthetic result. In live mode, it delegates to `ToolBroker.executeSafe`. Other modules in the security package use subprocess APIs and command strings for specialized tools. The codebase also contains platform and hardware-oriented execution helpers, including firmware operations, SDR probing, code-signing certificate discovery, background processes, and ticket-related command construction.

The implementation therefore has a meaningful distinction between simulation and execution, but the safety of that distinction depends on every caller passing the correct mode and on the broker/gate implementation remaining complete. A security review should specifically test every exported tool for mode propagation, command injection resistance, path validation, target scope enforcement, and output redaction.

## Live-mode and safety analysis

The shared resolver in `packages/security/src/exec_options.ts` returns live mode when any of the following is true: an explicit live option, `OURMINE_LIVE=1` or `true`, `OURMINE_TIER1=1` or `true`, `OURMINE_LAB_AUTONOMOUS=1`, a `--live` process argument, or detection of Kali Linux. An explicit dry-run option takes precedence. `requireLiveMode()` returns true for `OURMINE_REQUIRE_LIVE=1` or Kali detection.

This policy is operationally significant. **Kali detection is an implicit mode switch.** A user can clone the repository on a Kali host and obtain live behavior without passing `--live`, depending on the caller path. The installer additionally creates `~/.ourmine/env.sh` on Kali and writes `OURMINE_LIVE=1` and `OURMINE_REQUIRE_LIVE=1` into it. This is a surprising default for software that can perform network reconnaissance and execute security tools.

The MCP bash handler is more carefully structured: it refuses to execute in dry-run mode, calls `gateExecution`, and only then invokes `ToolBroker.executeSafe`. However, the overall system contains many modules and bridged paths. A single safe MCP handler does not establish that every exported module is equally constrained. The risk is amplified by the aggregate re-export in `security/src/index.ts` and by the ability of an LLM agent to discover and call tools autonomously.

## Dependency and build reproducibility

The root package uses npm scripts, but workspace package manifests contain the pnpm-style `catalog:` protocol. Running `npm install --ignore-scripts` failed with `EUNSUPPORTEDPROTOCOL` because npm does not understand `catalog:`. Running pnpm succeeded only with a warning that the `workspaces` field is unsupported and that a `pnpm-workspace.yaml` file should be created. In the checked-out state, pnpm installed only the root development dependencies, not the full monorepo package graph.

This means the repository currently has no single unambiguous clean-install path. The installer script compounds this ambiguity: it first runs `npm install --ignore-scripts`, falls back to `npm install`, and then ignores installation failure with `|| true`. It proceeds to `npm link --force` even when dependencies may be absent. A successful installer message can therefore be emitted after an incomplete installation.

The recommended remediation is to choose one package manager, commit its workspace configuration and lockfile, make scripts consistent with that choice, and fail installation on dependency errors. If pnpm is the intended manager, add `pnpm-workspace.yaml`, pin the package manager version, and replace the root npm-oriented installation instructions. If npm is required, remove or translate catalog dependencies and commit a valid npm lockfile.

## Validation results

The first safe validation attempt showed that the root npm scripts could not find `tsc` before dependencies were installed. After a controlled pnpm install, the root typecheck ran but failed with many diagnostics. The observed classes of errors included missing `@playwright/test` declarations, unresolved extensionless imports under NodeNext resolution, missing fixture modules, implicit `any` parameters, and strict DOM typing issues in performance/e2e files. The failure was not limited to one package or one generated file.

The root `npm test` command did not finish within the bounded audit window and was terminated. The repository contains many test suites across core, client, codemode, OpenCode, session UI, application e2e/performance, and security. The root test script itself targets only `packages/security/test/*.test.js`, while `test:all` depends on Bun being installed and loops over a selected subset of packages. This creates a mismatch between the apparent monorepo size and what a default root test actually validates.

| Check | Result | Evidence |
|---|---|---|
| Clone/revision | Passed | Revision `e5ff3d6`, clean branch at clone time |
| npm install | Failed | `EUNSUPPORTEDPROTOCOL` for `catalog:` |
| pnpm install | Completed with warning | No `pnpm-workspace.yaml`; only root dependencies were installed |
| Root typecheck | Failed | Missing modules, NodeNext import errors, strictness errors, e2e typing failures |
| Root test | Inconclusive/terminated | Did not complete in bounded audit window |
| Static secret-marker scan | No obvious private-key/API-key marker found in checked non-doc source | This is not proof that secrets are absent |
| CI discovery | No clear repository-level workflow was surfaced in the bounded inspection | Should be verified and formalized |

The checked-in `audit/` and `validation/vm/results/` artifacts also deserve caution. They contain benchmark and capability reports with tool command strings and captured outputs. Some recorded evidence is internally inconsistent—for example, an output may show a failed executable invocation while a higher-level parser marks a finding as confirmed. These artifacts should be treated as fixtures or claims until independently reproduced, not as authoritative security evidence.

## Security and operational risks

### High-risk capability concentration

The security package includes names and flows for credential attacks, lateral movement, post-exploitation, persistence, implants, C2, evasion, ransomware/impact assessment, hardware/firmware actions, and supply-chain operations. Some modules may be simulations or wrappers that require unavailable tools, but the presence of live execution code and command construction means the repository must be handled as high-risk software. The correct control boundary is the whole process and host, not an individual module.

### Scope and authorization enforcement

The code shown in the primary paths accepts a target string and a scope array, but the repository-wide audit did not establish a universal authorization or target-ownership check before every network-capable action. A production version should require an explicit signed engagement scope, reject private/link-local/metadata targets by default unless separately authorized, enforce DNS/IP allowlists, and require human approval before exploitation, credential operations, lateral movement, persistence, or impact actions.

### Command and path construction

Several execution helpers construct shell command strings from parameters such as targets, paths, domains, users, and output locations. Even if `ToolBroker` applies validation, every command construction path must be reviewed as a separate injection and argument-boundary risk. Prefer argument-array APIs, canonicalize and constrain paths, reject shell metacharacters where shell syntax is unnecessary, and centralize command policy rather than allowing modules to bypass the broker.

### LLM autonomy and untrusted output

The MCP server intentionally makes security tools available to an LLM. Tool outputs can contain attacker-controlled text, and context-guard wrapping is not equivalent to a complete prompt-injection defense. The system needs strict separation between tool data and instructions, schema validation on tool results, bounded execution budgets, approval checkpoints, and audit logging that records the exact principal, target, command, authorization, and result.

### Installer trust and persistence

The installer downloads and executes a remote OpenCode installation script when OpenCode is absent, clones the default branch, runs package-manager commands, links the CLI globally, and writes environment configuration on Kali. It does not pin a commit, verify a release signature, or fail closed when dependency installation fails. This is an unacceptable supply-chain posture for a tool that may later execute privileged security operations.

### Data handling

The repository includes a SQLite database, lab logs, captured tool outputs, wallet/backup-related terminology, and code that writes artifacts and scans for credentials/certificates. The `.gitignore` covers `.ourmine/` runtime artifacts and security test temporary directories, but operators still need explicit rules for logs, proof packs, credentials, session state, and target data. A secure deployment should encrypt sensitive artifacts, minimize retention, redact secrets before persistence, and prevent target data from entering telemetry or LLM prompts without authorization.

## Recommended remediation sequence

First, establish a reproducible build. Select pnpm or npm, commit the corresponding workspace metadata and lockfile, remove silent installation fallbacks, and add a clean CI job that installs from scratch and fails on any dependency or typecheck error.

Second, make dry-run the only default on every operating system. Remove implicit Kali live activation, require an explicit signed or interactive authorization for live mode, and make the MCP server refuse live operation unless an approval token and target scope are present.

Third, centralize the execution boundary. Ensure every network, subprocess, file-write, credential, and hardware operation routes through one policy-enforcing broker. Replace interpolated shell strings with argument arrays wherever possible, add target allowlists and forbidden-target checks, and add tests that prove bypass attempts fail.

Fourth, reduce the public surface. Export a deliberately documented tool registry rather than every namespace from `security/src/index.ts`. Separate harmless assessment/reporting modules from high-impact operations at the package and process level. High-impact capabilities should be excluded from ordinary installs and require an isolated lab build.

Fifth, repair the validation strategy. Make the root typecheck pass or explicitly partition tsconfigs by package. Install and type the Playwright/e2e dependencies correctly, fix NodeNext import extensions, and add a fast deterministic security test target that runs without external tools. Then add integration tests for dry-run/live transitions, MCP authorization, broker policy, output redaction, target scope, and installer failure behavior.

Sixth, harden supply chain and operations. Pin installer revisions, verify checksums/signatures, remove remote script execution where possible, fail closed on package installation errors, document required privileges, and ship a threat model and operational runbook. Treat benchmark artifacts as reproducible fixtures with provenance rather than as proof of capability.

## Final conclusion

The repository is best understood as **an OpenCode-based agent platform augmented with a broad autonomous security operations framework**. Its architecture is coherent at a high level: CLI dispatches to either OpenCode or ARES, ARES modules feed an agent/tool layer, and MCP exposes those tools to an LLM. The implementation also contains real live-execution pathways, not only mock demonstrations.

However, the current repository state has major engineering and governance gaps. Installation is not reproducible through the documented npm path, pnpm workspace metadata is incomplete, typechecking fails broadly, and the root test signal is insufficient. More importantly, implicit live-mode activation, broad module re-exports, autonomous MCP access, command construction, and a permissive installer create a high-risk operational profile. The code should not be deployed against real systems until authorization, default-deny execution, supply-chain verification, and CI validation are substantially strengthened.

## Source references

[1]: `README.md` — project overview, commands, launch model, and installation claims.
[2]: `package.json` — root scripts, workspace declaration, dependencies, and test/build commands.
[3]: `tsconfig.json` — root compiler settings, aliases, strictness, and excluded packages.
[4]: `bin/ourmine.ts` — CLI command classification, OpenCode delegation, security handlers, and live flags.
[5]: `packages/security/src/index.ts` — aggregate security namespace exports.
[6]: `packages/security/src/exec_options.ts` — live/dry-run resolution and Kali/environment behavior.
[7]: `packages/security/src/runtime_exec.ts` — dry-run display, subprocess execution boundary, and subagent simulation.
[8]: `packages/security/src/mcp_server.ts` — MCP JSON-RPC server, exposed tools, live handling, and OPSEC gate invocation.
[9]: `packages/security/src/agent_tools.ts` — security tool wrappers, dispatch map, and tool result handling.
[10]: `packages/security/src/ares/` — ARES orchestration and advanced operational modules.
[11]: `install.sh` — clone/update, OpenCode bootstrap, dependency installation, npm linking, and Kali environment setup.
[12]: `audit/offensive-capability-reality.md` and `validation/vm/results/` — checked-in benchmark and capability evidence artifacts.
[13]: `typecheck-pnpm.log` — captured root typecheck diagnostics from the audit environment.
[14]: `npm-install.log` and `pnpm-install.log` — captured package-manager behavior during the audit.

*Prepared by Manus AI.*


## Autonomous repair and proof pass — 2026-08-17

The repository was subsequently repaired and exercised inside a disposable loopback lab. The detached lab launcher was corrected, Bun workspace metadata was restored, and the stale `@ourmine/core` dependency was removed. Scanner execution boundaries were repaired so fallback selection invokes real executables. The central agent dispatcher now converts thrown module errors into explicit failed results instead of allowing callers to mistake exceptions or gated operations for success.

Validation planning now rejects malformed or out-of-scope `host:port` targets before command construction and emits bounded read-only commands for stateful HTTP, L3, and L4 plans. Live tunnel listeners now expose cleanup disposers and are unrefed; the tier-1 suite consequently exits cleanly after all live checks.

The isolated proof runner verified `/` with status 200, `/admin/` with status 200, and `/missing` with status 404. The live `nmap_scan` path selected the `curl` fallback, captured real HTTP headers including the fixture’s Log4j marker, and ingested port 8080 into the attack-surface graph. Gobuster and Nuclei were unavailable in the sandbox and correctly returned explicit failures rather than fabricated success.

The adversarial loopback run passed seven checks: dry-run denial, broker non-live denial, unknown-tool structured failure, malformed-target rejection, live tunnel binding, forwarding of lab state through the tunnel, and post-close listener cleanup. The focused agent-plus-validation regression run passed 29/29; the tier-1 live suite passed 18/18; and the direct top-cut rerun passed 19/19. The repository-wide typecheck remains a bounded blocker because the root command produces no diagnostics before timeout.

The conservative namespace matrix remains unproven for full capabilities. Passing tests and successful module imports do not promote an entire namespace to proven status; only the scoped loopback claims recorded in `audit/proof/capability-evidence.json` are marked proven.

See `audit/proof/final-validation-report.md` for the complete post-repair status and `audit/proof/capability-evidence.json` for machine-readable proof records.


## Phase-2 real-world runtime and autonomous discovery pass — 2026-08-17

The product/runtime boundary was corrected in response to the requirement that OurMine itself operate against real authorized environments rather than depending on a bundled lab. The former `lab/` tree is now under `validation/vm/`, the security HTTP fixture is test-only, root commands use explicit `validation:vm:*` names, and the production CLI no longer imports VM benchmark code. A static separation audit reports zero product references to `validation/vm` or the retired `lab/` path and zero legacy lab scripts.

The product no longer uses lab-specific autonomous environment names. The neutral controls are `OURMINE_AUTONOMOUS`, `OURMINE_TIER1_MFA`, and `OURMINE_ALLOW_FLASH_WRITE`. Runtime benchmark data uses an explicit `OURMINE_BENCHMARK_PATH` or neutral `.ourmine/benchmarks` storage, and hypervisor engagement artifacts use `.ourmine/engagement` rather than a lab directory.

Phase 2 now has a persistent `SecurityWorldModel` around `AttackSurfaceGraph`. It tracks typed entities, relationships, observations, capability contracts, objectives, knowledge status, confidence, temporal fields, and evidence provenance. It supports uncertainty queries, observed-versus-hypothesized path traversal, graph synchronization, and snapshot persistence with graph rehydration.

`CapabilityEffectRegistry` admits only trusted primitives with proof evidence and models prerequisites, effects, observable effects, failure modes, and rollback. `HypothesisEngine` generates competing hypotheses, ranks experiments by information gain and risk-aware criteria, and supplies counterfactual alternatives and falsification tests. `DiscoveryEngine` implements the observe-plan-critic-execute-verify loop, records failures as rejected observations, and prevents blind repeated attempts. Effect matching discovers capability compositions dynamically when one capability produces a state required by another. `DiscoveryOrchestrator` separates analyst, planner, critic, experimenter, verifier, and orchestration roles.

The Phase-1 registry remains conservative: 203 namespaces are uncertain, while only five scoped product primitives are eligible for Phase-2 reasoning. VM lifecycle evidence is excluded from trusted product capabilities. Pure Phase-2 tests pass 37/37, including world-model persistence, effect contracts, competing hypotheses, novel composition discovery, failure learning, role separation, and existing security regressions.

The current sandbox has no Docker, Podman, QEMU, libvirt, or Multipass runtime. Accordingly, no VM-backed live proof is claimed here. The validation suite is prepared for execution by an isolated VM worker with snapshot and teardown enforcement; the local smoke checks only verified relocation and path integrity.
