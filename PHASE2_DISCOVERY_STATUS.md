# OurMine Phase 2 — Autonomous Security Discovery Status

## Scope decision

OurMine production code is now separated from validation infrastructure. The product targets explicitly authorized real environments and no longer imports the VM validation tree, reads its result files, or exposes lab-named package scripts. The VM suite lives under `validation/vm` and is test infrastructure only.

> **Validation rule:** unit and reasoning tests may run without a target; live capability proofs must run only inside disposable VMs or VM-backed workers with snapshot, evidence collection, and teardown enforcement.

The current sandbox has no Docker, Podman, QEMU, libvirt, or Multipass runtime. Therefore, it cannot honestly claim a VM-backed live proof from this environment. The validation setup now requires `OURMINE_VALIDATION_VM=1` and correctly refuses to run without that marker. The separation audit passes statically; earlier local fixture smoke checks are retained only as path-regression evidence and are not promoted to VM proof.

## Phase-1 qualification

The Phase-1 registry contains 203 security namespaces, all conservatively marked `UNPROVEN`. The new `phase2-trust-registry.json` does not promote namespaces. It admits only five scoped product primitives with independent evidence: loopback scanner fallback, explicit optional-tool failure, validation target safety, tunnel lifecycle, and structured dispatcher failure. VM lifecycle evidence is deliberately excluded from the trusted product primitive set.

| Qualification class | Count | Meaning |
|---|---:|---|
| Trusted scoped primitives | 5 | Independently evidenced behavior eligible for reasoning |
| Uncertain namespaces | 203 | No complete namespace-level proof; cannot be silently upgraded |
| VM infrastructure capabilities | Excluded | Test support only; never a product primitive |

## Implemented Phase-2 architecture

`security_world_model.ts` extends `AttackSurfaceGraph` rather than replacing it. It represents hosts, services, applications, vulnerabilities, observations, relationships, capabilities, and objectives. Every item carries a knowledge status (`OBSERVED`, `INFERRED`, `HYPOTHESIZED`, `VERIFIED`, or `REJECTED`), confidence, timestamps, and evidence identifiers. The model supports relationship traversal, uncertainty queries, synchronization from the existing attack-surface graph, and JSON persistence with graph rehydration.

`capability_effects.ts` provides trusted capability contracts. A capability must be explicitly trusted and have proof evidence before registration. Contracts declare preconditions, effects, observable effects, failure modes, and rollback. Preconditions are checked against world-model facts. Successful effects become verified observations, while failures become rejected observations and remain available to later reasoning.

`hypothesis_engine.ts` generates competing hypotheses from observed entities and trusted capability effects. It ranks experiments by information gain, confidence, prerequisite satisfaction, reversibility, risk, and cost. Its critic requires provenance and observable consequences, carries alternative explanations, and produces falsification tests rather than allowing immediate execution of the first hypothesis.

`discovery_engine.ts` implements the feedback loop: observe, update, generate, critique, rank, select, execute through an injected executor, compare expected and observed evidence, and update the world model. A failed experiment becomes explicit failure knowledge, and each capability is attempted at most once per engine session to avoid blind indefinite retries.

`CapabilityEffectRegistry.discoverCompositions()` finds novel capability sequences by matching produced effects to another capability’s preconditions. This is effect-based composition, not a hard-coded playbook. `discovery_roles.ts` separates analyst, planner, critic, experimenter, verifier, and orchestrator responsibilities. The verifier independently checks expected observations after execution.

## Verification evidence

The pure Phase-2 reasoning suite passes four tests covering effect preconditions, competing hypothesis ranking, counterfactual critique, novel composition discovery, success verification, and failure learning. The world-model and graph regression suite passes 25 tests. The product-versus-VM separation audit passes with zero forbidden product references and zero legacy lab scripts.

| Check | Result |
|---|---:|
| Product/VM static separation | Passed |
| World-model and graph regression | 25/25 passed |
| Effect and hypothesis reasoning | 4/4 passed |
| Separated role orchestration | 1/1 passed |
| VM runtime availability in current sandbox | Not available |
| VM-backed live proof in current sandbox | Not claimed |
| Repository-wide typecheck | Still blocked by OOM on broad graph |

## Remaining work

The next implementation step is to connect the discovery engine to the existing authorized tool broker through an explicit executor adapter that supplies real target scope, evidence provenance, and rollback handles. That adapter must reject any capability not present in the trusted registry. VM validation should then be run on a worker with a real VM runtime, using snapshots and teardown rather than the local in-process fixture.

The broad namespace population remains intentionally uncertain. No Phase-2 reasoning result may claim a vulnerability, access transition, or attack path as verified unless the underlying capability has a complete proof contract and independent evidence.
