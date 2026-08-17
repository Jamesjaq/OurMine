# VM-only validation suite

This directory is **not part of the OurMine product runtime**. It contains disposable validation fixtures, benchmarks, and target helpers used only to test the product against isolated virtual machines or VM-backed environments.

The product itself targets explicitly authorized real environments. It must not import this directory, rely on its target addresses, read its result files, or infer live mode from a VM/test marker. The production runtime receives targets, scope, credentials, tool paths, and output locations from the operator or deployment configuration.

## Execution contract

Validation must run inside disposable VMs or VM-backed CI workers with no route to production networks. The current sandbox does not provide Docker, Podman, QEMU, libvirt, or Multipass, so it cannot honestly claim to provision a VM here. Unit and contract tests may run locally because they do not contact external targets; environment and live-capability proofs must run through this directory on an isolated VM worker.

The VM worker should expose only the fixture network required by the selected test, snapshot the guest before execution, collect evidence and state-transition records, and destroy or revert the guest after teardown. A successful test requires target-state verification, captured provenance, cleanup confirmation, and a clean worker reset.

## Commands

From the repository root, use `validation/vm/setup.sh` and `validation/vm/teardown.sh` only inside the isolated VM worker. The package scripts `validation:vm:up`, `validation:vm:down`, and `validation:vm:health` expose the VM-only lifecycle explicitly; capability benchmark scripts likewise live under the validation namespace.
