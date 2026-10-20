# Kubernetes pair anti-affinity implementation plan

> **For agentic workers:** Execute inline with superpowers:executing-plans. Use test-driven development and a final independent review.

**Goal:** Let operators require or prefer different Kubernetes nodes for each sandbox and its supervisor.

**Architecture:** Add `sandbox_runtime.pod_anti_affinity = off | preferred | required` to the Kubernetes driver. Render symmetric, namespace-local rules using the existing reserved pair and role labels and `kubernetes.io/hostname`. Reconcile driver-owned terms on restart and validate required rules on admitted pods before bootstrap release.

**Tech stack:** Rust, kube/k8s-openapi, Helm, local k3d.

**Spec:** The approved design in this conversation (2026-10-20).

## Constraints and review focus

- Default is off; caller driver config cannot override this operator policy.
- Required mode must not silently degrade, accept prebound pods, or lose its rule during admission.
- Restart must remove obsolete generated terms while preserving unrelated affinity.
- Each pair is independent; this does not segregate every workload from every supervisor.
- Existing running generations are unchanged; new generations use the current gateway configuration.

## Task 1: Configuration and scheduling policy

Files: driver `config.rs`, `lib.rs`, new `scheduling.rs`.

- [x] Add failing tests for parsing all modes, invalid modes, symmetric selectors, preferred weight, default-off behavior, preserving unrelated affinity, mode transitions, and admitted required-rule/prebinding validation.
- [x] Run the focused tests and confirm failure before implementing.
- [x] Add a strict enum and typed helpers for rendering/reconciling affinity and checking admitted pods.
- [x] Run the scheduling and config tests; expect all to pass.

## Task 2: Runtime integration and restart

Files: driver `driver.rs`, `sandbox_runtime.rs`, related tests.

- [x] Add rendering and restart regression tests that fail before wiring the policy.
- [x] Pass the policy to workload and supervisor rendering on create and restart.
- [x] Reconcile stored affinity using current config when starting a generation; validate both admitted pods before releasing gates.
- [x] Run all Kubernetes driver library tests and scoped Clippy; expect success.

## Task 3: Documentation and local Kubernetes verification

Files: Kubernetes driver README, gateway configuration MDX, relevant public/contributor skills, Kubernetes e2e coverage.

- [x] Document configuration, Helm values, pair scope, Pending behavior, and restart semantics.
- [x] Build current gateway/runtime images through repository tasks and deploy to an isolated two-node k3d cluster.
- [x] Verify required separation, restart, unrelated pairs, required failure with one eligible node, and preferred colocation.
- [x] Run applicable formatting/docs checks and obtain one independent code review; fix material findings and rerun affected checks.

## Execution record

- Branch: `feat/no-issue-pair-anti-affinity/russellb` (direct implementation request; no issue supplied).
- Existing untracked `docs/superpowers` files belong to earlier work and remain untouched.
- Baseline test command initially failed before compiling because sccache could not start; retrying without the wrapper.

- Baseline: 297 library tests passed. Final driver checks so far: 308 library tests and one standalone test passed; scoped Clippy passed.
- Independent review identified stale-bootstrap cleanup of Pending pairs and removal of unrelated preference weights. Both findings reproduced with failing tests and fixed. Supervisor scheduling failures now enter sandbox diagnostics.
- Documentation validation, Helm lint/render, and Markdown lint passed. The local cluster is `os-pair-affinity` with an isolated kubeconfig in `/tmp/openshell-affinity-kubeconfig`.

- Built Linux/ARM64 gateway, sandbox, and supervisor images through `mise run build:docker`; refreshed the gateway after review fixes.
- Local k3d E2E: `required_pair_separation_survives_stop_start` passed (two independent pairs, distinct nodes, replacement pod UIDs, usable exec after restart).
- Live required → preferred → off stop/start transitions preserved an unrelated required term, node affinity, and an operator-authored weight-50 preference while replacing only generated terms.
- With one node cordoned, required mode left a peer Pending. Advanced its recorded bootstrap start time by six minutes, observed it across two reconciliation intervals, and verified the same generation recovered when the node was uncordoned.
- Preferred mode successfully colocated the workload and supervisor on the sole eligible node. Both nodes were restored to schedulable, the test sandboxes were deleted, and gateway mode was restored to required.
- The container VM reached the kubelet image-GC threshold (85% disk use); reimported local runtime images before subsequent deployment stages. This required no source changes.
- Remaining test boundary: admission mutation rejection has unit coverage; no live mutating webhook was installed.
