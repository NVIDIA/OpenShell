---
name: test-audit
description: Use when writing, changing, reviewing, or sweeping tests in the OpenShell workspace (Rust crates, testkit suites, tmachine, remaining e2e, SDKs). Gates new tests and audits existing ones for low-value, implementation-coupled, mock-only, or duplicate tests and the test-only seams they force. Trigger keywords - test audit, audit tests, junk tests, low-value test, prune tests, test quality, mock-only coverage.
metadata:
  internal: true
---

# Test Audit

One value bar, three modes:

- **Authoring:** gate every new or changed test.
- **Audit:** focused sweep of one surface for junk tests and test-only seams.
- **Campaign:** prune one subsystem's tests as several audit passes, not one edit.

This skill judges quality, not coverage. File any gap left by deleting a mock-only test as its own issue.

## Test surfaces

| Surface | Location | Source of truth |
| --- | --- | --- |
| Unit and crate tests | `crates/*/src`, `crates/*/tests` | `TESTING.md`, `CONTRIBUTING.md` |
| Conformance suite | `tests/suites/conformance` | its README: what a test may assert |
| Feature and driver suites | `tests/suites/features`, `tests/suites/drivers/<driver>` | `TESTING.md` |
| testkit, runner, tmachine | `tests/testkit`, `tests/runner`, `tests/tmachine`, `tests/support` | `tests/testkit/README.md` |
| Remaining e2e | `e2e/rust`, `e2e/python` | `TESTING.md` |
| SDK tests | `sdk/typescript`, `python/` (frozen) | `AGENTS.md` |

- New e2e tests are `#[testkit::test]` suites, not `e2e/rust`.
- A portable contract belongs in conformance only if it meets the README criteria. Behavior only some drivers have belongs in `features` or `drivers`.
- Find the task and workflow that runs a test (`mise tasks ls`, `.github/workflows/`, `required-features`, exclusion lists, nextest archives). A well-formed test can be wired to nothing.
- Before calling a fixture unused, grep harness config and playbooks too.

## Authoring gate

Answer all four. A missing answer means do not add the test.

1. Which observable behavior or independent contract does it protect? Name each boundary it crosses (see Boundaries).
2. Which credible regression fails it?
3. Why does existing coverage miss that regression? Each contract has one owner at the strongest boundary. Extend a table-driven case or fixture before adding a near-duplicate.
4. Does it need a production seam (export, flag, wrapper, injection hook) with no production caller? Then test at the real boundary instead.

Then check the junk patterns. A bug regression test must fail on the pre-fix code for the intended reason, and cover the bug once at the owner boundary.

## Contract, not implementation

For every assertion, ask where the expected value came from.

- Traced or run from the code under test: circular. Rederive it independently or reject the test.
- From a spec, protocol, real dependency, or independent computation: valid.

Example: test a unit conversion by the limit a real container reports, not by what the helper returns. This applies to e2e and conformance assertions too.

## Boundaries

Mocking every collaborator proves each side against its own assumptions. Make at least one test cross each boundary for real:

| Boundary | Question |
| --- | --- |
| Process | Does an error reach the right exit code and message through the real entry point? |
| Privilege or identity | Is data written by one identity readable by the next (root fixture, unprivileged runner)? |
| Declaration to enforcement | Is a stored API value enforced underneath? |
| Our code to an external tool | Does the tool behave as we assume? Check the tool, not our comments. |

## Junk patterns

The gate rejects a new test that matches one. Audits hunt for existing ones.

| Pattern | Note |
| --- | --- |
| Assertion-free coverage probe | Runs code, asserts nothing |
| Self-comparison, identity copier | Compares a value with itself or a copy |
| Copied fixture, inventory, manifest, export list | Duplicates the source it checks |
| Exact source, import, or string grep | Breaks on rename, not behavior |
| Private predicate or call-shape test | Duplicated at real boundaries |
| Same contract replayed across unit, e2e, and conformance | One failure mode, several layers |
| Per-driver replay of a conformance contract | Conformance owns it |
| Test that only preserves a test-only export, global, or wrapper | |
| Production code whose only callers are tests | |
| Expected value taken from the implementation | See above |
| Mock that implements the asserted behavior, or one mock for different APIs | |
| Name or fixture promises more than the input exercises | "Rootful parity" test that runs rootless |
| Skips or returns early and passes | Fail with a message, or `#[ignore = "<issue link>"]`; green must not hide an unrun check |
| Conformance test that changes deployment config, needs launcher-set variables or one provisioning tool, or reaches the public internet | Move to `features` or `drivers`, or provision in the test environment |
| Assertion on human-formatted CLI output | Use `--output json` |
| Retry loop that hides a product race | Waiting for an expected state is fine; retrying a failed assertion is not |

## Retention bar

A test earns its cost by protecting behavior, a credible regression, or an independent contract. One that breaks under a behavior-preserving change is suspect, not deletable by default.

Keep tests that independently enforce:

- a public API or proto contract, `ComputeDriver` guarantee, gateway config schema, policy contract, security boundary, sandbox lifecycle invariant, SDK contract, or CI or release artifact contract;
- call order, when order is observable;
- source inspection, when it is the cheapest guard that fails on a contract change (config key, wire byte, CLI flag) and survives an identifier-only refactor.

A retained test that fails on the baseline is a possible product bug: reproduce it and fix the owner. Slow or static is not a deletion reason; a VM suite may be the only real-daemon proof. Prove redundancy before removing.

## Audit workflow

1. **Discover read-only.** One lane per surface; a few high-confidence candidates beat a speculative inventory (campaigns excepted).
2. **Read before judging:** the whole test, its production owner and callers, overlapping tests at other layers, CI routing, history, and scoped `AGENTS.md` files. Check dependency-backed claims against the real dependency.
3. **Record per candidate; a missing field means not ready to delete:**
   - location, and the failure it can detect;
   - non-test callers of the seam;
   - the stronger remaining proof, or why none is needed;
   - whether CI runs it, and the cost of deleting versus rewiring;
   - for ignored or skipped tests: rationale and tracking issue (none is a finding);
   - why the test exists and what removing it unlocks;
   - risk and the focused validation command.
4. **Edit one owner boundary at a time** (a crate, an SDK, one driver's tests). Delete dead exports and wrappers instead of aliasing them. Move retained regressions to their owner. Skip tests already queued by an open migration issue. Prefer net-negative production LOC; add no tests that restate the implementation.
5. **Validate** with the smallest owner and sibling tests first. Run e2e tests locally when a real driver is available. Run format and lint once per batch (`AGENTS.md`, `CONTRIBUTING.md`), then check `git diff --numstat`.

## Landing

The invoking workflow and `AGENTS.md` authorize commit, push, and PR. Use `create-github-pr`, one PR per audited surface.

First search issues (`--state all`, several phrasings) and open PRs for overlapping files. File coverage gaps with `create-github-issue` or `create-spike`, not in the audit PR.

Report: categories removed by surface, production simplifications, retained false positives and why, unfixed mock-only findings, proof run and not run, production versus test LOC, follow-ups.
