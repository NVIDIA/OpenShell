---
name: test-audit
description: Invoke whenever writing, changing, reviewing, or sweeping tests anywhere in the OpenShell workspace (Rust crates, the e2e and conformance suites, the tmachine harness, and the SDKs). Authoring gate for new tests plus an audit workflow for low-value, implementation-coupled, mock-only, or duplicative tests and the test-only production seams they demand. Trigger keywords - test audit, audit tests, junk tests, low-value test, prune tests, test quality, test coverage gap, mock-only coverage.
metadata:
  internal: true
---

# Test Audit

Three modes, one value bar. Authoring mode gates every new or changed test at
write time. Audit mode runs focused sweeps for tests that re-assert source,
duplicate stronger proof, couple behavior to implementation, use mocks where a
real dependency is cheap, or keep test-only production seams alive. Campaign
mode prunes one subsystem's whole test surface; treat it as several coherent
audit passes, not one giant edit.

This skill covers test quality, not coverage gaps. If an audit shows that a
mock-only test stands in for coverage that should exist against a real
dependency, record that as a coverage gap in its own issue (see Landing). Do
not delete the weak test and leave the gap unrecorded.

## Finding and verifying tests

Test surfaces differ in harness and failure mode: Rust unit tests with fakes,
e2e tests against a real gateway and driver, the portable conformance suite, the
tmachine VM harness, and each SDK's own runner. Do not rely on a remembered
layout.

- Discover where a test lives now. List `tests/`, `e2e/`, and each crate's
  `tests/`, and read the suite READMEs. RFC 0016 sorts e2e tests into
  conformance, feature, driver, and disruption families; use that vocabulary.
- For conformance placement and focused verification commands, use
  `tests/suites/conformance/README.md` as the source of truth. Sharing a
  contract across drivers is not enough on its own to move it there.
- For test and lint commands, follow the verification guidance in
  `CONTRIBUTING.md` and the task definitions under `tasks/` (`mise tasks ls`).
- A test can be well-formed and never run. Check which workflow and task
  executes it, its `required-features`, and any environment defaults. Check
  exclusion lists and wrapper allowlists too: a test can run in one lane and be
  excluded from another, and a nextest archive can only include or exclude whole
  test binaries.
- Before calling a fixture, script, or variable unused, read the harness
  configuration and playbooks that consume it. A grep over Rust sources misses
  consumers elsewhere.

## Authoring gate

Before adding any test, answer these. A missing answer means do not add it yet:

1. What observable behavior, invariant, or independent contract does it
   protect? If the feature crosses a real boundary, name the boundary (see
   Boundaries).
2. What credible regression makes it fail?
3. Why does existing coverage not already catch that failure? Each contract has
   one primary owner at the strongest boundary. Use the conformance README to
   decide whether a portable contract belongs in the conformance suite or is
   genuinely driver-specific. Another layer needs its own distinct risk, such as
   a real daemon that a mock cannot fail the way the real one does. Extend a
   table-driven case or shared fixture before writing a near-duplicate.
4. Does it need a production seam (export, flag, wrapper, injection hook) that
   no production caller needs? If so, move the test to the real boundary.

Then check the test against the junk patterns. A match fails the gate unless the
retention bar names the contract it independently guards. A test that breaks
under behavior-preserving refactoring asserts implementation; rewrite it at the
owning boundary first.

A bug regression test must fail on the pre-fix code for the intended reason and
pass after the owner-boundary repair. Cover the bug once at the owner boundary;
do not replay it at every layer it crosses.

## Verify the contract, not the implementation

Ask of every assertion: where did the expected value come from?

- Traced or run from the implementation itself is circular. It proves the code
  matches itself. Rederive it from an independent source or reject the test.
- Derived from a spec, protocol, real dependency, or independently computed
  value is valid, because it can fail when the code is wrong.

For example, a test of a unit-conversion helper should not hardcode what the
helper returns. It should check what a real consumer observes, such as the
resource limit a real container reports. When no ground truth exists, compute
the expectation by a different path than the implementation uses. The same rule
applies to e2e and conformance assertions computed by calling the code under
test a second time.

## Boundaries

A bug can live in the handoff between components, not inside either one.
Mocking every collaborator proves each side is correct given its assumptions
about the other, not that the assumptions hold. Name the boundaries a feature
crosses and make sure at least one test crosses each for real:

- **Process:** does an error surface as the right exit code and message through
  the real entry point?
- **Privilege or identity:** does data written by one identity stay readable by
  the identity that reads it later? A fixture captured as root but read back by
  an unprivileged runner passes every step in isolation and fails the handoff.
- **Declaration to enforcement:** does a value the API stores get enforced
  underneath? Proving storage says nothing about enforcement.
- **Our code to an external tool:** does the tool behave as our code assumes?
  Check against the tool or its documentation, not our own comments.

Ask: if every collaborator were mocked, which handoffs would never be
exercised? Those deserve a real dependency.

## Junk patterns

The authoring gate rejects a new test that matches one; audits hunt for existing
tests that do.

| Pattern | Notes |
| --- | --- |
| Assertion-free coverage probes | Runs code, asserts nothing |
| Self-comparisons, identity copiers | Compares a value with itself or a copy |
| Copied fixtures, inventories, manifests, export lists | Duplicates the source it checks |
| Exact source, import, or string greps | Breaks on rename, not on behavior |
| Private predicate or call-shape tests | Duplicated at real boundaries |
| Same contract replayed across unit, e2e, and conformance layers | No distinct failure mode per layer |
| Per-driver replays of a portable contract the conformance suite owns | |
| Tests that only preserve test-only exports, globals, or wrappers | |
| Dead production code whose only callers are tests | |
| Expected values taken from the implementation under test | See "Verify the contract" |
| Mocks that implement the asserted behavior, or one mock standing in for different APIs | |
| A mock standing in for a real dependency that is available and cheap in CI | Flag even if well-formed; the gap is coverage-shaped |
| Fixtures that supply the ordering or receipt the owner should produce, or persistence asserted against a store the path never writes | |
| Capability tests that restate declared flags | Should exercise what the flag promises |
| Negative controls that pass for an unrelated reason | A different guard denied it, the path was never reached, or the environment was never reached |
| Names or fixtures that promise more than the input exercises | A "rootful parity" test that only runs rootless |
| A test that skips or returns early and still passes | Fail with a clear message, or exclude or waive it with a rationale and tracking issue; a green result must never hide a check that did not run |
| A conformance test that changes deployment configuration, depends on launcher-set variables or one provisioning tool, or reaches a public internet service | Belongs in a driver, feature, or disruption suite, or its dependencies come from target preparation (RFC 0016) |
| Assertions on human-formatted CLI output where structured output exists | Use `--output json` or equivalent |
| Retry loops that hide a product race | Waiting for an expected eventual state is fine; retrying a failed assertion until it passes is not |

## Retention bar

A test justifies its maintenance cost by protecting behavior, a credible
regression, or an independently meaningful contract. An existing test that must
change for a behavior-preserving reorganization is suspect, not automatically
deletable. The authoring gate still rejects new ones.

Keep a test that independently enforces a public API or proto contract, a
`ComputeDriver` guarantee, the gateway config schema, a policy contract, a
security boundary, a sandbox lifecycle invariant, an SDK contract, or a CI or
release artifact contract. Also keep:

- call ordering when order is observable behavior;
- regressions with a credible failure mode;
- source inspection when it is the cheapest independent guard: it fails when the
  contract changes (a config key, a wire byte, a CLI flag) and survives an
  identifier-only refactor;
- a retained test that fails on the baseline. Treat it as a possible product
  bug, reproduce it, and repair the owner rather than deleting it.

Static or slow is not a deletion reason. A VM-backed suite may be the only real
daemon proof that exists. Prove a test is redundant before removing it.

## Auditing

Keep discovery read-only and report evidence before editing. For broad scope,
run parallel discovery lanes when available, one per surface. Outside campaign
mode, prefer a few high-confidence candidates over a large speculative
inventory.

Before judging a candidate, read the complete test and its production owner,
callers, sibling implementations, overlapping tests at other layers, CI routing,
and history. Read root and scoped `AGENTS.md` files first. When a test claims
dependency-backed behavior, verify it against the real dependency or its
documentation, not the mock.

Record each of these before editing. A missing field means the candidate is not
ready for deletion:

- test name and location, and the failure it can actually detect;
- non-test callers of the covered seam;
- the stronger remaining owner-boundary proof, or why none is needed;
- whether it runs in CI at all, and the cost of deleting it versus fixing its
  wiring;
- for an excluded, skipped, or ignored test, the rationale and tracking issue
  (none is itself a finding);
- why the test or seam exists, and what its removal unlocks;
- risk and the focused validation command.

Edit one coherent owner-boundary batch at a time: one crate, one SDK, or one
driver's tests. Delete obsolete test-only exports, wrappers, and dead production
paths instead of keeping aliases. Move retained regressions to their canonical
owner. Consolidate per-driver assertions of the same contract into one
conformance scenario only when it meets the conformance README's criteria; an
internal `ComputeDriver` contract stays with the driver. Coordinate with open
migration issues so an audit does not delete or rewrite a test already queued
to move. Prefer net-negative production LOC, and do not add replacement tests
that restate the implementation.

Validate with the smallest owner and sibling tests first. For e2e tests that
need a real driver and can run locally, build and run them instead of trusting a
compile check, because wiring bugs hide there. Run the language's own format,
lint and pre-commit gates (see `AGENTS.md`) once per coherent batch, not after
every edit, and inspect `git diff --numstat`.

## Landing

Commit, push, and PR authority belongs to the invoking workflow and `AGENTS.md`,
not this skill. Use `create-github-pr` for PR mechanics once authorized, with
one coherent PR per audited surface.

Before filing an issue or opening a PR, search issues with `--state all` and
more than one phrasing, and check open PRs for overlapping files or behavior,
not just titles. Cross-reference adjacent work and narrow scope instead of
duplicating it. A real product gap that an audit surfaces (missing coverage, not
a junk test) belongs in its own issue via `create-github-issue` or
`create-spike`, not in the audit PR.

Hand off by reporting: the low-value categories removed, by surface; production
simplifications; retained false positives and why they stay; mock-only coverage
findings not fixed here; the proof actually run and what could not be run
locally; production versus test LOC; PR and merge state; and named follow-ups.
