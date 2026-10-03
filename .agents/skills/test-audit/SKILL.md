---
name: test-audit
description: Invoke whenever writing, changing, reviewing, or sweeping tests anywhere in the OpenShell workspace (Rust crates, e2e/rust, the conformance suite, tests/ansible tmachine suites, Python, TypeScript SDK, Go SDK). Authoring gate for new tests plus an audit workflow for low-value, implementation-coupled, mock-only, or duplicative tests and the test-only production seams they demand. Trigger keywords - test audit, audit tests, junk tests, low-value test, prune tests, test quality, test coverage gap, mock-only coverage.
metadata:
  internal: true
---

# Test Audit

Three modes, one value bar. Authoring mode gates every new or changed test at
write time. Audit mode runs focused sweeps of tests that re-assert source,
duplicate stronger proof, couple behavior to implementation, rely on mocks
where a real dependency is cheap and available, or keep test-only production
seams alive. Campaign mode prunes one whole subsystem's test surface (every
test file a crate or SDK owns) — treat it as several coherent audit passes,
not one giant edit.

This skill covers test *quality*, not test *coverage gaps*. If you're looking
for missing coverage rather than junk coverage, that's a `create-spike`
investigation, not this skill. The two are complementary: an audit here can
surface that a mocked-only test is standing in for coverage that should exist
against a real dependency — file that as a coverage gap, don't just delete the
weak test and leave the gap unrecorded.

## Why this exists in OpenShell specifically

OpenShell spans five test surfaces that don't share a harness or a failure
mode:

- **Rust unit tests** (`crates/*/src/**`, inline `#[cfg(test)] mod tests`) —
  fast, run against fakes/stubs (e.g. `openshell-driver-podman`'s
  `test_utils::spawn_podman_stub`, a hyper server over a Unix socket standing
  in for the real daemon).
- **`e2e/rust/tests/`** — a real gateway + real driver (Docker, Podman,
  Kubernetes, VM), feature-gated per driver (`e2e-docker`, `e2e-podman`,
  `e2e-kubernetes*`), driven by shell scripts (`e2e-*.sh`) that stand up the
  actual stack.
- **`crates/openshell-conformance/src/scenarios/`** — driver-agnostic
  behavioral scenarios run against whichever driver-backed gateway `mise run
  e2e:*` points at. The right home for a `ComputeDriver`-contract guarantee
  that every driver must prove, instead of five copies of the same assertion.
- **`tests/ansible/` + `tests/suites/drivers/*` (the Nix `tmachine` harness)**
  — VM-backed driver-specific suites wired through `tests/config.nix`. Easy to
  believe a fixture is orphaned when it's actually consumed only here — a
  prior pass on #3663 wrongly called three Podman userns fixtures "orphaned"
  because their only consumer was an Ansible playbook, invisible to a
  `.rs`/`.yml` grep. Read `tests/config.nix` and the actual playbooks before
  concluding a fixture, script, or env var is unused.
- **Python (`python/`), TypeScript SDK (`sdk/typescript/`), Go SDK
  (`sdk/go/`)** — each with its own test runner and its own conventions; see
  Discovery below for the exact commands.

A test that passes against a mock but was never run against the real
dependency is a hypothesis, not proof. #3663 found exactly this for the
Podman driver: resource-limit admission and daemon-failure handling were
fully unit-tested against a fake client with zero real-daemon coverage — a
gap invisible from the outside, since the tests are green and clippy has
nothing to say about them. Mock-only coverage of a real-dependency contract is
a first-class junk pattern here (see below), not an afterthought.

## Authoring gate

Before adding any test, answer four questions; a missing answer means do not
add it yet:

1. What observable behavior, invariant, or independent contract does it
   protect? If the feature crosses a real boundary (process, privilege/identity,
   declaration-to-enforcement, our-code-to-external-tool — see
   [Integration boundaries](#integration-boundaries-test-what-crosses-not-just-whats-inside)),
   name the boundary explicitly; "the function returns the right value" is not
   the same claim as "the value survives the handoff to whatever consumes it."
2. What credible regression makes it fail?
3. Why does existing coverage not already catch that failure? Each contract
   has one primary test owner at the strongest boundary — usually the
   `crates/openshell-conformance` scenario if the contract applies to more
   than one driver, or the specific `e2e/rust/tests/<driver>_*.rs` file if it's
   genuinely driver-specific (a Podman API error shape, a rootless-only
   Podman flag). Another layer needs its own distinct risk, such as a real
   daemon a mock can't fail the way the real one does. Prefer extending a
   table-driven case or shared fixture over a near-duplicate test.
4. Does it need a production seam (export, flag, wrapper, injection hook) that
   no production caller needs? If yes, move the test to the real boundary
   instead.

Then check the test against every [junk pattern](#junk-patterns); a match
fails the gate unless the [retention bar](#retention-bar) names the contract
it independently guards. A test that would break under behavior-preserving
refactoring is asserting implementation, not behavior; rewrite it at the
owning boundary before landing it.

Bug regression tests must fail on the pre-fix code for the intended reason and
pass after the owner-boundary repair. A regression test that never
demonstrably failed proves the mock, not the fix. One regression at the owner
boundary covers the bug; do not replay the same scenario at every layer it
crosses (unit test, e2e test, and conformance scenario all asserting the same
Podman error string is three maintenance burdens for one bug).

## Unit tests: verify the contract, not the implementation

The most common defect in agent-authored unit tests looks like a passing
test: it runs, asserts, and stays green. The flaw is where the expected value
came from. Ask of every assertion: **where did this expected value come
from?**

- Traced or run from the implementation itself — circular. Proves the code
  matches itself, not that it's correct. Rederive from an independent source
  or reject the test.
- Derived from a spec, protocol, real dependency, or an independently
  computed value — valid, since it can actually fail when the code is wrong.

Example (#3663): `parse_cpu_to_microseconds`/`parse_memory_to_bytes` convert
`"500m"`/`"512Mi"` to cgroup values. Hardcoding `50_000`/`536_870_912`
because "that's what the function returns" proves nothing.
`podman_resource_limits.rs` instead checks a real `podman run
--cpus=0.5 --memory=512m` container's actual `cpu.max`/`memory.max` — an
independent yardstick that would catch a regression in the math.

When no independent ground truth exists, derive the expected value by a
different calculation path than the implementation, not by re-running it.
Same rule applies to e2e/conformance assertions computed by calling the same
code path a second time.

## Integration boundaries: test what crosses, not just what's inside

A test can pass the check above and still miss the bug, because the bug lives
in the handoff between components, not inside either one. Mocking every
collaborator proves each side behaves correctly given its assumptions about
the other — not that the assumption is true. Name the boundaries a feature
crosses and make sure at least one test crosses each for real:

- **Process** — does a `Result<(), Err>` actually surface as the right exit
  code and error text through `main()`? Only proven for `PodmanApiError::Connection`
  once `podman_preflight.rs` spawned the real binary and read its exit code.
- **Privilege/identity** — does data written by one identity stay readable by
  the identity that reads it later? The rootful playbook bug: a reference file
  was captured as `root` but always read back by the unprivileged `tmachine`
  test runner. Every task looked correct in isolation; the bug was the handoff.
- **Declaration-to-enforcement** — does a value the API echoes back actually
  get enforced underneath? `sandbox_templates.rs` proves the API stores
  `--cpu`/`--memory`; `podman_resource_limits.rs` proves cgroups enforce it.
  Different claims — one test passing says nothing about the other.
- **Our-code-to-external-tool** — does our belief about a real tool's
  behavior match the tool, not our assumption about it? Checked repeatedly
  against real Podman (man page, `podman run` output) rather than trusting
  driver-side comments.

A hundred green unit tests that all mock the far side of every seam will
never catch a boundary bug. Ask: "if I mocked every collaborator, which
handoffs would I never exercise?" Those are worth a real dependency instead of
a mock.

## Junk patterns

The shared checklist for both modes: the authoring gate rejects a new test
that matches one, and audits hunt for existing tests that do.

- assertion-free coverage probes;
- self-comparisons and identity copiers;
- copied fixtures, inventories, manifests, or export lists;
- exact source, import, or string greps;
- private predicate or call-shape tests duplicated at real boundaries;
- duplicate invocations of the same contract across unit, e2e, and
  conformance layers with no distinct failure mode at each layer;
- provider-local (per-driver) replays of a shared conformance-level contract;
- tests whose only purpose is preserving test-only exports, globals, or
  wrappers;
- dead production code whose only callers are tests;
- expected values produced by, traced from, or hand-simulated on the same
  implementation under test instead of an independent source — see
  [Unit tests: verify the contract, not the implementation](#unit-tests-verify-the-contract-not-the-implementation)
  for the diagnostic question and a worked example;
- mocks that implement the asserted behavior, or one identical mock standing
  in for different APIs;
- **a mock/stub standing in for a real dependency that is actually available
  and cheap to run in CI** (a `spawn_podman_stub`-style fake covering behavior
  a real `podman run` could prove directly) — flag this even if the test
  itself is well-formed, because the gap it's hiding is coverage-shaped, not
  junk-shaped;
- fixtures that supply the receipt, admission, or callback ordering the owner
  should produce, or persistence asserted against a store the path never
  writes;
- capability tests that restate declared flags instead of exercising the
  delivery or acknowledgement the flag promises;
- negative controls that pass for an unrelated reason, such as a denial from a
  different guard, a rejection the production path never reaches, or (Ansible
  suites specifically) an assertion that would pass trivially because the
  environment it's asserting against was never actually reached;
- names or fixtures that promise more than the input exercises, such as a
  "verifies rootful parity" test that only runs under rootless because a
  service-user assertion silently skipped it.

## Value bar

Tests justify their maintenance cost by protecting behavior, a credible
regression, or an independently meaningful contract. In an audit, an existing
test that must change for behavior-preserving source reorganization is
suspect, not automatically deletable; the authoring gate still rejects new
ones.

Before judging a candidate, read the complete test and its production owner,
entry point, callers, callees, sibling implementations across drivers,
overlapping tests at other layers, CI routing (which `mise run` task and which
`.github/workflows/*.yml` job actually executes it — a test can be well-formed
and simply never run; check `required-features` and workflow env vars, not
just the test file), and relevant history. Read root and scoped `AGENTS.md`
files first. When the test claims dependency-backed behavior (a Podman API
shape, a cgroup value, a systemd unit's behavior), verify it against the real
dependency or its documentation directly — don't take the mock's word for it.

## Discovery

Keep discovery read-only and report evidence before editing. For broad scope,
run parallel discovery lanes when available, one per surface:

- Rust unit tests: `cargo nextest run --config-file .config/nextest.toml` (or
  `mise run test:rust`) per crate under audit;
- `e2e/rust/tests/`: `cargo check --manifest-path e2e/rust/Cargo.toml
  --all-targets --features <e2e-driver-feature>` to enumerate what's gated
  behind which feature, then cross-reference against
  `.github/workflows/branch-e2e.yml` and `tasks/test.toml` to confirm the
  feature actually gets exercised in CI (it may not — see the Podman `E2E_FEATURES`
  empty-string wiring bug found in #3663, where a real, well-written test was
  silently skipped by an env var default);
- conformance suite: `crates/openshell-conformance/src/scenarios/`;
- `tests/ansible/` + `tests/suites/drivers/*`: read `tests/config.nix`'s
  `testsuites` list to find every playbook a suite actually runs, not just the
  ones with an obvious name;
- Python: `mise run test:python` (`uv run pytest python/`);
- TypeScript SDK: `mise run sdk:ts:test`;
- Go SDK: `mise run go:test` / `go:test:integration`;
- a cross-cutting pattern sweep (grep for the junk patterns above across
  whichever surfaces are in scope).

Outside campaign mode, prefer a few high-confidence candidates over a large
speculative inventory. Hunt for the [junk patterns](#junk-patterns).

## Retention bar

Keep a test when it independently enforces a public API, gRPC/proto contract,
`ComputeDriver` guarantee, gateway config schema, policy/OPA contract,
security boundary, sandbox lifecycle invariant, SDK (Go/TypeScript/Python)
contract, or CI/release artifact contract. Also keep:

- call ordering when order is observable behavior;
- regressions with a credible failure mode;
- source inspection when it is the cheapest independent guard: it fails when
  the contract changes (a config key, a wire byte, a CLI flag) and survives an
  identifier-only refactor;
- a retained test that fails on the baseline: treat it as a possible product
  bug, reproduce it, and repair the owner rather than deleting it.

Static or slow is not a deletion reason — a `tests/ansible` VM suite is slow
by nature and may still be the only real-daemon proof that exists. A test that
resembles implementation may still be the independent contract; prove
otherwise before removing it.

## Candidate evidence

Record every field below before editing. A missing field means the candidate
is not ready for deletion:

- exact test name and location (crate/file, or `e2e/rust/tests/<file>.rs`, or
  `tests/ansible/playbooks/...`);
- what failure it can actually detect;
- non-test callers of the covered production or support seam;
- stronger remaining owner-boundary proof, or why no proof is needed;
- whether it currently runs in CI at all (check the workflow, not just the
  feature gate — see Discovery above) and what happens if you delete it
  versus if you fix its wiring instead;
- relevant history and the reason the test or seam exists;
- production or test-support deletion unlocked;
- risk and the focused validation command.

## Edit shape

Choose one coherent owner-boundary batch, scoped to one crate, one SDK, or one
driver's `e2e/rust/tests/` files at a time. Delete obsolete test-only exports,
globals, wrappers, and dead production paths instead of preserving aliases.
Move retained regressions to their canonical owners (conformance suite if the
contract is driver-agnostic; the driver-specific file if it's genuinely
driver-local). Consolidate repeated per-driver assertions of the same
`ComputeDriver` contract into one conformance scenario.

Prefer net-negative production LOC. Do not add replacement tests that restate
the same implementation, and do not convert uncertain candidates into cleanup
to increase deletion counts. If an audit surfaces mock-only coverage of a
real-dependency contract, that is a coverage-gap finding, not a deletion — say
so explicitly in the handoff rather than silently leaving it.

## Validation

Follow the language's own pre-commit gate, not just the test itself — a
passing test in isolation can still fail `cargo fmt --all -- --check` or
`cargo clippy`.

1. Run the smallest owner and sibling tests directly (`cargo nextest run -p
   <crate> <filter>`, `cargo test --manifest-path e2e/rust/Cargo.toml --test
   <name> --features <feature>`, `uv run pytest python/<path>`, etc.) before
   running anything broader.
2. For e2e tests that need a real driver and are runnable locally (Podman is
   commonly available; Docker/Kubernetes/VM often are not in a given
   environment), actually build and run them rather than trusting a compile
   check — `cargo build -p openshell-driver-podman` then `cargo test
   --manifest-path e2e/rust/Cargo.toml --test <name> --features e2e-podman`
   is cheap and catches wiring bugs a `cargo check` won't.
3. For removed source greps or plan assertions, run the executable script or
   dry-run that owns the real contract.
4. Run `cargo fmt --all -- --check` (Rust) and the equivalent formatter for
   whatever language changed, then `git diff --check`.
5. Run `mise run pre-commit` once per coherent batch, not after every single
   file edit — it recompiles/clippies the full Rust workspace and is
   expensive; batch changes and run it before committing, not iteratively.
6. Inspect `git diff --numstat`; report production/tooling separately from
   tests and test support.

## Check for overlap before filing an issue or opening a PR

Before filing a new issue for a finding:

- Search issues with `--state all` (not just open) and more than one phrasing
  — component name, file path, symptom, and subsystem name can each surface
  different matching issues.
- If something adjacent but not identical exists, say so in the new issue
  rather than ignoring it or treating it as a duplicate.

Before opening a PR, or starting implementation:

- Check open PRs for overlapping files or behavior, not just titles
  (`gh pr list --search`, then `gh pr diff <number>` on anything adjacent) — a
  PR's title can be unrelated while its diff covers the same ground.
- If an in-flight PR already does part of the work, cross-reference it and
  narrow scope instead of duplicating it.
- Re-check if meaningful time passed since filing — overlap can appear later.

## Landing and continuation

Commit, push, open a PR, or land only when authorized — this repo requires
explicit permission before `git push` (see the repository's own CLAUDE.md
push-workflow rules) and only creates commits when asked. Use
`create-github-pr` for PR mechanics once authorized. Scope one coherent PR per
audited surface; after landing, rerun read-only discovery for the next
high-confidence batch rather than queuing speculative follow-ups.

A new or substantially changed test-audit finding that reveals a real product
gap (not a junk test, but missing coverage the audit surfaced) belongs in its
own issue via `create-github-issue` or `create-spike` — do not fold it into
the audit PR. Check for overlap first, per the section above, before filing
it.

## Handoff

Report:

- root cause and removed low-value categories, by surface (unit / e2e /
  conformance / tmachine / SDK);
- production owner simplifications;
- retained false positives and why they remain valuable;
- any mock-only-coverage findings surfaced but not fixed here (coverage gaps,
  not junk — flag for a separate issue);
- focused and full proof actually run, and what could not be run locally
  (e.g. drivers without local hardware/daemon access) versus what was
  verified end-to-end;
- production versus test LOC;
- PR and merge state;
- named follow-ups.
