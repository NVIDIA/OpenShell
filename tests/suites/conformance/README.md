# Conformance suites

The `conformance` crate holds the testkit suites for sandbox behavior that every
compute driver must provide. The family is this one crate, its own workspace.
It is a library: each module in `src/` is one suite, and `cargo test` and
nextest run the tests as the library's unit tests. The crate also builds the
`openshell-conformance` program, which runs the same tests.

| Suite | Covers |
|---|---|
| `smoke` | Create a sandbox, run `echo` in it, delete it |
| `lifecycle` | SDK: long-running and run-to-completion sandboxes, prompt delete when the workload is slow to handle TERM, the default command, restart of a stopped sandbox, deleting a stopped sandbox |
| `cli` | The same lifecycle through the `openshell` CLI: status, create, get, list, exec, stop, start, delete |
| `persistent-workspace` | Files in `/sandbox` survive stop and start |
| `policy-advisor` | `policy.local` accepts a proposed rule; a denied address or hostname yields one draft rule |
| `file-transfer` | `sandbox upload` and `download`: round trips, `.gitignore` filtering, workspace-escape and option-looking names |
| `credential-gating` | Provider credentials: admission of credentialed endpoints, REST body placeholders and rewriting, WebSocket binary frames, live policy binding |

`smoke` is the smallest end-to-end check that the runner can run a real test in a
tmachine environment on CI. The other suites are ports of the old
`conformance/cli` scenarios and of Evan Lezar's suites in NVIDIA/OpenShell#4629
(credited in each file). `file-transfer` runs `git` on the machine that runs the
tests, so a test environment needs it installed
(`tests/tmachine/ansible/playbooks/test-tools.yaml` does that for the tmachine
environments). `credential-gating`, ported from NVIDIA/OpenShell#5264, starts
servers (`tests/support/host-server`) on the machine that runs the tests and
reaches them from sandboxes created from `testkit::python_image()` through
`host.openshell.internal`.

## Running it

[TESTING.md](../../../TESTING.md) covers running it against a local Docker
gateway and in a tmachine VM, as CI does.

### The `openshell-conformance` program

`openshell-conformance` runs the suite against a gateway without cargo or
nextest, so a driver author or operator can check their own gateway. It finds
the gateway and the CLI as the tests do. Build it and run it with:

```shell
cargo build --locked --manifest-path tests/suites/conformance/Cargo.toml --bin openshell-conformance
tests/suites/conformance/target/debug/openshell-conformance list
tests/suites/conformance/target/debug/openshell-conformance ready
tests/suites/conformance/target/debug/openshell-conformance run --junit conformance.xml
```

The program runs only this suite: passing it means a gateway meets the
conformance contract below. The machine that runs it must be reachable from
sandboxes as `host.openshell.internal`, which rules out a gateway on a remote
Kubernetes cluster ([#5409](https://github.com/NVIDIA/OpenShell/issues/5409)).
Feature and driver suites are not part of it. The
[testkit README](../../testkit/README.md#test-programs) describes the commands
and exit codes. `tasks/scripts/check-conformance-program.sh` checks that it
lists the same tests as nextest.

## Adding a test

Add a `#[testkit::test]` function to a suite, or for a new area, a new file in
`src/` and a `mod` line for it in `src/lib.rs`. `openshell-conformance`
includes every test in the crate.

## What a test may assert

These tests run on every compute driver, so they check the public contract and
leave driver behavior alone.

- Assert only what the public contract promises: the proto comments and the
  published docs.
- Assert `phase` and `exit_code`. Don't assert condition reasons.
- Check that something did not happen by reading state, not by sleeping.
- Don't test behavior that only some drivers have. A test that can't pass on
  every environment isn't conformance; put it in `tests/suites/features` or
  `tests/suites/drivers`.
- Use the CLI for upload, download, connect and forward. Rely on its exit code
  and `--output json`.
- Add a testkit helper instead of calling raw gRPC from a test.
