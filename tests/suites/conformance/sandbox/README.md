# Sandbox conformance suite

The `sandbox` crate holds testkit suites for sandbox behavior that every compute
driver must provide. It is a member of the `conformance` workspace. Each file in
`tests/` is one suite.

| Suite | Covers |
|---|---|
| `smoke` | Create a sandbox, run `echo` in it, delete it |
| `lifecycle` | SDK: long-running and run-to-completion sandboxes, the default command, restart of a stopped sandbox, deleting a stopped sandbox |
| `cli` | The same lifecycle through the `openshell` CLI: status, create, get, list, exec, stop, start, delete |
| `persistent-workspace` | Files in `/sandbox` survive stop and start |
| `policy-advisor` | `policy.local` accepts a proposed rule; a denied address or hostname yields one draft rule |
| `file-transfer` | `sandbox upload` and `download`: round trips, `.gitignore` filtering, workspace-escape and option-looking names |

`smoke` is the smallest end-to-end check that the runner can run a real test in a
tmachine environment on CI. The other suites are ports of the old
`conformance/cli` scenarios and of Evan Lezar's suites in NVIDIA/OpenShell#4629
(credited in each file). `file-transfer` runs `git` on the machine that runs the
tests, so a test environment needs it installed
(`tests/tmachine/ansible/playbooks/test-tools.yaml` does that for the tmachine
environments).

## Running it

[TESTING.md](../../../../TESTING.md) covers running it against a local Docker
gateway and in a tmachine VM, as CI does.

## Adding a test

Add a `#[testkit::test]` function to a suite, or a new file in `tests/` for a new
area. No playbook, test archive or workflow entry is needed: the runner builds
and runs every test in the package.

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
