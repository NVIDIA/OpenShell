# Sandbox conformance suite

The `sandbox` crate holds testkit suites for sandbox behavior that every compute
driver must provide. It is a member of the `conformance` workspace. Each file in
`tests/` is one suite.

| Suite | Covers |
|---|---|
| `smoke` | Create a sandbox, run `echo` in it, delete it |

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
- Every environment must pass every test here. If a behavior is left to the
  driver, the test belongs in a `features` or `drivers` suite instead.
- Use the CLI for upload, download, connect and forward. Rely on its exit code
  and `--output json`.
- Add a testkit helper instead of calling raw gRPC from a test.
