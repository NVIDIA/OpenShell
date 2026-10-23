# Sandbox conformance suite

The `sandbox` crate holds testkit suites for sandbox behavior that every compute
driver must provide. It is a member of the `conformance` workspace. Each file in
`tests/` is one suite.

| Suite | Covers |
|---|---|
| `smoke` | Create a sandbox, run `echo` in it, delete it |

The suite is small on purpose. It proves that the runner can run a real test in
a tmachine environment on CI. The older suites move to testkit by adding suites
here, or a new family under `tests/suites/`.

## Running it

Against a local Docker gateway:

```shell
mise run e2e:testkit
```

Against any gateway the CLI can reach, with the testkit environment variables
described in [tests/testkit/README.md](../../../testkit/README.md):

```shell
OPENSHELL_GATEWAY=<name> cargo nextest run --locked \
  --manifest-path tests/suites/conformance/Cargo.toml -p sandbox --test-threads 1
```

In a tmachine VM, as CI runs it (see [TESTING.md](../../../../TESTING.md)):

```shell
nix run .#openshell-test-runner -- \
  --environment ubuntu-docker-rootful --installer deb \
  --family conformance --package sandbox
```

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

Guidance adapted from NVIDIA/OpenShell#4629 by Evan Lezar.
