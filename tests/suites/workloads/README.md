# Workloads suite

The `workloads` crate runs real tools doing realistic tasks in sandboxes, such
as building a C project with `make`. Conformance checks the contract every
driver must meet; a workload here checks that a tool users run actually works,
and may only work on some drivers. The crate also builds the
`openshell-workloads` program, which runs the same tests.

| Workload | Test | Covers |
|---|---|---|
| `make` | `make_builds_a_c_program` | `make` builds a C program, it runs, and `make -q` finds nothing to rebuild. Fails until [#4102](https://github.com/NVIDIA/OpenShell/issues/4102) is fixed |

Each workload has its own image, built from `<workload>/Dockerfile` on a base
pinned by digest, with the `sandbox` user (uid and gid 1000) that the testkit
base policy runs as. The tmachine `ubuntu-docker-rootful-workloads`
environment builds the images during setup
(`tests/tmachine/ansible/playbooks/workloads.yaml`) and names each in an
`OPENSHELL_TEST_WORKLOAD_<NAME>_IMAGE` variable. The tests need no network.

## Running it

In a tmachine VM, as CI does with the `test:e2e:workloads` label:

```shell
nix run .#openshell-test-runner -- run \
  --environment ubuntu-docker-rootful-workloads --installer deb \
  --family workloads
```

Against a local Docker gateway:

```shell
docker build -t localhost/openshell/workload-make:dev tests/suites/workloads/make
OPENSHELL_TEST_WORKLOAD_MAKE_IMAGE=localhost/openshell/workload-make:dev \
  e2e/with-docker-gateway.sh cargo nextest run --locked \
    --manifest-path tests/suites/workloads/Cargo.toml --test-threads 1
```

## Adding a workload

1. Add `<workload>/Dockerfile`.
2. Build it and publish its variable in `workloads.yaml`, and pass the
   Dockerfile as a setup input of the `workloads` feature in
   `tests/tmachine/config.nix`.
3. Add `src/<workload>.rs` with a `#[testkit::test]` and a `mod` line in
   `src/lib.rs`, and a row in the table above.
