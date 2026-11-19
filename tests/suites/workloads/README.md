# Workloads suite

The `workloads` crate runs real tools doing realistic tasks in sandboxes, such
as building a C project with `make`. Bugs that users hit with tools like
Chromium, bubblewrap or Bazel show up here before users find them. A new
compute driver or isolation backend can run the suite to check its edges.

The family is this one crate, its own workspace. Each module in `src/` is one
workload, and `cargo test` and nextest run the tests as the library's unit
tests. The crate also builds the `openshell-workloads` program, which runs the
same tests with the commands the [testkit README](../../testkit/README.md#test-programs)
describes.

| Workload | Test | Covers |
|---|---|---|
| `make` | `make_builds_a_c_program` | `make -j4` builds a small C project, the program runs, and `make -q` finds nothing to rebuild. Fails until [#4102](https://github.com/NVIDIA/OpenShell/issues/4102) is fixed: the sandbox denies the no-op `setresuid` make 4.3 makes before each recipe |

## What belongs here

Conformance checks the documented contract every driver must meet. "Bazel
works in a sandbox" is not part of that contract, and some workloads will only
work on some drivers, so they live here instead. A test here runs a real tool,
not a probe written for the test, and does what users do with it.

Each test has two steps:

1. **Start the tool and check that it's ready.** If the tool has its own
   protections, such as Chromium's sandbox or bubblewrap, start it with them on
   and check that they are on. A test must not pass because the tool fell back
   to a weaker mode, such as Chromium with `--no-sandbox`.
2. **Do the task users report, at the scale they report, and check each
   step.** For example, a build finishes, a request comes back, or 4 test
   processes connect. A failure then says which part broke.

Tests don't need the internet. The image has the tool, and anything the task
talks to is served from `tests/support/host-server`. A test that needs the
real internet says so in its name, so a run can leave it out. A workload that
no driver supports yet is marked `#[ignore = "<issue link>"]`.

## Images

Each workload has its own image, built from `<workload>/Dockerfile` on a base
pinned by digest, with the `sandbox` user the testkit base policy runs as. The
environment builds it and names it in `OPENSHELL_TEST_WORKLOAD_<NAME>_IMAGE`;
a test fails when its variable is unset. Inputs the test can send at run time,
such as the `make` workload's C project, stay out of the image, so changing
them needs no rebuild.

The tmachine `<base>-workloads` environments build the images during setup
(`tests/tmachine/ansible/playbooks/workloads.yaml`), so the setup layer caches
them and the tests run without network access.

## Running it

In a tmachine VM, as CI does:

```shell
nix run .#openshell-test-runner -- run \
  --environment ubuntu-docker-rootful-workloads --installer deb \
  --family workloads
```

Against a local Docker gateway, build the image into Docker and set its
variable:

```shell
docker build -t localhost/openshell/workload-make:dev tests/suites/workloads/make
OPENSHELL_TEST_WORKLOAD_MAKE_IMAGE=localhost/openshell/workload-make:dev \
  e2e/with-docker-gateway.sh cargo nextest run --locked \
    --manifest-path tests/suites/workloads/Cargo.toml --test-threads 1
```

On CI, the Branch E2E workflow runs the suite's rows in
`.github/workflows/e2e-suites.yml` on pull requests with the
`test:e2e-workloads` label and on manual runs.

## Adding a workload

1. Add `<workload>/Dockerfile`, starting from a base pinned by digest and
   creating the `sandbox` user (uid and gid 1000).
2. Add it to `workload_images` in `tests/tmachine/ansible/playbooks/workloads.yaml`
   with its image name and variable, and pass its Dockerfile as a setup input
   of the `workloads` feature in `tests/tmachine/config.nix`.
3. Add `src/<workload>.rs` with a `#[testkit::test]` that reads its image with
   `crate::workload_image`, and a `mod` line for it in `src/lib.rs`.
4. Add the workload to the table above.
