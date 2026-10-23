# Test plans

A plan lists which test suites run in which environments. CI and local runs read
the same file, and nothing else repeats it: a workflow does not carry a copy of
the lane list, and a suite does not carry a playbook that says where it runs.

```yaml
matrix:
  - type: conformance                     # a family: a workspace under tests/suites/
    suites: [smoke]                       # optional; omit to run every suite in the family
    environments:
      - tmachine.ubuntu2404-amd64.docker-rootful.deb   # IDs from tests/environments/
```

A `conformance` entry must select the same suites in every environment: the
runner refuses a plan that doesn't, so conformance means the same thing
everywhere. A test that can't pass everywhere belongs in another family.

A family is a Cargo workspace directly under `tests/suites/` with at least one
testkit suite. A suite is a test file in a crate's `tests/` directory containing
`#[testkit::test]` functions. Its name is the file name without `.rs`, with `_`
replaced by `-`: `tests/file_transfer.rs` is the suite `file-transfer`.

| Plan | Runs |
|---|---|
| `cpu-tests.yaml` | The `conformance` family on rootful Docker (Debian package), rootful and rootless Podman (RPM), and k3s and HA k3s, all amd64 |

## How a plan runs on CI

Branch E2E calls `.github/workflows/e2e-suites.yml` with the plan name when the
`test:e2e` label is set.

1. A planning job runs
   `openshell-test-runner test --plan tests/plans/<plan>.yaml --emit-github-matrix`. It
   prints one job per environment, with the GitHub runner label that can boot it.
2. Each job downloads the integration inputs the tmachine lanes use (the Debian
   and RPM packages and the images), then runs
   `nix run .#openshell-test-runner -- test --plan tests/plans/<plan>.yaml --env <id> --strict`.
3. The runner builds the family's tests for the guest, boots the environment
   with tmachine, and runs nextest in it with `OPENSHELL_GATEWAY` set to the
   gateway the installer registered and `OPENSHELL_BIN` set to the installed CLI. It checks the JUnit
   report against the tests it selected: a missing or skipped test fails the job.
4. The job uploads the JUnit reports and logs, and an aggregator job reports the
   result.

Adding an environment or a suite to a plan changes what CI runs with no workflow
change. Arm64 is not defined yet: it needs a runner that can boot guests with KVM and
arm64 build inputs. `tests/environments/docker.yaml` says how to add it.

## Running a plan locally

Print what a plan would run, without building or booting anything:

```shell
nix run .#openshell-test-runner -- test --plan tests/plans/cpu-tests.yaml --dry-run
```

Running it for real boots QEMU guests, so it needs KVM and the installer inputs in
`artifacts/` (`nix run .#build-artifacts`). The runner skips an environment the
host cannot boot unless you pass `--strict`, which is what CI does.

When debugging, `--env <id>` and `--suite <name>` narrow the run to part of the
plan, and `--keep` leaves each VM running after its tests until you press
Enter, so you can inspect it:

```shell
nix run .#openshell-test-runner -- test --plan tests/plans/cpu-tests.yaml \
  --env tmachine.ubuntu2404-amd64.docker-rootful.deb --suite smoke --keep
```

To run a suite against a gateway on your machine, without a guest, use the
Docker gateway wrapper. It exports `OPENSHELL_GATEWAY` and `OPENSHELL_BIN`, which
is how the runner points tests at the system under test:

```shell
mise run e2e:testkit
```
