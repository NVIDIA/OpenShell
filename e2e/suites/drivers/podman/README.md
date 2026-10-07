# Podman driver tests

These tests run inside a disposable tmachine guest against its shared Podman
gateway. Rootful and rootless Podman are separate tmachine environments.

The `user_namespaces` Cargo test target contains four story modules: `default`,
`auto`, `keep_id`, and `private`. Each compares OpenShell's UID mapping with a
direct Podman container in the gateway service user's execution context, and
checks that the non-root workload owns and can write to its managed workspace.
Both commands use the same workload image.

## Gateway fixture

The Rust fixture requires `/etc/openshell/gateway.toml`, the
`openshell-gateway.service` systemd unit, a registered candidate CLI, and
passwordless sudo in the guest. tmachine prepares the writable fixture directory
at `/var/lib/openshell-driver-tests/podman`. This is a dedicated test gateway:
its baseline must omit `userns`, `uidmap`, and `gidmap` and contain no sandboxes.

Ansible installs the archive and invokes nextest once with `--test-threads 1`.
A guest-side file lock also serializes separate Cargo or nextest invocations.
Under the lock, Rust captures the original config, applies the selected profile,
and restarts and checks gateway readiness. After success, an error, or an
assertion panic, it deletes tracked sandboxes, restores the exact original
configuration, restarts the gateway, and verifies health and sandbox absence.
Scenario failures and restoration failures remain test failures.

Before changing the gateway, the fixture writes a dirty marker. It removes that
marker only after successful restoration. An interrupted process or failed
restoration therefore prevents subsequent stories from treating modified state
as their baseline. Start a fresh tmachine invocation to recover; each invocation
uses a disposable overlay over the cached installed guest image.

## Run

Build the candidate runtime inputs and driver archive, then run either environment:

```shell
nix run .#build-podman-driver-test-archive
nix run .#tmachine -- test fedora-podman-rootful binaries driver-podman
nix run .#tmachine -- test fedora-podman-rootless binaries driver-podman
```

The tests may restart the gateway and require guest privileges. Run the pure
configuration and UID-map assertions on the development host with:

```shell
cargo test --locked --manifest-path e2e/suites/drivers/Cargo.toml \
  --package openshell-test-suite-podman --test user_namespaces ::tests::
```

Inside a prepared guest, a nextest test-name filter selects one profile. The
`fixture-validation` Cargo feature adds a deliberately failing panic scenario
for validating cleanup; it is excluded from normal archives. Execute that
scenario explicitly, require failure and successful restoration, then run a
normal profile in the same guest to verify recovery.
