<!--
SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# Test Guests

This prototype uses Nix, QEMU, and Ansible to boot and configure disposable Linux VMs for testing OpenShell packages and binaries. It supports HVF on Apple Silicon macOS, KVM on native-architecture Linux hosts, and a slower TCG fallback on Linux when KVM is unavailable.

## Requirements

- Nix with flakes enabled.
- Apple Silicon macOS with HVF, or a native-architecture Linux host. Linux uses KVM when `/dev/kvm` is available and falls back to QEMU TCG otherwise.
- Enough local capacity for a four-vCPU, 4 GiB guest and a disposable disk overlay.
- Native-architecture artifacts. TCG emulates the guest CPU on Linux but does not enable cross-architecture guests.

The first run downloads the selected cloud image and VM runtime. Nix reuses those immutable inputs on later runs, while each guest starts from a fresh writable overlay.

## Directory structure

```text
nix/test-guest/
├── README.md
├── default.nix
├── run.sh
├── cache.sh
├── cache-lib.sh
├── cache-seal.sh
├── distros/
│   ├── ubuntu.nix
│   ├── centos.nix
│   ├── fedora.nix
│   └── rocky.nix
└── configuration/
    ├── docker.yml
    ├── podman.yml
    └── selinux.yml
```

- `default.nix` assembles the guest and cache flake apps. It selects host architecture and acceleration, supplies the runtime tools, and exposes distro profiles and configuration playbooks as Nix-store catalogs.
- `run.sh` owns the disposable guest lifecycle: cache lookup, cloud-image realization, cloud-init seed creation, QEMU startup, SSH readiness, Ansible execution, artifact installation, guest command execution, and cleanup.
- `cache.sh` ensures an exact prepared disk exists locally. It can pull or explicitly push the disk as an OCI artifact.
- `cache-lib.sh` defines deterministic cache identity and validation helpers shared by the runner and cache command.
- `cache-seal.sh` removes per-instance state and zeroes free space inside a prepared guest before capture.
- `distros/*.nix` define the immutable base-image catalog. Each record pins and exports the image URL and hash and declares the expected OS ID, version, and package family.
- `configuration/*.yml` are host-executed Ansible playbooks that layer optional capabilities onto a base guest. Configurations remain independent and run in the order supplied with repeated `--with` arguments.
- `README.md` documents the supported combinations and developer interface.

The root [`flake.nix`](../../flake.nix) exposes this directory as the `test-guest` and `test-guest-cache` apps. Debian artifact creation remains outside the guest harness in [`tasks/scripts/package-deb.sh`](../../tasks/scripts/package-deb.sh); the runner only installs or copies artifacts that already exist.

## Supported configurations

| Distro | Docker | Podman | SELinux | Package format |
| --- | --- | --- | --- | --- |
| Ubuntu 24.04 | Yes | Yes | No | `.deb` |
| CentOS Stream 10 | No | Yes | Yes | `.rpm` |
| Fedora 44 | No | Yes | Yes | `.rpm` |
| Rocky Linux 9 | Yes | Yes | Yes | `.rpm` |

List the available distros and configurations:

```shell
nix run .#test-guest -- --list
```

## Run a host or test-guest E2E suite

[`e2e/run.sh`](../../e2e/run.sh) builds OpenShell from the current checkout, starts a gateway from a supplied TOML file, and runs one named host-side suite against it. This opt-in path is separate from `mise run e2e:vm`: `e2e/run.sh` selects where the gateway process runs, while the supplied gateway config selects the compute driver. It is not part of the default E2E task or CI graph.

Omit both `--vm` and `--with` to run the gateway on the host:

```shell
e2e/run.sh \
  --gateway-config e2e/configs/gateway/docker.toml \
  --suite smoke
```

Pass `--vm` or at least one `--with` to run the gateway in a disposable test guest:

```shell
e2e/run.sh \
  --vm ubuntu \
  --with docker \
  --gateway-config e2e/configs/gateway/docker.toml \
  --suite smoke
```

Use `--guest-setup` when a driver needs checkout-specific guest preparation
before the gateway starts. For example, the Podman shutdown suite builds a
supervisor image around the staged `openshell-sandbox` binary:

```shell
e2e/run.sh \
  --vm ubuntu \
  --with podman \
  --guest-setup e2e/guest-setup/podman-supervisor.sh \
  --gateway-config e2e/configs/gateway/podman.toml \
  --suite podman-shutdown
```

Set `OPENSHELL_E2E_EXPECT_SHUTDOWN_CLOSES=1` when a stacked change must
classify supervisor and relay transport closures as expected teardown events.

Supplying `--with` without `--vm` selects Ubuntu. `--with` is repeatable and configurations run in input order. Supplying `--vm` without `--with` boots the selected base image without adding software. The wrapper validates both values against the test-guest catalogs:

```shell
e2e/run.sh \
  --vm rocky \
  --with docker \
  --with selinux \
  --gateway-config e2e/configs/gateway/docker.toml \
  --suite smoke
```

The equivalent passthrough task accepts the same arguments:

```shell
mise run e2e:test -- \
  --with docker \
  --gateway-config e2e/configs/gateway/docker.toml \
  --suite smoke
```

The wrapper always builds the tested binaries; it does not accept packages or use release artifacts. Both modes build a native host `openshell` CLI and a static Linux `openshell-sandbox` for the host architecture. Host mode also builds a native `openshell-gateway` with bundled Z3. VM mode builds a static Linux `openshell` and a Linux GNU `openshell-gateway` with bundled Z3 and a glibc 2.28 floor, then stages all three guest binaries through the VM runner's `--copy` interface.

The Linux targets match the host and guest architecture:

| Host architecture | CLI and sandbox | Gateway |
| --- | --- | --- |
| x86_64 | `x86_64-unknown-linux-musl` | `x86_64-unknown-linux-gnu.2.28` |
| aarch64 | `aarch64-unknown-linux-musl` | `aarch64-unknown-linux-gnu.2.28` |

These cross-builds use the Zig and `cargo-zigbuild` versions pinned in [`mise.toml`](../../mise.toml). Install the repository's mise tools before running the wrapper. The wrapper also requires Python 3 and OpenSSL; VM mode requires `base64`. Cargo stores outputs in its normal target directory, so later runs reuse current artifacts. VM mode additionally requires the Nix, QEMU, and host-capacity prerequisites above; host mode does not invoke Nix, QEMU, or Ansible.

Gateway configs are ordinary, fully resolved TOML files under `e2e/configs/gateway/`. The wrapper does not inspect or rewrite them. It supplies only the bind address, gateway port, plaintext transport, and isolated XDG directories at launch. Use portable relative paths for host files. The initial Docker config points `supervisor_bin` at `.cache/openshell-e2e/bin/openshell-sandbox`; the wrapper stages that path under the repository in host mode and under `/home/openshell` in VM mode. It also generates and stages the local sandbox JWT material referenced by the initial config.

Suites are executable scripts under `e2e/suites/` and use lowercase letters, digits, and hyphens for their names. The wrapper exports the selected endpoint, isolated gateway registration, native host CLI path, mode metadata, source config path, and forwarded ports before executing a suite. Add new configs and suites without adding scenario branches to `e2e/run.sh`.

Set `OPENSHELL_E2E_KEEP=1` to retain wrapper state after a host-mode run. In VM mode the wrapper also passes `--keep` to the test-guest runner so its overlay and logs remain available.

## Open an interactive VM

Boot a base Ubuntu VM:

```shell
nix run .#test-guest -- --distro ubuntu
```

Apply the Docker configuration before opening the SSH session:

```shell
nix run .#test-guest -- --distro ubuntu --with docker
```

Other combinations use the same interface:

```shell
nix run .#test-guest -- --distro rocky --with docker
nix run .#test-guest -- --distro centos --with podman
nix run .#test-guest -- --distro fedora --with podman
```

Configurations are repeatable:

```shell
nix run .#test-guest -- \
  --distro ubuntu \
  --with docker \
  --with podman
```

Ensure SELinux is enforcing on CentOS, Fedora, or Rocky:

```shell
nix run .#test-guest -- \
  --distro rocky \
  --with docker \
  --with selinux \
  -- getenforce
```

`--with selinux` installs the required tooling, persists `SELINUX=enforcing`, applies enforcing mode live, and verifies the result. It fails on Ubuntu and on guests where SELinux is fully disabled and would require a reboot to enable.

## Ansible configurations

Configurations are Ansible playbooks stored under `nix/test-guest/configuration/`. Ansible runs on the host using the VM's ephemeral SSH key and loopback port. The guest does not install Ansible.

Configurations run in the order provided on the command line. OpenShell packages and copied binaries are installed after all configurations succeed.

## Prepared VM cache

The `test-guest-cache` app ensures a prepared disk exists for one exact distro, host architecture, and ordered configuration list. It checks the local cache first, optionally pulls a matching OCI artifact, or builds and validates a new local entry on a miss:

```shell
nix run .#test-guest-cache -- \
  --distro ubuntu \
  --with docker
```

Configure an OCI repository and a trusted manifest digest to use it as a shared
backing cache:

```shell
nix run .#test-guest-cache -- \
  --distro ubuntu \
  --with docker \
  --repository ghcr.io/nvidia/openshell/test-guest-cache \
  --digest sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

The command never publishes implicitly. Add `--push` after authenticating ORAS through its Docker-compatible credential configuration:

```shell
nix run .#test-guest-cache -- \
  --distro ubuntu \
  --with docker \
  --repository ghcr.io/nvidia/openshell/test-guest-cache \
  --push
```

A successful push prints the immutable `repository@sha256:...` reference. Supply
that digest to consumers through trusted CI configuration. Pulls by mutable tag
are not allowed. A pulled local entry records its manifest digest and is reused
only when it matches the requested trusted digest.

A cache build boots and configures a disposable VM, runs the internal sealing script, flattens the overlay into a standalone QCOW2 disk, and validates a fresh boot before committing the entry. The OCI artifact contains metadata and a `disk.qcow2.zst` layer.

The key includes the pinned base-image identity, guest architecture, ordered configuration file digests, Ansible version, cache generation, and sealing script digest. Installed packages, copied binaries, forwarded ports, and guest commands are never cached.

Normal `test-guest` runs automatically use an exact valid local entry after rechecking its disk checksum and QCOW2 structure. They create a fresh writable overlay, cloud-init instance, machine ID, and SSH identity. On a local miss, the runner uses the pinned cloud image and applies configurations normally. Set `OPENSHELL_TEST_GUEST_CACHE_DISABLE=1` to bypass local lookup.

The default cache directory is `${XDG_CACHE_HOME:-$HOME/.cache}/openshell/test-guest`. Override it with `--cache-dir` on the cache command or `OPENSHELL_TEST_GUEST_CACHE_DIR` for either app.

Cache command options:

```text
--distro NAME       Base distro: ubuntu, centos, fedora, or rocky
--with NAME         Apply docker, podman, or selinux; repeatable
--repository REF    OCI repository without a tag
--digest DIGEST     Trusted OCI manifest digest required for pulls
--cache-dir PATH    Override the local prepared-disk cache directory
--push              Publish the ensured entry to the repository
```

## Install an OpenShell package

Package existing ARM64 Linux binaries with the repository's `package:deb:arm64` mise task:

```shell
OPENSHELL_CLI_BINARY="$PWD/target/aarch64-unknown-linux-musl/release/openshell" \
OPENSHELL_GATEWAY_BINARY="$PWD/target/aarch64-unknown-linux-gnu/release/openshell-gateway" \
OPENSHELL_DRIVER_VM_BINARY="$PWD/target/aarch64-unknown-linux-gnu/release/openshell-driver-vm" \
OPENSHELL_DEB_VERSION=0.0.0-local \
OPENSHELL_OUTPUT_DIR="$PWD/artifacts" \
nix develop --command mise run package:deb:arm64
```

Install the package in an Ubuntu VM and run a command:

```shell
nix run .#test-guest -- \
  --distro ubuntu \
  --with docker \
  --install artifacts/openshell_0.0.0-local_arm64.deb \
  -- openshell --version
```

For an x86_64 Linux guest, supply x86_64 binaries and use `package:deb:amd64`. The package architecture must match the host and guest architecture.

`--install` is repeatable. Debian packages are accepted by Ubuntu; RPM packages are accepted by CentOS, Fedora, and Rocky Linux. This prototype can install an existing RPM but does not build one.

## Copy binaries directly

Use `--copy SOURCE:DEST` to install an executable without creating a package:

```shell
nix run .#test-guest -- \
  --distro ubuntu \
  --copy ./openshell:/usr/local/bin/openshell \
  -- openshell --version
```

The destination must be an absolute guest path. Copied files are installed with mode `0755`.

## Runner options

```text
--distro NAME       Base distro: ubuntu, centos, fedora, or rocky
--with NAME         Apply docker, podman, or selinux; repeatable
--install PATH      Install a .deb or .rpm package; repeatable
--copy SRC:DEST     Copy an executable into the guest; repeatable
--ssh-port PORT     Use a specific loopback SSH forwarding port
--forward-port HOST_PORT:GUEST_PORT
                    Forward a loopback host port to a guest port; repeatable
--keep              Preserve the disk overlay and logs after shutdown
--list              List distros and configurations
```

Each `--forward-port` binds only `127.0.0.1` on the host. Both ports must be unprivileged values from 1024 through 65535, and each host port may appear only once.

Arguments after `--` are executed inside the guest. Without a command, the runner opens an interactive SSH session.

## Lifecycle

Each invocation checks for an exact prepared local cache entry. On a miss, Nix realizes the hash-pinned cloud image and the runner applies the selected configurations. It then:

1. Creates a temporary QCOW2 overlay backed by the prepared cache disk or pinned cloud image.
2. Boots QEMU with HVF, KVM, or the Linux TCG fallback.
3. Creates a fresh cloud-init instance and ephemeral SSH key.
4. Applies the selected Ansible configurations only when the base is not prepared.
5. Installs or copies the supplied artifacts.
6. Opens SSH or executes the requested guest command.
7. Powers off QEMU and deletes the writable overlay.

Prepared cache disks remain read-only. Test-specific state exists only in the disposable overlay.

Use `--keep` to preserve the overlay, cloud-init seed, SSH key, and serial log for debugging. The retained directory is printed when the runner exits.

## Current limitations

- Host and guest architectures must match.
- TCG is slower than hardware virtualization and uses a longer SSH readiness timeout.
- Prepared cache entries are architecture-specific and match the exact ordered configuration list.
- OCI pulls transfer a complete compressed standalone disk; incremental disk layers are not implemented.
- Guest ports are reachable from the host only when explicitly exposed with loopback-only `--forward-port`.
- The low-level VM runner does not build OpenShell, configure a gateway, or select an E2E test suite. Use `e2e/run.sh` for that orchestration.
