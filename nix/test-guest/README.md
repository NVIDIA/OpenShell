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

On Apple Silicon, test guests deliberately take QEMU 11.0.2 and its matching OVMF
firmware from a separately pinned Nixpkgs revision. All other guest-runtime tools,
development dependencies, and cross-toolchain dependencies continue to use the main
current Nixpkgs input. This avoids a QEMU 11.1 HVF guest boot regression. Update
this pair only after validating an ARM64 Ubuntu guest boot with HVF.

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
│   ├── ubuntu-24-04.nix
│   ├── ubuntu-26-04.nix
│   ├── centos.nix
│   ├── fedora.nix
│   └── rocky.nix
└── configuration/
    ├── docker.yml
    ├── podman-rootless.yml
    ├── tasks/
    │   ├── podman-common.yml
    │   └── podman-rootless/
    │       ├── fedora.yml
    │       ├── shared.yml
    │       └── ubuntu.yml
    └── selinux.yml
└── provisioners/
    └── roles/
        ├── gateway-rootless-podman/
        ├── openshell-development/
        ├── openshell-rpm/
        └── openshell-rpm-gateway-upgrade/
```

- `default.nix` assembles the guest and cache flake apps. It selects host architecture and acceleration, supplies the runtime tools, and exposes distro profiles and configuration playbooks as Nix-store catalogs.
- `run.sh` owns the disposable guest lifecycle: cache lookup, cloud-image realization, cloud-init seed creation, QEMU startup, SSH readiness, Ansible execution, artifact installation, guest command execution, and cleanup.
- `cache.sh` ensures an exact prepared disk exists locally. It can pull or explicitly push the disk as an OCI artifact.
- `cache-lib.sh` defines deterministic cache identity and validation helpers shared by the runner and cache command.
- `cache-seal.sh` removes per-instance state and zeroes free space inside a prepared guest before capture.
- `distros/*.nix` define the immutable base-image catalog. Each record pins and exports the image URL and hash and declares the expected OS ID, version, and package family.
- `configuration/*.yml` are host-executed Ansible playbooks that layer optional capabilities onto a base guest. Configurations remain independent and run in the order supplied with repeated `--with` arguments.
- `provisioners/roles/*` are per-run Ansible roles that assemble a system from copied or installed artifacts. They run after artifact transfer and are never part of the prepared VM cache.
- `README.md` documents the supported combinations and developer interface.

The root [`flake.nix`](../../flake.nix) exposes this directory as the `test-guest` and `test-guest-cache` apps. Debian artifact creation remains outside the guest harness in [`tasks/scripts/package-deb.sh`](../../tasks/scripts/package-deb.sh); the runner only installs or copies artifacts that already exist.

## Supported configurations

| Distro | Docker | Rootless Podman | SELinux | Package format |
| --- | --- | --- | --- | --- |
| Ubuntu 24.04 | Yes | No | No | `.deb` |
| Ubuntu 26.04 | Yes | Yes | No | `.deb` |
| CentOS Stream 10 | No | No | Yes | `.rpm` |
| Fedora 44 | No | Yes | Yes | `.rpm` |
| Rocky Linux 9 | Yes | No | Yes | `.rpm` |

The `snapd` configuration is available for Ubuntu and prepares snapd for
local Snap lifecycle experiments. It does not install Docker, because the Snap
gateway reproduction uses the Docker **Snap** and its `docker:docker-daemon`
interface rather than the host-package Docker configuration.

`podman-rootless` configures the explicit rootless Podman guest setup used by
OpenShell tests. It supports Fedora and Ubuntu 26.04 or later. Ubuntu adds the
AppArmor rule that permits `pasta` to receive Podman stop signals. Fedora
installs the subordinate-ID utilities and rootless storage and network helpers.
Both configurations verify rootless mode and the `pasta` network helper
required by OpenShell sandbox callbacks. Ubuntu 24.04 ships Podman 4, which
does not provide that helper.

List the available distros and configurations:

```shell
nix run .#test-guest -- --list
```

## Open an interactive VM

Boot a base Ubuntu VM:

```shell
nix run .#test-guest -- --distro ubuntu-24-04
```

Apply the Docker configuration before opening the SSH session:

```shell
nix run .#test-guest -- --distro ubuntu-24-04 --with docker
```

Other combinations use the same interface:

```shell
nix run .#test-guest -- --distro rocky --with docker
nix run .#test-guest -- --distro ubuntu-26-04 --with podman-rootless
nix run .#test-guest -- --distro fedora --with podman-rootless
```

Configurations are repeatable:

```shell
nix run .#test-guest -- \
  --distro ubuntu-24-04 \
  --with docker \
  --with podman-rootless
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

Configurations run in the order provided on the command line. OpenShell packages and copied files are installed after all configurations succeed.

`--install` packages and `--copy` files are applied by a dedicated per-run
transfer step. `--copy` preserves each source file's ordinary permission bits
unless an octal mode is supplied. They are not stored in prepared VM cache
entries.

## System provisioners

`--provision NAME` applies a target-specific system setup after packages and
copied artifacts are present. Unlike `--with`, provisioners are not cached.
They can therefore install and start an OpenShell system without coupling the
prepared guest image to a particular build or driver configuration.

Provisioners that support gateway continuity install a target-control command:

```text
/home/openshell/.local/bin/openshell-test-guest-gateway-restart
```

It restarts an already-provisioned gateway and exits only after CLI health
succeeds. An explicit conformance plan consumes that stable test-guest contract
without knowing how the provisioner implements it:

```shell
openshell-conformance run --plan - <<'EOF'
version = 1

[[runs]]
scenario = "sandbox-continuity"
workload_expectation = "reconciled"

[[runs.actions]]
name = "gateway-restart"
command = "/home/openshell/.local/bin/openshell-test-guest-gateway-restart"
timeout_secs = 120
EOF
```

`openshell-development` expects these copied guest paths:

- `/usr/local/bin/openshell`
- `/usr/local/bin/openshell-gateway`
- `/usr/local/lib/openshell-sandbox.tar`

Compose it with `gateway-rootless-podman` to configure a rootless Podman
gateway. For example, run conformance after the provisioners complete:

```shell
nix run .#test-guest -- \
  --distro fedora --with podman-rootless --with selinux \
  --copy ./openshell:/usr/local/bin/openshell \
  --copy ./openshell-conformance:/usr/local/bin/openshell-conformance \
  --copy ./openshell-gateway:/usr/local/bin/openshell-gateway \
  --copy ./openshell-sandbox.tar:/usr/local/lib/openshell-sandbox.tar \
  --provision openshell-development \
  --provision gateway-rootless-podman \
  -- /usr/local/bin/openshell-conformance run --plan - <<'EOF'
version = 1

[[runs]]
scenario = "sandbox-continuity"
workload_expectation = "reconciled"

[[runs.actions]]
name = "gateway-restart"
command = "/home/openshell/.local/bin/openshell-test-guest-gateway-restart"
timeout_secs = 120
EOF
```

`openshell-rpm` expects OpenShell to have been installed with `--install`. It
uses the RPM-owned `/usr/bin` binaries and `openshell-gateway` user service,
without copied development artifacts or a supervisor archive. Compose it with
`gateway-rootless-podman` before an RPM action such as
`openshell-rpm-gateway-upgrade`.

`openshell-rpm-latest-release` downloads and installs the latest stable
OpenShell GitHub release for the guest architecture, then publishes the same
RPM installation contract. Compose it with `gateway-rootless-podman` and an
RPM gateway action when testing an upgrade from the current release.

Versioned plans under `nix/test-guest/conformance-plans/` bind conformance
scenarios to the stable action-command contracts installed by provisioners.
Copy the applicable plan to the guest and pass it to `openshell-conformance run
--plan`.

## Prepared VM cache

The `test-guest-cache` app ensures a prepared disk exists for one exact distro, host architecture, and ordered configuration list. It checks the local cache first, optionally pulls a matching OCI artifact, or builds and validates a new local entry on a miss:

```shell
nix run .#test-guest-cache -- \
  --distro ubuntu-24-04 \
  --with docker
```

Configure an OCI repository and a trusted manifest digest to use it as a shared
backing cache:

```shell
nix run .#test-guest-cache -- \
  --distro ubuntu-24-04 \
  --with docker \
  --repository ghcr.io/nvidia/openshell/test-guest-cache \
  --digest sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

The command never publishes implicitly. Add `--push` after authenticating ORAS through its Docker-compatible credential configuration:

```shell
nix run .#test-guest-cache -- \
  --distro ubuntu-24-04 \
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

Normal `test-guest` runs automatically use an exact valid local entry after
rechecking its disk checksum and QCOW2 structure. On a local miss, the runner
invokes the cache builder and stores the prepared disk before continuing. It
then creates a fresh writable overlay, cloud-init instance, machine ID, and SSH
identity from that entry. Set `OPENSHELL_TEST_GUEST_CACHE_DISABLE=1` to bypass
both local lookup and automatic population.

The default cache directory is `${XDG_CACHE_HOME:-$HOME/.cache}/openshell/test-guest`. Override it with `--cache-dir` on the cache command or `OPENSHELL_TEST_GUEST_CACHE_DIR` for either app.

Cache command options:

```text
--distro NAME       Base distro: ubuntu-24-04, ubuntu-26-04, centos, fedora, or rocky
--with NAME         Apply docker, podman-rootless, selinux, or snapd; repeatable
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
  --distro ubuntu-24-04 \
  --with docker \
  --install artifacts/openshell_0.0.0-local_arm64.deb \
  -- openshell --version
```

For an x86_64 Linux guest, supply x86_64 binaries and use `package:deb:amd64`. The package architecture must match the host and guest architecture.

`--install` is repeatable. Debian packages are accepted by Ubuntu; RPM packages are accepted by CentOS, Fedora, and Rocky Linux. This prototype can install an existing RPM but does not build one.

## Copy files directly

Use `--copy SOURCE:DEST[:MODE]` to copy a regular file without creating a
package. If `MODE` is omitted, the guest file preserves the source's ordinary
permission bits. Supply a bare octal mode such as `755` to override them:

```shell
nix run .#test-guest -- \
  --distro ubuntu-24-04 \
  --copy ./openshell:/usr/local/bin/openshell:755 \
  -- openshell --version
```

## Reproduce Snap gateway startup

The gateway Snap must be native to the guest architecture. Copy an existing
Snap artifact and the reproduction script into a prepared Ubuntu guest, then
run the script as root. It follows the Release Canary ordering exactly: install
the Snap, connect Docker/log/system interfaces, and immediately query the
gateway. On each failure it prints snapd and gateway journals.

```shell
nix run .#test-guest -- \
  --distro ubuntu-24-04 \
  --with snapd \
  --keep \
  --copy ./openshell_*.snap:/tmp/openshell.snap \
  --copy ./nix/test-guest/scripts/snap-gateway-repro.sh:/usr/local/bin/snap-gateway-repro \
  -- sudo /usr/local/bin/snap-gateway-repro /tmp/openshell.snap 10 30
```

`--keep` retains the overlay and serial log when diagnosing a failure. The
runner prints their location after shutdown. The final `30` accepts automatic
recovery for up to 30 seconds; omit it to require the canary's immediate check.


The destination must be an absolute guest path. Use bare octal permission bits
from `000` through `777` for explicit modes.

## Runner options

```text
--distro NAME       Base distro: ubuntu-24-04, ubuntu-26-04, centos, fedora, or rocky
--with NAME         Apply docker, podman-rootless, selinux, or snapd; repeatable
--install PATH      Install a .deb or .rpm package; repeatable
--copy SRC:DEST[:MODE]
                    Copy a regular file into the guest; use MODE when provided,
                    otherwise preserve the host mode; repeatable
--ssh-port PORT     Use a specific loopback SSH forwarding port
--forward-port HOST_PORT:GUEST_PORT
                    Forward a loopback host port to a guest port; repeatable
--keep              Preserve the disk overlay and logs after shutdown
--list              List distros, configurations, and provisioners
```

Each `--forward-port` binds only `127.0.0.1` on the host. Both ports must be unprivileged values from 1024 through 65535, and each host port may appear only once.

Arguments after `--` are executed inside the guest. Without a command, the runner opens an interactive SSH session.

## Lifecycle

Each invocation ensures an exact prepared local cache entry exists. On a miss,
the cache builder realizes the hash-pinned cloud image, applies the selected
configurations, seals and validates the prepared disk, and stores it locally.
The runner then:

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
- The runner does not build OpenShell, configure a gateway, or select an E2E test suite.
