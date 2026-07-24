<!--
SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# Test VMs

This prototype uses Nix, QEMU, and Ansible to boot and configure disposable Linux VMs for testing OpenShell packages and binaries. It supports HVF on Apple Silicon macOS and KVM on native-architecture Linux hosts.

## Requirements

- Nix with flakes enabled.
- Apple Silicon macOS with HVF, or Linux with readable and writable `/dev/kvm`.
- Enough local capacity for a four-vCPU, 4 GiB guest and a disposable disk overlay.
- Native-architecture artifacts. The runner does not use software emulation.

The first run downloads the selected cloud image and VM runtime. Nix reuses those immutable inputs on later runs, while each guest starts from a fresh writable overlay.

## Directory structure

```text
nix/vm/
├── README.md
├── default.nix
├── run.sh
├── distros/
│   ├── ubuntu.nix
│   ├── centos.nix
│   └── rocky.nix
└── configuration/
    ├── docker.yml
    ├── podman.yml
    └── selinux.yml
```

- `default.nix` assembles the VM flake app. It selects host architecture and acceleration, supplies QEMU and Ansible through the Nix runtime closure, and exposes distro profiles and configuration playbooks as Nix-store catalogs.
- `run.sh` owns the disposable VM lifecycle: argument validation, cloud-image realization, cloud-init seed creation, QEMU startup, SSH readiness, Ansible execution, artifact installation, guest command execution, and cleanup.
- `distros/*.nix` define the immutable base-image catalog. Each record pins the image URL and hash and declares the expected OS ID, version, and package family. Distro definitions do not provision extra software.
- `configuration/*.yml` are host-executed Ansible playbooks that layer optional capabilities onto a base guest. Configurations remain independent and run in the order supplied with repeated `--with` arguments.
- `README.md` documents the supported combinations and developer interface.

The root [`flake.nix`](../../flake.nix) exposes this directory as the `test-vm` app. Debian artifact creation remains outside the VM harness in [`tasks/scripts/package-deb.sh`](../../tasks/scripts/package-deb.sh); the runner only installs or copies artifacts that already exist.

## Supported configurations

| Distro | Docker | Podman | SELinux | Package format |
| --- | --- | --- | --- | --- |
| Ubuntu 24.04 | Yes | Yes | No | `.deb` |
| CentOS Stream 10 | No | Yes | Yes | `.rpm` |
| Rocky Linux 9 | Yes | Yes | Yes | `.rpm` |

List the available distros and configurations:

```shell
nix run .#test-vm -- --list
```

## Open an interactive VM

Boot a base Ubuntu VM:

```shell
nix run .#test-vm -- --distro ubuntu
```

Apply the Docker configuration before opening the SSH session:

```shell
nix run .#test-vm -- --distro ubuntu --with docker
```

Other combinations use the same interface:

```shell
nix run .#test-vm -- --distro rocky --with docker
nix run .#test-vm -- --distro centos --with podman
```

Configurations are repeatable:

```shell
nix run .#test-vm -- \
  --distro ubuntu \
  --with docker \
  --with podman
```

Ensure SELinux is enforcing on CentOS or Rocky:

```shell
nix run .#test-vm -- \
  --distro rocky \
  --with docker \
  --with selinux \
  -- getenforce
```

`--with selinux` installs the required tooling, persists `SELINUX=enforcing`, applies enforcing mode live, and verifies the result. It fails on Ubuntu and on guests where SELinux is fully disabled and would require a reboot to enable.

## Ansible configurations

Configurations are Ansible playbooks stored under `nix/vm/configuration/`. Ansible runs on the host using the VM's ephemeral SSH key and loopback port. The guest does not install Ansible.

Configurations run in the order provided on the command line. OpenShell packages and copied binaries are installed after all configurations succeed.

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
nix run .#test-vm -- \
  --distro ubuntu \
  --with docker \
  --install artifacts/openshell_0.0.0-local_arm64.deb \
  -- openshell --version
```

For an x86_64 Linux guest, supply x86_64 binaries and use `package:deb:amd64`. The package architecture must match the host and guest architecture.

`--install` is repeatable. Debian packages are accepted by Ubuntu; RPM packages are accepted by CentOS and Rocky Linux. This prototype can install an existing RPM but does not build one.

## Copy binaries directly

Use `--copy SOURCE:DEST` to install an executable without creating a package:

```shell
nix run .#test-vm -- \
  --distro ubuntu \
  --copy ./openshell:/usr/local/bin/openshell \
  -- openshell --version
```

The destination must be an absolute guest path. Copied files are installed with mode `0755`.

## Runner options

```text
--distro NAME       Base distro: ubuntu, centos, or rocky
--with NAME         Apply docker, podman, or selinux; repeatable
--install PATH      Install a .deb or .rpm package; repeatable
--copy SRC:DEST     Copy an executable into the guest; repeatable
--ssh-port PORT     Use a specific loopback SSH forwarding port
--keep              Preserve the disk overlay and logs after shutdown
--list              List distros and configurations
```

Arguments after `--` are executed inside the guest. Without a command, the runner opens an interactive SSH session.

## Lifecycle

Nix downloads and caches the selected, hash-pinned cloud image. Each invocation then:

1. Creates a temporary QCOW2 overlay.
2. Boots QEMU with HVF or KVM acceleration.
3. Creates an ephemeral `openshell` user and SSH key through cloud-init.
4. Applies the selected Ansible configurations.
5. Installs or copies the supplied artifacts.
6. Opens SSH or executes the requested guest command.
7. Powers off QEMU and deletes the overlay.

Use `--keep` to preserve the overlay, cloud-init seed, SSH key, and serial log for debugging. The retained directory is printed when the runner exits.

## Current limitations

- Host and guest architectures must match.
- Software emulation without HVF or KVM is not supported.
- Configurations are applied fresh on every run; prepared VM caching is not implemented.
- Only loopback SSH is forwarded to the host; guest gateway ports are not exposed.
- The runner does not build OpenShell, configure a gateway, or select an E2E test suite.
