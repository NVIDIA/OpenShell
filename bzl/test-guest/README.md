<!--
SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# Test Guests

Bazel builds and runs disposable Linux QEMU guests for testing OpenShell
packages and binaries. Nix supplies a pinned host-tool closure containing QEMU,
OVMF, Ansible, SSH, and supporting utilities. Bazel owns the cloud-image inputs,
prepared QCOW2 outputs, cache keys, run targets, and test targets.

The harness supports HVF on Apple Silicon macOS, KVM on native-architecture
Linux hosts, and a slower TCG fallback on Linux when KVM is unavailable.

## Requirements

- Bazel at the version pinned in `.bazelversion`.
- Nix with flakes enabled so `rules_nixpkgs` can realize the host tools.
- Apple Silicon macOS with HVF, or a native-architecture Linux host. Linux uses
  KVM when `/dev/kvm` is available and otherwise falls back to QEMU TCG.
- Capacity for a four-vCPU, 4 GiB guest and a disposable disk overlay.
- Native-architecture artifacts. TCG does not enable cross-architecture guests.

## Build an image

Build a prepared Fedora image with Podman:

```shell
bazel build //bzl/test-guest:fedora_podman_image
```

The target produces cacheable Bazel outputs:

```text
bazel-bin/bzl/test-guest/fedora_podman_image.qcow2
bazel-bin/bzl/test-guest/fedora_podman_image.metadata.json
```

The image action boots the pinned cloud image, applies its declared Ansible
playbooks, removes instance-specific state, flattens the disk to a standalone
compressed QCOW2, and validates a fresh boot from that output.

## Run a guest

Run an interactive guest backed by the prepared image:

```shell
bazel run //bzl/test-guest:fedora_podman
```

Arguments after the Bazel separator are passed to the guest runner:

```shell
bazel run //bzl/test-guest:ubuntu_docker -- \
  -- uname -a
```

Without a command, the target opens an interactive SSH session. Every run
creates a fresh writable overlay; the prepared Bazel output remains unchanged.

## Run a Bazel test

`bazel test` is the canonical entrypoint for automated test-guest execution.
The representative smoke test consumes the same prepared image provider:

```shell
bazel test //bzl/test-guest:fedora_podman_smoke
```

Image and VM test actions execute locally because they require networking and
a host accelerator. They remain eligible for Bazel local and remote caching.
The generated launchers use `rules_shell` and Bazel's standard runfiles
library.

## Supported variants

| Distro | Base | Docker | Podman | SELinux combinations |
| --- | --- | --- | --- | --- |
| Ubuntu 24.04 | `ubuntu` | `ubuntu_docker` | `ubuntu_podman` | None |
| CentOS Stream 10 | `centos` | None | `centos_podman` | `centos_selinux`, `centos_podman_selinux` |
| Fedora 44 | `fedora` | None | `fedora_podman` | `fedora_selinux`, `fedora_podman_selinux` |
| Rocky Linux 9 | `rocky` | `rocky_docker` | `rocky_podman` | `rocky_selinux`, `rocky_docker_selinux`, `rocky_podman_selinux` |

Append `_image` to a variant to build its QCOW2 directly. Query the package to
see every generated target:

```shell
bazel query //bzl/test-guest:all
```

Ubuntu 24.04 provides Podman 4 without the `pasta` helper required by OpenShell
sandbox callbacks. Podman E2E runs use Fedora, which provides Podman 5 and
`pasta`.

## Cache and reproducibility boundary

Bazel's action cache is the only prepared-image cache. The harness does not
maintain a second local cache or publish OCI image-cache artifacts.

Base cloud images, host tools, playbooks, and sealing logic are declared inputs.
Image metadata contains no wall-clock build time. Guest package repositories
are still live, however, so an uncached rebuild is not yet bit-reproducible.
Only the trusted image-warming workflow should have remote-cache write
credentials; ordinary CI and developer clients should use read-only cache
credentials. Bump the image `generation` when intentionally refreshing guest
packages. Strict reproducibility requires pinned distro repository snapshots.

## Declare build artifacts

Test-guest consumers take Bazel targets, not host filesystem paths. Declare
packages with `packages` and files copied into the guest with `copies`:

```starlark
load("//bzl/test-guest:test_guest.bzl", "test_guest_test")

test_guest_test(
    name = "fedora_podman_openshell",
    command = ["/usr/local/bin/openshell", "--version"],
    copies = {
        "//bazel/releases:openshell_linux_aarch64": "/usr/local/bin/openshell",
    },
    image = "//bzl/test-guest:fedora_podman_image",
    size = "enormous",
)
```

Each label must produce exactly one file. `packages` accepts `.deb` outputs for
Ubuntu and `.rpm` outputs for CentOS, Fedora, and Rocky. `copies` maps an output
label to an absolute guest destination and installs it with mode `0755`. Use a
host-native artifact target or a platform `select()` because guest architecture
must match the host. Bazel builds the artifacts and includes them in the
consumer's runfiles automatically; they are never included in the prepared
QCOW2.

Forward a loopback port with `--forward-port HOST_PORT:GUEST_PORT`. Both ports
must be between 1024 and 65535, and each host port may appear only once.

## Directory structure

```text
bzl/test-guest/
├── README.md
├── BUILD.bazel
├── catalog.bzl
├── extensions.bzl
├── test-guest.MODULE.bazel
├── test_guest.bzl
├── host-tools.nix
├── host-tools.BUILD.bazel
├── nixpkgs.nix
├── build-image.sh
├── image-seal.sh
├── run.sh
└── configuration/
    ├── docker.yml
    ├── podman.yml
    └── selinux.yml
```

- `catalog.bzl` is the single source for Bazel cloud-image provenance, guest
  metadata, and supported variants.
- `extensions.bzl` creates pinned cloud-image repositories from the catalog.
- `host-tools.nix` builds the Nix host-tool closure imported through
  `rules_nixpkgs`; `nixpkgs.nix` ties it to the repository `flake.lock`.
- `test_guest.bzl` defines the providers, host-tools toolchain, image action,
  and `rules_shell` run and test launchers.
- `build-image.sh` adapts the QEMU lifecycle to explicit Bazel inputs and
  outputs.
- `image-seal.sh` removes per-instance state and zeroes free space before image
  capture.
- `run.sh` owns cloud-init generation, QEMU startup, SSH readiness, Ansible
  execution, artifact installation, guest commands, and cleanup.
- `configuration/*.yml` are host-executed Ansible playbooks applied in their
  declared order.

## Current limitations

- Guest architecture must match the host architecture.
- Image preparation requires local execution, networking, and a working host
  accelerator or the slower TCG fallback.
- The image rule does not yet pin distro package repositories.
- The runner supports QEMU/HVF on Apple Silicon macOS and QEMU/KVM or TCG on
  Linux; Intel macOS is not supported.
