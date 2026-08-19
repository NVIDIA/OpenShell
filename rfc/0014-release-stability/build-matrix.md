# RFC 0014 Supplement - Build Matrix

This supplement defines the build targets for the release system described by
RFC 0014. The targets follow the structure of the
[proposed support matrix](https://github.com/NVIDIA/OpenShell/blob/d575cf85f8c520774cc3e307ec1bcdabf57cd682/docs/reference/support-matrix.mdx)
and describe the intended final state.

These tables enumerate build and capability targets. They do not imply that
every cross-product of platform, architecture, installation method, driver,
topology, and capability is supported. The
[release qualification supplement](release-qualification.md) defines the
minimal blocking release gate. It contains one conformance workflow per compute
driver, one Kubernetes conformance workflow per supported gateway topology, and
one upgrade workflow per installation package, plus one breaking API change
review and one security review per pre-release. Other supported dimensions are
exercised as subcases or separate CI controls rather than as a Cartesian product
of release jobs.

## Platforms

| Platform | Installation methods | Requirements |
| --- | --- | --- |
| macOS (Apple Silicon) | Homebrew | macOS 13.3 or later |
| Linux (x86_64, arm64) | APT/DEB, RPM, Snap | glibc 2.28 or later |
| Windows (x86_64, arm64) | MSI, WinGet | Documented minimum Windows version and MSVC toolchain |

Package installers include the CLI, TUI, gateway, and supported local drivers.
Standalone CLI and TUI binaries are also published for remote gateway access.

## Compute drivers

| Driver | Supported hosts | Minimum version | Requirements |
| --- | --- | --- | --- |
| Docker | macOS, Linux, Windows | 28.0.4 or later | Docker Engine or Docker Desktop |
| Podman | macOS, Linux, Windows | 5.x | Podman socket, rootless networking, and cgroups v2 |
| MicroVM | macOS, Linux | macOS 13.3 or later; KVM on Linux | Host virtualization, Hypervisor.framework on macOS, and KVM on Linux |
| Kubernetes | Kubernetes clusters | 1.29 or later | Helm 3.x and a compatible Agent Sandbox controller and CRDs |

## GPU support

| Compute driver | Supported environment | Device interface | Requirements and limits |
| --- | --- | --- | --- |
| Docker | Linux; Windows through WSL2 | NVIDIA CDI | CDI-enabled runtime with visible NVIDIA devices; default and counted GPU requests |
| Podman | Linux; Windows through WSL2 | NVIDIA CDI | Visible NVIDIA CDI devices; default and counted GPU requests |
| MicroVM | Linux | QEMU/VFIO PCI passthrough | IOMMU, VFIO, root privileges, compatible sandbox image, and one GPU per sandbox |
| Kubernetes | Linux GPU nodes | `nvidia.com/gpu` extended resources | NVIDIA GPU Device Plugin and a compatible sandbox image |

Release qualification accepts current CUDA drivers and validates against the
Tesla Recommended Driver branches.

## Kubernetes

| Component | Supported version | Notes |
| --- | --- | --- |
| Kubernetes | 1.29 or later | Required for Helm deployments and sandbox scheduling |
| Helm | 3.x | Required to install and upgrade the OpenShell chart |
| Agent Sandbox controller and CRDs | Compatible release | Required before installing the OpenShell chart |
| User namespaces | 1.33 or later | Optional; enables `hostUsers: false` for UID remapping |

GKE Standard, GKE Autopilot, and OpenShift 4.x are supported. OpenShift uses
the OpenShift-specific SCC binding and chart configuration.

## SDKs

| SDK | Minimum version |
| --- | --- |
| Python | 3.12 |
| TypeScript | 5.7 |
| Rust | 1.90 |
| Go | 1.24 |
