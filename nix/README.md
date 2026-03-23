# OpenShell Nix Infrastructure

Modular Nix flake for building, developing, and containerizing OpenShell.

## What is Nix?

[Nix](https://nixos.org) is a package manager that provides **reproducible, isolated**
environments. It tracks all dependencies and pins exact versions so every developer
gets the same toolchain. Nix packages live in `/nix/store/` and do not interfere
with your system packages.

## Quick Start

### 1. Install Nix

If you don't have Nix installed, grab it from <https://nixos.org/download/>.

**Multi-user install** (recommended):

```bash
bash <(curl -L https://nixos.org/nix/install) --daemon
```

**Single-user install** (no root required):

```bash
bash <(curl -L https://nixos.org/nix/install) --no-daemon
```

### 2. Enable Flakes

OpenShell uses Nix **flakes**, which are still marked "experimental" in Nix.

**Per-command** (no config changes needed):

```bash
nix --extra-experimental-features 'nix-command flakes' develop
```

**Permanently** (recommended):

```bash
test -d /etc/nix || sudo mkdir /etc/nix
echo 'experimental-features = nix-command flakes' | sudo tee -a /etc/nix/nix.conf
```

### 3. Build and Develop

```bash
# Enter dev shell with all build/lint/test tools
nix develop

# Build OpenShell (all 3 binaries: openshell, openshell-server, openshell-sandbox)
nix build

# Run the CLI
nix run -- --version

# Build OCI container image
nix build .#container

# Smoke-test the container (requires Docker daemon)
nix run .#container-test

# Format Nix files
nix fmt
```

### First Run

On the first run, Nix downloads and builds all dependencies. This can take
5-15 minutes (protobuf-src compiles from C++ source). Subsequent runs reuse
the cache in `/nix/store/` and are nearly instant.

## Container Usage

### Build and Load

```bash
nix build .#container
docker load < result
```

### Run

```bash
# Default entrypoint shows help
docker run --rm openshell:0.0.0

# Interactive shell
docker run --rm -it --entrypoint /bin/bash openshell:0.0.0
```

### Image Size

| Metric | Size |
|--------|------|
| Compressed tarball (`result`) | ~48 MiB |
| Uncompressed (Docker) | ~131 MiB |

The image uses `dockerTools.buildLayeredImage` with 80 max layers. It is
small because it only contains Rust static binaries, bash, coreutils, and
CA certificates — no Python, Node.js, or other runtimes.

### Smoke Test

```bash
# Build, load, and run structural checks (requires Docker daemon)
nix run .#container-test
```

The test runs 15 structural checks. See [Tested Results](#tested-results) for the full list.

## Architecture

```text
flake.nix                    # Coordinator — imports from ./nix/
  |
  +-- nix/constants.nix      # Pure data: version, user config, exclude patterns
  +-- nix/source-filter.nix  # Filtered sources for reproducible builds
  +-- nix/package.nix        # rustPlatform.buildRustPackage (workspace)
  +-- nix/shell.nix          # Dev shell (mkShell + inputsFrom)
  +-- nix/container.nix      # OCI image (dockerTools.buildLayeredImage)
  +-- nix/container-test.nix # Container smoke tests (writeShellApplication)
```

### Module Dependencies

```text
constants.nix --+---> source-filter.nix ---> package.nix --+---> container.nix
                |                                          |
                +---> (all modules read constants)         +---> shell.nix
```

## File Reference

| File | Purpose |
|------|---------|
| `constants.nix` | Shared config: version, user, exclude patterns |
| `source-filter.nix` | `lib.cleanSourceWith` filter for Rust build files |
| `package.nix` | `rustPlatform.buildRustPackage` for the whole workspace |
| `shell.nix` | Dev shell via `mkShell` with `inputsFrom` |
| `container.nix` | OCI image via `dockerTools.buildLayeredImage` |
| `container-test.nix` | Container smoke tests via `writeShellApplication` |

## Tested Results

All outputs verified on Linux x86_64 (2026-03-23):

| Command | Result |
|---------|--------|
| `nix build` | 3 binaries built in ~5 min (`openshell`, `openshell-server`, `openshell-sandbox`) |
| `nix run -- --version` | `openshell 0.0.0` |
| `nix develop -c rustc --version` | `rustc 1.94.0` with clippy, rustfmt, protoc, kubectl, helm, etc. |
| `nix build .#container` | 48 MiB compressed tarball, 131 MiB uncompressed |
| `docker load < result` | `Loaded image: openshell:0.0.0` |
| `nix run .#container-test` | **15/15 checks passed** |
| `nix fmt -- --check` | All Nix files formatted |

### Container Smoke Test Checks (15/15)

- `openshell`, `openshell-server`, `openshell-sandbox`, `bash` on PATH
- `--version` works for all 3 binaries
- Runs as uid 65532, gid 65532
- `/etc/passwd` and `/etc/group` exist
- Home directory exists and is writable
- CA certs available at `/etc/ssl/certs/ca-bundle.crt`
- Entrypoint contains `openshell`

## Key Design Decisions

- **`rustPlatform.buildRustPackage`** with `cargoLock.lockFile` — no manual hash updates
- **Single package builds all 3 binaries** — workspace-wide `cargo build`
- **`protobuf-src` compiles protoc from source** — needs `cmake` + C++ compiler (from `stdenv`)
- **Minimal container** — Rust binaries are statically linked with rustls; only bash, coreutils, cacert needed
- **Non-root container user** — uid/gid 65532
- **Git version fallback** — `build.rs` gracefully falls back to `CARGO_PKG_VERSION` in Nix sandbox

## Sandboxing: OpenShell vs Nix

OpenShell and Nix both sandbox Linux processes using overlapping kernel primitives,
but they solve fundamentally different problems. Nix isolates *builds* to guarantee
reproducibility. OpenShell isolates *running AI agents* to enforce security policy
at runtime. Neither subsumes the other.

### What They Share

Both systems use:

- **Linux namespaces** — mount, PID, network, user (Nix uses all six; OpenShell uses mount, PID, network, and user)
- **seccomp** — syscall filtering to reduce kernel attack surface
- **Privilege dropping** — both run sandboxed processes as non-root
- **Mount isolation** — restricted filesystem views via bind mounts and pivot_root (Nix) or mount namespaces (OpenShell)

### Comparison

| Dimension | Nix | OpenShell |
|-----------|-----|-----------|
| **Goal** | Reproducible builds — same inputs always produce same outputs | Runtime agent isolation — enforce what a running process can reach |
| **When it runs** | Build time only | Runtime (long-lived agent sessions) |
| **Network model** | Binary: full access (fixed-output derivations) or no access (normal builds) | Per-host, per-port, per-path policy via OPA/Rego; HTTP CONNECT proxy for egress |
| **Filesystem model** | Curated `/nix/store` paths bind-mounted read-only; no access outside the closure | Landlock LSM restricts filesystem paths per-agent; policy-driven |
| **Namespace usage** | 6 namespaces (mount, PID, network, user, UTS, IPC) + pivot_root + chroot | Mount, PID, network, user namespaces + Landlock + seccomp |
| **Policy engine** | Hardcoded in C++ (`libstore/unix/build/`) | OPA/Rego policies, hot-reloadable at runtime (`openshell-policy` crate) |
| **L7 inspection** | None | Optional TLS MITM via `openshell-sandbox` for HTTP request/response inspection |
| **Process identity** | None beyond builder UID mapping | Per-process identity binding tracked across sandbox lifetime |
| **Platform support** | Linux, macOS (Seatbelt), FreeBSD | Linux only |
| **Infrastructure** | Just the Nix daemon | Kubernetes cluster, gRPC control plane, mTLS PKI |
| **Maturity** | ~20 years, battle-tested across NixOS and CI farms | Young project, under active development |

### Where Nix Is Stronger

- **Simplicity.** The sandbox is binary: either the build has network access or it
  does not. There is no policy language to learn, no proxy to configure, no MITM
  certificates to manage.
- **Cross-platform.** Nix sandboxes builds on Linux (namespaces), macOS (Seatbelt/sandbox-exec),
  and FreeBSD. OpenShell's sandbox is Linux-only due to Landlock and seccompiler dependencies.
- **Battle-tested.** Nix's sandbox has been hardened over ~20 years across thousands of
  packages and CI systems. Edge cases around builder UID mapping, `/dev` access, and
  store path isolation are well-understood.
- **Zero infrastructure.** A single `nix-daemon` process is all you need. No cluster,
  no control plane, no certificate authority.

### Where OpenShell Is Stronger

- **Granular network policy.** OpenShell can allow `api.example.com:443` on `GET /v1/models`
  while blocking everything else. Nix's fixed-output derivations get unrestricted network
  access — there is no middle ground.
- **Runtime enforcement.** Policies apply to long-running agent processes, not just builds.
  OpenShell can revoke access mid-session without restarting the sandbox.
- **L7 visibility.** The HTTP CONNECT proxy in `openshell-sandbox` can inspect request
  and response bodies, enabling content-based policy decisions. Nix has no equivalent.
- **Hot-reloadable policies.** OPA/Rego policies can be updated without restarting the
  sandbox. Nix's sandbox rules are compiled into the daemon.
- **Process identity tracking.** OpenShell binds identity to individual processes within
  a sandbox, enabling per-agent audit trails. Nix tracks builds, not individual processes.

### Where Nix Is Weaker

- **No granular network control.** Fixed-output derivations bypass the sandbox entirely
  for network access. A compromised `fetchurl` derivation can reach any host.
- **Build-time only.** Nix cannot enforce policy on running services or long-lived
  processes. Once a build completes, the sandbox is gone.
- **macOS sandbox is aging.** Nix's macOS sandbox uses Apple's `sandbox-exec` / Seatbelt
  API, which Apple has deprecated. Future macOS releases may break it.

### Where OpenShell Is Weaker

- **Linux-only.** The `openshell-sandbox` crate depends on Landlock (Linux 5.13+) and
  seccompiler. No macOS or FreeBSD support.
- **Complexity.** The full stack involves OPA policy evaluation, an HTTP CONNECT proxy,
  TOFU certificate pinning, optional TLS MITM, and a Kubernetes control plane. More
  moving parts means more ways to misconfigure.
- **Infrastructure requirements.** OpenShell needs a Kubernetes cluster, gRPC gateway,
  and mTLS PKI. Nix needs a daemon.
- **Young project.** OpenShell's sandbox has not been through the years of edge-case
  hardening that Nix's has. Expect rough edges.

### Summary

Nix's sandbox is simple, cross-platform, and proven — ideal for hermetic builds where
binary network access control is sufficient. OpenShell's sandbox trades that simplicity
for granular, policy-driven runtime isolation — necessary when AI agents need controlled
access to external services during execution, not just during builds.

## Troubleshooting

**"error: experimental Nix feature 'flakes' is disabled"**

Enable flakes per-command or permanently (see above).

**First build is slow (5-15 minutes)**

Expected. Nix is compiling protobuf-src from C++ source plus all Rust dependencies.
After the first build, everything is cached in `/nix/store/`.

**Build fails on macOS**

`openshell-sandbox` uses Linux-only crates (`landlock`, `seccompiler`). The workspace
build may fail on macOS. Use Linux or restrict the build to specific crates.

**"hash mismatch" or cargo lock errors**

Make sure `Cargo.lock` is committed and up to date. Run `cargo update` if needed,
then try `nix build` again.

**Container test fails with "Cannot connect to the Docker daemon"**

The `container-test` target requires a running Docker daemon. Make sure Docker
is installed and your user is in the `docker` group.
