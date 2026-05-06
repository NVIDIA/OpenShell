# VM Driver Runtime

> Status: Experimental. VM support is under active development and may change.

This directory owns the pinned runtime inputs for `openshell-driver-vm`:

```text
runtime/
  pins.env
  kernel/
    openshell.kconfig
```

`openshell-driver-vm` embeds libkrun, libkrunfw, gvproxy, and the bundled
`openshell-sandbox` supervisor. The legacy `crates/openshell-vm` crate remains
in the repository, but normal workspace builds and release workflows do not use
it.

## Why

The stock `libkrunfw` kernel does not include the bridge, netfilter,
conntrack, cgroup, seccomp, and Landlock features the sandbox supervisor needs
inside each microVM. `kernel/openshell.kconfig` extends the libkrunfw kernel so
VM sandboxes can run the same supervisor enforcement path as other backends.

## Build Scripts

| Script | Platform | Purpose |
|---|---|---|
| `tasks/scripts/vm/build-libkrun.sh` | Linux | Builds libkrunfw and libkrun from source with the custom kernel config |
| `tasks/scripts/vm/build-libkrun-macos.sh` | macOS | Builds portable libkrunfw and libkrun from a prebuilt `kernel.c` |
| `tasks/scripts/vm/package-vm-runtime.sh` | Any | Packages `vm-runtime-<platform>.tar.zst` with libraries, gvproxy, and provenance |
| `tasks/scripts/vm/download-kernel-runtime.sh` | Any | Downloads runtime tarballs from the `vm-runtime` release and stages compressed files |

## Local Flow

```shell
# Download the current pre-built runtime and stage compressed artifacts
mise run vm:setup

# Build the bundled guest supervisor
mise run vm:supervisor

# Build the gateway and VM driver with embedded runtime artifacts
OPENSHELL_VM_RUNTIME_COMPRESSED_DIR=$PWD/target/vm-runtime-compressed \
  cargo build -p openshell-server -p openshell-driver-vm
```

Use `FROM_SOURCE=1 mise run vm:setup` to build the runtime from source instead
of downloading `vm-runtime-<platform>.tar.zst`.

## CI Ownership

`release-vm-kernel.yml` is the on-demand producer for:

- `vm-runtime-linux-aarch64.tar.zst`
- `vm-runtime-linux-x86_64.tar.zst`
- `vm-runtime-darwin-aarch64.tar.zst`

Those artifacts stay on the rolling `vm-runtime` release. Normal `dev` and `v*`
release workflows download them, embed them into `openshell-driver-vm`, and
publish the driver binary next to `openshell-gateway`.

## Provenance

`package-vm-runtime.sh` writes `provenance.json` into each runtime tarball with
the platform, libkrunfw commit, kernel version, GitHub SHA, and build time. The
driver logs this metadata when it extracts and loads a runtime bundle.

The release workflow also publishes GitHub artifact attestations for each
runtime tarball. Verify a downloaded runtime with:

```bash
gh attestation verify vm-runtime-linux-x86_64.tar.zst -R NVIDIA/OpenShell
```
