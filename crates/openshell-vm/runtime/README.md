# Custom libkrunfw Runtime

> Status: Experimental and work in progress (WIP). VM support is under active development and may change.

This directory contains the build infrastructure for a custom `libkrunfw` runtime
that enables bridge CNI and netfilter support in the OpenShell gateway VM.

## Why

The stock `libkrunfw` (from Homebrew) ships a kernel without bridge, netfilter,
or conntrack support. This means the VM cannot:

- Create `cni0` bridge interfaces (required by the bridge CNI plugin)
- Run kube-proxy (requires nftables)
- Route service VIP traffic (requires NAT/conntrack)

The custom runtime builds libkrunfw with an additional kernel config fragment
that enables these networking and sandboxing features.

## Directory Structure

```
runtime/
  build-custom-libkrunfw.sh   # Build script for custom libkrunfw
  kernel/
    openshell.kconfig          # Kernel config fragment (networking + sandboxing)
```

## Building

### Prerequisites

- Rust toolchain
- make, git, curl
- On macOS: Xcode command line tools and cross-compilation tools for aarch64

### Quick Build

```bash
# Build custom libkrunfw (clones libkrunfw repo, applies config, builds)
./crates/openshell-vm/runtime/build-custom-libkrunfw.sh

# Or build the full runtime from source via mise:
FROM_SOURCE=1 mise run vm:setup
```

### Output

Build artifacts are placed in `target/custom-runtime/`:

```
target/custom-runtime/
  libkrunfw.dylib              # The custom library
  libkrunfw.<version>.dylib    # Version-suffixed copy
  provenance.json              # Build metadata (commit, hash, timestamp)
  openshell.kconfig            # The config fragment used
  kernel.config                # Full kernel .config (for debugging)
```

### Using the Custom Runtime

```bash
# Point the bundle script at the custom build and rebuild:
export OPENSHELL_VM_RUNTIME_SOURCE_DIR=target/custom-runtime
mise run vm:build

# Then boot the VM as usual:
mise run vm
```

## Networking

The VM uses bridge CNI for pod networking with nftables-mode kube-proxy for
service VIP / ClusterIP support. The kernel config fragment enables both
iptables (for CNI bridge masquerade) and nftables (for kube-proxy).

k3s is started with `--kube-proxy-arg=proxy-mode=nftables` because the
bundled iptables binaries in k3s have revision-negotiation issues with the
libkrun kernel's xt_MARK module. nftables mode uses the kernel's nf_tables
subsystem directly and avoids this entirely.

## Runtime Provenance

At VM boot, the openshell-vm binary logs provenance information about the loaded
runtime:

```
runtime: /path/to/openshell-vm.runtime
  libkrunfw: libkrunfw.dylib
  sha256: a1b2c3d4e5f6...
  type: custom (OpenShell-built)
  libkrunfw-commit: abc1234
  kernel-version: 6.6.30
  build-timestamp: 2026-03-23T10:00:00Z
```

For stock runtimes:
```
runtime: /path/to/openshell-vm.runtime
  libkrunfw: libkrunfw.dylib
  sha256: f6e5d4c3b2a1...
  type: stock (system/homebrew)
```

## Verification

### Capability Check (inside VM)

```bash
# Run inside the VM to verify kernel capabilities:
/srv/check-vm-capabilities.sh

# JSON output for CI:
/srv/check-vm-capabilities.sh --json
```

### Rollback

To revert to the stock runtime:

```bash
# Unset the custom runtime source:
unset OPENSHELL_VM_RUNTIME_SOURCE_DIR

# Re-download pre-built runtime and rebuild:
mise run vm:setup
mise run vm:build

# Boot:
mise run vm
```

## Troubleshooting

### "FailedCreatePodSandBox" bridge errors

The kernel does not have bridge support. Verify:
```bash
# Inside VM:
ip link add test0 type bridge && echo "bridge OK" && ip link del test0
```

If this fails, you are running the stock runtime. Build and use the custom one.

### kube-proxy CrashLoopBackOff

kube-proxy runs in nftables mode. If it crashes, verify nftables support:
```bash
# Inside VM:
nft list ruleset
```

If this fails, the kernel may lack `CONFIG_NF_TABLES`. Use the custom runtime.

Common errors:
- `unknown option "--xor-mark"`: kube-proxy is running in iptables mode instead
  of nftables. Verify `--kube-proxy-arg=proxy-mode=nftables` is in the k3s args.

### Runtime mismatch after upgrade

If libkrunfw is updated (e.g., via `brew upgrade`), the stock runtime may
change. Check provenance:
```bash
# Look for provenance info in VM boot output
grep "runtime:" ~/.local/share/openshell/openshell-vm/console.log
```

Re-build the custom runtime if needed:
```bash
FROM_SOURCE=1 mise run vm:setup
mise run vm:build
```
