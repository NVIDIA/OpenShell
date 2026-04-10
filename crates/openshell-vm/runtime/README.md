# Custom libkrunfw Runtime

> Status: Experimental and work in progress (WIP). VM support is under active development and may change.

This directory contains the kernel config fragment for a custom `libkrunfw` runtime
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
  kernel/
    openshell.kconfig          # Kernel config fragment (networking + sandboxing)
```

## Build Pipeline

Each platform builds its own kernel and runtime natively.

```
Linux ARM64:  builds aarch64 kernel -> .so  (parallel)
Linux AMD64:  builds x86_64 kernel  -> .so  (parallel)
macOS ARM64:  builds aarch64 kernel -> .dylib
```

### Build Scripts

| Script | Platform | What it does |
|--------|----------|-------------|
| `tasks/scripts/vm/build-libkrun.sh` | Linux | Builds libkrunfw + libkrun from source |
| `tasks/scripts/vm/build-libkrun-macos.sh` | macOS | Builds libkrunfw + libkrun from source |
| `tasks/scripts/vm/package-vm-runtime.sh` | Any | Packages runtime tarball (libs + gvproxy + provenance) |

### Quick Build (Linux)

```bash
# Build both libkrunfw and libkrun from source
tasks/scripts/vm/build-libkrun.sh

# Or build the full runtime from source via mise:
FROM_SOURCE=1 mise run vm:setup
```

### Quick Build (macOS)

```bash
# Download pre-built runtime (recommended, ~30s):
mise run vm:setup

# Or build from source:
FROM_SOURCE=1 mise run vm:setup
```

### Output

Build artifacts are placed in `target/libkrun-build/`:

```
target/libkrun-build/
  libkrun.so / libkrun.dylib       # The VMM library
  libkrunfw.so* / libkrunfw.dylib  # Kernel firmware library
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
