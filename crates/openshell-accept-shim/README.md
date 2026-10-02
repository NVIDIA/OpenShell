<!--
SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# openshell-accept-shim

Peer-address compatibility library for seccomp listeners that lack
`SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV`.

The crate carries three things: the freestanding C source for the library, a
build script that compiles and embeds it, and the Rust helpers the sandbox uses
to materialize it and compose `LD_PRELOAD`.

## Why it exists

`SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV` arrived in Linux 5.19. Without it the
broker cannot hold a notified workload thread in a kill-only wait, so it cannot
safely write into workload memory and fails closed with `EOPNOTSUPP` on every
mediated syscall whose result is an output buffer. `accept(fd, &addr, &len)` is
exactly that shape, so a server workload on RHEL 9.x or RHCOS sees `EOPNOTSUPP`
where it expects a connection.

The library rewrites that call into two syscalls the broker can satisfy in this
mode:

1. `accept4(fd, NULL, NULL, flags)` — no output buffer, so the broker injects
   the accepted descriptor without touching workload memory.
2. `getpeername(accepted, addr, addrlen)` — the broker answers this with
   `SECCOMP_USER_NOTIF_FLAG_CONTINUE` for a directly connected socket, so the
   *kernel* writes the address into the caller's buffer.

Both halves are required. Step 2 depends on the broker's `CONTINUE` for
`getpeername`; without it, step 2 fails closed for the same reason step 1 did.

Because the workload writes its own memory, the cross-process TOCTOU that
`WAIT_KILLABLE_RECV` exists to close does not apply here.

## Not a security control

Nothing in OpenShell trusts this library's output.

The broker's loopback and authorization decisions use the kernel's own peer
address, obtained from the broker's own `accept4`. The library's result never
re-enters OpenShell's trust domain. A workload can unset `LD_PRELOAD`, link
statically, or issue raw syscalls, and gains nothing it did not already have —
it only loses the compatibility benefit. The enforcement boundary remains the
broker's fail-closed behavior.

This is why the library's location on disk carries no privilege weight.

## Coverage

`LD_PRELOAD` interposes library symbols, not syscalls.

| Runtime | Address-bearing `accept` | Reason |
| --- | --- | --- |
| Bun | Covered | Calls `accept4` through libc with a peer buffer |
| CPython | Covered | `sock_accept` passes a buffer, through libc |
| Node.js | Not needed | libuv always passes `NULL`; it resolves the peer lazily via `getpeername`, which the broker fix handles |
| Go | Not covered | `net` issues the syscall instruction directly |
| Static / `AT_SECURE` binaries | Not covered | No dynamic loader, or the preload is ignored |

`getpeername` is fixed for every runtime, including Go, because the kernel
answers it.

## Build invariants

The source is freestanding C rather than a Rust `cdylib`, because a `cdylib`
would carry a `DT_NEEDED` entry on either glibc or musl and be unloadable in the
other. The build script compiles with `-shared -fPIC -O2 -nostdlib
-fno-stack-protector`. Four properties must hold, and a regression in any of
them is a bug:

| Invariant | Why |
| --- | --- |
| No `DT_NEEDED` | One build per architecture loads under both glibc and musl |
| No `TEXTREL` | Avoids requiring SELinux `execmod`, the permission most likely denied to `container_t` |
| Required `__errno_location` and weak `pthread_setcanceltype` references | Resolve from the workload's libc or already-loaded libpthread without adding a loader dependency |
| Exactly two exported `FUNC` symbols, `accept` and `accept4` | Prevents accidental interposition of unrelated symbols such as `memcpy` |
| ELF machine matches the Rust target | A host object loads nowhere, and the loader reports it as `cannot open shared object file` — indistinguishable from a policy denial |

Supported architectures are `x86_64` and `aarch64`; the source fails to compile
on anything else rather than silently producing a non-functional object.

The build script resolves the C compiler through the `cc` crate, so the
standard `CC_<target>`, `TARGET_CC`, and `CC` overrides apply, as do the
per-target wrappers `cargo-zigbuild` installs when the release binaries are
cross-compiled from a non-Linux host. It then checks the emitted object's ELF
header against `CARGO_CFG_TARGET_ARCH` and fails the build on a mismatch,
because a misresolved compiler otherwise produces a valid object for the wrong
architecture.

The code performs no allocation, takes no locks, and cannot panic. When
`getpeername` fails on an already-accepted connection it reports a zero-length
address — what the kernel itself reports for an unnamed peer — rather than
leaking the descriptor or failing an accept that has already succeeded.

The blocking accept phase preserves libc's pthread cancellation behavior by
temporarily switching the caller to asynchronous cancellation, then restoring
its previous cancellation type before querying the peer. Disabled cancellation
remains disabled. The pthread symbol is weak so a single-threaded workload on
older glibc does not need to load libpthread just to use the shim.

Unix installation helpers and their tests are gated with `cfg(unix)`. The
preload-composition helpers also compile in the Windows workspace checks.

## Installation

`install_shim` materializes the embedded object at
`/run/openshell-compat/accept_shim.so`. The sandbox calls it during startup,
only when `listener.writes_disabled()` reports legacy mode.

The path is constrained from both sides:

- **Not under `/.openshell`.** The capability-free Landlock baseline grants each
  top-level filesystem entry *except* the driver-owned `.openshell` hierarchy,
  and a user ruleset can only narrow the baseline. A workload physically cannot
  open a file there, so a library placed there could never be preloaded.
- **Not under the supervisor CA tmpfs.** That mount is `noexec`, so the loader
  cannot map an object from it.

`/run` satisfies both. On Docker and Podman it is part of the workload's own
writable, exec-capable rootfs. On Kubernetes the workload receives it as an
`emptyDir{medium: Memory}` tmpfs, mounted `rw,seclabel,relatime` with no
`noexec` and mode `1777`, so a non-root sandbox identity can create its own
subdirectory there. No compute driver needs a packaging change: the object is
embedded in the `openshell-sandbox` binary with `include_bytes!`.

Installation creates the directory, writes through a temporary file, `rename`s
it into place, then seals both the file and the directory to `0o555`. Symlinked
directories and symlinked targets are refused rather than followed. Failure is
non-fatal and logged as an OCSF `Config State Change` event — the sandbox starts
without the library and keeps the broker's existing fail-closed behavior.

`LD_PRELOAD` composition preserves any value the workload supplied and is
idempotent, so a child that re-inherits the variable and spawns its own child
does not accumulate duplicate entries.

## Validation

Validated on OpenShift 4.21 / RHCOS 9.6 (kernel `5.14.0-570.141.1.el9_6`,
SELinux enforcing), against the `emptyDir{medium: Memory}` mount the Kubernetes
workload actually receives, running as a non-root uid with
`readOnlyRootFilesystem: true`, all capabilities dropped, and the
`RuntimeDefault` seccomp profile: the object maps `r-xp` with zero AVC denials.

When validating across architectures, check `e_machine` in the ELF header
before drawing conclusions. A wrong-architecture object produces
`cannot open shared object file` from the loader, which reads like an SELinux
denial and is not one.
