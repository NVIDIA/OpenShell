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

## Coverage

`LD_PRELOAD` interposes library symbols, not syscalls.

| Runtime | Address-bearing `accept` | Reason |
| --- | --- | --- |
| Bun | Covered | Calls `accept4` through libc with a peer buffer |
| CPython | Covered | `sock_accept` passes a buffer, through libc |
| Node.js | Not needed | libuv always passes `NULL`; it resolves the peer lazily via `getpeername`, which the broker fix handles |
| Go | Not covered | `net` issues the syscall instruction directly |
| Static / `AT_SECURE` binaries | Not covered | No dynamic loader, or the preload is ignored |

On directly connected sockets, `getpeername` reports the true peer for every
runtime, including Go, because the kernel answers it. In legacy mode the
broker also continues `getpeername` on relayed outbound sockets, allowing the
query to succeed with the loopback relay's address rather than the upstream
destination. This fallback does not need the shim and does not change outbound
authorization. Modern listeners still substitute the original upstream address
through the broker's safe task-memory write path.

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
| Required `__errno_location` and `dl_iterate_phdr` references | Resolve from glibc or musl without a loader dependency |
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

The shim resolves libc's `accept4` from the already-loaded ELF image that
provides `__errno_location`, using `dl_iterate_phdr`. Delegating the blocking
phase preserves libc's cancellation handling, including the accepted-fd race
addressed by glibc BZ #12683. Peer lookup and error-path close use raw syscalls,
which are not cancellation points. A failed peer lookup closes the descriptor
and returns the kernel error; `ENOTCONN` becomes `ECONNABORTED` so a reset peer
does not produce a successful accept with an unusable address. Invalid output
pointers return `EFAULT` without userspace dereferences.

## Installation and child environments

The sandbox probes installation only for a legacy read-only listener. It
creates a sealed executable memfd instead of writing into the image's `/run`.
This works with a non-root identity, a read-only rootfs, and noexec temporary
mounts. There are no workload-selected pathname components or symlinks. Write,
grow, shrink, and seal seals prevent changing its bytes. The boundary's private
probe descriptor is close-on-exec.

Each entrypoint or exec launch gets a fresh sealed memfd inode. Its descriptor
remains close-on-exec in the boundary and is made inheritable only in its own
forked child. The loader opens `/proc/self/fd/N`.
A workload can close or chmod its own inode, but cannot replace the object or
change permissions on the inode used by a later operator exec session.
Anonymous inodes need no extra Landlock admission, so the shim does not create
a restrictive user ruleset when the authored policy has none.

Installation checks executable mapping before setting `LD_PRELOAD`. It requests
`MFD_EXEC` where supported and falls back to the pre-6.3 ABI on older kernels.
A host that forbids executable memfds keeps the broker's fail-closed behavior;
installation failure is non-fatal and logged.

Both launch paths compose the shim after all environment sources have been
applied, preserving the final provider, workload, or per-session override.
Directly launched ELF binaries for a different class or architecture do not
receive the shim. Descendants inherit ordinary `LD_PRELOAD` semantics: a child
that closes the descriptor, hides `/proc`, or invokes a foreign-architecture
loader must remove the shim entry itself. The boundary cannot check arbitrary
descendant execs, and those loaders may otherwise emit a preload warning.
Static and secure-execution loaders do not use the shim.

## Validation

Tests check the embedded target-compiler output for ELF target, no `DT_NEEDED`,
no text relocations, a non-executable stack, exactly `accept` and `accept4`
exports, and the expected libc references. Behavioral tests cover IPv4, IPv6,
truncation, reset peers, invalid length pointers, accepted streams, and pthread
cancellation, including coexistence with a provider preload defining `accept4`.
C fixtures use the same resolved target compiler as the shim.

Sandbox tests exercise a forced legacy listener with the real broker and
preloaded CPython: a rejected raw address-bearing accept must leave its client
queued for a subsequent shimmed accept. They also check connected DNS peer
queries and shim access under unrestricted and restricted Landlock policies.
