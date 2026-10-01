// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Peer-address shim for seccomp listeners without WAIT_KILLABLE_RECV.
//
// On kernels that reject SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV the broker
// cannot safely write into workload memory, so it fails closed on any
// mediated syscall whose result is an output buffer. `accept`/`accept4` with
// a non-NULL address argument is exactly that shape, and the workload sees
// EOPNOTSUPP instead of a connection.
//
// This object is preloaded into the workload and rewrites the request into
// two syscalls the broker can satisfy in that mode:
//
//   1. accept4(fd, NULL, NULL, flags) — no output buffer, so the broker
//      injects the accepted descriptor without touching workload memory.
//   2. getpeername(accepted, addr, addrlen) — the broker answers this for a
//      directly connected socket with SECCOMP_USER_NOTIF_FLAG_CONTINUE, so
//      the kernel itself stores the address into the caller's buffer.
//
// Both halves are required: without the broker's CONTINUE for `getpeername`
// step 2 fails closed for the same reason step 1 did.
//
// Raw syscalls are used rather than dlsym(RTLD_NEXT, ...) so the object needs
// no DT_NEEDED entry and no loader-visible libc dependency. One build per
// architecture therefore loads correctly under both glibc and musl. The only
// undefined symbol is `__errno_location`, which both libcs export and the
// dynamic linker resolves from the already-loaded libc at relocation time.
//
// Interposing here covers runtimes that call these functions through the
// PLT (CPython, Node, Bun, and anything else dynamically linked against
// libc). It cannot cover statically linked binaries or programs that issue
// the syscall instruction directly; those remain subject to the broker's
// fail-closed behavior.

typedef unsigned int shim_socklen_t;

extern int *__errno_location(void);

#if defined(__x86_64__)
#define SHIM_NR_ACCEPT 43
#define SHIM_NR_GETPEERNAME 52
#define SHIM_NR_ACCEPT4 288

static long shim_syscall3(long number, long a0, long a1, long a2) {
    long result;
    __asm__ volatile("syscall"
                     : "=a"(result)
                     : "a"(number), "D"(a0), "S"(a1), "d"(a2)
                     : "rcx", "r11", "memory");
    return result;
}

static long shim_syscall4(long number, long a0, long a1, long a2, long a3) {
    long result;
    register long r10 __asm__("r10") = a3;
    __asm__ volatile("syscall"
                     : "=a"(result)
                     : "a"(number), "D"(a0), "S"(a1), "d"(a2), "r"(r10)
                     : "rcx", "r11", "memory");
    return result;
}

#elif defined(__aarch64__)
#define SHIM_NR_ACCEPT 202
#define SHIM_NR_GETPEERNAME 205
#define SHIM_NR_ACCEPT4 242

static long shim_syscall4(long number, long a0, long a1, long a2, long a3) {
    register long x8 __asm__("x8") = number;
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    __asm__ volatile("svc #0"
                     : "+r"(x0)
                     : "r"(x1), "r"(x2), "r"(x3), "r"(x8)
                     : "memory");
    return x0;
}

static long shim_syscall3(long number, long a0, long a1, long a2) {
    return shim_syscall4(number, a0, a1, a2, 0);
}

#else
#error "openshell-accept-shim supports x86_64 and aarch64 only"
#endif

// Translate a raw syscall return into the libc convention: negative values
// carry -errno, which the caller expects in errno with a -1 return.
static int shim_finish(long result) {
    if (result < 0 && result >= -4095) {
        *__errno_location() = (int)-result;
        return -1;
    }
    return (int)result;
}

static int shim_accept4(int sockfd, void *addr, shim_socklen_t *addrlen,
                        int flags) {
    // Without an output buffer the broker's existing path already works, so
    // forward unchanged and preserve its exact semantics.
    if (addr == 0 || addrlen == 0) {
        return shim_finish(
            shim_syscall4(SHIM_NR_ACCEPT4, sockfd, 0, 0, flags));
    }

    long accepted = shim_syscall4(SHIM_NR_ACCEPT4, sockfd, 0, 0, flags);
    if (accepted < 0) {
        return shim_finish(accepted);
    }

    // The connection is already established; a failure to report its address
    // must not leak the descriptor or fail the accept. Report a zero-length
    // address instead, which is the same thing the kernel reports for an
    // unnamed peer, rather than leaving the caller's buffer undefined.
    if (shim_syscall3(SHIM_NR_GETPEERNAME, accepted, (long)addr,
                      (long)addrlen) < 0) {
        *addrlen = 0;
    }
    return (int)accepted;
}

int accept4(int sockfd, void *addr, shim_socklen_t *addrlen, int flags) {
    return shim_accept4(sockfd, addr, addrlen, flags);
}

int accept(int sockfd, void *addr, shim_socklen_t *addrlen) {
    return shim_accept4(sockfd, addr, addrlen, 0);
}
