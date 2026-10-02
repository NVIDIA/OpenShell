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
// Delegate the blocking call to libc's accept4 wrapper. Its cancellation
// assembly distinguishes a cancelled syscall from one that already returned
// an fd (glibc BZ #12683). Switching to asynchronous cancellation around a raw
// syscall cannot make that distinction and can leak the accepted descriptor.
// Resolve the wrapper from loaded ELF objects without dlsym: older glibc puts
// dlsym in libdl, while dl_iterate_phdr is provided by both glibc and musl.
// ELF64 ABI definitions: keeping this source header-free lets the release
// compiler build it with -nostdlib, without selecting a libc sysroot.
typedef unsigned long size_t;
typedef unsigned long ElfAddr;
typedef struct {
    unsigned int p_type, p_flags;
    unsigned long p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align;
} ElfPhdr;
typedef struct {
    long d_tag;
    union { unsigned long d_ptr, d_val; } d_un;
} ElfDyn;
typedef struct {
    unsigned int st_name;
    unsigned char st_info, st_other;
    unsigned short st_shndx;
    unsigned long st_value, st_size;
} ElfSym;
// The first four fields are the stable dl_iterate_phdr ABI on glibc and musl.
struct dl_phdr_info {
    ElfAddr dlpi_addr;
    const char *dlpi_name;
    const ElfPhdr *dlpi_phdr;
    unsigned short dlpi_phnum;
};
extern int dl_iterate_phdr(int (*)(struct dl_phdr_info *, size_t, void *), void *);
#define PT_LOAD 1
#define PT_DYNAMIC 2
#define DT_NULL 0
#define DT_HASH 4
#define DT_STRTAB 5
#define DT_SYMTAB 6
#define DT_GNU_HASH 0x6ffffef5
#define SHN_UNDEF 0
#define STT_FUNC 2

typedef unsigned int shim_socklen_t;
extern int *__errno_location(void);
int accept4(int, void *, shim_socklen_t *, int);
typedef int (*accept4_fn)(int, void *, shim_socklen_t *, int);
static accept4_fn libc_accept4;

static unsigned long dynamic_pointer(unsigned long base, unsigned long value) {
    // glibc relocates these pointers; musl leaves them relative to the DSO.
    return value < base ? base + value : value;
}

static int find_accept4(struct dl_phdr_info *info, size_t size, void *data) {
    (void)size;
    (void)data;
    // Resolve only inside the DSO providing libc's errno accessor. Selecting
    // an arbitrary provider preload's accept4 can recurse back through accept
    // and need not preserve libc cancellation semantics.
    int is_libc = 0;
    for (unsigned int i = 0; i < info->dlpi_phnum; ++i) {
        const ElfPhdr *segment = info->dlpi_phdr + i;
        unsigned long start = info->dlpi_addr + segment->p_vaddr;
        if (segment->p_type == PT_LOAD && (unsigned long)__errno_location >= start &&
            (unsigned long)__errno_location - start < segment->p_memsz) is_libc = 1;
    }
    if (!is_libc) return 0;
    const ElfDyn *dynamic = 0;
    for (unsigned int i = 0; i < info->dlpi_phnum; ++i) {
        if (info->dlpi_phdr[i].p_type == PT_DYNAMIC) {
            dynamic = (const ElfDyn *)(info->dlpi_addr + info->dlpi_phdr[i].p_vaddr);
            break;
        }
    }
    if (!dynamic) return 0;
    const ElfSym *symbols = 0;
    const char *strings = 0;
    const unsigned int *hash = 0;
    const unsigned int *gnu_hash = 0;
    for (; dynamic->d_tag != DT_NULL; ++dynamic) {
        unsigned long pointer = dynamic_pointer(info->dlpi_addr, dynamic->d_un.d_ptr);
        if (dynamic->d_tag == DT_SYMTAB) symbols = (const ElfSym *)pointer;
        if (dynamic->d_tag == DT_STRTAB) strings = (const char *)pointer;
        if (dynamic->d_tag == DT_HASH) hash = (const unsigned int *)pointer;
        if (dynamic->d_tag == DT_GNU_HASH) gnu_hash = (const unsigned int *)pointer;
    }
    if (!symbols || !strings) return 0;
    unsigned int count = 0;
    if (hash) {
        count = hash[1];
    } else if (gnu_hash) {
        // The last nonempty GNU hash bucket ends at the highest symbol index.
        const unsigned int *buckets = (const unsigned int *)
            ((const ElfAddr *)(gnu_hash + 4) + gnu_hash[2]);
        const unsigned int *chains = buckets + gnu_hash[0];
        unsigned int last = 0;
        for (unsigned int i = 0; i < gnu_hash[0]; ++i)
            if (buckets[i] > last) last = buckets[i];
        if (last) {
            count = last;
            while (!(chains[count - gnu_hash[1]] & 1)) ++count;
            ++count;
        }
    }
    for (unsigned int i = 0; i < count; ++i) {
        const ElfSym *symbol = symbols + i;
        if (symbol->st_shndx == SHN_UNDEF || (symbol->st_info & 15) != STT_FUNC)
            continue;
        const char *name = strings + symbol->st_name;
        const char wanted[] = "accept4";
        unsigned int j = 0;
        while (name[j] && name[j] == wanted[j]) ++j;
        if (name[j] != wanted[j]) continue;
        accept4_fn candidate = (accept4_fn)(info->dlpi_addr + symbol->st_value);
        libc_accept4 = candidate;
        return 1;
    }
    return 0;
}

__attribute__((constructor)) static void resolve_accept4(void) {
    dl_iterate_phdr(find_accept4, 0);
}

#if defined(__x86_64__)
#define SHIM_NR_CLOSE 3
#define SHIM_NR_GETPEERNAME 52

static long shim_syscall3(long number, long a0, long a1, long a2) {
    long result;
    __asm__ volatile("syscall"
                     : "=a"(result)
                     : "a"(number), "D"(a0), "S"(a1), "d"(a2)
                     : "rcx", "r11", "memory");
    return result;
}

#elif defined(__aarch64__)
#define SHIM_NR_CLOSE 57
#define SHIM_NR_GETPEERNAME 205

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
    if (!libc_accept4) {
        return shim_finish(-95); // EOPNOTSUPP: unsupported dynamic loader.
    }
    int accepted = libc_accept4(sockfd, 0, 0, flags);
    if (accepted < 0) {
        return accepted;
    }

    if (addr != 0) {
        long result = shim_syscall3(SHIM_NR_GETPEERNAME, accepted, (long)addr,
                                   (long)addrlen);
        if (result < 0) {
            // Never dereference output pointers in userspace. The kernel
            // reports EFAULT, and a reset queued peer may report ENOTCONN.
            shim_syscall3(SHIM_NR_CLOSE, accepted, 0, 0);
            return shim_finish(result == -107 ? -103 : result); // ENOTCONN -> ECONNABORTED
        }
    }
    return (int)accepted;
}

int accept4(int sockfd, void *addr, shim_socklen_t *addrlen, int flags) {
    return shim_accept4(sockfd, addr, addrlen, flags);
}

int accept(int sockfd, void *addr, shim_socklen_t *addrlen) {
    return shim_accept4(sockfd, addr, addrlen, 0);
}
