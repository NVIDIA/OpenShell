// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Shared helpers for the stock-gVisor ptrace mediation probes. Each probe is
// one small program that prints "RESULT <name> PASS|FAIL <detail>" lines and
// exits nonzero if any of its checks failed.
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifdef __aarch64__
#include <asm/ptrace.h>
typedef struct user_pt_regs regs_t;
#define REG_NR(r) ((r).regs[8])
#define REG_RET(r) ((r).regs[0])
#define REG_ARG(r, i) ((r).regs[i])
#else
#include <sys/user.h>
typedef struct user_regs_struct regs_t;
#define REG_NR(r) ((r).orig_rax)
#define REG_RET(r) ((r).rax)
#define REG_ARG(r, i) ((i) == 0 ? (r).rdi : (i) == 1 ? (r).rsi : (r).rdx)
#endif

#ifndef PIDFD_THREAD
#define PIDFD_THREAD O_EXCL
#endif

static int failures;

static void result(const char *name, int ok, const char *fmt, ...)
    __attribute__((format(printf, 3, 4), unused));
static __attribute__((unused)) void result(const char *name, int ok, const char *fmt, ...) {
  char detail[512];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(detail, sizeof(detail), fmt, ap);
  va_end(ap);
  printf("RESULT %s %s %s\n", name, ok ? "PASS" : "FAIL", detail);
  fflush(stdout);
  if (!ok) failures++;
}

static __attribute__((unused)) void skip(const char *name, const char *why) {
  printf("RESULT %s SKIP %s\n", name, why);
  fflush(stdout);
}

static __attribute__((unused)) void must(int ok, const char *what) {
  if (!ok) {
    printf("RESULT harness FAIL %s: %s\n", what, strerror(errno));
    fflush(stdout);
    exit(2);
  }
}

static __attribute__((unused)) long getregs(pid_t tid, regs_t *regs) {
  struct iovec io = {regs, sizeof(*regs)};
  return ptrace(PTRACE_GETREGSET, tid, (void *)1 /* NT_PRSTATUS */, &io);
}

static __attribute__((unused)) long setregs(pid_t tid, regs_t *regs) {
  struct iovec io = {regs, sizeof(*regs)};
  return ptrace(PTRACE_SETREGSET, tid, (void *)1 /* NT_PRSTATUS */, &io);
}

// Set the pending syscall number to -1 (skip). Linux arm64 reads the number
// from NT_ARM_SYSTEM_CALL; gVisor arm64 exposes only NT_PRSTATUS and reads x8.
// Returns 1 if NT_ARM_SYSTEM_CALL was accepted, 0 if only x8 was written.
static __attribute__((unused)) int skip_syscall(pid_t tid, regs_t *regs) {
  REG_NR(*regs) = (unsigned long long)-1;
  must(setregs(tid, regs) == 0, "SETREGSET skip");
#ifdef __aarch64__
  int nr = -1;
  struct iovec io = {&nr, sizeof(nr)};
  return ptrace(PTRACE_SETREGSET, tid, (void *)0x404 /* NT_ARM_SYSTEM_CALL */, &io) == 0;
#else
  return 0;
#endif
}

// Install a filter that returns SECCOMP_RET_TRACE for each listed syscall.
// With data_arg0, the low 16 bits of arg0 become SECCOMP_RET_DATA when
// arg0 < 65536; larger arg0 values are refused with EBADF in the filter.
static __attribute__((unused)) void install_trace_filter(const int *nrs, int count, int data_arg0) {
  struct sock_filter f[64];
  int n = 0;
  f[n++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                                        offsetof(struct seccomp_data, nr));
  for (int i = 0; i < count; i++) {
    // Jump to the shared "traced" block that follows the ALLOW.
    f[n] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, nrs[i],
                                        (unsigned char)(count - i), 0);
    n++;
  }
  f[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
  if (data_arg0) {
    f[n++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                                          offsetof(struct seccomp_data, args[0]) + 4);
    f[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 0);
    f[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EBADF);
    f[n++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                                          offsetof(struct seccomp_data, args[0]));
    f[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 65536, 0, 1);
    f[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EBADF);
    f[n++] = (struct sock_filter)BPF_STMT(BPF_ALU | BPF_OR | BPF_K, SECCOMP_RET_TRACE);
    f[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_A, 0);
  } else {
    f[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE);
  }
  struct sock_fprog prog = {(unsigned short)n, f};
  must(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0, "no_new_privs");
  must(syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog) == 0, "seccomp filter");
}

// Fork a child that stops itself, then is seized with the given options.
// The child runs body() after the parent resumes it and exits with its result.
static __attribute__((unused)) pid_t spawn_traced(int (*body)(void *), void *arg, long options) {
  pid_t child = fork();
  must(child >= 0, "fork");
  if (child == 0) {
    raise(SIGSTOP);
    _exit(body(arg));
  }
  int status;
  must(waitpid(child, &status, WUNTRACED) == child && WIFSTOPPED(status), "child stop");
  must(ptrace(PTRACE_SEIZE, child, 0, options) == 0, "PTRACE_SEIZE");
  must(kill(child, SIGCONT) == 0, "SIGCONT");
  return child;
}

static __attribute__((unused)) unsigned event_of(int status) { return (unsigned)status >> 16; }

static __attribute__((unused)) double now_us(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ts.tv_sec * 1e6 + ts.tv_nsec / 1e3;
}

static __attribute__((unused)) struct sockaddr_in addr4(const char *ip, int port) {
  struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons((uint16_t)port)};
  inet_pton(AF_INET, ip, &a.sin_addr);
  return a;
}

static __attribute__((unused)) int finish(void) {
  printf("SUMMARY failures=%d\n", failures);
  return failures ? 1 : 0;
}
