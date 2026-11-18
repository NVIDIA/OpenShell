// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Gate 1 (fatal-first): what a tracer can see and change at a
// PTRACE_EVENT_SECCOMP stop for an unmodified connect(fd, external).
// - Is arg0 (the fd) visible in NT_PRSTATUS x0 / rdi?
// - Is it visible anywhere else (/proc/<tid>/syscall, PTRACE_PEEKUSER)?
// - Does SECCOMP_RET_DATA carry arg0 when the filter encodes it?
// - Does nr=-1 with a result register skip the call, and which stops follow?
#include "gv.h"

#define TRACEE_FD 77

static int connect_body(void *arg) {
  int use_data = *(int *)arg;
  int s = socket(AF_INET, SOCK_STREAM, 0);
  if (s < 0 || dup2(s, TRACEE_FD) != TRACEE_FD) return 10;
  close(s);
  int nr = SYS_connect;
  install_trace_filter(&nr, 1, use_data);
  struct sockaddr_in a = addr4("203.0.113.9", 443);
  errno = 0;
  int rc = connect(TRACEE_FD, (void *)&a, sizeof(a));
  int err = errno;
  struct sockaddr_in peer;
  socklen_t len = sizeof(peer);
  int connected = getpeername(TRACEE_FD, (void *)&peer, &len) == 0;
  printf("tracee connect rc=%d errno=%d connected_after=%d\n", rc, err, connected);
  fflush(stdout);
  return (rc == -1 && err == EACCES && !connected) ? 0 : 11;
}

static void read_proc_syscall(pid_t tid, char *out, size_t size) {
  char path[64];
  snprintf(path, sizeof(path), "/proc/%d/syscall", tid);
  int fd = open(path, O_RDONLY);
  if (fd < 0) {
    snprintf(out, size, "open-errno=%d", errno);
    return;
  }
  ssize_t n = read(fd, out, size - 1);
  out[n > 0 ? n : 0] = 0;
  if (n > 0 && out[n - 1] == '\n') out[n - 1] = 0;
  if (n < 0) snprintf(out, size, "read-errno=%d", errno);
  close(fd);
}

// strategy 0: write the result at the seccomp stop and PTRACE_CONT.
// strategy 1: skip at the seccomp stop, PTRACE_SYSCALL, write the result at
//             the next syscall stop (the syscall-exit stop).
static void run(int use_data, int strategy) {
  char tag[32], name[96];
  snprintf(tag, sizeof(tag), "%s.%s", use_data ? "retdata" : "plain",
           strategy ? "exitstop" : "cont");
  pid_t child = spawn_traced(connect_body, &use_data,
                             PTRACE_O_TRACESECCOMP | PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL);
  int status, seccomp_stops = 0, after_stops = 0, sysnr_regset = -1;
  unsigned long msg = 0;
  while (waitpid(child, &status, __WALL) == child) {
    if (WIFEXITED(status) || WIFSIGNALED(status)) break;
    unsigned ev = event_of(status);
    int sig = WSTOPSIG(status);
    if (ev == PTRACE_EVENT_SECCOMP) {
      seccomp_stops++;
      regs_t r;
      must(getregs(child, &r) == 0, "GETREGSET");
      must(ptrace(PTRACE_GETEVENTMSG, child, 0, &msg) == 0, "GETEVENTMSG");
      long arg0 = (long)REG_ARG(r, 0);
      char proc[256];
      read_proc_syscall(child, proc, sizeof(proc));
      errno = 0;
      long peek = ptrace(PTRACE_PEEKUSER, child, 0, 0);
      int peek_errno = errno;
      printf("%s seccomp_stop nr=%llu x0_or_rdi=%ld x1_or_rsi=%#llx eventmsg=%lu "
             "peekuser0=%ld/errno=%d proc_syscall=\"%s\"\n",
             tag, (unsigned long long)REG_NR(r), arg0, (unsigned long long)REG_ARG(r, 1), msg,
             peek, peek_errno, proc);
      if (strategy == 0) {
        snprintf(name, sizeof(name), "%s.arg0_in_regs", use_data ? "retdata" : "plain");
        result(name, arg0 == TRACEE_FD, "x0/rdi=%ld expected fd %d", arg0, TRACEE_FD);
        if (use_data)
          result("retdata.arg0_in_retdata", msg == TRACEE_FD, "eventmsg=%lu expected %d", msg,
                 TRACEE_FD);
      }
      if (strategy == 0) REG_RET(r) = (unsigned long long)-EACCES;
      sysnr_regset = skip_syscall(child, &r);
      must(ptrace(strategy ? PTRACE_SYSCALL : PTRACE_CONT, child, 0, 0) == 0, "resume");
    } else if (sig == (SIGTRAP | 0x80)) {
      after_stops++;
      regs_t r;
      must(getregs(child, &r) == 0, "GETREGSET");
      printf("%s syscall_stop#%d nr=%lld ret=%lld\n", tag, after_stops, (long long)REG_NR(r),
             (long long)REG_RET(r));
      REG_RET(r) = (unsigned long long)-EACCES;
      must(setregs(child, &r) == 0, "SETREGSET result");
      must(ptrace(PTRACE_CONT, child, 0, 0) == 0, "PTRACE_CONT");
    } else if (ev == PTRACE_EVENT_STOP) {
      must(ptrace(PTRACE_CONT, child, 0, 0) == 0, "CONT after event stop");
    } else {
      must(ptrace(PTRACE_CONT, child, 0, sig == SIGCONT ? 0 : sig) == 0, "CONT signal");
    }
  }
  printf("%s nt_arm_system_call_accepted=%d\n", tag, sysnr_regset);
  snprintf(name, sizeof(name), "%s.skip_errno", tag);
  result(name, WIFEXITED(status) && WEXITSTATUS(status) == 0,
         "tracee saw -1/EACCES and socket not connected (exit=%d)",
         WIFEXITED(status) ? WEXITSTATUS(status) : -WTERMSIG(status));
  snprintf(name, sizeof(name), "%s.stops_after_skip", tag);
  result(name, seccomp_stops == 1 && after_stops == strategy,
         "seccomp_stops=%d syscall_stops_after_skip=%d expected=%d", seccomp_stops, after_stops,
         strategy);
}

int main(void) {
  setvbuf(stdout, NULL, _IOLBF, 0);
#ifdef __aarch64__
  printf("arch=aarch64\n");
#else
  printf("arch=x86_64\n");
#endif
  for (int data = 0; data < 2; data++)
    for (int strategy = 0; strategy < 2; strategy++) run(data, strategy);
  return finish();
}
