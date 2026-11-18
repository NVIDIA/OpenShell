// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Gate 4: seccomp filter stacking against the trusted TRACE filter.
// - benign: a Docker-style filter (ERRNO for one unrelated syscall, ALLOW
//   otherwise) stacks; the trusted TRACE stop still fires with the real fd.
// - forged: the workload stacks connect -> SECCOMP_RET_TRACE|12. If the
//   tracer sees eventmsg 12 for a connect on fd 77, SECCOMP_RET_DATA is
//   attacker-controlled and cannot carry arg0 on arm64 gVisor.
#include "gv.h"

#define TRACEE_FD 77
#define FORGED 12

static int body(void *arg) {
  int forged = *(int *)arg;
  int s = socket(AF_INET, SOCK_STREAM, 0);
  if (s < 0 || dup2(s, TRACEE_FD) != TRACEE_FD) return 10;
  close(s);
  int nr = SYS_connect;
  install_trace_filter(&nr, 1, 1);  // trusted: TRACE | arg0
  struct sock_filter stacked[] = {
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, forged ? SYS_connect : SYS_acct, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, forged ? SECCOMP_RET_TRACE | FORGED : SECCOMP_RET_ERRNO | EPERM),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
  };
  struct sock_fprog prog = {4, stacked};
  if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog) != 0) return 12;
  struct sockaddr_in a = addr4("203.0.113.9", 443);
  errno = 0;
  int rc = connect(TRACEE_FD, (void *)&a, sizeof(a));
  return rc == -1 && errno == EACCES ? 0 : 11;
}

static void run(int forged) {
  const char *tag = forged ? "forged" : "benign";
  char name[64];
  pid_t child = spawn_traced(body, &forged,
                             PTRACE_O_TRACESECCOMP | PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL);
  int status, stops = 0;
  unsigned long msg = 0;
  while (waitpid(child, &status, __WALL) == child && WIFSTOPPED(status)) {
    if (event_of(status) == PTRACE_EVENT_SECCOMP) {
      stops++;
      regs_t r;
      must(getregs(child, &r) == 0, "GETREGSET");
      must(ptrace(PTRACE_GETEVENTMSG, child, 0, &msg) == 0, "GETEVENTMSG");
      printf("%s seccomp_stop nr=%llu x0=%lld eventmsg=%lu (real fd %d)\n", tag,
             (unsigned long long)REG_NR(r), (long long)REG_RET(r), msg, TRACEE_FD);
      REG_RET(r) = (unsigned long long)-EACCES;
      skip_syscall(child, &r);
    }
    int sig = WSTOPSIG(status);
    int pass = event_of(status) || sig == SIGCONT || sig == SIGTRAP ? 0 : sig;
    must(ptrace(PTRACE_CONT, child, 0, pass) == 0, "CONT");
  }
  snprintf(name, sizeof(name), "%s.tracee_denied", tag);
  result(name, WIFEXITED(status) && WEXITSTATUS(status) == 0 && stops == 1,
         "stacked filter installed, one TRACE stop, connect skipped with EACCES (exit=%d stops=%d)",
         WIFEXITED(status) ? WEXITSTATUS(status) : -1, stops);
  snprintf(name, sizeof(name), "%s.retdata_is_real_fd", tag);
  result(name, msg == TRACEE_FD, "eventmsg=%lu real fd=%d%s", msg, TRACEE_FD,
         msg == FORGED ? " -- workload-chosen data replaced the trusted filter's data" : "");
}

int main(void) {
  setvbuf(stdout, NULL, _IOLBF, 0);
  run(0);
  run(1);
  return finish();
}
