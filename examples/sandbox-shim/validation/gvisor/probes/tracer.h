// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Minimal multi-task tracer loop for the probes. It follows fork, vfork,
// clone, and exec; hands PTRACE_EVENT_SECCOMP stops to a callback; and passes
// signals through. It is deliberately not a mediator implementation.
#include "gv.h"

#define TRACE_OPTIONS                                                                   \
  (PTRACE_O_TRACESECCOMP | PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL |                  \
   PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC)

// Syscalls the probes trace; RET_DATA carries arg0 (see regs.c).
static const int traced_nrs[] = {SYS_socket, SYS_connect, SYS_bind, SYS_listen,
                                 SYS_sendto, SYS_sendmsg, SYS_sendmmsg};

struct stop {
  pid_t tid;
  long nr;
  unsigned long arg0;  // from SECCOMP_RET_DATA
  regs_t regs;
};

// Return 0 to let the syscall run, or a negative errno to skip it with that
// result. The callback may also emulate the call and return its result as
// 0 / -errno with *emulated set.
typedef long (*seccomp_cb)(struct stop *s, int *emulated, void *ctx);

static __attribute__((unused)) void exe_of(pid_t tid, char *out, size_t size) {
  char path[64];
  snprintf(path, sizeof(path), "/proc/%d/exe", tid);
  ssize_t n = readlink(path, out, size - 1);
  out[n > 0 ? n : 0] = 0;
  if (n < 0) snprintf(out, size, "?errno=%d", errno);
}

static __attribute__((unused)) void install_probe_filter(void) {
  install_trace_filter(traced_nrs, (int)(sizeof(traced_nrs) / sizeof(traced_nrs[0])), 1);
}

struct trace_stats {
  int seccomp, forks, vforks, clones, execs, exits;
  pid_t last_exec_tid;
  unsigned long last_exec_former;
  // If > 0, report tids as {kind, tid} pairs: 'e' for a fork/vfork/clone
  // PTRACE_GETEVENTMSG value, 'w' for a new tracee's first waitpid() stop.
  int report_fd;
};

// Trace until `root` exits (or every tracee, with all=1). Returns root's
// wait status.
static __attribute__((unused)) int trace_loop(pid_t root, seccomp_cb cb, void *ctx,
                                              struct trace_stats *st, int all) {
  int root_status = -1, status;
  pid_t tid;
  while ((tid = waitpid(-1, &status, __WALL)) > 0) {
    if (WIFEXITED(status) || WIFSIGNALED(status)) {
      st->exits++;
      if (tid == root) {
        root_status = status;
        if (!all) return root_status;
      }
      continue;
    }
    unsigned ev = event_of(status);
    int sig = WSTOPSIG(status);
    unsigned long msg = 0;
    if (ev == PTRACE_EVENT_SECCOMP) {
      st->seccomp++;
      struct stop s = {.tid = tid};
      if (getregs(tid, &s.regs) != 0 || ptrace(PTRACE_GETEVENTMSG, tid, 0, &msg) != 0) {
        continue;  // Killed while stopped; the exit is reported next.
      }
      s.nr = (long)REG_NR(s.regs);
      s.arg0 = msg;
      int emulated = 0;
      long rc = cb ? cb(&s, &emulated, ctx) : 0;
      if (rc != 0 || emulated) {
        REG_RET(s.regs) = (unsigned long long)rc;
        skip_syscall(tid, &s.regs);
      }
      ptrace(PTRACE_CONT, tid, 0, 0);
    } else if (ev == PTRACE_EVENT_FORK || ev == PTRACE_EVENT_VFORK ||
               ev == PTRACE_EVENT_CLONE) {
      if (ev == PTRACE_EVENT_FORK) st->forks++;
      if (ev == PTRACE_EVENT_VFORK) st->vforks++;
      if (ev == PTRACE_EVENT_CLONE) st->clones++;
      if (st->report_fd > 0 && ptrace(PTRACE_GETEVENTMSG, tid, 0, &msg) == 0) {
        pid_t pair[2] = {'e', (pid_t)msg};
        if (write(st->report_fd, pair, sizeof(pair)) != sizeof(pair)) st->report_fd = 0;
      }
      ptrace(PTRACE_CONT, tid, 0, 0);
    } else if (ev == PTRACE_EVENT_EXEC) {
      st->execs++;
      ptrace(PTRACE_GETEVENTMSG, tid, 0, &msg);
      st->last_exec_tid = tid;
      st->last_exec_former = msg;
      ptrace(PTRACE_CONT, tid, 0, 0);
    } else if (ev == PTRACE_EVENT_STOP) {
      // Seized auto-attach stop (SIGTRAP) or group-stop.
      if (sig == SIGTRAP && st->report_fd > 0) {
        pid_t pair[2] = {'w', tid};
        if (write(st->report_fd, pair, sizeof(pair)) != sizeof(pair)) st->report_fd = 0;
      }
      if (sig == SIGSTOP || sig == SIGTSTP || sig == SIGTTIN || sig == SIGTTOU)
        ptrace(PTRACE_LISTEN, tid, 0, 0);
      else
        ptrace(PTRACE_CONT, tid, 0, 0);
    } else {
      ptrace(PTRACE_CONT, tid, 0, sig);
    }
  }
  return root_status;
}
