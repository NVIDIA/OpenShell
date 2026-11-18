// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Gate 4 (root tracer only): a root tracer over a workload that dropped to
// uid/gid 10001 and cleared dumpable.
// - The tracer can still seize it, read /proc/<pid>/exe, and pidfd_getfd.
// - The workload cannot signal or ptrace the tracer.
#include "gv.h"
#include <grp.h>

static int workload(int report) {
  int s = socket(AF_INET, SOCK_STREAM, 0);
  if (dup2(s, 50) != 50) return 10;
  close(s);
  if (setgroups(0, NULL) || setgid(10001) || setuid(10001)) return 11;
  prctl(PR_SET_DUMPABLE, 0);
  pid_t tracer = getppid();
  int r[2];
  r[0] = kill(tracer, SIGKILL) == -1 ? errno : 0;
  r[1] = ptrace(PTRACE_ATTACH, tracer, 0, 0) == -1 ? errno : 0;
  if (write(report, r, sizeof(r)) != sizeof(r)) return 12;
  pause();
  return 0;
}

int main(void) {
  setvbuf(stdout, NULL, _IOLBF, 0);
  if (getuid() != 0) {
    skip("creds", "needs a root tracer (run in direct mode)");
    return finish();
  }
  int p[2];
  must(pipe(p) == 0, "pipe");
  pid_t child = fork();
  must(child >= 0, "fork");
  if (child == 0) _exit(workload(p[1]));
  int r[2];
  must(read(p[0], r, sizeof(r)) == sizeof(r), "workload report");
  result("creds.workload_cannot_kill_tracer", r[0] == EPERM, "kill(tracer) errno=%d", r[0]);
  result("creds.workload_cannot_ptrace_tracer", r[1] == EPERM, "PTRACE_ATTACH errno=%d", r[1]);

  long seized = ptrace(PTRACE_SEIZE, child, 0, PTRACE_O_EXITKILL);
  result("creds.root_seizes_nondumpable", seized == 0, "PTRACE_SEIZE errno=%d",
         seized ? errno : 0);
  char path[64], exe[256] = {0};
  snprintf(path, sizeof(path), "/proc/%d/exe", child);
  ssize_t n = readlink(path, exe, sizeof(exe) - 1);
  result("creds.root_reads_exe", n > 0, "%s -> %s", path, n > 0 ? exe : strerror(errno));
  int pidfd = (int)syscall(SYS_pidfd_open, child, 0);
  int dup = pidfd >= 0 ? (int)syscall(SYS_pidfd_getfd, pidfd, 50, 0) : -1;
  result("creds.root_pidfd_getfd_nondumpable", dup >= 0, "pidfd_getfd errno=%d",
         dup >= 0 ? 0 : errno);
  kill(child, SIGKILL);
  waitpid(child, NULL, __WALL);
  return finish();
}
