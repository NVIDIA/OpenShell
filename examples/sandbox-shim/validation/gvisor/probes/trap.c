// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Candidate A: SECCOMP_RET_TRAP + ptrace SIGSYS signal-delivery-stop.
// The trusted filter returns TRAP for connect. The tracer authenticates the
// SIGSYS stop, reads arguments from registers, and suppresses the signal.
// - arg0: is the real fd in x0 at the stop (fd 77 and fd > 65535)?
// - relay: pidfd_getfd(observed x0) and connect the dup to a local relay.
// - forged: can the workload queue a SYS_SECCOMP SIGSYS to itself? (yes;
//   register checks reject only this simple forgery)
// - precedence: a workload deny-connect ERRNO filter is outranked by TRAP.
// - blocked/ignored SIGSYS: does the forced signal rewrite workload state?
// - no tracer: what happens to a TRAP'd connect with no tracer?
// - syscall-entry stop: is x0 also clobbered there (PTRACE_SYSCALL)?
#include "gv.h"

#include <pthread.h>
#include <sys/resource.h>

#ifndef SYS_SECCOMP
#define SYS_SECCOMP 1
#endif
#define TRAP_DATA 0x5157
#define LOW_FD 77
#define HIGH_FD 70000

enum mode { M_ARG0, M_RELAY, M_FORGED, M_PRECEDENCE, M_BLOCKED, M_IGNORED, M_NOTRACER };

struct args {
  enum mode mode;
  int fd;
  int relay_port;
};

static void install_trap_filter(void) {
  struct sock_filter f[] = {
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_connect, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP | TRAP_DATA),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
  };
  struct sock_fprog prog = {4, f};
  must(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0, "no_new_privs");
  must(syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog) == 0, "trap filter");
}

// A legitimate, benign workload policy: deny connect with EPERM.
static int install_deny_connect(void) {
  struct sock_filter f[] = {
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_connect, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
  };
  struct sock_fprog prog = {4, f};
  return (int)syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog);
}

static int sock_at(int fd) {
  int s = socket(AF_INET, SOCK_STREAM, 0);
  if (s < 0) return -1;
  if (s != fd && dup2(s, fd) != fd) return -1;
  if (s != fd) close(s);
  return fd;
}

static int body(void *arg) {
  struct args *a = arg;
  if (a->fd >= 65536) {
    struct rlimit rl = {HIGH_FD + 16, HIGH_FD + 16};
    if (setrlimit(RLIMIT_NOFILE, &rl) != 0) return 20;
  }
  if (sock_at(a->fd) != a->fd) return 21;
  if (a->mode == M_BLOCKED) {
    sigset_t s;
    sigemptyset(&s);
    sigaddset(&s, SIGSYS);
    sigprocmask(SIG_BLOCK, &s, NULL);
  }
  if (a->mode == M_IGNORED) signal(SIGSYS, SIG_IGN);
  install_trap_filter();
  if (a->mode == M_PRECEDENCE && install_deny_connect() != 0) return 22;
  if (a->mode == M_FORGED) {
    siginfo_t si;
    memset(&si, 0, sizeof(si));
    si.si_signo = SIGSYS;
    si.si_code = SYS_SECCOMP;
    si.si_errno = TRAP_DATA;
    si.si_call_addr = (void *)0x1234;
    si.si_syscall = SYS_connect;
    si.si_arch = 0xc00000b7;  // AUDIT_ARCH_AARCH64
    errno = 0;
    long rc = syscall(SYS_rt_tgsigqueueinfo, getpid(), (pid_t)syscall(SYS_gettid), SIGSYS, &si);
    printf("forged rt_tgsigqueueinfo rc=%ld errno=%d\n", rc, errno);
    fflush(stdout);
    return rc == 0 ? 30 : 31;
  }
  struct sockaddr_in dst = addr4("203.0.113.9", 443);
  errno = 0;
  int rc = connect(a->fd, (void *)&dst, sizeof(dst));
  int err = errno;
  if (a->mode == M_BLOCKED || a->mode == M_IGNORED) {
    sigset_t cur;
    sigprocmask(SIG_BLOCK, NULL, &cur);
    struct sigaction sa;
    sigaction(SIGSYS, NULL, &sa);
    printf("after trap: sigsys_blocked=%d sigsys_handler=%s\n", sigismember(&cur, SIGSYS),
           sa.sa_handler == SIG_DFL ? "SIG_DFL" : sa.sa_handler == SIG_IGN ? "SIG_IGN" : "other");
    fflush(stdout);
    int changed = a->mode == M_BLOCKED ? !sigismember(&cur, SIGSYS) : sa.sa_handler != SIG_IGN;
    return changed ? 40 : 41;
  }
  if (a->mode == M_RELAY) {
    const char msg[] = "hello-relay";
    if (rc != 0) return 50;
    if (write(a->fd, msg, sizeof(msg)) != (ssize_t)sizeof(msg)) return 51;
    char reply[16] = {0};
    if (read(a->fd, reply, sizeof(reply) - 1) <= 0) return 52;
    return strcmp(reply, "ack") == 0 ? 0 : 53;
  }
  printf("tracee connect rc=%d errno=%d\n", rc, err);
  fflush(stdout);
  if (a->mode == M_PRECEDENCE) return err == EPERM ? 0 : (err == EACCES ? 61 : 62);
  return rc == -1 && err == EACCES ? 0 : 11;
}

static int listener(int *port) {
  int l = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in a = addr4("127.0.0.1", 0);
  must(l >= 0 && bind(l, (void *)&a, sizeof(a)) == 0 && listen(l, 4) == 0, "listen");
  socklen_t len = sizeof(a);
  getsockname(l, (void *)&a, &len);
  *port = ntohs(a.sin_port);
  return l;
}

struct trap_seen {
  int stops;
  int code, err, syscall_nr;
  unsigned arch;
  unsigned long call_addr, pc, x0, x1, x2, x8;
  int dup_ok, relay_ok;
};

// Authenticate and service one SIGSYS stop. Returns 1 if it was handled
// (suppressed), 0 if the signal should be passed through.
static int on_sigsys(pid_t tid, struct args *a, int lfd, struct trap_seen *s) {
  siginfo_t si;
  must(ptrace(PTRACE_GETSIGINFO, tid, 0, &si) == 0, "GETSIGINFO");
  regs_t r;
  must(getregs(tid, &r) == 0, "GETREGSET");
  s->stops++;
  s->code = si.si_code;
  s->err = si.si_errno;
  s->syscall_nr = si.si_syscall;
  s->arch = si.si_arch;
  s->call_addr = (unsigned long)si.si_call_addr;
#ifdef __aarch64__
  s->pc = r.pc;
#else
  s->pc = r.rip;
#endif
  s->x0 = REG_ARG(r, 0);
  s->x1 = REG_ARG(r, 1);
  s->x2 = REG_ARG(r, 2);
  s->x8 = REG_NR(r);
  printf("sigsys stop: code=%d errno=%#x syscall=%d arch=%#x call_addr=%#lx pc=%#lx "
         "x0=%lu x1=%#lx x2=%lu nr=%lu\n",
         s->code, s->err, s->syscall_nr, s->arch, s->call_addr, s->pc, s->x0, s->x1, s->x2, s->x8);
  if (si.si_code != SYS_SECCOMP || si.si_syscall != SYS_connect || s->x8 != SYS_connect ||
      s->call_addr != s->pc)
    return 0;
  int result = -EACCES;
  int pidfd = (int)syscall(SYS_pidfd_open, tid, PIDFD_THREAD);
  int dup = pidfd >= 0 ? (int)syscall(SYS_pidfd_getfd, pidfd, (int)s->x0, 0) : -1;
  s->dup_ok = dup >= 0;
  if (dup >= 0 && a->mode == M_RELAY) {
    struct sockaddr_in want;
    struct iovec local = {&want, sizeof(want)}, remote = {(void *)s->x1, sizeof(want)};
    if (s->x2 == sizeof(want) && process_vm_readv(tid, &local, 1, &remote, 1, 0) == sizeof(want)) {
      printf("relay: workload asked for %s:%d; redirecting to relay\n",
             inet_ntoa(want.sin_addr), ntohs(want.sin_port));
      struct sockaddr_in relay = addr4("127.0.0.1", a->relay_port);
      result = connect(dup, (void *)&relay, sizeof(relay)) == 0 ? 0 : -errno;
    }
    (void)lfd;
  }
  if (dup >= 0) close(dup);
  if (pidfd >= 0) close(pidfd);
  REG_RET(r) = (unsigned long long)(long long)result;
  must(setregs(tid, &r) == 0, "SETREGSET result");
  return 1;
}

static void run(const char *tag, enum mode mode, int fd) {
  struct args a = {mode, fd, 0};
  int lfd = -1;
  if (mode == M_RELAY) lfd = listener(&a.relay_port);
  if (mode == M_NOTRACER) {
    pid_t c = fork();
    if (c == 0) _exit(body(&a));
    int st;
    waitpid(c, &st, 0);
    char name[64];
    snprintf(name, sizeof(name), "%s.no_tracer_sigsys_kills", tag);
    result(name, WIFSIGNALED(st) && WTERMSIG(st) == SIGSYS,
           "no tracer: workload %s %d (TRAP is fail-closed but kills, unlike TRACE -> ENOSYS)",
           WIFSIGNALED(st) ? "killed by signal" : "exited", WIFSIGNALED(st) ? WTERMSIG(st) : WEXITSTATUS(st));
    return;
  }
  pid_t child = spawn_traced(body, &a, PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL);
  struct trap_seen s = {0};
  int status, passed = 0;
  while (waitpid(child, &status, __WALL) == child && WIFSTOPPED(status)) {
    int sig = WSTOPSIG(status);
    int deliver = 0;
    if (event_of(status)) {
      deliver = 0;
    } else if (sig == SIGSYS) {
      deliver = on_sigsys(child, &a, lfd, &s) ? 0 : SIGSYS;
      if (deliver) passed++;
    } else if (sig != SIGCONT && sig != SIGTRAP) {
      deliver = sig;
    }
    must(ptrace(PTRACE_CONT, child, 0, deliver) == 0, "CONT");
    if (mode == M_RELAY && s.stops == 1 && lfd >= 0) {
      int c = accept(lfd, NULL, NULL);
      char buf[32] = {0};
      if (c >= 0 && read(c, buf, sizeof(buf)) > 0) {
        s.relay_ok = strcmp(buf, "hello-relay") == 0;
        if (write(c, "ack", 3) != 3) s.relay_ok = 0;
      }
      if (c >= 0) close(c);
      close(lfd);
      lfd = -1;
    }
  }
  int code = WIFEXITED(status) ? WEXITSTATUS(status) : -WTERMSIG(status);
  char name[96];
  switch (mode) {
    case M_ARG0:
      if (code == 20) {
        skip(tag, "setrlimit(RLIMIT_NOFILE) above the host hard limit needs privileges");
        break;
      }
      snprintf(name, sizeof(name), "%s.siginfo_fields", tag);
      result(name, s.stops == 1 && s.code == SYS_SECCOMP && s.syscall_nr == SYS_connect &&
                       s.arch == 0xc00000b7 && s.err == TRAP_DATA && s.call_addr == s.pc,
             "stops=%d code=%d syscall=%d arch=%#x si_errno=%#x call_addr==pc:%d", s.stops, s.code,
             s.syscall_nr, s.arch, s.err, s.call_addr == s.pc);
      snprintf(name, sizeof(name), "%s.arg0_in_x0", tag);
      result(name, s.x0 == (unsigned long)fd, "x0=%lu expected fd %d", s.x0, fd);
      snprintf(name, sizeof(name), "%s.pidfd_getfd_observed_x0", tag);
      result(name, s.dup_ok, "pidfd_getfd(thread pidfd, x0) %s", s.dup_ok ? "ok" : "failed");
      snprintf(name, sizeof(name), "%s.emulated_eacces", tag);
      result(name, code == 0, "signal suppressed, tracee saw -1/EACCES (exit=%d)", code);
      break;
    case M_RELAY:
      snprintf(name, sizeof(name), "%s.relay_connect", tag);
      result(name, code == 0 && s.relay_ok && s.dup_ok,
             "tracer connected dup of observed x0 to relay; data and reply crossed (exit=%d)", code);
      break;
    case M_FORGED:
      snprintf(name, sizeof(name), "%s.forged_queued_sigsys_reproduced", tag);
      result(name, s.stops == 1 && s.code == SYS_SECCOMP && s.syscall_nr == SYS_connect,
             "workload queued SIGSYS code=%d syscall=%d to itself; tracer saw stop with x8=%lu "
             "call_addr=%#lx pc=%#lx (passed through=%d, exit=%d)",
             s.code, s.syscall_nr, s.x8, s.call_addr, s.pc, passed, code);
      // Partial only: rt_sigreturn can load attacker-chosen x8/pc before a
      // pending SIGSYS is delivered, so these checks are not authentication.
      snprintf(name, sizeof(name), "%s.partial_reject_by_regs", tag);
      result(name, passed == 1, "this forgery failed x8/call_addr checks and was passed through; "
             "sigreturn-loaded registers were not tested");
      break;
    case M_PRECEDENCE:
      snprintf(name, sizeof(name), "%s.workload_errno_filter_preserved", tag);
      result(name, code == 0,
             "workload deny-connect ERRNO(EPERM) filter; TRAP stops=%d tracee exit=%d (%s)", s.stops,
             code,
             code == 61 ? "TRAP outranked the workload ERRNO: mediator emulated over a deny"
                        : code == 0 ? "EPERM preserved" : "other");
      break;
    case M_BLOCKED:
    case M_IGNORED:
      snprintf(name, sizeof(name), "%s.sigsys_state_rewritten_reproduced", tag);
      result(name, code == 40,
             "after a suppressed TRAP the workload's SIGSYS %s was reset (exit=%d)",
             mode == M_BLOCKED ? "mask bit" : "SIG_IGN disposition", code);
      break;
    default:
      break;
  }
}

// Plain PTRACE_SYSCALL entry stop: is x0 also clobbered there?
static int entry_body(void *arg) {
  (void)arg;
  if (sock_at(LOW_FD) != LOW_FD) return 10;
  raise(SIGUSR1);  // sync point: start PTRACE_SYSCALL from here
  struct sockaddr_in dst = addr4("203.0.113.9", 443);
  connect(LOW_FD, (void *)&dst, sizeof(dst));
  return 0;
}

static void entry_stop(void) {
  pid_t child = spawn_traced(entry_body, NULL, PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL);
  int status, tracing = 0, in_syscall = 0;
  long x0 = 0;
  int seen = 0;
  while (waitpid(child, &status, __WALL) == child && WIFSTOPPED(status)) {
    int sig = WSTOPSIG(status);
    if (sig == (SIGTRAP | 0x80)) {
      regs_t r;
      must(getregs(child, &r) == 0, "GETREGSET");
      if (!in_syscall && REG_NR(r) == SYS_connect) {
        x0 = (long)REG_ARG(r, 0);
        seen = 1;
        REG_RET(r) = (unsigned long long)-EACCES;
        skip_syscall(child, &r);
      }
      in_syscall = !in_syscall;
      must(ptrace(PTRACE_SYSCALL, child, 0, 0) == 0, "SYSCALL");
      continue;
    }
    if (sig == SIGUSR1) tracing = 1;
    must(ptrace(tracing ? PTRACE_SYSCALL : PTRACE_CONT, child, 0, 0) == 0, "resume");
  }
  result("syscall_entry.arg0_in_x0", seen && x0 == LOW_FD,
         "PTRACE_SYSCALL entry stop for connect: x0=%ld expected %d", x0, LOW_FD);
}

int main(void) {
  setvbuf(stdout, NULL, _IOLBF, 0);
  run("trap.fd77", M_ARG0, LOW_FD);
  run("trap.fd70000", M_ARG0, HIGH_FD);
  run("trap.relay", M_RELAY, LOW_FD);
  run("trap.forged", M_FORGED, LOW_FD);
  run("trap.deny_filter", M_PRECEDENCE, LOW_FD);
  run("trap.blocked", M_BLOCKED, LOW_FD);
  run("trap.ignored", M_IGNORED, LOW_FD);
  run("trap", M_NOTRACER, LOW_FD);
  entry_stop();
  return finish();
}
