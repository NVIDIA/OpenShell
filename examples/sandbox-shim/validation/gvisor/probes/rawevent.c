// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Candidate D: gettid substitution + trusted raw SecCheck metadata.
// At the connect SECCOMP_RET_TRACE stop (x0 = -38 on arm64 gVisor), the
// tracer does not run connect. It changes only x8 to gettid and x4/x5 to a
// fresh 128-bit nonce. gVisor passes the hidden OrigR0 as args[0] and emits
// the raw syscall/sysno/178/enter point (Arg1 = original fd, Arg5/Arg6 =
// nonce, thread_id in the root PID namespace) to the host collector before
// gettid runs (task_syscall.go executeSyscall). At the gettid exit stop the
// tracer asks the host collector for the event matching {tid, nonce} and
// waits for the reply with the tracee still stopped. With a match it
// pidfd_getfd()s that fd, decides, restores every original register with the
// result, and resumes. With no match, the original connect never ran and the
// caller is denied.
//
// Needs the raw harness mode (run.py raw): runsc with --pod-init-config
// pointing the remote sink at host/collector.c, and --host-uds=create so the
// collector can connect into this tracer's private channel. Elsewhere every
// check is SKIP.
#include "gv.h"
#include "rawproto.h"

#ifndef __aarch64__
#error "Candidate D probe is arm64-only: it targets the hidden x0 and uses x4/x5"
#endif

#include <dirent.h>
#include <linux/aio_abi.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <sys/random.h>
#include <sys/resource.h>
#include <sys/un.h>

#define FD 77
#define DECOY 78
#define ALIAS 79
#define HIGH_FD 70000
#define ITER 200
#define QUERY_TIMEOUT_MS 500
#define REPLY_DEADLINE_MS 1000

enum mode {
  M_DENY, M_HIGH, M_RELAY, M_ERRNO_EPERM, M_ERRNO_ENOSYS, M_FORGED_TRACE, M_SPAM, M_DROP,
  M_DELAY, M_REPLAY, M_MISMATCH, M_EXEC, M_PIDNS, M_UID, M_WRITERS,
  // Fault injection with a real loopback destination owned by the tracer.
  M_FAULT_ABORT,   // hook: treat the gettid exit stop as unexpected
  M_INTERRUPT,     // real PTRACE_INTERRUPT between the entry and exit stops
  M_UNSAFE_ENTRY,  // the bug being guarded against: restore connect at ENTRY
};

struct cfg {
  enum mode mode;
  int relay_port;
};

static int ctl = -1;  // trusted host collector connection; never inherited
static uint32_t seq;
static int self_exe = -1;

// ----------------------------------------------------------- workload ----

static void install_connect_trace(void) {
  int nr = SYS_connect;
  install_trace_filter(&nr, 1, 0);
}

static int stack_filter(int nr, unsigned action) {
  struct sock_filter f[] = {
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (unsigned)nr, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, action),
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

static int count_fds(void) {
  DIR *d = opendir("/proc/self/fd");
  int n = 0;
  struct dirent *e;
  while (d && (e = readdir(d)))
    if (e->d_name[0] != '.') n++;
  if (d) closedir(d);
  return n;
}

static int try_connect(int fd) {
  struct sockaddr_in dst = addr4("203.0.113.9", 443);
  errno = 0;
  return connect(fd, (void *)&dst, sizeof(dst)) == -1 ? errno : 0;
}

static int unconnected(int fd) {
  struct sockaddr_in peer;
  socklen_t len = sizeof(peer);
  return getpeername(fd, (void *)&peer, &len) != 0 && errno == ENOTCONN;
}

static volatile sig_atomic_t usr1_seen;
static void on_usr1(int sig) { (void)sig; usr1_seen++; }

static int connect_once(enum mode mode) {
  int fd = mode == M_HIGH ? HIGH_FD : FD;
  if (sock_at(fd) != fd || sock_at(DECOY) != DECOY || dup2(fd, ALIAS) != ALIAS) return 21;
  if (mode == M_SPAM) {
    // Workload-generated raw gettid events from the same tid with chosen
    // x4/x5 values must not satisfy the tracer's match.
    for (int i = 0; i < 100; i++)
      syscall(SYS_gettid, 0, 0, 0, 0, 0x4141414141414141ull + i, 0x4242424242424242ull);
  }
  sigset_t s;
  sigemptyset(&s);
  sigaddset(&s, SIGUSR1);
  signal(SIGUSR1, on_usr1);
  sigprocmask(SIG_BLOCK, &s, NULL);
  raise(SIGUSR1);
  int err = try_connect(fd);
  sigprocmask(SIG_UNBLOCK, &s, NULL);
  int unconn = unconnected(fd);
  printf("tracee mode=%d connect errno=%d unconnected=%d usr1_seen=%d\n", mode, err, unconn,
         (int)usr1_seen);
  fflush(stdout);
  int want = mode == M_ERRNO_EPERM ? EPERM : mode == M_ERRNO_ENOSYS ? ENOSYS : EACCES;
  if (err != want) return 30 + (err & 0x3f);
  if (mode == M_DELAY) {
    usleep(3500 * 1000);  // let the late reply reach the tracer's channel first
    if (try_connect(fd) != EACCES) return 23;  // the next transaction still works
  }
  return !unconn || usr1_seen != 1 ? 22 : 0;
}

// Fault modes connect to a live loopback listener owned by the tracer, so an
// original connect that ever ran would be accepted there.
static int fault_body(struct cfg *c) {
  if (sock_at(FD) != FD) return 21;
  struct sockaddr_in dst = addr4("127.0.0.1", c->relay_port);
  errno = 0;
  int rc = connect(FD, (void *)&dst, sizeof(dst));
  int err = errno, unconn = unconnected(FD);
  printf("tracee fault mode=%d connect rc=%d errno=%d unconnected=%d\n", c->mode, rc, err,
         unconn);
  fflush(stdout);
  return rc == -1 && err == EACCES && unconn ? 0 : 60;
}

static int relay_body(void) {
  int before = count_fds();
  for (int i = 0; i < 50; i++) {
    if (sock_at(FD) != FD) return 21;
    if (try_connect(FD) != 0) return 22;
    char msg[32], reply[40] = {0};
    int n = snprintf(msg, sizeof(msg), "hello-%d", i);
    if (write(FD, msg, (size_t)n) != n) return 23;
    if (read(FD, reply, sizeof(reply) - 1) <= 0) return 24;
    if (strncmp(reply, "ack-", 4) || strcmp(reply + 4, msg)) return 25;
    close(FD);
  }
  int after = count_fds();
  printf("tracee relay fds before=%d after=%d\n", before, after);
  fflush(stdout);
  return before == after ? 0 : 26;
}

// Private-memory writers: a sibling thread and AIO preads into the same
// dedicated buffer. Neither the buffer nor its address is a metadata input.
// AIO completion overlap with metadata capture is not measured here.
static uint64_t writer_buffer[128];
static _Atomic uintptr_t writer_addr;
static atomic_int race_stop;

static void *sprayer(void *arg) {
  (void)arg;
  while (!atomic_load(&race_stop)) {
    uintptr_t base = atomic_load(&writer_addr);
    if (!base) continue;
    for (uintptr_t p = base; p < base + 1024; p += 8) *(volatile uint64_t *)p = 0x4545454545454545ull;
  }
  return NULL;
}

static __attribute__((noinline)) int writers_loop(aio_context_t ctx, int f) {
  static struct iocb cbs[64];
  struct iocb *ptrs[64];
  int denied = 0, submitted = 0;
  uintptr_t base = (uintptr_t)writer_buffer;
  atomic_store(&writer_addr, base);
  for (int i = 0; i < ITER; i++) {
    struct io_event ev[64];
    while (syscall(SYS_io_getevents, ctx, 0, 64, ev, NULL) > 0) {}
    for (int j = 0; j < 64; j++) {
      cbs[j] = (struct iocb){.aio_lio_opcode = IOCB_CMD_PREAD, .aio_fildes = (uint32_t)f,
                             .aio_buf = base + 16 * (uint64_t)j, .aio_nbytes = 16};
      ptrs[j] = &cbs[j];
    }
    long accepted = syscall(SYS_io_submit, ctx, 64, ptrs);
    if (accepted != 64) {
      printf("writer stress: io_submit accepted=%ld errno=%d at iteration=%d\n", accepted, errno, i);
      return -1;
    }
    submitted += (int)accepted;
    if (try_connect(FD) == EACCES) denied++;
  }
  printf("writer stress: accepted AIO requests=%d; completion overlap not measured\n", submitted);
  return denied;
}

static int writers_body(void) {
  if (sock_at(FD) != FD || sock_at(DECOY) != DECOY) return 21;
  int f = open("/tmp/forge", O_RDWR | O_CREAT | O_TRUNC, 0600);
  uint64_t pat[2] = {0x4646464646464646ull, 0x4646464646464646ull};
  if (f < 0 || write(f, pat, sizeof(pat)) != sizeof(pat)) return 22;
  aio_context_t ctx = 0;
  if (syscall(SYS_io_setup, 4096, &ctx) != 0) return 23;
  pthread_t t;
  if (pthread_create(&t, NULL, sprayer, NULL) != 0) return 24;
  int denied = writers_loop(ctx, f);
  atomic_store(&race_stop, 1);
  pthread_join(t, NULL);
  struct io_event ev[64];
  while (syscall(SYS_io_getevents, ctx, 0, 64, ev, NULL) > 0) {}
  syscall(SYS_io_destroy, ctx);
  return denied == ITER && unconnected(FD) ? 0 : 25;
}

static int body(void *arg) {
  struct cfg *c = arg;
  // The workload must not inherit the trusted channel.
  close(ctl);
  if (c->mode == M_HIGH) {
    struct rlimit rl = {HIGH_FD + 16, HIGH_FD + 16};
    if (setrlimit(RLIMIT_NOFILE, &rl) != 0) return 77;
  }
  if (c->mode == M_UID) {
    if (sock_at(FD) != FD) return 21;
    if (setresgid(10001, 10001, 10001) || setresuid(10001, 10001, 10001)) return 77;
    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
    install_connect_trace();
    return try_connect(FD) == EACCES && unconnected(FD) ? 0 : 52;
  }
  if (c->mode == M_PIDNS) {
    if (unshare(CLONE_NEWPID) != 0) return 77;
    install_connect_trace();
    pid_t p = fork();
    if (p == 0) _exit(connect_once(M_DENY));
    int st;
    if (waitpid(p, &st, 0) != p) return 40;
    return WIFEXITED(st) ? WEXITSTATUS(st) : 41;
  }
  install_connect_trace();
  switch (c->mode) {
    case M_ERRNO_EPERM: if (stack_filter(SYS_connect, SECCOMP_RET_ERRNO | EPERM)) return 50; break;
    case M_ERRNO_ENOSYS: if (stack_filter(SYS_connect, SECCOMP_RET_ERRNO | ENOSYS)) return 50; break;
    case M_FORGED_TRACE: if (stack_filter(SYS_connect, SECCOMP_RET_TRACE | 12)) return 50; break;
    case M_EXEC: {
      char *argv[] = {"rawevent", "exec-child", NULL};
      char *envp[] = {NULL};
      syscall(SYS_execveat, self_exe, "", argv, envp, AT_EMPTY_PATH);
      return 51;
    }
    default: break;
  }
  if (c->mode == M_RELAY) return relay_body();
  if (c->mode == M_WRITERS) return writers_body();
  if (c->mode >= M_FAULT_ABORT) return fault_body(c);
  return connect_once(c->mode);
}

// ------------------------------------------------------------- tracer ----

struct stats {
  int stops, found, exact, wrong, timeouts, stale_replies, getfd_failed, unexpected, aborted;
  int interrupt_stop, unsafe_restored, accepted;
  int64_t start_ns;
  int reaped_exit;  // exit status of a tid reaped inside a transaction
  int root_exit, relay_conns, relay_eof, replay_rejected, mismatch_rejected;
  uint32_t dropped, other_events;
  long first_x0, first_fd;
};

// Ask the host collector for the raw event matching {tid, nonce}. Returns 1
// and the fd only for a FOUND reply to this exact query before the deadline.
static int ask(pid_t tid, const uint64_t nonce[2], uint32_t flags, uint32_t delay_ms,
               uint64_t *fd, struct stats *s) {
  struct raw_query q = {RAW_QUERY_MAGIC, ++seq, tid, flags, {nonce[0], nonce[1]},
                        QUERY_TIMEOUT_MS, delay_ms};
  must(send(ctl, &q, sizeof(q), MSG_NOSIGNAL) == sizeof(q), "send query");
  double deadline = now_us() + REPLY_DEADLINE_MS * 1000.0;
  for (;;) {
    int left = (int)((deadline - now_us()) / 1000);
    struct pollfd p = {ctl, POLLIN, 0};
    if (left <= 0 || poll(&p, 1, left) <= 0) {
      s->timeouts++;
      return 0;
    }
    struct raw_reply r;
    must(recv(ctl, &r, sizeof(r), MSG_WAITALL) == sizeof(r) && r.magic == RAW_REPLY_MAGIC,
         "reply");
    if (r.seq != q.seq || r.tid != tid) {
      s->stale_replies++;  // late reply to an earlier, already-denied query
      continue;
    }
    s->dropped = r.dropped;
    s->other_events += r.other_events_same_tid;
    if (r.status != RAW_FOUND) {
      s->timeouts++;
      return 0;
    }
    *fd = r.fd;
    s->start_ns = r.start_ns;  // reported only; not validated against the task
    return 1;
  }
}

// Fail closed when the transaction is no longer in a known state: kill the
// tracee's thread group and reap this tid. The substituted registers (and
// nonce) never return to user mode, and the original connect never runs.
// A production tracer must instead preserve queued signals; this spike kills.
static int abort_kill(pid_t tid, int pidfd, struct stats *s, const char *why) {
  s->aborted++;
  printf("abort transaction tid=%d: %s; killing tracee\n", tid, why);
  must(syscall(SYS_pidfd_send_signal, pidfd, SIGKILL, NULL, 0) == 0, "pidfd SIGKILL");
  int status;
  while (waitpid(tid, &status, __WALL) == tid && WIFSTOPPED(status)) {
    // Killed tasks may still report stops; resume them so the kill lands.
    ptrace(PTRACE_CONT, tid, 0, 0);
  }
  s->reaped_exit = WIFEXITED(status) ? WEXITSTATUS(status) : -WTERMSIG(status);
  close(pidfd);
  return 1;
}

// Wait for the next stop of tid and require a syscall stop for gettid.
static int expect_gettid_stop(pid_t tid, int *status) {
  pid_t waited;
  do {
    waited = waitpid(tid, status, __WALL);
  } while (waited < 0 && errno == EINTR);
  must(waited == tid, "wait gettid stop");
  if (!WIFSTOPPED(*status)) return -1;
  regs_t now;
  if (getregs(tid, &now) != 0) return 0;
  return WSTOPSIG(*status) == (SIGTRAP | 0x80) && REG_NR(now) == RAW_SYSNO_GETTID;
}

static int transaction(pid_t tid, struct cfg *c, struct stats *s) {
  regs_t orig, r;
  must(getregs(tid, &orig) == 0, "GETREGSET");
  if (REG_NR(orig) != SYS_connect) {
    must(ptrace(PTRACE_CONT, tid, 0, 0) == 0, "CONT other");
    return 0;
  }
  s->stops++;
  if (s->stops == 1) s->first_x0 = (long)REG_RET(orig);
  // Bind the exact task before substitution; the fd lookup uses this pidfd.
  int pidfd = (int)syscall(SYS_pidfd_open, tid, PIDFD_THREAD);
  if (pidfd < 0) {
    // Still at the seccomp stop: skipping here is the established safe path.
    r = orig;
    REG_RET(r) = (unsigned long long)-EACCES;
    skip_syscall(tid, &r);
    must(ptrace(PTRACE_CONT, tid, 0, 0) == 0, "CONT skipped");
    return 0;
  }
  uint64_t nonce[2];
  must(getrandom(nonce, sizeof(nonce), 0) == sizeof(nonce), "getrandom");
  r = orig;
  r.regs[4] = nonce[0];
  r.regs[5] = nonce[1];
  REG_NR(r) = RAW_SYSNO_GETTID;
  must(setregs(tid, &r) == 0, "SETREGSET substitute");
  // gVisor runs seccomp before the syscall-entry stop, so exactly one entry
  // stop and one exit stop for gettid follow. Nothing else is accepted: an
  // entry stop restored to connect would run the original connect.
  int status;
  must(ptrace(PTRACE_SYSCALL, tid, 0, 0) == 0, "PTRACE_SYSCALL entry");
  int st = expect_gettid_stop(tid, &status);
  if (st < 0) {
    s->reaped_exit = WIFEXITED(status) ? WEXITSTATUS(status) : -WTERMSIG(status);
    return close(pidfd), 1;
  }
  if (!st) return s->unexpected++, abort_kill(tid, pidfd, s, "unexpected stop for entry");
  if (c->mode == M_UNSAFE_ENTRY) {
    // Reproduce the hazard: restoring connect at the entry stop runs it.
    s->unsafe_restored++;
    REG_RET(orig) = (unsigned long long)-EACCES;
    must(setregs(tid, &orig) == 0, "unsafe restore");
    must(ptrace(PTRACE_CONT, tid, 0, 0) == 0, "unsafe resume");
    close(pidfd);
    return 0;
  }
  if (c->mode == M_INTERRUPT) must(ptrace(PTRACE_INTERRUPT, tid, 0, 0) == 0, "PTRACE_INTERRUPT");
  must(ptrace(PTRACE_SYSCALL, tid, 0, 0) == 0, "PTRACE_SYSCALL exit");
  st = expect_gettid_stop(tid, &status);
  if (st < 0) {
    s->reaped_exit = WIFEXITED(status) ? WEXITSTATUS(status) : -WTERMSIG(status);
    return close(pidfd), 1;
  }
  if (c->mode == M_INTERRUPT && !st) s->interrupt_stop = status;
  if (!st) return s->unexpected++, abort_kill(tid, pidfd, s, "unexpected stop for exit");
  if (c->mode == M_FAULT_ABORT) return abort_kill(tid, pidfd, s, "fault hook at exit stop");
  // Proven at the gettid exit stop: the original connect cannot run now.
  long result = -EACCES;
  uint64_t fd = 0;
  uint64_t asked[2] = {nonce[0], nonce[1]};
  if (c->mode == M_MISMATCH) asked[1] ^= 1;
  uint32_t flags = c->mode == M_DROP ? RAW_HOOK_DROP : 0;
  uint32_t delay = c->mode == M_DELAY && s->stops == 1 ? 3 * REPLY_DEADLINE_MS : 0;
  int ok = ask(tid, asked, flags, delay, &fd, s);
  if (c->mode == M_MISMATCH && !ok) s->mismatch_rejected++;
  if (ok && c->mode == M_REPLAY) {
    uint64_t again;
    if (!ask(tid, nonce, 0, 0, &again, s)) s->replay_rejected++;
  }
  if (ok) {
    s->found++;
    if (s->found == 1) s->first_fd = (long)fd;
    int dup = (int)syscall(SYS_pidfd_getfd, pidfd, (int)fd, 0);
    if (dup < 0) {
      s->getfd_failed++;
      result = -EBADF;
    } else {
      struct stat sb;
      if (fd == FD || fd == HIGH_FD) s->exact++;
      else s->wrong++;
      if (fstat(dup, &sb) != 0 || !S_ISSOCK(sb.st_mode)) {
        result = -ENOTSOCK;
      } else if (c->mode == M_RELAY) {
        struct sockaddr_in relay = addr4("127.0.0.1", c->relay_port);
        result = connect(dup, (void *)&relay, sizeof(relay)) == 0 ? 0 : -errno;
      }
      close(dup);
    }
  }
  close(pidfd);
  REG_RET(orig) = (unsigned long long)result;
  must(setregs(tid, &orig) == 0, "restore original regs");
  must(ptrace(PTRACE_CONT, tid, 0, 0) == 0, "resume caller");
  return 0;
}

struct relay {
  int lfd;
  struct stats *s;
};

static void *relay_server(void *arg) {
  struct relay *r = arg;
  struct timeval tv = {5, 0};
  for (int i = 0; i < 50; i++) {
    int c = accept(r->lfd, NULL, NULL);
    if (c < 0) break;
    setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    char buf[32] = {0}, out[40];
    ssize_t n = read(c, buf, sizeof(buf) - 1);
    if (n > 0) {
      int m = snprintf(out, sizeof(out), "ack-%s", buf);
      if (write(c, out, (size_t)m) != m) break;
      r->s->relay_conns++;
      if (read(c, buf, sizeof(buf)) == 0) r->s->relay_eof++;
    }
    close(c);
  }
  return NULL;
}

static struct stats session(struct cfg *c) {
  struct stats s = {0};
  s.root_exit = -999;
  struct relay rel = {-1, &s};
  pthread_t server;
  int fault_lfd = -1;
  if (c->mode >= M_FAULT_ABORT) {
    fault_lfd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    struct sockaddr_in a = addr4("127.0.0.1", 0);
    socklen_t len = sizeof(a);
    must(bind(fault_lfd, (void *)&a, sizeof(a)) == 0 && listen(fault_lfd, 8) == 0, "listen");
    getsockname(fault_lfd, (void *)&a, &len);
    c->relay_port = ntohs(a.sin_port);
  }
  if (c->mode == M_RELAY) {
    rel.lfd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_in a = addr4("127.0.0.1", 0);
    socklen_t len = sizeof(a);
    must(bind(rel.lfd, (void *)&a, sizeof(a)) == 0 && listen(rel.lfd, 64) == 0, "listen");
    getsockname(rel.lfd, (void *)&a, &len);
    c->relay_port = ntohs(a.sin_port);
    pthread_create(&server, NULL, relay_server, &rel);
  }
  long opts = PTRACE_O_TRACESECCOMP | PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL |
              PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACEEXEC;
  pid_t root = spawn_traced(body, c, opts);
  int live = 1, status;
  while (live > 0) {
    pid_t tid = waitpid(-1, &status, __WALL);
    if (tid < 0) break;
    if (!WIFSTOPPED(status)) {
      if (tid == root) s.root_exit = WIFEXITED(status) ? WEXITSTATUS(status) : -WTERMSIG(status);
      live--;
      continue;
    }
    unsigned ev = event_of(status);
    int sig = WSTOPSIG(status);
    if (ev == PTRACE_EVENT_CLONE || ev == PTRACE_EVENT_FORK || ev == PTRACE_EVENT_VFORK) live++;
    if (ev == PTRACE_EVENT_SECCOMP) {
      if (transaction(tid, c, &s)) {
        live--;
        if (tid == root) s.root_exit = s.reaped_exit;
      }
      continue;
    }
    int pass = ev || sig == SIGTRAP || sig == SIGSTOP || sig == SIGCONT ? 0 : sig;
    must(ptrace(PTRACE_CONT, tid, 0, pass) == 0, "CONT");
  }
  if (fault_lfd >= 0) {
    int a;
    while ((a = accept(fault_lfd, NULL, NULL)) >= 0) {
      s.accepted++;
      close(a);
    }
    close(fault_lfd);
  }
  if (c->mode == M_RELAY) {
    shutdown(rel.lfd, SHUT_RDWR);
    close(rel.lfd);
    pthread_join(server, NULL);
  }
  return s;
}

static void report(const char *tag, enum mode mode) {
  struct cfg c = {mode, 0};
  int fds_before = count_fds();
  struct stats s = session(&c);
  int fds_after = count_fds();
  char n[96];
  printf("%s: root_exit=%d stops=%d found=%d exact=%d wrong=%d timeouts=%d stale=%d "
         "getfd_failed=%d unexpected=%d other_gettid_events_same_tid=%u sink_dropped=%u "
         "first_ptrace_x0=%ld first_raw_fd=%ld start_ns=%lld aborted=%d accepted=%d "
         "tracer_fds=%d->%d\n",
         tag, s.root_exit, s.stops, s.found, s.exact, s.wrong, s.timeouts, s.stale_replies,
         s.getfd_failed, s.unexpected, s.other_events, s.dropped, s.first_x0, s.first_fd,
         (long long)s.start_ns, s.aborted, s.accepted,
         fds_before, fds_after);
  if (s.root_exit == 77) {
    skip(tag, "setup needs privileges this run lacks");
    return;
  }
  int clean = s.unexpected == 0 && s.wrong == 0 && fds_before == fds_after;
  int fd_ok = s.stops == 1 && s.found == 1 && s.exact == 1;
  switch (mode) {
    case M_DENY: case M_HIGH: case M_FORGED_TRACE: case M_EXEC: case M_PIDNS: case M_UID:
    case M_SPAM:
      snprintf(n, sizeof(n), "%s.raw_fd_while_x0_hidden", tag);
      result(n, fd_ok && s.first_x0 == -ENOSYS && clean,
             "ptrace x0=%ld; Sentry raw arg1=%ld for the tracer's {tid, nonce}", s.first_x0,
             s.first_fd);
      snprintf(n, sizeof(n), "%s.caller_denied_state_preserved", tag);
      result(n, s.root_exit == 0,
             "EACCES, socket unconnected%s (exit=%d)",
             mode == M_UID ? "" : ", pending SIGUSR1 delivered once", s.root_exit);
      if (mode == M_SPAM) {
        snprintf(n, sizeof(n), "%s.workload_gettid_events_not_matched", tag);
        result(n, s.other_events > 0 && fd_ok,
               "%u workload gettid events from the same tid with chosen x4/x5 were ignored",
               s.other_events);
      }
      break;
    case M_RELAY:
      snprintf(n, sizeof(n), "%s.relay_bidirectional", tag);
      result(n, s.root_exit == 0 && s.exact == 50 && s.relay_conns == 50 && clean,
             "50 connects relayed through the raw-event fd (exit=%d conns=%d exact=%d)",
             s.root_exit, s.relay_conns, s.exact);
      snprintf(n, sizeof(n), "%s.no_leak_eof", tag);
      result(n, s.relay_eof == 50 && fds_before == fds_after,
             "peer EOF on every workload close (%d/50); tracee fd count unchanged; tracer fds "
             "%d->%d", s.relay_eof, fds_before, fds_after);
      break;
    case M_ERRNO_EPERM: case M_ERRNO_ENOSYS:
      snprintf(n, sizeof(n), "%s.workload_errno_wins", tag);
      result(n, s.root_exit == 0 && s.stops == 0,
             "workload ERRNO(%s) outranks TRACE; no stop, no substitution (exit=%d stops=%d)",
             mode == M_ERRNO_EPERM ? "EPERM" : "ENOSYS", s.root_exit, s.stops);
      break;
    case M_DROP:
      snprintf(n, sizeof(n), "%s.missing_event_fails_closed", tag);
      result(n, s.root_exit == 0 && s.found == 0 && s.timeouts == 1,
             "collector discarded the matching event; tracer denied, socket unconnected "
             "(exit=%d timeouts=%d)", s.root_exit, s.timeouts);
      break;
    case M_DELAY:
      snprintf(n, sizeof(n), "%s.late_reply_fails_closed", tag);
      result(n, s.root_exit == 0 && s.stops == 2 && s.timeouts == 1 && s.found == 1 &&
                    s.stale_replies == 1,
             "first reply arrived after the deadline: denied; stale reply discarded by seq; "
             "next transaction matched (exit=%d stale=%d)", s.root_exit, s.stale_replies);
      break;
    case M_REPLAY:
      snprintf(n, sizeof(n), "%s.replayed_query_rejected", tag);
      result(n, s.root_exit == 0 && s.replay_rejected == 1,
             "second query for a used {tid, nonce} found nothing (exit=%d)", s.root_exit);
      break;
    case M_MISMATCH:
      snprintf(n, sizeof(n), "%s.mismatched_nonce_fails_closed", tag);
      result(n, s.root_exit == 0 && s.found == 0 && s.mismatch_rejected == 1,
             "query with a nonce differing in one bit found nothing; denied (exit=%d)",
             s.root_exit);
      break;
    case M_FAULT_ABORT:
      snprintf(n, sizeof(n), "%s.abort_kills_never_runs_connect", tag);
      result(n, s.aborted == 1 && s.root_exit == -SIGKILL && s.accepted == 0,
             "abort at a stop the tracer did not expect: tracee killed (exit=%d), loopback "
             "listener accepted %d", s.root_exit, s.accepted);
      break;
    case M_INTERRUPT:
      snprintf(n, sizeof(n), "%s.interrupt_never_runs_connect", tag);
      result(n, s.accepted == 0 && (s.root_exit == 0 || (s.aborted == 1 && s.root_exit == -SIGKILL)),
             "PTRACE_INTERRUPT between entry and exit: next stop %s; exit=%d accepted=%d",
             s.interrupt_stop ? "was not the gettid exit (aborted)" : "was the gettid exit",
             s.root_exit, s.accepted);
      break;
    case M_UNSAFE_ENTRY:
      snprintf(n, sizeof(n), "%s.entry_restore_runs_connect_reproduced", tag);
      result(n, s.unsafe_restored == 1 && s.accepted == 1,
             "restoring connect at the gettid ENTRY stop ran the original connect: listener "
             "accepted %d (tracee exit=%d). Never restore before the exit stop", s.accepted,
             s.root_exit);
      break;
    case M_WRITERS:
      snprintf(n, sizeof(n), "%s.no_freeze_writers_irrelevant", tag);
      result(n, s.root_exit == 0 && s.exact == ITER && clean,
             "private-memory writer + accepted AIO submissions, no freeze: exact=%d/%d wrong=%d "
             "(exit=%d)", s.exact, ITER, s.wrong, s.root_exit);
      break;
  }
}

static int open_channel(const char *path) {
  int l = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  struct sockaddr_un a = {.sun_family = AF_UNIX};
  snprintf(a.sun_path, sizeof(a.sun_path), "%s", path);
  unlink(path);
  must(l >= 0 && bind(l, (void *)&a, sizeof(a)) == 0 && listen(l, 1) == 0, "channel listen");
  struct pollfd p = {l, POLLIN, 0};
  must(poll(&p, 1, 30000) == 1, "host collector connect");
  int c = accept4(l, NULL, NULL, SOCK_CLOEXEC);
  must(c >= 0, "accept collector");
  // One trusted peer only: drop the listener and its path before any
  // workload exists.
  close(l);
  unlink(path);
  return c;
}

int main(int argc, char **argv) {
  setvbuf(stdout, NULL, _IOLBF, 0);
  if (argc > 1 && strcmp(argv[1], "exec-child") == 0) return connect_once(M_DENY);
  const char *chan = getenv("GV_RAW_CHANNEL");
  if (!chan) {
    skip("raw", "needs run.py raw: runsc SecCheck remote sink + host collector");
    return finish();
  }
  ctl = open_channel(chan);
  printf("tracer: host collector connected; channel path removed\n");
  // Readiness: the handshake alone does not prove the trace session exists
  // (the Sentry only warns on a bad session). Require one full round trip:
  // the tracer's own gettid with a sentinel arg1 and a fresh nonce.
  {
    struct stats rs = {0};
    uint64_t nonce[2], fd = 0;
    must(getrandom(nonce, sizeof(nonce), 0) == sizeof(nonce), "getrandom");
    syscall(SYS_gettid, 0x5eedull, 0, 0, 0, nonce[0], nonce[1]);
    int ok = ask((pid_t)syscall(SYS_gettid), nonce, 0, 0, &fd, &rs) && fd == 0x5eed;
    result("raw.readiness_token_roundtrip", ok,
           "own gettid(arg1=0x5eed, nonce) returned through Sentry -> collector -> tracer");
    if (!ok) return finish();  // no workload without a working event path
  }
  self_exe = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
  report("raw.fd77", M_DENY);
  report("raw.fd70000", M_HIGH);
  report("raw.relay", M_RELAY);
  report("raw.errno_eperm", M_ERRNO_EPERM);
  report("raw.errno_enosys", M_ERRNO_ENOSYS);
  report("raw.forged_trace_data", M_FORGED_TRACE);
  report("raw.workload_gettid_spam", M_SPAM);
  report("raw.drop", M_DROP);
  report("raw.delay", M_DELAY);
  report("raw.replay", M_REPLAY);
  report("raw.mismatch", M_MISMATCH);
  report("raw.after_exec", M_EXEC);
  report("raw.pidns_child", M_PIDNS);
  report("raw.uid10001", M_UID);
  report("raw.writers", M_WRITERS);
  report("raw.fault_abort", M_FAULT_ABORT);
  report("raw.fault_interrupt", M_INTERRUPT);
  report("raw.unsafe_entry_restore", M_UNSAFE_ENTRY);
  return finish();
}
