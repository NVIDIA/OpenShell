// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Candidate C: fstat substitution at the connect SECCOMP_RET_TRACE stop.
// arm64 gVisor hides arg0 (x0 = -ENOSYS) but still passes the hidden OrigR0
// to whatever syscall runs after the stop. The tracer swaps the syscall
// number to fstat and points x1 at scratch memory below the saved SP. fstat
// therefore stats the original fd. The tracer reads st_dev/st_ino, restores
// the scratch bytes, finds the fd in /proc/<tid>/fd whose pidfd_getfd dup has
// that identity, decides, then restores the original registers with a result.
// The tracer never reads arg0, never receives the fd number from the
// workload, creates no tracee fd, and writes no executable memory.
//
// The scratch read is only meaningful if nothing else can write the scratch
// between fstat and the read. The race variants show the forgery without a
// freeze and test an all-traced-task freeze. They do not qualify AIO,
// io_uring, untraced writers, or shared mappings.
#include "gv.h"

#include <dirent.h>
#include <linux/aio_abi.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <sys/resource.h>

#define FD 77
#define DECOY 78
#define ALIAS 79
#define HIGH_FD 70000
#define MAX_TASKS 64
#define ITER 200

#ifndef PTRACE_GET_SYSCALL_INFO
#define PTRACE_GET_SYSCALL_INFO 0x420e
#endif

enum mode {
  M_DENY, M_HIGH, M_RELAY, M_ERRNO_EPERM, M_ERRNO_ENOSYS, M_FORGED_TRACE, M_FSTAT_FILTER,
  M_EXEC, M_PIDNS, M_UID, M_RACE, M_AIO
};

struct cfg {
  enum mode mode;
  int freeze;
  int relay_port;
};

static int self_exe = -1;

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

static int deny_connect(int fd) {
  struct sockaddr_in dst = addr4("203.0.113.9", 443);
  errno = 0;
  int rc = connect(fd, (void *)&dst, sizeof(dst));
  return rc == -1 ? errno : 0;
}

static volatile sig_atomic_t usr1_seen;
static void on_usr1(int sig) { (void)sig; usr1_seen++; }

// Single-connect body used by most modes; returns 0 if the tracee saw the
// expected outcome.
static int connect_once(enum mode mode) {
  int fd = mode == M_HIGH ? HIGH_FD : FD;
  if (sock_at(fd) != fd || sock_at(DECOY) != DECOY || dup2(fd, ALIAS) != ALIAS) return 21;
  // A signal that is pending across the substitution must still arrive.
  sigset_t s;
  sigemptyset(&s);
  sigaddset(&s, SIGUSR1);
  signal(SIGUSR1, on_usr1);
  sigprocmask(SIG_BLOCK, &s, NULL);
  raise(SIGUSR1);
  int err = deny_connect(fd);
  sigprocmask(SIG_UNBLOCK, &s, NULL);
  struct sockaddr_in peer;
  socklen_t len = sizeof(peer);
  int connected = getpeername(fd, (void *)&peer, &len) == 0;
  printf("tracee mode=%d connect errno=%d connected=%d usr1_seen=%d\n", mode, err, connected,
         (int)usr1_seen);
  fflush(stdout);
  int want = mode == M_ERRNO_EPERM ? EPERM : mode == M_ERRNO_ENOSYS ? ENOSYS : EACCES;
  if (err != want) return 30 + (err & 0x3f);
  return connected || usr1_seen != 1 ? 22 : 0;
}

static int relay_body(struct cfg *c) {
  (void)c;
  int before = count_fds();
  for (int i = 0; i < 50; i++) {
    if (sock_at(FD) != FD) return 21;
    struct sockaddr_in dst = addr4("203.0.113.9", 443);
    if (connect(FD, (void *)&dst, sizeof(dst)) != 0) return 22;
    char msg[32], reply[32] = {0};
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

// Race: the main thread connects ITER times on FD with a decoy socket at
// DECOY. A sibling thread continuously writes the decoy's dev/ino over the
// region where the tracer puts its scratch buffer.
static _Atomic uintptr_t race_sp;
static atomic_int race_stop;
static struct stat decoy_st;

static void *sprayer(void *arg) {
  (void)arg;
  while (!atomic_load(&race_stop)) {
    uintptr_t sp = atomic_load(&race_sp);
    if (!sp) continue;
    uintptr_t base = ((sp - 2048) & ~(uintptr_t)15) - 512;
    for (uintptr_t p = base; p < base + 1024; p += 16) {
      volatile uint64_t *w = (volatile uint64_t *)p;
      w[0] = decoy_st.st_dev;
      w[1] = decoy_st.st_ino;
    }
  }
  return NULL;
}

static __attribute__((noinline)) int race_loop(void) {
  int denied = 0;
  atomic_store(&race_sp, (uintptr_t)__builtin_frame_address(0));
  for (int i = 0; i < ITER; i++) {
    struct sockaddr_in dst = addr4("203.0.113.9", 443);
    if (connect(FD, (void *)&dst, sizeof(dst)) == -1 && errno == EACCES) denied++;
  }
  return denied;
}

static int race_body(void) {
  if (sock_at(FD) != FD || sock_at(DECOY) != DECOY) return 21;
  if (fstat(DECOY, &decoy_st) != 0) return 22;
  pthread_t t;
  if (pthread_create(&t, NULL, sprayer, NULL) != 0) return 23;
  while (!atomic_load(&race_sp)) atomic_store(&race_sp, (uintptr_t)__builtin_frame_address(0));
  int denied = race_loop();
  atomic_store(&race_stop, 1);
  pthread_join(t, NULL);
  return denied == ITER ? 0 : 24;
}

// Async writer: before each connect, queue AIO preads of the decoy dev/ino
// from a file onto the scratch region. Kernel-side completion does not need
// any workload task to run, so a ptrace freeze does not stop it.
static int aio_body(void) {
  if (sock_at(FD) != FD || sock_at(DECOY) != DECOY) return 21;
  if (fstat(DECOY, &decoy_st) != 0) return 22;
  int f = open("/tmp/forge", O_RDWR | O_CREAT | O_TRUNC, 0600);
  uint64_t pat[2] = {decoy_st.st_dev, decoy_st.st_ino};
  if (f < 0 || write(f, pat, sizeof(pat)) != sizeof(pat)) return 23;
  aio_context_t ctx = 0;
  if (syscall(SYS_io_setup, 4096, &ctx) != 0) return 77;
  static struct iocb cbs[64];
  struct iocb *ptrs[64];
  int denied = 0;
  for (int i = 0; i < ITER; i++) {
    uintptr_t base = (((uintptr_t)__builtin_frame_address(0) - 2048) & ~(uintptr_t)15) - 512;
    struct io_event ev[64];
    while (syscall(SYS_io_getevents, ctx, 0, 64, ev, NULL) > 0) {}
    for (int j = 0; j < 64; j++) {
      cbs[j] = (struct iocb){.aio_lio_opcode = IOCB_CMD_PREAD, .aio_fildes = (uint32_t)f,
                             .aio_buf = base + 16 * (uint64_t)j, .aio_nbytes = 16};
      ptrs[j] = &cbs[j];
    }
    syscall(SYS_io_submit, ctx, 64, ptrs);
    struct sockaddr_in dst = addr4("203.0.113.9", 443);
    if (connect(FD, (void *)&dst, sizeof(dst)) == -1 && errno == EACCES) denied++;
  }
  struct io_event ev[64];
  while (syscall(SYS_io_getevents, ctx, 0, 64, ev, NULL) > 0) {}
  syscall(SYS_io_destroy, ctx);
  return denied == ITER ? 0 : 24;
}

static int body(void *arg) {
  struct cfg *c = arg;
  if (c->mode == M_HIGH) {
    struct rlimit rl = {HIGH_FD + 16, HIGH_FD + 16};
    if (setrlimit(RLIMIT_NOFILE, &rl) != 0) return 77;  // reported as SKIP
  }
  if (c->mode == M_UID) {
    if (sock_at(FD) != FD) return 21;
    if (setresgid(10001, 10001, 10001) || setresuid(10001, 10001, 10001)) return 77;
    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
  }
  if (c->mode == M_PIDNS) {
    if (unshare(CLONE_NEWPID | (geteuid() ? CLONE_NEWUSER : 0)) != 0) return 77;
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
    case M_FSTAT_FILTER: if (stack_filter(SYS_fstat, SECCOMP_RET_ERRNO | ENOSYS)) return 50; break;
    case M_EXEC: {
      char *argv[] = {"snapshot", "exec-child", NULL};
      char *envp[] = {NULL};
      syscall(SYS_execveat, self_exe, "", argv, envp, AT_EMPTY_PATH);
      return 51;
    }
    default: break;
  }
  if (c->mode == M_RELAY) return relay_body(c);
  if (c->mode == M_RACE) return race_body();
  if (c->mode == M_AIO) return aio_body();
  if (c->mode == M_UID) return deny_connect(FD) == EACCES ? 0 : 52;
  return connect_once(c->mode);
}

// ---------------------------------------------------------------- tracer --

struct task {
  pid_t tid;
  int deferred, status;  // stopped with a not-yet-handled waitpid status
};

static struct task tasks[MAX_TASKS];
static int ntasks;

static struct task *task_of(pid_t tid) {
  for (int i = 0; i < ntasks; i++)
    if (tasks[i].tid == tid) return &tasks[i];
  must(ntasks < MAX_TASKS, "task table");
  tasks[ntasks] = (struct task){tid, 0, 0};
  return &tasks[ntasks++];
}

static void forget(pid_t tid) {
  for (int i = 0; i < ntasks; i++)
    if (tasks[i].tid == tid) tasks[i] = tasks[--ntasks];
}

struct stats {
  int stops, captured, exact, forged, alias_only, no_private, no_match, subst_failed, linux_info;
  int root_exit, frozen_tasks;
  int relay_eof, relay_conns;
};

static long set_sysno(pid_t tid, regs_t *r, long nr) {
  REG_NR(*r) = (unsigned long long)nr;
  long rc = setregs(tid, r);
#ifdef __aarch64__
  int n = (int)nr;
  struct iovec io = {&n, sizeof(n)};
  ptrace(PTRACE_SETREGSET, tid, (void *)0x404 /* NT_ARM_SYSTEM_CALL */, &io);
#endif
  return rc;
}

static unsigned long reg_sp(regs_t *r) {
#ifdef __aarch64__
  return r->sp;
#else
  return r->rsp;
#endif
}

static void set_arg1(regs_t *r, unsigned long v) {
#ifdef __aarch64__
  r->regs[1] = v;
#else
  r->rsi = v;
#endif
}

// The scratch range must lie in one private, writable, non-shared mapping.
static int private_rw(pid_t tid, uintptr_t lo, uintptr_t hi, char *line_out, size_t size) {
  char path[64], line[512];
  snprintf(path, sizeof(path), "/proc/%d/maps", tid);
  FILE *f = fopen(path, "r");
  if (!f) return 0;
  int ok = 0;
  while (fgets(line, sizeof(line), f)) {
    unsigned long a, b;
    char perms[8];
    if (sscanf(line, "%lx-%lx %7s", &a, &b, perms) != 3) continue;
    if (lo >= a && hi <= b) {
      ok = perms[0] == 'r' && perms[1] == 'w' && perms[3] == 'p';
      snprintf(line_out, size, "%.200s", line);
      line_out[strcspn(line_out, "\n")] = 0;
      break;
    }
  }
  fclose(f);
  return ok;
}

static int mem_rw(pid_t tid, void *buf, uintptr_t addr, size_t n, int write) {
  struct iovec local = {buf, n}, remote = {(void *)addr, n};
  if (!write) return process_vm_readv(tid, &local, 1, &remote, 1, 0) == (ssize_t)n;
  for (size_t i = 0; i < n; i += sizeof(long)) {
    long w;
    memcpy(&w, (char *)buf + i, sizeof(w));
    if (ptrace(PTRACE_POKEDATA, tid, (void *)(addr + i), (void *)w) != 0) return 0;
  }
  return 1;
}

// Find the fds in tid's table whose trusted dup has dev/ino. Returns a dup
// of the first match (or -1) and fills the match list.
static int resolve(pid_t tid, const struct stat *want, int *matches, int max, int *nmatch) {
  char dir[64];
  snprintf(dir, sizeof(dir), "/proc/%d/fd", tid);
  int pidfd = (int)syscall(SYS_pidfd_open, tid, PIDFD_THREAD);
  DIR *d = opendir(dir);
  int found = -1;
  *nmatch = 0;
  struct dirent *e;
  while (pidfd >= 0 && d && (e = readdir(d))) {
    char *end;
    long n = strtol(e->d_name, &end, 10);
    if (*end || e->d_name[0] == '.') continue;
    int dup = (int)syscall(SYS_pidfd_getfd, pidfd, (int)n, 0);
    struct stat got;
    if (dup < 0) continue;
    if (fstat(dup, &got) == 0 && got.st_dev == want->st_dev && got.st_ino == want->st_ino) {
      if (*nmatch < max) matches[*nmatch] = (int)n;
      (*nmatch)++;
      if (found < 0) {
        found = dup;
        continue;
      }
    }
    close(dup);
  }
  if (d) closedir(d);
  if (pidfd >= 0) close(pidfd);
  return found;
}

static void freeze_others(pid_t self, struct stats *s) {
  for (int i = 0; i < ntasks; i++) {
    struct task *t = &tasks[i];
    if (t->tid == self || t->deferred) continue;
    must(ptrace(PTRACE_INTERRUPT, t->tid, 0, 0) == 0, "PTRACE_INTERRUPT");
    int st;
    must(waitpid(t->tid, &st, __WALL) == t->tid, "wait frozen task");
    if (!WIFSTOPPED(st)) {
      forget(t->tid);
      i--;
      continue;
    }
    t->deferred = 1;
    t->status = st;
    s->frozen_tasks++;
  }
}

// Resume tasks that only stopped for our interrupt; keep real events queued.
static void thaw(void) {
  for (int i = 0; i < ntasks; i++) {
    struct task *t = &tasks[i];
    if (t->deferred && event_of(t->status) == PTRACE_EVENT_STOP && WSTOPSIG(t->status) == SIGTRAP) {
      t->deferred = 0;
      must(ptrace(PTRACE_CONT, t->tid, 0, 0) == 0, "thaw");
    }
  }
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
      // EOF must arrive once the workload closes: no live dup retained.
      if (read(c, buf, sizeof(buf)) == 0) r->s->relay_eof++;
    }
    close(c);
  }
  return NULL;
}

// One mediated connect: called at the seccomp stop of tid.
static int transaction(pid_t tid, struct cfg *c, struct stats *s) {
  regs_t orig, r;
  must(getregs(tid, &orig) == 0, "GETREGSET");
  s->stops++;
  if (REG_NR(orig) != SYS_connect) {
    must(ptrace(PTRACE_CONT, tid, 0, 0) == 0, "CONT other");
    return 0;
  }
  if (c->freeze) freeze_others(tid, s);
  uintptr_t scratch = (reg_sp(&orig) - 2048) & ~(uintptr_t)15;
  unsigned char saved[sizeof(struct stat)];
  struct stat st;
  char maps[256] = "";
  long result = -EACCES;
  int dup = -1;
  if (!private_rw(tid, scratch, scratch + sizeof(st), maps, sizeof(maps)) ||
      !mem_rw(tid, saved, scratch, sizeof(saved), 0)) {
    s->no_private++;
    printf("fail closed: scratch %#lx not in private rw mapping (%s)\n", (unsigned long)scratch, maps);
    r = orig;
    REG_RET(r) = (unsigned long long)-EACCES;
    skip_syscall(tid, &r);
    must(ptrace(PTRACE_CONT, tid, 0, 0) == 0, "CONT denied");
    if (c->freeze) thaw();
    return 0;
  }
  r = orig;
  set_arg1(&r, scratch);
  must(set_sysno(tid, &r, SYS_fstat) == 0, "substitute fstat");
  // Explicit stop phases: Linux reports the op; gVisor runs seccomp before
  // the syscall-entry stop (task_syscall.go doSyscall -> doSyscallEnter), so
  // an entry stop precedes the exit stop.
  int status, exited = 0, phase = 0;
  long ret = 0;
  for (;;) {
    must(ptrace(PTRACE_SYSCALL, tid, 0, 0) == 0, "PTRACE_SYSCALL");
    must(waitpid(tid, &status, __WALL) == tid, "wait substitution");
    if (!WIFSTOPPED(status)) { exited = 1; break; }
    if (WSTOPSIG(status) != (SIGTRAP | 0x80)) {
      printf("unexpected stop %#x during substitution\n", status);
      continue;  // a signal stop here would be a gate failure; logged above
    }
    unsigned char info[88];
    long n = ptrace(PTRACE_GET_SYSCALL_INFO, tid, (void *)sizeof(info), info);
    regs_t now;
    must(getregs(tid, &now) == 0, "regs at substitution stop");
    int is_exit;
    if (n > 0) {
      s->linux_info = 1;
      is_exit = info[0] == 2 /* PTRACE_SYSCALL_INFO_EXIT */;
    } else {
      is_exit = phase++ % 2;  // gVisor: entry then exit
      if (!is_exit && REG_NR(now) != SYS_fstat) s->subst_failed++;
    }
    if (is_exit) {
      ret = (long)REG_RET(now);
      break;
    }
  }
  if (exited) return 1;
  if (ret == 0 && mem_rw(tid, &st, scratch, sizeof(st), 0)) {
    s->captured++;
    int matches[8], nm;
    dup = resolve(tid, &st, matches, 8, &nm);
    int exact = 0, decoy = 0;
    for (int i = 0; i < nm && i < 8; i++) {
      exact |= matches[i] == FD || matches[i] == HIGH_FD;
      decoy |= matches[i] == DECOY;
    }
    if (decoy) s->forged++;
    else if (exact) s->exact++;
    else if (nm) s->alias_only++;
    else s->no_match++;
    if (s->stops <= 2 || decoy)
      printf("captured dev=%lu ino=%lu mode=%o matches=%d first=%d%s maps=%s\n",
             (unsigned long)st.st_dev, (unsigned long)st.st_ino, st.st_mode, nm,
             nm ? matches[0] : -1, decoy ? " FORGED(decoy)" : "", maps);
  } else {
    s->subst_failed++;
    printf("substituted fstat returned %ld\n", ret);
  }
  must(mem_rw(tid, saved, scratch, sizeof(saved), 1), "restore scratch");
  if (dup >= 0 && c->mode == M_RELAY) {
    struct sockaddr_in relay = addr4("127.0.0.1", c->relay_port);
    result = connect(dup, (void *)&relay, sizeof(relay)) == 0 ? 0 : -errno;
  }
  if (dup >= 0) close(dup);
  REG_RET(orig) = (unsigned long long)result;
  must(setregs(tid, &orig) == 0, "restore original regs");
  if (c->freeze) thaw();
  must(ptrace(PTRACE_CONT, tid, 0, 0) == 0, "resume caller");
  return 0;
}

static void handle(pid_t tid, int status, struct cfg *c, struct stats *s, pid_t root) {
  if (!WIFSTOPPED(status)) {
    if (tid == root) s->root_exit = WIFEXITED(status) ? WEXITSTATUS(status) : -WTERMSIG(status);
    forget(tid);
    return;
  }
  task_of(tid);
  unsigned ev = event_of(status);
  int sig = WSTOPSIG(status);
  if (ev == PTRACE_EVENT_SECCOMP) {
    if (transaction(tid, c, s)) forget(tid);
    return;
  }
  int pass = ev || sig == SIGTRAP || sig == SIGSTOP || sig == SIGCONT ? 0 : sig;
  must(ptrace(PTRACE_CONT, tid, 0, pass) == 0, "CONT");
}

static struct stats session(struct cfg *c) {
  struct stats s = {0};
  s.root_exit = -999;
  ntasks = 0;
  struct relay rel = {-1, &s};
  pthread_t server;
  if (c->mode == M_RELAY) {
    rel.lfd = socket(AF_INET, SOCK_STREAM, 0);
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
  task_of(root);
  while (ntasks > 0) {
    int i, status;
    for (i = 0; i < ntasks && !tasks[i].deferred; i++) {}
    if (i < ntasks) {
      tasks[i].deferred = 0;
      handle(tasks[i].tid, tasks[i].status, c, &s, root);
      continue;
    }
    pid_t tid = waitpid(-1, &status, __WALL);
    if (tid < 0) break;
    handle(tid, status, c, &s, root);
  }
  if (c->mode == M_RELAY) {
    shutdown(rel.lfd, SHUT_RDWR);
    close(rel.lfd);
    pthread_join(server, NULL);
  }
  return s;
}

static void report(const char *tag, enum mode mode, int freeze) {
  struct cfg c = {mode, freeze, 0};
  int fds_before = count_fds();
  struct stats s = session(&c);
  int fds_after = count_fds();
  char n[96];
  printf("%s: root_exit=%d stops=%d captured=%d exact=%d forged=%d alias_only=%d no_match=%d "
         "no_private=%d subst_failed=%d frozen_tasks=%d linux_syscall_info=%d tracer_fds=%d->%d\n",
         tag, s.root_exit, s.stops, s.captured, s.exact, s.forged, s.alias_only, s.no_match,
         s.no_private, s.subst_failed, s.frozen_tasks, s.linux_info, fds_before, fds_after);
  if (s.root_exit == 77) {
    snprintf(n, sizeof(n), "%s", tag);
    skip(n, "setup needs privileges this host run lacks");
    return;
  }
  int one_exact = s.stops == 1 && s.exact == 1 && s.forged == 0;
  switch (mode) {
    case M_DENY: case M_HIGH: case M_EXEC: case M_PIDNS: case M_UID: case M_FORGED_TRACE:
      snprintf(n, sizeof(n), "%s.identity_without_arg0", tag);
      result(n, one_exact, "fstat substitution resolved the connect fd by dev/ino");
      snprintf(n, sizeof(n), "%s.caller_denied_state_preserved", tag);
      result(n, s.root_exit == 0 && fds_before == fds_after,
             "EACCES, %sno tracer fd leak (exit=%d)",
             mode == M_UID ? "" : "socket unconnected, pending SIGUSR1 delivered once, ",
             s.root_exit);
      break;
    case M_RELAY:
      snprintf(n, sizeof(n), "%s.relay_bidirectional", tag);
      result(n, s.root_exit == 0 && s.exact == 50 && s.relay_conns == 50,
             "50 connects relayed through the discovered object (exit=%d conns=%d exact=%d)",
             s.root_exit, s.relay_conns, s.exact);
      snprintf(n, sizeof(n), "%s.no_leak_eof", tag);
      result(n, s.relay_eof == 50 && fds_before == fds_after,
             "peer EOF on every workload close (%d/50); tracee fd count unchanged; tracer fds %d->%d",
             s.relay_eof, fds_before, fds_after);
      break;
    case M_ERRNO_EPERM: case M_ERRNO_ENOSYS:
      snprintf(n, sizeof(n), "%s.workload_errno_wins", tag);
      result(n, s.root_exit == 0 && s.stops == 0,
             "workload ERRNO(%s) filter outranks the TRACE filter; no stop (exit=%d stops=%d)",
             mode == M_ERRNO_EPERM ? "EPERM" : "ENOSYS", s.root_exit, s.stops);
      break;
    case M_FSTAT_FILTER:
      snprintf(n, sizeof(n), "%s.fail_closed", tag);
      result(n, s.root_exit == 0 && s.forged == 0,
             "workload fstat->ERRNO(ENOSYS) filter: captured=%d subst_failed=%d (exit=%d)",
             s.captured, s.subst_failed, s.root_exit);
      printf("%s observed: substituted fstat %s the workload's fstat filter\n", tag,
             s.captured ? "was NOT rechecked against" : "was rechecked and denied by");
      break;
    case M_AIO:
      snprintf(n, sizeof(n), "%s.frozen_async_writer", tag);
      if (s.forged > 0) {
        result(n, 0, "AIO preads landed the decoy identity in %d/%d frozen captures",
               s.forged, s.captured);
      } else {
        char why[160];
        snprintf(why, sizeof(why), "not reproduced (0/%d): AIO submission success and "
                 "completion overlap were not established; no safety claim",
                 s.captured);
        skip(n, why);
      }
      break;
    case M_RACE:
      if (!freeze) {
        snprintf(n, sizeof(n), "%s.unfrozen_scratch_forgery_reproduced", tag);
        result(n, s.forged > 0,
               "sibling writer substituted the decoy identity in %d/%d captures", s.forged,
               s.captured);
      } else {
        snprintf(n, sizeof(n), "%s.frozen_no_forgery", tag);
        result(n, s.root_exit == 0 && s.forged == 0 && s.exact == ITER,
               "all traced tasks interrupted: exact=%d/%d forged=%d frozen=%d (exit=%d)", s.exact,
               ITER, s.forged, s.frozen_tasks, s.root_exit);
      }
      break;
  }
}

int main(int argc, char **argv) {
  setvbuf(stdout, NULL, _IOLBF, 0);
  if (argc > 1 && strcmp(argv[1], "exec-child") == 0) return connect_once(M_DENY);
  self_exe = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
  report("snap.fd77", M_DENY, 0);
  report("snap.fd70000", M_HIGH, 0);
  report("snap.relay", M_RELAY, 0);
  report("snap.errno_eperm", M_ERRNO_EPERM, 0);
  report("snap.errno_enosys", M_ERRNO_ENOSYS, 0);
  report("snap.forged_trace_data", M_FORGED_TRACE, 0);
  report("snap.fstat_filter", M_FSTAT_FILTER, 0);
  report("snap.after_exec", M_EXEC, 0);
  report("snap.pidns_child", M_PIDNS, 0);
  report("snap.uid10001", M_UID, 0);
  report("snap.race", M_RACE, 0);
  report("snap.race", M_RACE, 1);
  report("snap.aio", M_AIO, 1);
  return finish();
}
