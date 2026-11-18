// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Gates 1-2: fail-closed lifecycle and descendant coverage.
// - notracer: SECCOMP_RET_TRACE with no tracer returns ENOSYS.
// - cover: thread, fork, vfork+exec, non-leader exec, and a child in new
//   user+PID namespaces all stop for connect; the tracer resolves exe and
//   NSpid from its own PID namespace.
// - exitkill: SIGKILL of the tracer kills every descendant, including idle
//   ones, a thread, and both tasks of a nested PID namespace.
#include "tracer.h"
#include <pthread.h>
#include <dirent.h>
#include <sched.h>

#define BASH_CONNECT "exec 3<>/dev/tcp/203.0.113.9/80"

static int try_connect(void) {
  int s = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in a = addr4("203.0.113.9", 80);
  int rc = connect(s, (void *)&a, sizeof(a));
  int err = errno;
  close(s);
  return rc == -1 ? err : 0;
}

static int notracer_body(void) {
  int nr = SYS_connect;
  install_trace_filter(&nr, 1, 0);
  return try_connect();
}

static void *thread_connect(void *out) {
  *(int *)out = try_connect();
  return NULL;
}

static void *thread_exec(void *unused) {
  execl("/bin/bash", "bash", "-c", BASH_CONNECT, (char *)NULL);
  return unused;
}

static int exit_code(pid_t pid) {
  int status;
  if (waitpid(pid, &status, 0) != pid) return -1;
  return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
}

// Returns a bitmask of failed steps.
static int cover_body(void *unused __attribute__((unused))) {
  install_probe_filter();
  int failed = 0, err = 0;
  pthread_t t;
  pthread_create(&t, NULL, thread_connect, &err);
  pthread_join(t, NULL);
  if (err != EACCES) failed |= 1;
  pid_t c = fork();
  if (c == 0) _exit(try_connect());
  if (exit_code(c) != EACCES) failed |= 2;
  c = vfork();
  if (c == 0) {
    execl("/bin/bash", "bash", "-c", BASH_CONNECT, (char *)NULL);
    _exit(127);
  }
  if (exit_code(c) == 0) failed |= 4;  // bash must fail to open the socket
  c = fork();
  if (c == 0) {
    pthread_t e;
    pthread_create(&e, NULL, thread_exec, NULL);
    pause();
  }
  if (exit_code(c) == 0) failed |= 32;
  // Last: after the namespace init exits, this process cannot fork again.
  if (unshare(CLONE_NEWUSER | CLONE_NEWPID) == 0) {
    c = fork();
    if (c == 0) _exit(getpid() == 1 ? try_connect() : 99);
    if (exit_code(c) != EACCES) failed |= 8;
  } else {
    failed |= 16;  // reported as a skip by the tracer side
  }
  return failed;
}

struct seen {
  int connects, bash, nested_init, nspid_present;
  pid_t tids[32];
  int distinct;
};

static long deny_connect(struct stop *s, int *emulated, void *ctx) {
  struct seen *seen = ctx;
  if (s->nr != SYS_connect) return 0;
  char exe[256], path[64], status[4096] = {0}, *nspid;
  exe_of(s->tid, exe, sizeof(exe));
  snprintf(path, sizeof(path), "/proc/%d/status", s->tid);
  int fd = open(path, O_RDONLY);
  if (fd >= 0) {
    ssize_t n = read(fd, status, sizeof(status) - 1);
    (void)n;
    close(fd);
  }
  nspid = strstr(status, "NSpid:");
  char *end = nspid ? strchr(nspid, '\n') : NULL;
  if (end) *end = 0;
  printf("connect stop tid=%d exe=%s %s fd=%lu\n", s->tid, exe, nspid ? nspid : "NSpid:?",
         s->arg0);
  seen->connects++;
  seen->nspid_present += nspid != NULL;
  int known = 0;
  for (int i = 0; i < seen->distinct; i++) known |= seen->tids[i] == s->tid;
  if (!known && seen->distinct < 32) {
    seen->tids[seen->distinct++] = s->tid;
    if (strstr(exe, "bash")) seen->bash++;
  }
  // NSpid lists the tid in the tracer's namespace first and 1 last for a
  // nested PID namespace init.
  if (nspid && end && end - nspid > 2 && strcmp(end - 2, "\t1") == 0) seen->nested_init++;
  *emulated = 1;
  return -EACCES;
}

static void cover(void) {
  struct seen seen = {0};
  struct trace_stats st = {0};
  pid_t child = spawn_traced(cover_body, NULL, TRACE_OPTIONS);
  int status = trace_loop(child, deny_connect, &seen, &st, 1);
  int failed = WIFEXITED(status) ? WEXITSTATUS(status) : 255;
  printf("cover: failed_mask=%d forks=%d vforks=%d clones=%d execs=%d last_exec tid=%d "
         "former=%lu\n", failed, st.forks, st.vforks, st.clones, st.execs, st.last_exec_tid,
         st.last_exec_former);
  result("cover.thread_denied", !(failed & 1), "pthread connect -> EACCES via tracer");
  result("cover.fork_denied", !(failed & 2), "fork child connect -> EACCES");
  result("cover.vfork_exec_denied", !(failed & 4) && seen.bash >= 1,
         "vfork+exec bash /dev/tcp refused; tracer saw exe=bash");
  if (failed & 16)
    skip("cover.userns_pidns_denied", "unshare(CLONE_NEWUSER|CLONE_NEWPID) refused here");
  else
    result("cover.userns_pidns_denied", !(failed & 8),
           "pid-namespace init (getpid()==1) connect -> EACCES via tracer");
  if (seen.nspid_present)
    result("cover.nspid_resolves_nested_init", seen.nested_init == 1,
           "tracer-side /proc/<tid>/status NSpid ends in 1 for the nested init");
  else
    skip("cover.nspid_resolves_nested_init", "/proc/<tid>/status has no NSpid line here");
  result("cover.nonleader_exec_denied",
         !(failed & 32) && seen.bash == 2 && st.last_exec_former != (unsigned long)st.last_exec_tid,
         "thread exec: PTRACE_EVENT_EXEC on leader tid=%d, former tid=%lu; bash connect seen",
         st.last_exec_tid, st.last_exec_former);
  int want = failed & 16 ? 4 : 5;
  result("cover.every_task_stopped", seen.distinct == want,
         "distinct connecting tasks stopped=%d expected=%d (total connect stops=%d)",
         seen.distinct, want, seen.connects);
}

static void *idle_thread(void *unused) {
  pause();
  return unused;
}

static int exitkill_body(void *ready_fd) {
  install_probe_filter();
  int ready = *(int *)ready_fd;
  if (fork() == 0) pause();  // idle child
  if (fork() == 0) {
    // unshare(CLONE_NEWUSER) needs a single-threaded caller.
    if (unshare(CLONE_NEWUSER | CLONE_NEWPID) == 0 && fork() == 0) {
      if (fork() == 0) pause();  // pid 2 in the nested namespace
      pause();                   // pid 1
    }
    pause();
  }
  pthread_t t;
  pthread_create(&t, NULL, idle_thread, NULL);
  if (fork() == 0) {
    setsid();
    if (fork() == 0) pause();  // daemonized grandchild
    _exit(0);
  }

  sleep(1);
  char ok = 1;
  if (write(ready, &ok, 1) != 1) return 1;
  pause();
  return 0;
}

static int alive(pid_t tid) {
  char path[64], stat[256] = {0};
  snprintf(path, sizeof(path), "/proc/%d/stat", tid);
  int fd = open(path, O_RDONLY);
  if (fd < 0) return 0;
  ssize_t n = read(fd, stat, sizeof(stat) - 1);
  close(fd);
  char *paren = n > 0 ? strrchr(stat, ')') : NULL;
  return paren && paren[2] != 'Z' && paren[2] != 'X';
}

static void exitkill(void) {
  prctl(PR_SET_CHILD_SUBREAPER, 1);
  int tids[2], ready[2];
  must(pipe(tids) == 0 && pipe(ready) == 0, "pipes");
  pid_t tracer = fork();
  must(tracer >= 0, "fork tracer");
  if (tracer == 0) {
    close(tids[0]), close(ready[0]);
    int fd = ready[1];
    pid_t w = spawn_traced(exitkill_body, &fd, TRACE_OPTIONS);
    must(write(tids[1], &w, sizeof(w)) == sizeof(w), "report root");
    struct trace_stats st = {.report_fd = tids[1]};
    trace_loop(w, NULL, NULL, &st, 1);
    _exit(0);
  }
  close(tids[1]), close(ready[1]);
  char ok;
  must(read(ready[0], &ok, 1) == 1, "workload ready");
  // Tracked tids are those a tracer can trust: the root plus every new
  // tracee's first waitpid() stop. Event-message tids are compared to them.
  pid_t all[64], events[64], pair[2];
  int n = 0, ne = 0;
  fcntl(tids[0], F_SETFL, O_NONBLOCK);
  must(read(tids[0], &all[n++], sizeof(pid_t)) == sizeof(pid_t), "root tid");
  while (read(tids[0], pair, sizeof(pair)) == sizeof(pair)) {
    int dup = 0;
    for (int j = 0; j < n; j++) dup |= all[j] == pair[1];
    if (pair[0] == 'w' && !dup && n < 64) all[n++] = pair[1];
    if (pair[0] == 'e' && ne < 64) events[ne++] = pair[1];
  }
  int mismatched = 0;
  for (int i = 0; i < ne; i++) {
    int found = 0;
    for (int j = 0; j < n; j++) found |= events[i] == all[j];
    if (!found) printf("exitkill: event tid %d is not a tracee tid in the tracer's namespace\n",
                       events[i]);
    mismatched += !found;
  }
  result("events.fork_eventmsg_in_tracer_pidns", ne == n - 1 && mismatched == 0,
         "fork/clone event tids=%d, waitpid-discovered tracees=%d, not in tracer namespace=%d",
         ne, n - 1, mismatched);
  int before = 0;
  for (int i = 0; i < n; i++) {
    printf("exitkill: tracked tid=%d alive=%d\n", all[i], alive(all[i]));
    before += alive(all[i]);
  }
  kill(tracer, SIGKILL);
  int survivors = before;
  for (int round = 0; round < 50 && survivors; round++) {
    usleep(100000);
    while (waitpid(-1, NULL, WNOHANG) > 0) {}
    survivors = 0;
    for (int i = 0; i < n; i++) survivors += alive(all[i]);
  }
  printf("exitkill: tracked tids=%d alive_before=%d survivors_after_5s=%d\n", n, before,
         survivors);
  if (getpid() == 1) {
    // As the sandbox init, every other live process is a survivor.
    DIR *proc = opendir("/proc");
    struct dirent *e;
    int others = 0;
    while (proc && (e = readdir(proc))) {
      int pid = atoi(e->d_name);
      if (pid > 1 && alive(pid)) printf("exitkill: untracked survivor pid=%d\n", pid), others++;
    }
    if (proc) closedir(proc);
    result("exitkill.sandbox_has_no_survivors", others == 0, "live non-init processes=%d",
           others);
  }
  // The daemon's intermediate parent exits by design, so 7 of 8 are alive.
  result("exitkill.descendants_killed", n == 8 && before == 7 && survivors == 0,
         "tracked=%d (root, idle child, daemon parent+grandchild, namespace creator, nested "
         "init+child, thread) "
         "alive_before=%d survivors=%d", n, before, survivors);
  while (waitpid(-1, NULL, WNOHANG) > 0) {}
}

int main(void) {
  setvbuf(stdout, NULL, _IOLBF, 0);
  pid_t c = fork();
  must(c >= 0, "fork");
  if (c == 0) _exit(notracer_body());
  int code = exit_code(c);
  result("notracer.enosys", code == ENOSYS, "connect with TRACE filter and no tracer: errno=%d",
         code);
  cover();
  exitkill();
  return finish();
}
