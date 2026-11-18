// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Gate 3: exact socket object and lifetime without SO_COOKIE.
// The parent plays the tracer; the child is the workload. No seccomp is
// needed: these checks qualify pidfd_getfd, O_PATH pins, and inode identity.
// - PIDFD_THREAD reaches a non-leader thread's private fd table
//   (unshare(CLONE_FILES)); a leader pidfd reaches a different object.
// - dup and SCM_RIGHTS aliases share an inode; an accepted socket does not.
// - An O_PATH pin made from the tracer's own pidfd_getfd duplicate keeps
//   the inode but does not delay EOF or hold a listening port; a live
//   duplicate (control) does both.
// - Socket inode numbers are not reused over a bounded churn.
#include "gv.h"
#include <poll.h>
#include <pthread.h>
#include <sched.h>

#define FD_SHARED 50
enum { ACCEPTED = 60, CLIENT = 61, LISTENER = 62, ALIAS = 63, SCM = 64,
       ACCEPTED2 = 70, CLIENT2 = 71, LISTENER2 = 72 };

struct report {
  pid_t leader, thread;
  ino_t leader_ino, thread_ino, accepted, alias, scm, listener_ino, listener2_ino;
  int port, port2;
};

static int to_parent, from_parent;
static pthread_barrier_t barrier;
static struct report rep;

static ino_t ino_of(int fd) {
  struct stat st;
  return fstat(fd, &st) == 0 ? st.st_ino : 0;
}

static void *thread_main(void *unused) {
  rep.thread = (pid_t)syscall(SYS_gettid);
  must(unshare(CLONE_FILES) == 0, "unshare(CLONE_FILES)");
  int s = socket(AF_INET, SOCK_DGRAM, 0);
  must(dup2(s, FD_SHARED) == FD_SHARED, "thread dup2");
  close(s);
  rep.thread_ino = ino_of(FD_SHARED);
  pthread_barrier_wait(&barrier);
  pause();  // keep the private table alive
  return unused;
}

static int listen_on(int fd, int port) {
  int s = socket(AF_INET, SOCK_STREAM, 0);
  int one = 1;
  setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  struct sockaddr_in a = addr4("127.0.0.1", port);
  if (bind(s, (void *)&a, sizeof(a)) != 0 || listen(s, 4) != 0) {
    close(s);
    return -errno;
  }
  if (fd >= 0) {
    dup2(s, fd);
    close(s);
    return fd;
  }
  return s;
}

static int port_of(int fd) {
  struct sockaddr_in a;
  socklen_t len = sizeof(a);
  getsockname(fd, (void *)&a, &len);
  return ntohs(a.sin_port);
}

static void pair(int listener, int accepted_fd, int client_fd) {
  int c = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in a = addr4("127.0.0.1", port_of(listener));
  must(connect(c, (void *)&a, sizeof(a)) == 0, "connect pair");
  int acc = accept(listener, 0, 0);
  must(acc >= 0, "accept");
  dup2(acc, accepted_fd), close(acc), dup2(c, client_fd), close(c);
}

static int eof_within(int fd, int ms) {
  struct pollfd p = {fd, POLLIN, 0};
  char b;
  return poll(&p, 1, ms) == 1 && read(fd, &b, 1) == 0;
}

static int workload(void) {
  int s = socket(AF_INET, SOCK_STREAM, 0);
  must(dup2(s, FD_SHARED) == FD_SHARED, "leader dup2");
  close(s);
  pthread_barrier_init(&barrier, NULL, 2);
  pthread_t t;
  pthread_create(&t, NULL, thread_main, NULL);
  pthread_barrier_wait(&barrier);
  rep.leader = getpid();
  rep.leader_ino = ino_of(FD_SHARED);
  int l = listen_on(-1, 0);
  pair(l, ACCEPTED, CLIENT);
  pair(l, ACCEPTED2, CLIENT2);
  close(l);
  rep.accepted = ino_of(ACCEPTED);
  must(dup2(ACCEPTED, ALIAS) == ALIAS, "alias");
  rep.alias = ino_of(ALIAS);
  int sp[2];
  must(socketpair(AF_UNIX, SOCK_DGRAM, 0, sp) == 0, "socketpair");
  char cbuf[CMSG_SPACE(sizeof(int))] = {0}, byte = 'x';
  struct iovec io = {&byte, 1};
  struct msghdr m = {.msg_iov = &io, .msg_iovlen = 1, .msg_control = cbuf,
                     .msg_controllen = sizeof(cbuf)};
  struct cmsghdr *c = CMSG_FIRSTHDR(&m);
  c->cmsg_level = SOL_SOCKET, c->cmsg_type = SCM_RIGHTS, c->cmsg_len = CMSG_LEN(sizeof(int));
  int send_fd = ACCEPTED;
  memcpy(CMSG_DATA(c), &send_fd, sizeof(int));
  must(sendmsg(sp[0], &m, 0) == 1, "SCM_RIGHTS send");
  must(recvmsg(sp[1], &m, 0) == 1, "SCM_RIGHTS recv");
  int received;
  memcpy(&received, CMSG_DATA(CMSG_FIRSTHDR(&m)), sizeof(int));
  dup2(received, SCM), close(received), close(sp[0]), close(sp[1]);
  rep.scm = ino_of(SCM);
  close(ALIAS), close(SCM);  // ACCEPTED is now the only workload reference
  must(listen_on(LISTENER, 0) == LISTENER && listen_on(LISTENER2, 0) == LISTENER2, "listeners");
  rep.port = port_of(LISTENER), rep.port2 = port_of(LISTENER2);
  rep.listener_ino = ino_of(LISTENER), rep.listener2_ino = ino_of(LISTENER2);
  must(write(to_parent, &rep, sizeof(rep)) == sizeof(rep), "report");
  char cmd;
  while (read(from_parent, &cmd, 1) == 1) {
    int answer = 0;
    if (cmd == 'a') close(ACCEPTED), answer = eof_within(CLIENT, 500);
    if (cmd == 'b') close(ACCEPTED2), answer = eof_within(CLIENT2, 500);
    if (cmd == 'c') close(LISTENER), answer = listen_on(-1, rep.port);
    if (cmd == 'd') close(LISTENER2), answer = listen_on(-1, rep.port2);
    must(write(to_parent, &answer, sizeof(answer)) == sizeof(answer), "answer");
  }
  return 0;
}

static int ask(int w, int r, char cmd) {
  int answer = -1;
  must(write(w, &cmd, 1) == 1 && read(r, &answer, sizeof(answer)) == sizeof(answer), "ask");
  return answer;
}

static int getfd(pid_t tid, unsigned flags, int fd, int *err) {
  int pidfd = (int)syscall(SYS_pidfd_open, tid, flags);
  if (pidfd < 0) return *err = errno, -1;
  int dup = (int)syscall(SYS_pidfd_getfd, pidfd, fd, 0);
  *err = dup < 0 ? errno : 0;
  close(pidfd);
  return dup;
}

static int pin_of(int dup) {
  char path[64];
  snprintf(path, sizeof(path), "/proc/self/fd/%d", dup);
  int pin = open(path, O_PATH | O_CLOEXEC);
  close(dup);
  return pin;
}

static int cmp_ino(const void *a, const void *b) {
  ino_t x = *(const ino_t *)a, y = *(const ino_t *)b;
  return x < y ? -1 : x > y;
}

static void churn(void) {
  enum { N = 20000 };
  static ino_t seen[N];
  int monotonic = 1, reused = 0;
  for (int i = 0; i < N; i++) {
    int domain = i % 3 == 0 ? AF_UNIX : AF_INET, type = i % 2 ? SOCK_DGRAM : SOCK_STREAM;
    int s = socket(domain, type, 0);
    must(s >= 0, "churn socket");
    seen[i] = ino_of(s);
    close(s);
    if (i && seen[i] <= seen[i - 1]) monotonic = 0;
  }
  qsort(seen, N, sizeof(seen[0]), cmp_ino);
  for (int i = 1; i < N; i++) reused += seen[i] == seen[i - 1];
  result("churn.no_inode_reuse", reused == 0,
         "%d create/close cycles, min=%lu max=%lu strictly_increasing=%d duplicate_inodes=%d", N,
         (unsigned long)seen[0], (unsigned long)seen[N - 1], monotonic, reused);
}

int main(void) {
  setvbuf(stdout, NULL, _IOLBF, 0);
  int up[2], down[2];
  must(pipe(up) == 0 && pipe(down) == 0, "pipes");
  pid_t child = fork();
  must(child >= 0, "fork");
  if (child == 0) {
    close(up[0]), close(down[1]);
    to_parent = up[1], from_parent = down[0];
    _exit(workload());
  }
  close(up[1]), close(down[0]);
  struct report r;
  must(read(up[0], &r, sizeof(r)) == sizeof(r), "read report");
  int err;

  int d = getfd(r.thread, 0, FD_SHARED, &err);
  result("pidfd.nonleader_without_thread_flag_refused", d < 0,
         "pidfd_open(non-leader tid, 0) errno=%d", err);
  if (d >= 0) close(d);
  d = getfd(r.thread, PIDFD_THREAD, FD_SHARED, &err);
  ino_t thread_dup = d >= 0 ? ino_of(d) : 0;
  result("pidfd.thread_flag_reaches_private_table", d >= 0 && thread_dup == r.thread_ino,
         "PIDFD_THREAD getfd errno=%d ino=%lu thread_ino=%lu", err, (unsigned long)thread_dup,
         (unsigned long)r.thread_ino);
  if (d >= 0) close(d);
  d = getfd(r.leader, 0, FD_SHARED, &err);
  ino_t leader_dup = d >= 0 ? ino_of(d) : 0;
  result("pidfd.leader_pidfd_is_a_different_object", leader_dup == r.leader_ino &&
         leader_dup != r.thread_ino,
         "leader getfd ino=%lu leader_ino=%lu thread_ino=%lu (leader pidfd must not be used "
         "for a thread with a private table)", (unsigned long)leader_dup,
         (unsigned long)r.leader_ino, (unsigned long)r.thread_ino);
  if (d >= 0) close(d);
  char path[96], link[64] = {0};
  snprintf(path, sizeof(path), "/proc/%d/task/%d/fd/%d", r.leader, r.thread, FD_SHARED);
  ssize_t n = readlink(path, link, sizeof(link) - 1);
  char want[64];
  snprintf(want, sizeof(want), "socket:[%lu]", (unsigned long)r.thread_ino);
  result("procfs.task_fd_link_names_thread_object", n > 0 && strcmp(link, want) == 0,
         "%s -> %s", path, n > 0 ? link : strerror(errno));

  result("alias.dup_and_scm_rights_share_inode",
         r.alias == r.accepted && r.scm == r.accepted && r.accepted != r.listener_ino,
         "accepted=%lu dup=%lu scm=%lu listener=%lu", (unsigned long)r.accepted,
         (unsigned long)r.alias, (unsigned long)r.scm, (unsigned long)r.listener_ino);

  int pin = pin_of(getfd(r.leader, 0, ACCEPTED, &err));
  result("opath.pin_from_tracer_dup_keeps_identity", pin >= 0 && ino_of(pin) == r.accepted,
         "O_PATH pin ino=%lu accepted=%lu", (unsigned long)ino_of(pin),
         (unsigned long)r.accepted);
  result("opath.pin_does_not_delay_eof", ask(down[1], up[0], 'a') == 1,
         "peer saw EOF within 500ms after workload close while tracer holds only O_PATH pin");
  result("opath.pin_identity_after_close", ino_of(pin) == r.accepted,
         "pin still stats ino=%lu after the socket closed", (unsigned long)ino_of(pin));
  int live = getfd(r.leader, 0, ACCEPTED2, &err);
  int eof = ask(down[1], up[0], 'b');
  result("control.live_dup_delays_eof", live >= 0 && eof == 0,
         "peer EOF within 500ms=%d while tracer holds a live duplicate", eof);
  close(live);

  int lpin = pin_of(getfd(r.leader, 0, LISTENER, &err));
  int rebind = ask(down[1], up[0], 'c');
  result("opath.pin_does_not_hold_listener_port", rebind >= 0 && ino_of(lpin) == r.listener_ino,
         "rebind port %d after close: %s", r.port, rebind >= 0 ? "ok" : strerror(-rebind));
  int llive = getfd(r.leader, 0, LISTENER2, &err);
  rebind = ask(down[1], up[0], 'd');
  result("control.live_dup_holds_listener_port", rebind == -EADDRINUSE,
         "rebind port %d with live duplicate: %s", r.port2,
         rebind >= 0 ? "ok" : strerror(-rebind));
  close(llive), close(pin), close(lpin);

  close(down[1]);
  kill(child, SIGKILL);
  waitpid(child, NULL, 0);
  churn();
  return finish();
}
