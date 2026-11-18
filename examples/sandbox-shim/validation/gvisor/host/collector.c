// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Spike-only model of a supervisor-side SecCheck adapter for Candidate D.
// It runs on the host side of runsc (inside the Docker helper), never inside
// the sandbox:
//   1. It listens on a private SOCK_SEQPACKET path named in the pod init
//      config. runsc connects to it during sandbox setup and passes the
//      endpoint to the Sentry. The first and only accepted connection is the
//      trusted event source for this sandbox generation.
//   2. It records raw syscall/sysno/178/enter (gettid) events: root-namespace
//      thread_id, task start time, and the six raw arguments.
//   3. It connects into the guest tracer's listener (created through
//      --host-uds=create) and answers queries {tid, 128-bit nonce} with the
//      raw arg1 (the hidden original fd) of a matching unused event.
// An event is used at most once. A query with no match is answered with
// TIMEOUT after its deadline; absence never authorizes.
#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "../probes/rawproto.h"

#define MAX_EVENTS 8192
#define MAX_PENDING 64

struct event {
  int32_t tid;
  int64_t start_ns;
  uint64_t sysno, arg[6];
  int used, dropped;
};

static struct event events[MAX_EVENTS];
static int nevents;
static uint32_t sink_dropped;
static unsigned long raw_total, gettid_total;

struct pending {
  struct raw_query q;
  int64_t deadline_ms, reply_at_ms;
  int found;
  struct raw_reply r;
};
static struct pending pend[MAX_PENDING];
static int npend;

static int64_t now_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int varint(const uint8_t **p, const uint8_t *end, uint64_t *v) {
  *v = 0;
  for (int shift = 0; shift < 64 && *p < end; shift += 7) {
    uint8_t b = *(*p)++;
    *v |= (uint64_t)(b & 0x7f) << shift;
    if (!(b & 0x80)) return 1;
  }
  return 0;
}

// Bounded parse of the fields Candidate D needs; unknown fields are skipped.
static int parse_fields(const uint8_t *p, const uint8_t *end, struct event *e, int ctx) {
  while (p < end) {
    uint64_t key, v;
    if (!varint(&p, end, &key)) return 0;
    unsigned field = (unsigned)(key >> 3), wt = key & 7;
    if (wt == 0) {
      if (!varint(&p, end, &v)) return 0;
      if (ctx && field == 2) e->tid = (int32_t)v;
      if (ctx && field == 3) e->start_ns = (int64_t)v;
      if (!ctx && field == 4) e->sysno = v;
      if (!ctx && field >= 5 && field <= 10) e->arg[field - 5] = v;
    } else if (wt == 2) {
      if (!varint(&p, end, &v) || v > (uint64_t)(end - p)) return 0;
      if (!ctx && field == 1 && !parse_fields(p, p + v, e, 1)) return 0;
      p += v;
    } else if (wt == 1) {
      if (end - p < 8) return 0;
      p += 8;
    } else if (wt == 5) {
      if (end - p < 4) return 0;
      p += 4;
    } else {
      return 0;
    }
  }
  return 1;
}

static int match(const struct raw_query *q, struct event *e) {
  return !e->used && e->sysno == RAW_SYSNO_GETTID && e->tid == q->tid && e->arg[4] == q->nonce[0] &&
         e->arg[5] == q->nonce[1];
}

static void complete(struct pending *pd, struct event *e) {
  pd->found = 1;
  e->used = 1;
  pd->r.status = RAW_FOUND;
  pd->r.fd = e->arg[0];
  pd->r.start_ns = e->start_ns;
}

static void on_event(struct event *e) {
  for (int i = 0; i < npend; i++) {
    struct pending *pd = &pend[i];
    if (pd->found || !match(&pd->q, e)) continue;
    if (pd->q.flags & RAW_HOOK_DROP) {
      e->used = e->dropped = 1;  // test hook: simulate event loss
      printf("collector: hook dropped matching event tid=%d seq=%u\n", e->tid, pd->q.seq);
      return;
    }
    complete(pd, e);
    return;
  }
}

// Validate one sink packet: 8-byte native header {u16 header size, u16
// message type, u32 dropped count}, then a raw Syscall protobuf. Returns 1
// only for a well-formed gettid event that carries a thread id.
static int parse_packet(const uint8_t *buf, size_t n, struct event *e, uint32_t *dropped) {
  if (n < 8) return 0;
  uint16_t hsize, type;
  memcpy(&hsize, buf, 2);
  memcpy(&type, buf + 2, 2);
  memcpy(dropped, buf + 4, 4);
  if (hsize < 8 || hsize > n || type != RAW_MESSAGE_SYSCALL_RAW) return 0;
  memset(e, 0, sizeof(*e));
  return parse_fields(buf + hsize, buf + n, e, 0) && e->sysno == RAW_SYSNO_GETTID && e->tid > 0;
}

static void read_sink(int sink) {
  uint8_t buf[65536];
  ssize_t n = recv(sink, buf, sizeof(buf), MSG_DONTWAIT);
  if (n <= 0) return;
  raw_total++;
  struct event e;
  uint32_t dropped = 0;
  int ok = parse_packet(buf, (size_t)n, &e, &dropped);
  if (n >= 8) sink_dropped = dropped;
  if (!ok) return;
  gettid_total++;
  if (nevents == MAX_EVENTS) {
    memmove(events, events + MAX_EVENTS / 2, sizeof(events[0]) * (MAX_EVENTS / 2));
    nevents = MAX_EVENTS / 2;
  }
  events[nevents] = e;
  on_event(&events[nevents]);
  nevents++;
}

static void on_query(struct raw_query *q) {
  struct pending *pd = &pend[npend < MAX_PENDING ? npend++ : MAX_PENDING - 1];
  memset(pd, 0, sizeof(*pd));
  pd->q = *q;
  pd->deadline_ms = now_ms() + q->timeout_ms;
  pd->r = (struct raw_reply){RAW_REPLY_MAGIC, q->seq, RAW_TIMEOUT, q->tid, 0, 0, 0, 0};
  for (int i = 0; i < nevents; i++) {
    if (events[i].sysno == RAW_SYSNO_GETTID && events[i].tid == q->tid && !match(q, &events[i]))
      pd->r.other_events_same_tid++;
  }
  for (int i = nevents - 1; i >= 0; i--) {
    if (match(q, &events[i]) && (q->flags & RAW_HOOK_DROP)) {
      events[i].used = events[i].dropped = 1;  // test hook: simulate event loss
      printf("collector: hook dropped matching event tid=%d seq=%u\n", q->tid, q->seq);
    } else if (match(q, &events[i])) {
      complete(pd, &events[i]);
      break;
    }
  }
}

// Reply when found (after any test delay) or when the deadline passes.
static void flush(int chan) {
  int64_t t = now_ms();
  for (int i = 0; i < npend;) {
    struct pending *pd = &pend[i];
    int due = pd->found || t >= pd->deadline_ms;
    if (due && !pd->reply_at_ms) pd->reply_at_ms = t + pd->q.delay_ms;
    if (due && t >= pd->reply_at_ms) {
      pd->r.dropped = sink_dropped;
      if (send(chan, &pd->r, sizeof(pd->r), MSG_NOSIGNAL) != sizeof(pd->r)) exit(3);
      pend[i] = pend[--npend];
      continue;
    }
    i++;
  }
}

// Malformed and hostile packets must be rejected without matching anything.
static int selftest(void) {
  // Valid: header + {1: {2: tid 7, 3: start 9}, 4: 178, 5: 77, 9: n0, 10: n1}
  const uint8_t good[] = {8, 0, 6, 0, 0, 0, 0, 0, 0x0a, 4, 0x10, 7, 0x18, 9, 0x20, 178, 1,
                          0x28, 77, 0x48, 0x11, 0x50, 0x22};
  struct {
    const char *name;
    uint8_t buf[32];
    size_t n;
    int want;
  } cases[] = {
      {"valid", {0}, sizeof(good), 1},
      {"short_header", {8, 0, 6, 0}, 4, 0},
      {"header_size_past_end", {64, 0, 6, 0, 0, 0, 0, 0, 0x20, 178, 1}, 11, 0},
      {"header_size_too_small", {4, 0, 6, 0, 0, 0, 0, 0, 0x20, 178, 1}, 11, 0},
      {"wrong_message_type", {8, 0, 7, 0, 0, 0, 0, 0, 0x20, 178, 1, 0x0a, 2, 0x10, 7}, 15, 0},
      {"truncated_varint", {8, 0, 6, 0, 0, 0, 0, 0, 0x20, 0xb2}, 10, 0},
      {"length_overflow", {8, 0, 6, 0, 0, 0, 0, 0, 0x0a, 0x7f, 0x10, 7}, 12, 0},
      {"group_wire_type", {8, 0, 6, 0, 0, 0, 0, 0, 0x0b, 0x20, 178, 1}, 12, 0},
      {"no_thread_id", {8, 0, 6, 0, 0, 0, 0, 0, 0x20, 178, 1, 0x28, 77}, 13, 0},
      {"other_sysno", {8, 0, 6, 0, 0, 0, 0, 0, 0x0a, 2, 0x10, 7, 0x20, 203, 1}, 15, 0},
  };
  memcpy(cases[0].buf, good, sizeof(good));
  int failures = 0;
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    struct event e;
    uint32_t dropped;
    int got = parse_packet(cases[i].buf, cases[i].n, &e, &dropped);
    int ok = got == cases[i].want &&
             (!got || (e.tid == 7 && e.start_ns == 9 && e.arg[0] == 77 && e.arg[4] == 0x11 &&
                       e.arg[5] == 0x22));
    printf("RESULT collector.parse.%s %s accepted=%d\n", cases[i].name, ok ? "PASS" : "FAIL", got);
    failures += !ok;
  }
  printf("SUMMARY failures=%d\n", failures);
  return failures != 0;
}

int main(int argc, char **argv) {
  setvbuf(stdout, NULL, _IOLBF, 0);
  if (argc == 2 && strcmp(argv[1], "--selftest") == 0) return selftest();
  if (argc != 3) {
    fprintf(stderr, "usage: collector SINK_PATH GUEST_CHANNEL_PATH\n");
    return 2;
  }
  struct sockaddr_un a = {.sun_family = AF_UNIX};
  int l = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
  snprintf(a.sun_path, sizeof(a.sun_path), "%s", argv[1]);
  if (l < 0 || bind(l, (void *)&a, sizeof(a)) || listen(l, 1)) {
    perror("collector: sink listen");
    return 2;
  }
  printf("collector: sink listening on %s\n", argv[1]);
  // Exactly one event source: the connection runsc makes during setup.
  int sink = accept4(l, NULL, NULL, SOCK_CLOEXEC);
  close(l);
  unlink(argv[1]);
  uint8_t hs[64];
  ssize_t n = recv(sink, hs, sizeof(hs), 0);
  const uint8_t hello[] = {0x08, 0x01};  // Handshake{version: 1}
  if (n <= 0 || send(sink, hello, sizeof(hello), 0) != sizeof(hello)) {
    perror("collector: handshake");
    return 2;
  }
  printf("collector: runsc sink connected, handshake %zd bytes\n", n);
  int chan = -1;
  struct sockaddr_un g = {.sun_family = AF_UNIX};
  snprintf(g.sun_path, sizeof(g.sun_path), "%s", argv[2]);
  for (int i = 0; i < 3000 && chan < 0; i++) {
    struct pollfd p = {sink, POLLIN, 0};
    if (poll(&p, 1, 10) > 0) read_sink(sink);
    int c = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (connect(c, (void *)&g, sizeof(g)) == 0) chan = c;
    else close(c);
  }
  if (chan < 0) {
    printf("collector: guest channel never appeared\n");
    return 2;
  }
  printf("collector: connected to guest tracer channel\n");
  for (;;) {
    struct pollfd p[2] = {{sink, POLLIN, 0}, {chan, POLLIN, 0}};
    poll(p, 2, npend ? 1 : 100);
    if (p[0].revents & POLLIN) {
      for (int i = 0; i < 64; i++) read_sink(sink);
    }
    if (p[1].revents & (POLLIN | POLLHUP)) {
      struct raw_query q;
      ssize_t r = recv(chan, &q, sizeof(q), MSG_WAITALL);
      if (r == 0) break;
      if (r != sizeof(q) || q.magic != RAW_QUERY_MAGIC) {
        printf("collector: bad query, closing\n");
        break;
      }
      on_query(&q);
    }
    flush(chan);
  }
  printf("collector: done raw_messages=%lu gettid_events=%lu sink_dropped=%u\n", raw_total,
         gettid_total, sink_dropped);
  return 0;
}
