// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static void check(int ok, const char *what) {
    if (!ok) { perror(what); exit(1); }
}

static uint64_t now(void) {
    struct timespec t;
    check(clock_gettime(CLOCK_MONOTONIC, &t) == 0, "clock_gettime");
    return (uint64_t)t.tv_sec * 1000000000 + t.tv_nsec;
}

static void nodelay(int fd) {
    int one = 1;
    check(setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) == 0, "TCP_NODELAY");
}

struct fixture { int listener; uint64_t count; int stream; };

static void exchange(int fd, int server) {
    char data[64] = {0};
    if (!server) check(send(fd, data, sizeof(data), MSG_NOSIGNAL) == sizeof(data), "send");
    check(recv(fd, data, sizeof(data), MSG_WAITALL) == sizeof(data), "recv");
    if (server) check(send(fd, data, sizeof(data), MSG_NOSIGNAL) == sizeof(data), "send");
}

// File-open attribution controls. They are additional cases; the original
// `file` case below is unchanged.
static const char *FILE_PATH = "/etc/passwd";

static uint64_t open_read_close(void) {
    char data[64];
    int fd = open(FILE_PATH, O_RDONLY | O_CLOEXEC);
    check(fd >= 0, "open");
    check(read(fd, data, sizeof(data)) == sizeof(data), "read");
    check(close(fd) == 0, "close");
    return (unsigned char)data[0];
}

struct opener { uint64_t count; uint64_t checksum; };

static void *open_files(void *arg) {
    struct opener *o = arg;
    for (uint64_t i = 0; i < o->count; i++) o->checksum += open_read_close();
    return NULL;
}

// Split `count` open/read/close operations across `threads` threads that
// start together, and time them all.
static uint64_t threaded_file(uint64_t count, unsigned threads, uint64_t *checksum) {
    pthread_t ids[16];
    struct opener openers[16];
    check(threads > 0 && threads <= 16, "thread count");
    for (unsigned i = 0; i < threads; i++) {
        openers[i].count = count / threads + (i < count % threads);
        openers[i].checksum = 0;
    }
    uint64_t start = now();
    for (unsigned i = 0; i < threads; i++)
        check(pthread_create(&ids[i], NULL, open_files, &openers[i]) == 0, "pthread_create");
    for (unsigned i = 0; i < threads; i++) {
        check(pthread_join(ids[i], NULL) == 0, "pthread_join");
        *checksum += openers[i].checksum;
    }
    return now() - start;
}

static int compare_u64(const void *left, const void *right) {
    uint64_t a = *(const uint64_t *)left, b = *(const uint64_t *)right;
    return (a > b) - (a < b);
}

static void *serve(void *arg) {
    struct fixture *f = arg;
    int fd = -1;
    for (uint64_t i = 0; i < f->count; i++) {
        if (!f->stream || i == 0) {
            fd = accept(f->listener, NULL, NULL);
            check(fd >= 0, "accept");
            nodelay(fd);
        }
        exchange(fd, 1);
        if (!f->stream) check(close(fd) == 0, "close");
    }
    if (f->stream) check(close(fd) == 0, "close");
    return NULL;
}

int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: workload CASE ITERATIONS\n"); return 2; }
    char *end;
    errno = 0;
    uint64_t count = strtoull(argv[2], &end, 10);
    if (errno || *end || !count || argv[2][0] == '-') return 2;
    const char *name = argv[1];
    uint64_t start, elapsed, checksum = 0;
    // Per-operation latency, reported only by the `file-latency` case.
    uint64_t p50 = 0, p99 = 0, slowest = 0;
    int latency = 0;
    if (!strcmp(name, "tcp-connect") || !strcmp(name, "tcp-stream")) {
        int stream = !strcmp(name, "tcp-stream");
        int listener = socket(AF_INET, SOCK_STREAM, 0);
        check(listener >= 0, "socket");
        struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
        check(bind(listener, (struct sockaddr *)&address, sizeof(address)) == 0, "bind");
        check(listen(listener, 128) == 0, "listen");
        socklen_t len = sizeof(address);
        check(getsockname(listener, (struct sockaddr *)&address, &len) == 0, "getsockname");
        struct fixture f = {listener, count, stream};
        pthread_t thread;
        check(pthread_create(&thread, NULL, serve, &f) == 0, "pthread_create");
        int fd = -1;
        // Established-stream case excludes connection setup; connect case includes it.
        if (stream) {
            fd = socket(AF_INET, SOCK_STREAM, 0);
            check(fd >= 0, "socket"); nodelay(fd);
            check(connect(fd, (struct sockaddr *)&address, sizeof(address)) == 0, "connect");
        }
        start = now();
        for (uint64_t i = 0; i < count; i++) {
            if (!stream) {
                fd = socket(AF_INET, SOCK_STREAM, 0);
                check(fd >= 0, "socket"); nodelay(fd);
                check(connect(fd, (struct sockaddr *)&address, sizeof(address)) == 0, "connect");
            }
            exchange(fd, 0);
            if (!stream) check(close(fd) == 0, "close");
        }
        elapsed = now() - start;
        if (stream) check(close(fd) == 0, "close");
        check(pthread_join(thread, NULL) == 0, "pthread_join");
        check(close(listener) == 0, "close");
    } else {
        // Set by a case that times only part of its own work.
        uint64_t measured = 0;
        start = now();
        if (!strcmp(name, "cpu")) {
            volatile uint64_t value = 1;
            for (uint64_t i = 0; i < count; i++) value = value * 6364136223846793005ULL + 1;
            checksum = value;
        } else if (!strcmp(name, "getpid")) {
            for (uint64_t i = 0; i < count; i++) {
                long pid = syscall(SYS_getpid);
                check(pid > 0, "getpid"); checksum += (uint64_t)pid;
            }
        } else if (!strcmp(name, "file")) {
            for (uint64_t i = 0; i < count; i++) {
                char data[64];
                int fd = open("/etc/passwd", O_RDONLY | O_CLOEXEC);
                check(fd >= 0, "open");
                check(read(fd, data, sizeof(data)) == sizeof(data), "read");
                checksum += (unsigned char)data[0];
                check(close(fd) == 0, "close");
            }
        } else if (!strcmp(name, "file-open")) {
            // Open and close only: the interception cost without a read.
            for (uint64_t i = 0; i < count; i++) {
                int fd = open(FILE_PATH, O_RDONLY | O_CLOEXEC);
                check(fd >= 0, "open");
                checksum += (uint64_t)(fd > 0);
                check(close(fd) == 0, "close");
            }
        } else if (!strcmp(name, "file-read")) {
            // Reads on one descriptor opened before the timer: no open is
            // measured, so this bounds what interception can cost a read.
            char data[64];
            int fd = open(FILE_PATH, O_RDONLY | O_CLOEXEC);
            check(fd >= 0, "open");
            start = now();
            for (uint64_t i = 0; i < count; i++) {
                check(pread(fd, data, sizeof(data), 0) == sizeof(data), "pread");
                checksum += (unsigned char)data[0];
            }
            measured = now() - start;
            check(close(fd) == 0, "close");
        } else if (!strcmp(name, "file-t4") || !strcmp(name, "file-t16")) {
            unsigned threads = !strcmp(name, "file-t4") ? 4 : 16;
            measured = threaded_file(count, threads, &checksum);
        } else if (!strcmp(name, "file-latency")) {
            // The `file` operation with each iteration timed. The two clock
            // reads per iteration are part of the measured interval.
            uint64_t *samples = malloc(count * sizeof(*samples));
            check(samples != NULL, "malloc");
            for (uint64_t i = 0; i < count; i++) {
                uint64_t begin = now();
                checksum += open_read_close();
                samples[i] = now() - begin;
            }
            measured = now() - start;
            qsort(samples, count, sizeof(*samples), compare_u64);
            p50 = samples[(count - 1) / 2];
            p99 = samples[(count - 1) * 99 / 100];
            slowest = samples[count - 1];
            latency = 1;
            free(samples);
        } else if (!strcmp(name, "spawn")) {
            for (uint64_t i = 0; i < count; i++) {
                pid_t child = fork();
                check(child >= 0, "fork");
                if (!child) { execl("/bin/true", "true", NULL); _exit(127); }
                int status;
                check(waitpid(child, &status, 0) == child, "waitpid");
                check(WIFEXITED(status) && WEXITSTATUS(status) == 0, "child exit");
            }
        } else { fprintf(stderr, "unknown case: %s\n", name); return 2; }
        elapsed = measured ? measured : now() - start;
    }
    char cwd[PATH_MAX];
    check(getcwd(cwd, sizeof(cwd)) != NULL, "getcwd");
    // The fixed benchmark workspace contains no JSON metacharacters.
    check(strcmp(cwd, "/sandbox") == 0, "expected /sandbox workdir");
    printf("{\"case\":\"%s\",\"iterations\":%llu,\"elapsed_ns\":%llu,\"checksum\":%llu,"
           "\"uid\":%u,\"gid\":%u,\"cwd\":\"%s\"",
           name, (unsigned long long)count, (unsigned long long)elapsed,
           (unsigned long long)checksum, (unsigned)getuid(), (unsigned)getgid(), cwd);
    if (latency)
        printf(",\"p50_ns\":%llu,\"p99_ns\":%llu,\"max_ns\":%llu", (unsigned long long)p50,
               (unsigned long long)p99, (unsigned long long)slowest);
    printf("}\n");
    return 0;
}
