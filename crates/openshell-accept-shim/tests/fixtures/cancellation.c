// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Run in its own C process: pthread cancellation must not unwind Rust frames.
#define _GNU_SOURCE
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

static int listener;
static int use_accept4;
static int with_address;
static int disable_cancellation;
static atomic_int ready;
static atomic_int go;

static void *worker(void *unused) {
    (void)unused;
    if (disable_cancellation &&
        pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL) != 0) {
        abort();
    }
    atomic_store(&ready, 1);
    // Stage cancellation before accept, without passing a cancellation point.
    while (!atomic_load(&go)) {
        sched_yield();
    }
    struct sockaddr_storage peer;
    socklen_t length = sizeof(peer);
    struct sockaddr *address = with_address ? (struct sockaddr *)&peer : NULL;
    socklen_t *address_length = with_address ? &length : NULL;
    int accepted = use_accept4 ? accept4(listener, address, address_length, 0)
                               : accept(listener, address, address_length);
    if (!disable_cancellation || accepted < 0) {
        abort();
    }
    close(accepted);
    int old_type;
    int old_state;
    if (pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, &old_type) != 0 ||
        old_type != PTHREAD_CANCEL_DEFERRED ||
        pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &old_state) != 0 ||
        old_state != PTHREAD_CANCEL_DISABLE) {
        abort();
    }
    // The shim must preserve disabled cancellation and restore the type.
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    pthread_testcancel();
    abort();
}

int main(int argc, char **argv) {
    if (argc != 4) {
        return 2;
    }
    use_accept4 = atoi(argv[1]);
    with_address = atoi(argv[2]);
    disable_cancellation = atoi(argv[3]);
    listener = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    snprintf(address.sun_path + 1, sizeof(address.sun_path) - 1,
             "openshell-cancellation-%ld", (long)getpid());
    if (listener < 0 || bind(listener, (struct sockaddr *)&address,
                             sizeof(address)) != 0 || listen(listener, 1) != 0) {
        perror("listener");
        return 1;
    }
    pthread_t thread;
    if (pthread_create(&thread, NULL, worker, NULL) != 0) {
        return 1;
    }
    while (!atomic_load(&ready)) {
        sched_yield();
    }
    if (pthread_cancel(thread) != 0) {
        return 1;
    }
    int client = -1;
    if (disable_cancellation) {
        client = socket(AF_UNIX, SOCK_STREAM, 0);
        if (client < 0 || connect(client, (struct sockaddr *)&address,
                                  sizeof(address)) != 0) {
            perror("connect");
            return 1;
        }
    }
    atomic_store(&go, 1);
    struct timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += 2;
    void *result;
    int error = pthread_timedjoin_np(thread, &result, &deadline);
    if (error != 0 || result != PTHREAD_CANCELED) {
        fprintf(stderr, "join error=%d; expected a cancelled worker\n", error);
        return 1;
    }
    if (client >= 0) {
        close(client);
    }
    close(listener);
    return 0;
}
