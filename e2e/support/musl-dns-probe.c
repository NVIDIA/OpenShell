// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static bool is_synthetic_ipv4(const struct sockaddr *address) {
    if (address->sa_family != AF_INET) {
        return false;
    }

    const struct sockaddr_in *ipv4 = (const struct sockaddr_in *)address;
    const unsigned long host = ntohl(ipv4->sin_addr.s_addr);
    return (host & 0xfffe0000UL) == 0xc6120000UL;
}

static int connect_synthetic(const struct addrinfo *results) {
    for (const struct addrinfo *candidate = results; candidate != NULL;
         candidate = candidate->ai_next) {
        if (!is_synthetic_ipv4(candidate->ai_addr)) {
            continue;
        }

        int fd = socket(candidate->ai_family, candidate->ai_socktype,
                        candidate->ai_protocol);
        if (fd < 0) {
            continue;
        }

        struct timeval timeout = {.tv_sec = 5, .tv_usec = 0};
        (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                         sizeof(timeout));
        (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout,
                         sizeof(timeout));

        if (connect(fd, candidate->ai_addr, candidate->ai_addrlen) == 0) {
            return fd;
        }
        (void)close(fd);
    }

    return -1;
}

static bool send_all(int fd, const char *bytes, size_t length) {
    size_t sent = 0;
    while (sent < length) {
        const ssize_t result = send(fd, bytes + sent, length - sent, 0);
        if (result <= 0) {
            return false;
        }
        sent += (size_t)result;
    }
    return true;
}

static bool receive_exact(int fd, char *bytes, size_t length) {
    size_t received = 0;
    while (received < length) {
        const ssize_t result = recv(fd, bytes + received, length - received, 0);
        if (result <= 0) {
            return false;
        }
        received += (size_t)result;
    }
    return true;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s HOST PORT\n", argv[0]);
        return 2;
    }

    const struct addrinfo hints = {
        .ai_family = AF_UNSPEC,
        .ai_socktype = SOCK_STREAM,
        .ai_protocol = IPPROTO_TCP,
    };
    struct addrinfo *results = NULL;
    const int resolve_status = getaddrinfo(argv[1], argv[2], &hints, &results);
    if (resolve_status != 0) {
        fprintf(stderr, "musl getaddrinfo failed: %s\n",
                gai_strerror(resolve_status));
        return 1;
    }

    const int fd = connect_synthetic(results);
    freeaddrinfo(results);
    if (fd < 0) {
        fprintf(stderr,
                "musl getaddrinfo returned no connectable synthetic IPv4 address\n");
        return 1;
    }

    static const char request[] = "probe";
    if (!send_all(fd, request, sizeof(request) - 1)) {
        fprintf(stderr, "send failed: %s\n", strerror(errno));
        (void)close(fd);
        return 1;
    }

    static const char expected[] = "musl-native-tcp-ok:probe";
    char response[sizeof(expected) - 1] = {0};
    const bool received = receive_exact(fd, response, sizeof(response));
    (void)close(fd);
    if (!received) {
        fprintf(stderr, "receive failed: %s\n", strerror(errno));
        return 1;
    }

    if (memcmp(response, expected, sizeof(response)) != 0) {
        fprintf(stderr, "unexpected response: %.*s\n", (int)sizeof(response),
                response);
        return 1;
    }

    puts("musl-policy-dns-ok");
    return 0;
}
