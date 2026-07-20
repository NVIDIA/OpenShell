// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Verify the capability-bounding-set condition behind issue #2069 from
// inside a rootless Podman container.

#include <errno.h>
#include <linux/capability.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>

static unsigned long long status_capability(const char *field) {
    FILE *status = fopen("/proc/self/status", "r");
    if (status == NULL) {
        perror("fopen(/proc/self/status)");
        exit(EXIT_FAILURE);
    }

    char line[256];
    unsigned long long value = 0;
    int found = 0;
    while (fgets(line, sizeof(line), status) != NULL) {
        char name[32];
        unsigned long long candidate;
        if (sscanf(line, "%31[^:]:%llx", name, &candidate) == 2 &&
            strcmp(name, field) == 0) {
            value = candidate;
            found = 1;
            break;
        }
    }
    fclose(status);

    if (!found) {
        fprintf(stderr, "missing %s in /proc/self/status\n", field);
        exit(EXIT_FAILURE);
    }
    return value;
}

static void print_apparmor_profile(void) {
    FILE *profile = fopen("/proc/self/attr/current", "r");
    if (profile == NULL) {
        perror("fopen(/proc/self/attr/current)");
        return;
    }

    char line[256];
    if (fgets(line, sizeof(line), profile) != NULL) {
        printf("apparmor_profile=%s", line);
        if (strchr(line, '\n') == NULL) {
            putchar('\n');
        }
    }
    fclose(profile);
}

int main(int argc, char **argv) {
    if (argc != 1) {
        fprintf(stderr, "usage: %s\n", argv[0]);
        return EXIT_FAILURE;
    }

    const unsigned long long setpcap_mask = 1ULL << CAP_SETPCAP;
    const unsigned long long cap_bnd_before = status_capability("CapBnd");
    const unsigned long long cap_eff_before = status_capability("CapEff");
    const int setpcap_before = prctl(PR_CAPBSET_READ, CAP_SETPCAP, 0, 0, 0);
    if (setpcap_before == -1) {
        perror("prctl(PR_CAPBSET_READ) before drop");
        return EXIT_FAILURE;
    }

    print_apparmor_profile();
    printf("cap_bnd_before=%016llx\n", cap_bnd_before);
    printf("cap_eff_before=%016llx\n", cap_eff_before);
    printf("setpcap_bounding_before=%d\n", setpcap_before);

    if (cap_bnd_before == 0 || (cap_bnd_before & setpcap_mask) == 0 ||
        (cap_eff_before & setpcap_mask) == 0 || setpcap_before != 1) {
        fprintf(stderr, "CAP_SETPCAP must be effective and present in a non-empty bounding set\n");
        return EXIT_FAILURE;
    }

    errno = 0;
    const int drop_result = prctl(PR_CAPBSET_DROP, CAP_SETPCAP, 0, 0, 0);
    const int drop_errno = errno;
    const unsigned long long cap_bnd_after = status_capability("CapBnd");
    const int setpcap_after = prctl(PR_CAPBSET_READ, CAP_SETPCAP, 0, 0, 0);

    printf("drop_result=%d\n", drop_result);
    printf("drop_errno=%d (%s)\n", drop_errno, strerror(drop_errno));
    printf("cap_bnd_after=%016llx\n", cap_bnd_after);
    printf("setpcap_bounding_after=%d\n", setpcap_after);

    if (drop_result == 0) {
        if (setpcap_after != 0 || (cap_bnd_after & setpcap_mask) != 0) {
            fprintf(stderr, "CAP_SETPCAP remained in the bounding set after a successful drop\n");
            return EXIT_FAILURE;
        }
    } else if (drop_errno == EPERM) {
        if (setpcap_after != 1 || (cap_bnd_after & setpcap_mask) == 0) {
            fprintf(stderr, "CAP_SETPCAP changed in the bounding set after EPERM\n");
            return EXIT_FAILURE;
        }
    } else {
        fprintf(stderr, "unexpected PR_CAPBSET_DROP result\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
