// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// A provider preload must not be mistaken for libc's cancellation wrapper.
// Resolving this accept4 from the shim would recurse through shimmed accept.
extern int accept(int, void *, unsigned int *);
int accept4(int fd, void *address, unsigned int *length, int flags) {
    (void)flags;
    return accept(fd, address, length);
}
