# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Fails if this process holds the socket whose inode is argv[1].
import os
import sys

inode = int(sys.argv[1])
for fd in os.listdir('/proc/self/fd'):
    try:
        target = os.readlink('/proc/self/fd/' + fd)
    except FileNotFoundError:
        continue
    assert target != 'socket:[' + str(inode) + ']', (fd, target)
