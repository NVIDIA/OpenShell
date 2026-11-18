# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Opens an inheritable socket, writes its inode to /sandbox/preconnect-inode,
# and sleeps. It asks libc for the socket, since Python's socket constructor
# requests SOCK_CLOEXEC, which would hide an inheritance bug.
import ctypes
import os
import socket
import time

libc = ctypes.CDLL(None, use_errno=True)
fd = libc.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
assert fd >= 0, ctypes.get_errno()
assert os.get_inheritable(fd)
inode = int(os.readlink('/proc/self/fd/' + str(fd))[8:-1])
with open('/sandbox/preconnect-inode.tmp', 'w') as f:
    f.write(str(inode))
os.rename('/sandbox/preconnect-inode.tmp', '/sandbox/preconnect-inode')
while True:
    time.sleep(60)
