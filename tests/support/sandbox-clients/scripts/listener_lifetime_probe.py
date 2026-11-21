# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Closes listeners and exits a child that owns one, and checks each time that
# the port refuses connections and can be bound again. Prints the child
# listener's address and socket inode as JSON.
import errno, json, os, socket, subprocess, sys

def assert_closed(address, inode):
    # Check before bind can trigger the broker's stale-descriptor collection.
    for table in ('/proc/net/tcp', '/proc/net/tcp6'):
        for line in open(table):
            fields = line.split()
            assert not (len(fields) > 9 and fields[3] == '0A' and fields[9] == str(inode)), line
    with socket.socket() as client:
        client.settimeout(2)
        assert client.connect_ex(tuple(address)) == errno.ECONNREFUSED, address
    with socket.socket() as replacement:
        replacement.bind(tuple(address))

def inode(sock):
    return int(os.readlink('/proc/self/fd/' + str(sock.fileno()))[8:-1])

with socket.socket() as bound:
    bound.bind(('127.0.0.1', 0))
    address = bound.getsockname()
with socket.socket() as client:
    client.settimeout(2)
    assert client.connect_ex(address) == errno.ECONNREFUSED

for host in ('127.0.0.1', '::1'):
    family = socket.AF_INET if host == '127.0.0.1' else socket.AF_INET6
    listener = socket.socket(family)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((host, 0))
    listener.listen(1)
    listener.listen(8)
    address, identity = listener.getsockname(), inode(listener)
    for operation, expected in ((lambda: listener.bind(address), errno.EINVAL),
                                (lambda: listener.connect(address), errno.EISCONN)):
        try:
            operation()
            raise AssertionError('operation on listener unexpectedly succeeded')
        except OSError as error:
            assert error.errno == expected, error
    alias = listener.dup()
    alias.settimeout(2)
    listener.close()
    with socket.socket(family) as client:
        client.settimeout(2)
        client.connect(address)
        accepted, _ = alias.accept()
        with accepted:
            accepted.sendall(b'ok')
            assert client.recv(2) == b'ok'
    alias.close()
    table = '/proc/net/tcp' if family == socket.AF_INET else '/proc/net/tcp6'
    for line in open(table):
        fields = line.split()
        assert not (len(fields) > 9 and fields[3] == '0A' and fields[9] == str(identity)), line
    with socket.socket(family) as client:
        client.settimeout(2)
        assert client.connect_ex(address) == errno.ECONNREFUSED
    with socket.socket(family) as replacement:
        replacement.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        replacement.bind(address)

# The child exits while still owning its listener. Its broker must not keep it alive.
child = r'''
import json, os, socket
s = socket.socket()
s.bind(('127.0.0.1', 0))
s.listen()
inode = int(os.readlink('/proc/self/fd/' + str(s.fileno()))[8:-1])
print(json.dumps([s.getsockname(), inode]), flush=True)
os._exit(0)
'''
result = subprocess.run([sys.executable, '-c', child], check=True, capture_output=True, text=True, timeout=10)
address, identity = json.loads(result.stdout)
assert_closed(address, identity)
print(json.dumps([address, identity]))
