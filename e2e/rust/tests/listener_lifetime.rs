// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e")]

use openshell_e2e::harness::sandbox::SandboxGuard;

const LIFETIME_PROBE: &str = r"
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
";

#[tokio::test]
async fn closing_or_exiting_listener_refuses_connections_and_releases_port() {
    let mut sandbox = SandboxGuard::create(&[]).await.expect("create sandbox");
    let output = sandbox
        .exec(&["python3", "-c", LIFETIME_PROBE])
        .await
        .expect("listener lifetime probe");
    let observer = r"
import json, os, sys
_, inode = json.loads(sys.argv[1])
for fd in os.listdir('/proc/self/fd'):
    try:
        target = os.readlink('/proc/self/fd/' + fd)
    except FileNotFoundError:
        continue
    assert target != 'socket:[' + str(inode) + ']', (fd, target)
";
    sandbox
        .exec(&["python3", "-c", observer, output.trim()])
        .await
        .expect("subsequent exec must not inherit closed listener");
    sandbox.cleanup().await;
}

#[tokio::test]
async fn unrelated_exec_does_not_inherit_broker_preconnect_socket() {
    // Request a non-CLOEXEC socket explicitly; Python's socket constructor
    // otherwise masks broker inheritance bugs by requesting SOCK_CLOEXEC.
    let owner = r"
import ctypes, json, os, socket, time
libc = ctypes.CDLL(None, use_errno=True)
fd = libc.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
assert fd >= 0, ctypes.get_errno()
assert os.get_inheritable(fd)
inode = int(os.readlink('/proc/self/fd/' + str(fd))[8:-1])
with open('/sandbox/preconnect-inode.json', 'w') as f:
    json.dump(inode, f)
while True:
    time.sleep(60)
";
    let mut sandbox = SandboxGuard::create_detached_main(&["python3", "-c", owner])
        .await
        .expect("create socket owner");
    let observer = r"
import json, os, time
path = '/sandbox/preconnect-inode.json'
for _ in range(100):
    try:
        with open(path) as f:
            inode = json.load(f)
        break
    except (FileNotFoundError, json.JSONDecodeError):
        time.sleep(0.1)
else:
    raise AssertionError('socket owner did not publish its inode')
for fd in os.listdir('/proc/self/fd'):
    try:
        target = os.readlink('/proc/self/fd/' + fd)
    except FileNotFoundError:
        continue
    assert target != 'socket:[' + str(inode) + ']', (fd, target)
print('broker socket was not inherited')
";
    sandbox
        .exec(&["python3", "-c", observer])
        .await
        .expect("unrelated exec inherited broker descriptor");
    sandbox.cleanup().await;
}
