# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Runs inside the sandbox, so the sandbox policy applies to its connection.
# It follows the contract in tests/testkit/README.md ("Writing a sandbox
# client"): standard library only, input from argv, one JSON line out, and
# parsing in Rust (src/probe.rs).
#
# Connects to argv[1]:argv[2], sends the bytes hex-encoded in argv[3] ("-"
# to only connect), and reads until the connection ends. Prints how each step
# went as one JSON line; failures to connect or read are results, not errors.
#
# argv[4]: connect timeout in seconds.
# argv[5]: timeout in seconds for sending and all of the reading.
# argv[6]: idle timeout in seconds: stop reading after this long without
#          bytes. 0 waits for the read timeout instead.
import json
import socket
import sys
import time

HOST = sys.argv[1]
PORT = int(sys.argv[2])
PAYLOAD = None if sys.argv[3] == "-" else bytes.fromhex(sys.argv[3])
CONNECT_TIMEOUT = float(sys.argv[4])
READ_TIMEOUT = float(sys.argv[5])
IDLE_TIMEOUT = float(sys.argv[6])

result = {
    "connect": None,
    "errno": None,
    "dns": False,
    "error": None,
    "connect_ms": None,
    "read_end": None,
    "read_errno": None,
    "read_error": None,
    "received_hex": "",
}


def millis(since):
    return int((time.monotonic() - since) * 1000)


def exchange(sock):
    """Send PAYLOAD and read until the connection ends. Returns the bytes
    read and how reading ended."""
    received = bytearray()
    deadline = time.monotonic() + READ_TIMEOUT
    try:
        sock.settimeout(READ_TIMEOUT)
        sock.sendall(PAYLOAD)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return received, "timeout"
            idle = 0 < IDLE_TIMEOUT < remaining
            sock.settimeout(IDLE_TIMEOUT if idle else remaining)
            try:
                chunk = sock.recv(65536)
            except socket.timeout:
                return received, "idle" if idle else "timeout"
            if not chunk:
                return received, "closed"
            received += chunk
    except socket.timeout:
        return received, "timeout"
    except ConnectionResetError:
        return received, "reset"
    except OSError as error:
        result["read_errno"] = error.errno
        result["read_error"] = repr(error)
        return received, "failed"


start = time.monotonic()
try:
    sock = socket.create_connection((HOST, PORT), timeout=CONNECT_TIMEOUT)
except socket.timeout:
    result["connect"] = "timeout"
except OSError as error:
    result["connect"] = "failed"
    # A resolver failure's code is an EAI_* value, not an errno.
    if isinstance(error, socket.gaierror):
        result["dns"] = True
    else:
        result["errno"] = error.errno
    result["error"] = repr(error)
else:
    result["connect"] = "ok"
result["connect_ms"] = millis(start)

if result["connect"] == "ok":
    with sock:
        if PAYLOAD is not None:
            received, read_end = exchange(sock)
            result["received_hex"] = received.hex()
            result["read_end"] = read_end

print(json.dumps(result, sort_keys=True), flush=True)
