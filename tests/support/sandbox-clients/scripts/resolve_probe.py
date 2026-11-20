# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Runs inside the sandbox, so its lookup goes through the sandbox's resolver.
# It follows the contract in tests/testkit/README.md ("Writing a sandbox
# client"): standard library only, input from argv, one JSON line out, and
# parsing in Rust (src/resolve.rs).
#
# Resolves argv[1] for TCP port argv[2] with getaddrinfo, and prints the
# distinct addresses it returned, or the resolver's error, as one JSON line.
import json
import socket
import sys

HOST = sys.argv[1]
PORT = int(sys.argv[2])

result = {"addresses": [], "error": None}
try:
    answers = socket.getaddrinfo(HOST, PORT, type=socket.SOCK_STREAM)
except OSError as error:
    result["error"] = repr(error)
else:
    result["addresses"] = sorted({answer[4][0] for answer in answers})

print(json.dumps(result, sort_keys=True), flush=True)
