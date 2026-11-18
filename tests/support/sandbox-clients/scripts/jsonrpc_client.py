# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Sends JSON-RPC calls, batches, and invalid JSON to HOST:PORT/rpc with
# urllib (`forward_*`) and raw sockets (`raw_*`), and prints each status and
# the `error` code of its JSON body as JSON.
import json
import socket
import sys
import urllib.error
import urllib.request

HOST = sys.argv[1]
PORT = int(sys.argv[2])
TARGET = f"{HOST}:{PORT}"

def outcome(status, body):
    try:
        error = json.loads(body).get("error")
    except (ValueError, AttributeError):
        error = None
    return {"status": status, "error": error if isinstance(error, str) else None}

def forward(body):
    request = urllib.request.Request(
        f"http://{TARGET}/rpc",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return outcome(response.status, response.read())
    except urllib.error.HTTPError as error:
        return outcome(error.code, error.read())

def raw(request):
    with socket.create_connection((HOST, PORT), timeout=15) as sock:
        sock.sendall(request)
        sock.shutdown(socket.SHUT_WR)
        response = b""
        while chunk := sock.recv(4096):
            response += chunk
    head, _, body = response.partition(b"\r\n\r\n")
    status_line = head.split(b"\r\n", 1)[0].split()
    if len(status_line) < 2 or not status_line[1].isdigit():
        return {"status": None, "error": None, "raw": response.decode(errors="replace")}
    return outcome(int(status_line[1]), body)

def call(method, params=None):
    body = {"jsonrpc": "2.0", "id": 1, "method": method}
    if params is not None:
        body["params"] = params
    return json.dumps(body).encode()

def raw_post(path, body):
    return raw((
        f"POST {path} HTTP/1.1\r\nHost: {TARGET}\r\nContent-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
    ).encode() + body)

def raw_rpc(body):
    return raw_post("/rpc", body)

INITIALIZE = call("initialize", {"protocolVersion": "2025-11-25", "capabilities": {}})
CALLS = {
    "method_initialize_allowed": INITIALIZE,
    "method_tools_list_allowed": call("tools/list"),
    "method_tools_call_allowed": call("tools/call", {"name": "read_status"}),
    "method_tools_call_with_unmatched_params_allowed": call(
        "tools/call", {"name": "blocked_action", "arguments": {"scope": "ignored"}}
    ),
    "method_tools_delete_denied": call("tools/delete", {"name": "purge_cache"}),
    "unlisted_method_denied": call("admin.delete"),
}

results = {
    # The broad REST endpoint still permits requests outside the RPC route.
    "rest_route_allowed": raw_post("/api/status", b""),
    # One denied call in a batch denies the whole batch.
    "forward_batch_all_allowed": forward(json.dumps([
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "read_status"}},
    ]).encode()),
    "forward_batch_one_denied": forward(json.dumps([
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/delete", "params": {"name": "purge_cache"}},
    ]).encode()),
    # An invalid JSON body fails closed before generic rules apply.
    "forward_invalid_json_denied": forward(b"not valid json {"),
}
for key, body in CALLS.items():
    results[f"forward_{key}"] = forward(body)
    results[f"raw_{key}"] = raw_rpc(body)
print(json.dumps(results, sort_keys=True))
