# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Sends JSON-RPC calls, batches, and invalid JSON to HOST:PORT/rpc with
# urllib (`forward_*`) and raw sockets (`raw_*`), and prints each status as
# JSON.
import json
import socket
import sys
import time
import urllib.error
import urllib.request

HOST = sys.argv[1]
PORT = int(sys.argv[2])
DETAILS = {
    "debug_target": {"host": HOST, "port": PORT},
}

def text(data):
    return data.decode(errors="replace")

def selected_headers(headers):
    return {
        key.lower(): value
        for key, value in headers.items()
        if key.lower() in ("content-type", "content-length", "server")
    }

def record_http_error(label, error, request_body):
    response_body = error.read()
    DETAILS[f"{label}_request"] = request_body
    DETAILS[f"{label}_response"] = {
        "status": error.code,
        "reason": str(error.reason),
        "headers": selected_headers(error.headers),
        "body": text(response_body),
    }
    return error.code

def post_jsonrpc(label, method, params=None, req_id=1):
    body = {"jsonrpc": "2.0", "id": req_id, "method": method}
    if params is not None:
        body["params"] = params
    encoded = json.dumps(body).encode()
    request = urllib.request.Request(
        f"http://{HOST}:{PORT}/rpc",
        data=encoded,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            response.read()
            return response.status
    except urllib.error.HTTPError as error:
        return record_http_error(label, error, body)

def post_jsonrpc_batch(label, requests):
    encoded = json.dumps(requests).encode()
    request = urllib.request.Request(
        f"http://{HOST}:{PORT}/rpc",
        data=encoded,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            response.read()
            return response.status
    except urllib.error.HTTPError as error:
        return record_http_error(label, error, requests)

def post_invalid_json(label):
    encoded = b"not valid json {"
    request = urllib.request.Request(
        f"http://{HOST}:{PORT}/rpc",
        data=encoded,
        headers={"Content-Type": "application/json", "Content-Length": str(len(encoded))},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            response.read()
            return response.status
    except urllib.error.HTTPError as error:
        return record_http_error(label, error, text(encoded))

def read_until(sock, marker):
    data = b""
    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data

def read_response(sock):
    response = read_until(sock, b"\r\n\r\n")
    headers, _, body = response.partition(b"\r\n\r\n")
    content_length = 0
    for line in headers.split(b"\r\n")[1:]:
        if line.lower().startswith(b"content-length:"):
            content_length = int(line.split(b":", 1)[1].strip())
            break
    while len(body) < content_length:
        chunk = sock.recv(4096)
        if not chunk:
            break
        body += chunk
    return response, body

def status_code(response, label):
    parts = response.split()
    if len(parts) < 2:
        DETAILS[f"{label}_raw"] = response.decode(errors="replace")
        raise RuntimeError(f"{label}: malformed HTTP response: {response!r}")
    try:
        return int(parts[1])
    except ValueError as error:
        DETAILS[f"{label}_raw"] = response.decode(errors="replace")
        raise RuntimeError(f"{label}: non-numeric HTTP status: {response!r}") from error

def record_raw_response(label, response, body=b""):
    code = status_code(response, label)
    if code != 200:
        DETAILS[f"{label}_raw"] = text(response)
        if body:
            DETAILS[f"{label}_body"] = text(body)
    return code

def raw_http_status(label, request):
    last_error = None
    for attempt in range(5):
        try:
            with socket.create_connection((HOST, PORT), timeout=15) as sock:
                sock.sendall(request)
                sock.shutdown(socket.SHUT_WR)
                response, body = read_response(sock)
                return record_raw_response(f"{label}_response", response, body)
        except (OSError, RuntimeError) as error:
            last_error = error
            DETAILS[f"{label}_attempt_{attempt + 1}_error"] = str(error)
            time.sleep(0.2)

    raise RuntimeError(f"{label}: failed after 5 attempts: {last_error}")

def raw_jsonrpc_status(method, params, label):
    target = f"{HOST}:{PORT}"
    body = {"jsonrpc": "2.0", "id": 1, "method": method}
    if params is not None:
        body["params"] = params
    encoded = json.dumps(body).encode()
    request = (
        f"POST /rpc HTTP/1.1\r\n"
        f"Host: {target}\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: {len(encoded)}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode() + encoded
    return raw_http_status(label, request)

results = {
    # forward proxy — method-only allow rules
    "forward_method_initialize_allowed": post_jsonrpc("forward_method_initialize_allowed", "initialize", {"protocolVersion": "2025-11-25", "capabilities": {}}),
    "forward_method_tools_list_allowed": post_jsonrpc("forward_method_tools_list_allowed", "tools/list"),

    # forward proxy — method allow/deny rules
    "forward_method_tools_call_allowed": post_jsonrpc("forward_method_tools_call_allowed", "tools/call", {"name": "read_status"}),
    "forward_method_tools_call_with_unmatched_params_allowed": post_jsonrpc("forward_method_tools_call_with_unmatched_params_allowed", "tools/call", {"name": "blocked_action", "arguments": {"scope": "ignored"}}),
    "forward_method_tools_delete_denied": post_jsonrpc("forward_method_tools_delete_denied", "tools/delete", {"name": "purge_cache"}),

    # forward proxy — batch: all requests allowed
    "forward_batch_all_allowed": post_jsonrpc_batch("forward_batch_all_allowed", [
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "read_status"}},
    ]),

    # forward proxy — batch: one denied request causes full batch denial
    "forward_batch_one_denied": post_jsonrpc_batch("forward_batch_one_denied", [
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/delete", "params": {"name": "purge_cache"}},
    ]),

    # forward proxy — invalid JSON body fails closed before generic rules apply
    "forward_invalid_json_denied": post_invalid_json("forward_invalid_json_denied"),

    # raw socket path — representative allowed and denied cases
    "raw_method_initialize_allowed": raw_jsonrpc_status("initialize", {"protocolVersion": "2025-11-25", "capabilities": {}}, "raw_method_initialize_allowed"),
    "raw_method_tools_list_allowed": raw_jsonrpc_status("tools/list", None, "raw_method_tools_list_allowed"),
    "raw_method_tools_call_allowed": raw_jsonrpc_status("tools/call", {"name": "read_status"}, "raw_method_tools_call_allowed"),
    "raw_method_tools_call_with_unmatched_params_allowed": raw_jsonrpc_status("tools/call", {"name": "blocked_action", "arguments": {"scope": "ignored"}}, "raw_method_tools_call_with_unmatched_params_allowed"),
    "raw_method_tools_delete_denied": raw_jsonrpc_status("tools/delete", {"name": "purge_cache"}, "raw_method_tools_delete_denied"),
}
results.update(DETAILS)
print(json.dumps(results, sort_keys=True))
