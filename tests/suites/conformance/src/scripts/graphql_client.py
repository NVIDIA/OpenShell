# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Sends GraphQL queries, mutations, and persisted queries to HOST:PORT with
# urllib (`forward_*`) and raw sockets (`raw_*`), and prints each status as
# JSON.
import json
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

HOST = sys.argv[1]
PORT = int(sys.argv[2])
DETAILS = {}

QUERY_VIEWER = "query Viewer { viewer { login } }"
QUERY_REPOSITORY = "query Repo { repository(owner:\"o\", name:\"r\") { id } }"
MUTATION_CREATE = "mutation Create { createIssue(input:{repositoryId:\"r\", title:\"t\", body:\"b\"}) { issue { id } } }"
MUTATION_DELETE = "mutation Delete { deleteRepository(input:{repositoryId:\"r\"}) { clientMutationId } }"

def forward_status(query):
    body = json.dumps({"query": query}).encode()
    request = urllib.request.Request(
        f"http://{HOST}:{PORT}/graphql",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            response.read()
            return response.status
    except urllib.error.HTTPError as error:
        error.read()
        return error.code

def forward_get_status(query):
    encoded = urllib.parse.urlencode({"query": query})
    request = urllib.request.Request(
        f"http://{HOST}:{PORT}/graphql?{encoded}",
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            response.read()
            return response.status
    except urllib.error.HTTPError as error:
        error.read()
        return error.code

def forward_duplicate_get_status():
    safe = urllib.parse.quote_plus(QUERY_VIEWER)
    unsafe = urllib.parse.quote_plus(MUTATION_DELETE)
    request = urllib.request.Request(
        f"http://{HOST}:{PORT}/graphql?query={safe}&query={unsafe}",
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            response.read()
            return response.status
    except urllib.error.HTTPError as error:
        error.read()
        return error.code

def forward_persisted_get_status(hash_value):
    extensions = json.dumps({"persistedQuery": {"version": 1, "sha256Hash": hash_value}})
    encoded = urllib.parse.urlencode({"operationName": "Viewer", "extensions": extensions})
    request = urllib.request.Request(
        f"http://{HOST}:{PORT}/graphql?{encoded}",
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            response.read()
            return response.status
    except urllib.error.HTTPError as error:
        error.read()
        return error.code

def forward_chunked_status(query):
    target = f"{HOST}:{PORT}"
    body = json.dumps({"query": query}).encode()
    chunk = f"{len(body):x}\r\n".encode() + body + b"\r\n0\r\n\r\n"

    with socket.create_connection((HOST, PORT), timeout=15) as sock:
        request = (
            f"POST /graphql HTTP/1.1\r\n"
            f"Host: {target}\r\n"
            f"Content-Type: application/json\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode() + chunk
        sock.sendall(request)
        response, body = read_response(sock)
        DETAILS["forward_chunked_query_allowed_detail"] = body.decode(errors="replace")
        return status_code(response, "forward_chunked_response")

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

def raw_http_status(label, request):
    last_error = None
    for attempt in range(5):
        try:
            with socket.create_connection((HOST, PORT), timeout=15) as sock:
                sock.sendall(request)
                sock.shutdown(socket.SHUT_WR)
                response = read_until(sock, b"\r\n\r\n")
                return status_code(response, f"{label}_response")
        except (OSError, RuntimeError) as error:
            last_error = error
            DETAILS[f"{label}_attempt_{attempt + 1}_error"] = str(error)
            time.sleep(0.2)

    raise RuntimeError(f"{label}: failed after 5 attempts: {last_error}")

def raw_status(query, label):
    target = f"{HOST}:{PORT}"
    body = json.dumps({"query": query}).encode()

    request = (
        f"POST /graphql HTTP/1.1\r\n"
        f"Host: {target}\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode() + body
    return raw_http_status(label, request)

def raw_get_status(query, label):
    target = f"{HOST}:{PORT}"
    encoded = urllib.parse.urlencode({"query": query})

    request = (
        f"GET /graphql?{encoded} HTTP/1.1\r\n"
        f"Host: {target}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode()
    return raw_http_status(label, request)

def raw_duplicate_get_status():
    target = f"{HOST}:{PORT}"
    safe = urllib.parse.quote_plus(QUERY_VIEWER)
    unsafe = urllib.parse.quote_plus(MUTATION_DELETE)

    request = (
        f"GET /graphql?query={safe}&query={unsafe} HTTP/1.1\r\n"
        f"Host: {target}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode()
    return raw_http_status("raw_duplicate_get_denied", request)

def raw_persisted_get_status(hash_value, label):
    target = f"{HOST}:{PORT}"
    extensions = json.dumps({"persistedQuery": {"version": 1, "sha256Hash": hash_value}})
    encoded = urllib.parse.urlencode({"operationName": "Viewer", "extensions": extensions})

    request = (
        f"GET /graphql?{encoded} HTTP/1.1\r\n"
        f"Host: {target}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode()
    return raw_http_status(label, request)

def raw_chunked_status(query):
    target = f"{HOST}:{PORT}"
    body = json.dumps({"query": query}).encode()
    chunk = f"{len(body):x}\r\n".encode() + body + b"\r\n0\r\n\r\n"

    request = (
        f"POST /graphql HTTP/1.1\r\n"
        f"Host: {target}\r\n"
        f"Content-Type: application/json\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode() + chunk
    return raw_http_status("raw_chunked_query_allowed", request)

results = {
    "forward_query_allowed": forward_status(QUERY_VIEWER),
    "forward_get_query_allowed": forward_get_status(QUERY_VIEWER),
    "forward_duplicate_get_denied": forward_duplicate_get_status(),
    "forward_persisted_get_allowed": forward_persisted_get_status("abc123"),
    "forward_unregistered_persisted_get_denied": forward_persisted_get_status("missing"),
    "forward_chunked_query_allowed": forward_chunked_status(QUERY_VIEWER),
    "forward_unlisted_field_denied": forward_status(QUERY_REPOSITORY),
    "forward_mutation_allowed": forward_status(MUTATION_CREATE),
    "forward_deny_rule_denied": forward_status(MUTATION_DELETE),
    "raw_query_allowed": raw_status(QUERY_VIEWER, "raw_query_allowed"),
    "raw_get_query_allowed": raw_get_status(QUERY_VIEWER, "raw_get_query_allowed"),
    "raw_duplicate_get_denied": raw_duplicate_get_status(),
    "raw_persisted_get_allowed": raw_persisted_get_status("abc123", "raw_persisted_get_allowed"),
    "raw_unregistered_persisted_get_denied": raw_persisted_get_status("missing", "raw_unregistered_persisted_get_denied"),
    "raw_chunked_query_allowed": raw_chunked_status(QUERY_VIEWER),
    "raw_unlisted_field_denied": raw_status(QUERY_REPOSITORY, "raw_unlisted_field_denied"),
    "raw_mutation_allowed": raw_status(MUTATION_CREATE, "raw_mutation_allowed"),
    "raw_deny_rule_denied": raw_status(MUTATION_DELETE, "raw_deny_rule_denied"),
}
results.update(DETAILS)
print(json.dumps(results, sort_keys=True))
