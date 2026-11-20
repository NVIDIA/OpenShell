# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Sends GraphQL queries, mutations, and persisted queries to HOST:PORT with
# urllib (`forward_*`) and raw sockets (`raw_*`), and prints each status and
# the `error` code of its JSON body as JSON.
import json
import socket
import sys
import urllib.error
import urllib.parse
import urllib.request

HOST = sys.argv[1]
PORT = int(sys.argv[2])
TARGET = f"{HOST}:{PORT}"

QUERY_VIEWER = "query Viewer { viewer { login } }"
QUERY_REPOSITORY = "query Repo { repository(owner:\"o\", name:\"r\") { id } }"
MUTATION_CREATE = "mutation Create { createIssue(input:{repositoryId:\"r\", title:\"t\", body:\"b\"}) { issue { id } } }"
MUTATION_DELETE = "mutation Delete { deleteRepository(input:{repositoryId:\"r\"}) { clientMutationId } }"

def outcome(status, body):
    try:
        error = json.loads(body).get("error")
    except (ValueError, AttributeError):
        error = None
    return {"status": status, "error": error if isinstance(error, str) else None}

def urllib_outcome(request):
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return outcome(response.status, response.read())
    except urllib.error.HTTPError as error:
        return outcome(error.code, error.read())

def forward_post(query):
    return urllib_outcome(urllib.request.Request(
        f"http://{TARGET}/graphql",
        data=json.dumps({"query": query}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    ))

def forward_get(query_string):
    return urllib_outcome(urllib.request.Request(
        f"http://{TARGET}/graphql?{query_string}",
        method="GET",
    ))

def raw(request):
    with socket.create_connection((HOST, PORT), timeout=15) as sock:
        sock.sendall(request)
        response = b""
        while chunk := sock.recv(4096):
            response += chunk
    head, _, body = response.partition(b"\r\n\r\n")
    status_line = head.split(b"\r\n", 1)[0].split()
    if len(status_line) < 2 or not status_line[1].isdigit():
        return {"status": None, "error": None, "raw": response.decode(errors="replace")}
    return outcome(int(status_line[1]), body)

def raw_post(query, chunked=False):
    body = json.dumps({"query": query}).encode()
    if chunked:
        framing = "Transfer-Encoding: chunked"
        body = f"{len(body):x}\r\n".encode() + body + b"\r\n0\r\n\r\n"
    else:
        framing = f"Content-Length: {len(body)}"
    return raw((
        f"POST /graphql HTTP/1.1\r\nHost: {TARGET}\r\n"
        f"Content-Type: application/json\r\n{framing}\r\nConnection: close\r\n\r\n"
    ).encode() + body)

def raw_get(query_string):
    return raw((
        f"GET /graphql?{query_string} HTTP/1.1\r\nHost: {TARGET}\r\nConnection: close\r\n\r\n"
    ).encode())

def get_query(query):
    return urllib.parse.urlencode({"query": query})

def duplicate_get_query():
    safe = urllib.parse.quote_plus(QUERY_VIEWER)
    unsafe = urllib.parse.quote_plus(MUTATION_DELETE)
    return f"query={safe}&query={unsafe}"

def persisted_get_query(hash_value):
    extensions = json.dumps({"persistedQuery": {"version": 1, "sha256Hash": hash_value}})
    return urllib.parse.urlencode({"operationName": "Viewer", "extensions": extensions})

results = {}
for path, post, get in [("forward", forward_post, forward_get), ("raw", raw_post, raw_get)]:
    results.update({
        f"{path}_query_allowed": post(QUERY_VIEWER),
        f"{path}_get_query_allowed": get(get_query(QUERY_VIEWER)),
        f"{path}_duplicate_get_denied": get(duplicate_get_query()),
        f"{path}_persisted_get_allowed": get(persisted_get_query("abc123")),
        f"{path}_unregistered_persisted_get_denied": get(persisted_get_query("missing")),
        f"{path}_chunked_query_allowed": raw_post(QUERY_VIEWER, chunked=True),
        f"{path}_unlisted_field_denied": post(QUERY_REPOSITORY),
        f"{path}_mutation_allowed": post(MUTATION_CREATE),
        f"{path}_deny_rule_denied": post(MUTATION_DELETE),
    })
print(json.dumps(results, sort_keys=True))
