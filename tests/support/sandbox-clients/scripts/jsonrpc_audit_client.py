# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Sends an unlisted JSON-RPC method and a response frame to HOST:PORT/rpc,
# and prints each status and the `error` code of its JSON body as JSON.
import json
import sys
import urllib.error
import urllib.request

HOST = sys.argv[1]
PORT = int(sys.argv[2])

def outcome(status, body):
    try:
        error = json.loads(body).get("error")
    except (ValueError, AttributeError):
        error = None
    return {"status": status, "error": error if isinstance(error, str) else None}

def post_jsonrpc(body):
    encoded = json.dumps(body).encode()
    request = urllib.request.Request(
        f"http://{HOST}:{PORT}/rpc",
        data=encoded,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return outcome(response.status, response.read())
    except urllib.error.HTTPError as error:
        return outcome(error.code, error.read())

results = {
    "forward_unknown_method_audited": post_jsonrpc({"jsonrpc": "2.0", "id": 1, "method": "unknown/method"}),
    "forward_response_frame_hard_denied": post_jsonrpc({"jsonrpc": "2.0", "id": 1, "result": {}}),
}
print(json.dumps(results, sort_keys=True))
