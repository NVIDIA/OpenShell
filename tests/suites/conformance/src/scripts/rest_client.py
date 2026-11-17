# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Prints the status of GET and POST to /allowed as JSON.
import json
import sys
import urllib.error
import urllib.request

HOST = sys.argv[1]
PORT = int(sys.argv[2])


def status(method, data=None):
    request = urllib.request.Request(f"http://{HOST}:{PORT}/allowed", data=data, method=method)
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            response.read()
            return response.status
    except urllib.error.HTTPError as error:
        error.read()
        return error.code


print(json.dumps({"get": status("GET"), "post": status("POST", b"test")}, sort_keys=True))
