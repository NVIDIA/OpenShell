# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Host-side HTTP server for the Cedar e2e suite.

Answers every request with JSON describing the method, path, and body it
received, so the test can see exactly what reached the upstream. Binds an
ephemeral port on all interfaces and writes the port to the path given as the
first argument.
"""

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

STATE_LOCK = threading.Lock()
STATE = {"paths": {}}
STATE_PATH = None


class EchoHandler(BaseHTTPRequestHandler):
    def _echo(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        # Synthetic fixture credentials stay in this server. Responses and
        # observations contain only generation labels, never header values.
        authorization = self.headers.get("Authorization")
        generation = {
            "Bearer cedar-e2e-dummy-initial": "initial",
            "Bearer cedar-e2e-dummy-rotated": "rotated",
        }.get(authorization, "missing" if authorization is None else "unknown")
        with STATE_LOCK:
            STATE["paths"][self.path] = STATE["paths"].get(self.path, 0) + 1
            if STATE_PATH:
                temporary = STATE_PATH.with_suffix(".tmp")
                with temporary.open("w", encoding="utf-8") as state_file:
                    json.dump(STATE, state_file)
                temporary.replace(STATE_PATH)
        payload = json.dumps(
            {
                "method": self.command,
                "path": self.path,
                "body": body,
                "credential_generation": generation,
            }
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_GET = _echo
    do_POST = _echo
    do_PUT = _echo
    do_DELETE = _echo

    def log_message(self, _format: str, *_args: object) -> None:
        return


def main() -> None:
    global STATE_PATH
    STATE_PATH = Path(sys.argv[2]) if len(sys.argv) > 2 else None
    if STATE_PATH:
        with STATE_PATH.open("w", encoding="utf-8") as state_file:
            json.dump(STATE, state_file)
    server = ThreadingHTTPServer(("0.0.0.0", 0), EchoHandler)
    with Path(sys.argv[1]).open("w", encoding="utf-8") as port_file:
        port_file.write(str(server.server_address[1]))
    server.serve_forever()


if __name__ == "__main__":
    main()
