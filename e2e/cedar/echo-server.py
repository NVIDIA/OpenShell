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
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class EchoHandler(BaseHTTPRequestHandler):
    def _echo(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        payload = json.dumps(
            {"method": self.command, "path": self.path, "body": body}
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

    def log_message(self, format: str, *args: object) -> None:
        return


def main() -> None:
    server = ThreadingHTTPServer(("0.0.0.0", 0), EchoHandler)
    with open(sys.argv[1], "w", encoding="utf-8") as port_file:
        port_file.write(str(server.server_address[1]))
    server.serve_forever()


if __name__ == "__main__":
    main()
