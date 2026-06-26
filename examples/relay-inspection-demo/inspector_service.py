#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def redact_text(value: str) -> str:
    return value.replace("alice@example.com", "[redacted-email]")


def redact_json(value):
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, list):
        return [redact_json(item) for item in value]
    if isinstance(value, dict):
        return {key: redact_json(item) for key, item in value.items()}
    return value


def inspect(payload: dict) -> dict:
    target = payload.get("target") or {}
    kind = target.get("kind")

    if kind == "llm_request":
        request = target.get("request")
        if isinstance(request, dict):
            redacted = redact_json(request)
            if redacted != request:
                return {
                    "kind": "mutate",
                    "target": {
                        "kind": "llm_request",
                        "provider": target.get("provider", ""),
                        "request": redacted,
                    },
                    "findings": [
                        {
                            "code": "pii_redacted",
                            "message": "redacted email address from llm request",
                        }
                    ],
                }
        return {"kind": "allow"}

    if kind == "tool_request":
        tool_name = target.get("tool_name", "")
        tool_input = target.get("input")
        encoded = json.dumps(tool_input, sort_keys=True)
        if "DROP TABLE" in encoded:
            return {
                "kind": "deny",
                "reason": f"blocked dangerous tool input for {tool_name}",
                "findings": [
                    {
                        "code": "dangerous_tool_input",
                        "message": "tool input matched blocked sql pattern",
                    }
                ],
            }
        if isinstance(tool_input, dict) and tool_input.get("query") == "books":
            mutated = dict(tool_input)
            mutated["relay_inspected"] = True
            return {
                "kind": "mutate",
                "target": {
                    "kind": "tool_request",
                    "tool_name": tool_name,
                    "input": mutated,
                },
                "findings": [
                    {
                        "code": "tool_request_annotated",
                        "message": "annotated tool request for demo visibility",
                    }
                ],
            }
        return {"kind": "allow"}

    if kind == "http_request":
        path = target.get("path", "")
        headers = target.get("headers") or []
        if path == "/blocked":
            return {
                "kind": "deny",
                "reason": "blocked outbound request by path",
                "findings": [
                    {
                        "code": "blocked_path",
                        "message": "http request matched blocked demo path",
                    }
                ],
            }
        header_names = {name.lower() for name, _ in headers if isinstance(name, str)}
        if "x-inspected" not in header_names:
            mutated = list(headers)
            mutated.append(("x-inspected", "true"))
            return {
                "kind": "mutate",
                "target": {
                    "kind": "http_request",
                    "method": target.get("method", ""),
                    "path": path,
                    "headers": mutated,
                    "body": target.get("body", []),
                },
                "findings": [
                    {
                        "code": "header_injected",
                        "message": "added x-inspected header at runtime boundary",
                    }
                ],
            }
        return {"kind": "allow"}

    return {"kind": "allow"}


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/inspect":
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        payload = json.loads(body or b"{}")
        response = inspect(payload)
        encoded = json.dumps(response).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, *_args):
        return


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=7777)
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"relay inspection demo listening on http://{args.host}:{args.port}/inspect")
    server.serve_forever()


if __name__ == "__main__":
    main()
