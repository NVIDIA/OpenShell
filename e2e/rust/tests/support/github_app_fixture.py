# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Local installation-token issuer, authenticated REST API, and smart Git HTTPS."""

import base64
import json
import os
import socket
import ssl
import subprocess
import tempfile
import threading
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

root = Path(tempfile.mkdtemp())
os.chdir(root)


def run(*args):
    return subprocess.run(args, check=True, capture_output=True)


run(
    "openssl",
    "req",
    "-x509",
    "-newkey",
    "rsa:2048",
    "-nodes",
    "-days",
    "1",
    "-subj",
    "/CN=OpenShell E2E CA",
    "-keyout",
    "ca.key",
    "-out",
    "ca.crt",
    "-addext",
    "basicConstraints=critical,CA:TRUE",
)
run(
    "openssl",
    "req",
    "-newkey",
    "rsa:2048",
    "-nodes",
    "-subj",
    "/CN=FIXTURE_HOST",
    "-keyout",
    "server.key",
    "-out",
    "server.csr",
)
Path("server.ext").write_text(
    "subjectAltName=IP:FIXTURE_HOST\nbasicConstraints=critical,CA:FALSE\nextendedKeyUsage=serverAuth\n"
)
run(
    "openssl",
    "x509",
    "-req",
    "-in",
    "server.csr",
    "-CA",
    "ca.crt",
    "-CAkey",
    "ca.key",
    "-CAcreateserial",
    "-days",
    "1",
    "-extfile",
    "server.ext",
    "-out",
    "server.crt",
)
print(Path("ca.crt").read_text(), flush=True)

run("git", "init", "--initial-branch=main", "seed")
Path("seed/README.md").write_text("GitHub App installation token E2E\n")
run("git", "-C", "seed", "add", "README.md")
run(
    "git",
    "-C",
    "seed",
    "-c",
    "user.name=E2E",
    "-c",
    "user.email=e2e@example.invalid",
    "commit",
    "-m",
    "Initial fixture",
)
run("git", "clone", "--bare", "seed", "repo.git")

current_token = "bootstrap-token"
generation = 0
lock = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    def reply(self, status, body=b"", content_type="application/json"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def authorized(self):
        with lock:
            token = current_token
        basic = "Basic " + base64.b64encode(f"x-access-token:{token}".encode()).decode()
        if self.path == "/probe":
            return self.headers.get("Authorization") in (f"Bearer {token}", basic)
        # Require the proper auth style on each surface. Never log headers.
        expected = basic if self.path.startswith("/repo.git/") else f"Bearer {token}"
        return self.headers.get("Authorization") == expected

    def do_POST(self):
        global current_token, generation
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        if self.path == "/token" and self.server.server_port == 8000:
            with lock:
                generation += 1
                current_token = f"oauth-token-{generation}"
                token = current_token
            self.reply(
                200,
                json.dumps(
                    {"access_token": token, "expires_in": 300, "token_type": "Bearer"}
                ).encode(),
            )
            return
        if (
            self.path == "/app/installations/123/access_tokens"
            and self.server.server_port == 8000
        ):
            if json.loads(body) != {
                "repository_ids": [42],
                "permissions": {"contents": "read"},
            } or not self.headers.get("Authorization", "").startswith("Bearer ey"):
                self.reply(422)
                return
            with lock:
                generation += 1
                current_token = f"installation-token-{generation}"
                token = current_token
            self.reply(
                201,
                json.dumps(
                    {
                        "token": token,
                        "expires_at": (
                            datetime.now(UTC) + timedelta(seconds=300)
                        ).isoformat(),
                    }
                ).encode(),
            )
        elif self.path == "/repo.git/git-upload-pack" and self.authorized():
            self.git_backend(body)
        else:
            self.reply(401)

    def do_GET(self):
        if self.path == "/":
            self.reply(204)
        elif not self.authorized():
            self.reply(401)
        elif self.path == "/probe":
            self.reply(204)
        elif self.path == "/repos/e2e/repo/contents/README.md":
            self.reply(200, json.dumps({"name": "README.md", "private": True}).encode())
        elif self.path.startswith("/repo.git/info/refs?"):
            self.git_backend(b"")
        else:
            self.reply(404)

    def git_backend(self, body):
        url = urlsplit(self.path)
        env = dict(
            os.environ,
            GIT_PROJECT_ROOT=str(root),
            GIT_HTTP_EXPORT_ALL="1",
            PATH_INFO=url.path,
            QUERY_STRING=url.query,
            REQUEST_METHOD=self.command,
            CONTENT_TYPE=self.headers.get("Content-Type", ""),
            CONTENT_LENGTH=str(len(body)),
        )
        # Let the real Git backend negotiate and transfer objects.
        response = subprocess.run(
            ["git", "http-backend"],
            input=body,
            env=env,
            check=True,
            stdout=subprocess.PIPE,
        ).stdout
        headers, payload = response.split(b"\r\n\r\n", 1)
        self.send_response(200)
        for line in headers.split(b"\r\n"):
            name, value = line.decode().split(":", 1)
            self.send_header(name, value.strip())
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_args):
        pass


tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
tls.load_cert_chain("server.crt", "server.key")


class HttpsServer(ThreadingHTTPServer):
    def get_request(self):
        stream, address = super().get_request()
        stream.settimeout(20)
        stream.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        # Handshake in the request thread. A preconnected or abandoned socket
        # must not block accept() and starve subsequent gh/Git connections.
        return tls.wrap_socket(
            stream, server_side=True, do_handshake_on_connect=False
        ), address


https = HttpsServer(("0.0.0.0", 8443), Handler)
threading.Thread(target=https.serve_forever, daemon=True).start()
ThreadingHTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
