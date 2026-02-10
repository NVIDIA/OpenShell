from __future__ import annotations

import os
import pathlib
import socket
import subprocess
import threading
import time

import pytest

REGO_POLICY = os.environ.get("NAVIGATOR_REGO_POLICY", "/var/navigator/policy.rego")
REGO_DATA = os.environ.get("NAVIGATOR_REGO_DATA", "/var/navigator/policy-data.rego")
SANDBOX_BIN = os.environ.get("NAVIGATOR_SANDBOX_BIN", "/usr/local/bin/navigator-sandbox")
LOG_PATH = "/var/log/navigator.log"
PROXY_ADDR = ("127.0.0.1", 3128)
PROXY_URL = "http://127.0.0.1:3128"


def run_sandbox(command: list[str], workdir: str | None = "/sandbox") -> subprocess.CompletedProcess[str]:
    args = [SANDBOX_BIN, "--rego-policy", REGO_POLICY, "--rego-data", REGO_DATA]
    if workdir is not None:
        args += ["--workdir", workdir]
    args += command
    env = os.environ.copy()
    env.setdefault("NAVIGATOR_LOG_LEVEL", "warn")
    return subprocess.run(args, env=env, capture_output=True, text=True, check=False)


def run_python_in_sandbox(code: str, workdir: str | None = "/sandbox") -> subprocess.CompletedProcess[str]:
    return run_sandbox(["python", "-c", code], workdir=workdir)


def start_tcp_server_once(port: int) -> threading.Thread:
    ready = threading.Event()

    def runner() -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", port))
        sock.listen(1)
        ready.set()
        conn, _addr = sock.accept()
        conn.close()
        sock.close()

    thread = threading.Thread(target=runner, daemon=True)
    thread.start()
    if not ready.wait(timeout=2):
        raise RuntimeError("TCP server failed to start")
    return thread


def truncate_log() -> None:
    pathlib.Path(LOG_PATH).write_text("")


def test_proxy_envs_set() -> None:
    output_path = "/tmp/sandbox-env.txt"
    code = (
        "import os; "
        f"open({output_path!r}, 'w').write("
        "'\\n'.join(["
        "os.environ.get('HTTP_PROXY',''),"
        "os.environ.get('HTTPS_PROXY',''),"
        "os.environ.get('ALL_PROXY','')])"
        ")"
    )
    result = run_python_in_sandbox(code)
    assert result.returncode == 0, result.stderr

    output = pathlib.Path(output_path).read_text().splitlines()
    assert output == [PROXY_URL, PROXY_URL, PROXY_URL]


def test_runs_as_sandbox_user() -> None:
    output_path = "/tmp/sandbox-user.txt"
    code = (
        "import os, pwd; "
        f"open({output_path!r}, 'w').write(pwd.getpwuid(os.getuid()).pw_name)"
    )
    result = run_python_in_sandbox(code)
    assert result.returncode == 0, result.stderr
    assert pathlib.Path(output_path).read_text() == "sandbox"


def test_filesystem_writes_allowed() -> None:
    code = (
        "import pathlib; "
        "pathlib.Path('/sandbox/allowed.txt').write_text('ok'); "
        "pathlib.Path('/tmp/allowed.txt').write_text('ok')"
    )
    result = run_python_in_sandbox(code)
    assert result.returncode == 0, result.stderr


def test_filesystem_writes_blocked_when_landlock_available() -> None:
    truncate_log()
    code = (
        "import pathlib, sys; "
        "try: "
        "  pathlib.Path('/usr/landlock-test.txt').write_text('no'); "
        "  sys.exit(0) "
        "except Exception: "
        "  sys.exit(1)"
    )
    result = run_python_in_sandbox(code)

    log = pathlib.Path(LOG_PATH).read_text()
    if "Landlock unavailable" in log:
        pytest.skip("Landlock not available in this environment")

    assert result.returncode != 0


def test_proxy_denies_disallowed_host() -> None:
    output_path = "/tmp/proxy-deny.txt"
    code = (
        "import socket; "
        f"s = socket.create_connection({PROXY_ADDR!r}, timeout=5); "
        "s.sendall(b'CONNECT example.com:443 HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n'); "
        "data = s.recv(128); "
        f"open({output_path!r}, 'wb').write(data); "
        "s.close()"
    )
    result = run_python_in_sandbox(code)
    assert result.returncode == 0, result.stderr
    response = pathlib.Path(output_path).read_bytes()
    assert b"403" in response


def test_proxy_allows_allowed_host() -> None:
    server_thread = start_tcp_server_once(443)
    output_path = "/tmp/proxy-allow.txt"
    code = (
        "import socket; "
        f"s = socket.create_connection({PROXY_ADDR!r}, timeout=5); "
        "s.sendall(b'CONNECT api.openai.com:443 HTTP/1.1\\r\\nHost: api.openai.com\\r\\n\\r\\n'); "
        "data = s.recv(128); "
        f"open({output_path!r}, 'wb').write(data); "
        "s.close()"
    )
    result = run_python_in_sandbox(code)
    assert result.returncode == 0, result.stderr
    response = pathlib.Path(output_path).read_bytes()
    assert b"200" in response

    server_thread.join(timeout=2)
    assert not server_thread.is_alive()
