#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# End-to-end test for a sandbox whose policy is written in pure Cedar.
#
# Network and filesystem access come from policy.template.cedar. Middleware is
# configuration, not policy, so it comes from middleware.template.yaml through
# --middleware. Syscall filtering is not authored policy; the test checks that
# the sandbox's seccomp restrictions still hold when the policy is Cedar.
#
# Prereqs: a running gateway (see README.md) and python3 on the host.

set -euo pipefail
export NO_COLOR=1

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
OPENSHELL_BIN="${OPENSHELL_BIN:-${REPO_ROOT}/target/debug/openshell}"
# Sandbox names are limited to 19 characters.
RUN_ID="${RUN_ID:-$(date +%H%M%S)}"
SANDBOX="${SANDBOX:-cedar-e2e-${RUN_ID}}"
TMP_DIR="$(mktemp -d)"
SERVER_PID=""
FAILURES=0

cleanup() {
    if [[ "${CEDAR_E2E_KEEP_SANDBOX:-0}" != "1" ]]; then
        "$OPENSHELL_BIN" sandbox delete "$SANDBOX" >/dev/null 2>&1 || true
    fi
    if [[ -n "$SERVER_PID" ]]; then
        kill "$SERVER_PID" >/dev/null 2>&1 || true
    fi
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

pass() { printf 'PASS  %s\n' "$1"; }
fail() {
    printf 'FAIL  %s\n' "$1"
    if [[ $# -gt 1 ]]; then
        printf '      %s\n' "$2"
    fi
    FAILURES=$((FAILURES + 1))
}

# Asserts that $2 equals $3.
expect_eq() {
    if [[ "$2" == "$3" ]]; then pass "$1"; else fail "$1" "expected '$3', got '$2'"; fi
}

# Asserts that $2 contains $3.
expect_contains() {
    if [[ "$2" == *"$3"* ]]; then pass "$1"; else fail "$1" "expected to find '$3' in: $2"; fi
}

# Runs a shell command inside the sandbox, returning its output and status.
in_sandbox() {
    # Without </dev/null, exec forwards this script's stdin and waits for EOF.
    "$OPENSHELL_BIN" sandbox exec --name "$SANDBOX" --no-tty -- sh -c "$1" 2>&1 </dev/null
}

# Like in_sandbox, but never fails, for captured output that a check inspects.
capture_in_sandbox() {
    in_sandbox "$1" || true
}

# Runs a host-side Python file inside the sandbox and prints its last line.
python_in_sandbox() {
    local encoded
    encoded="$(base64 < "$1" | tr -d '\n')"
    capture_in_sandbox "echo '${encoded}' | base64 -d > /tmp/cedar-e2e.py && python3 /tmp/cedar-e2e.py" | tail -1
}

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

# By default the upstream is echo-server.py on this host, reached through the
# host gateway alias. CEDAR_E2E_UPSTREAM_URL selects another echo service that
# reflects request bodies, such as https://httpbin.org/anything, for hosts
# where the alias is not trusted. On macOS the Docker driver never trusts the
# alias, so that is the default there.
if [[ -z "${CEDAR_E2E_UPSTREAM_URL:-}" && "$(uname -s)" == "Darwin" ]]; then
    CEDAR_E2E_UPSTREAM_URL="https://httpbin.org/anything"
fi
if [[ -n "${CEDAR_E2E_UPSTREAM_URL:-}" ]]; then
    ECHO_URL="${CEDAR_E2E_UPSTREAM_URL%/}"
else
    python3 "${SCRIPT_DIR}/echo-server.py" "${TMP_DIR}/port" &
    SERVER_PID=$!
    for _ in $(seq 1 50); do
        [[ -s "${TMP_DIR}/port" ]] && break
        sleep 0.1
    done
    ECHO_URL="http://host.openshell.internal:$(cat "${TMP_DIR}/port")"
fi
read -r UP_HOST UP_PORT UP_PREFIX < <(python3 - "$ECHO_URL" <<'PY'
import sys
from urllib.parse import urlsplit

url = urlsplit(sys.argv[1])
port = url.port or (443 if url.scheme == "https" else 80)
print(url.hostname, port, url.path.rstrip("/") or "")
PY
)

sed -e "s|__HOST__|${UP_HOST}|g" -e "s|__PORT__|${UP_PORT}|g" -e "s|__PREFIX__|${UP_PREFIX}|g" \
    "${SCRIPT_DIR}/policy.template.cedar" > "${TMP_DIR}/policy.cedar"
sed -e "s|__HOST__|${UP_HOST}|g" \
    "${SCRIPT_DIR}/middleware.template.yaml" > "${TMP_DIR}/middleware.yaml"

"$OPENSHELL_BIN" sandbox create \
    --name "$SANDBOX" \
    --policy "${TMP_DIR}/policy.cedar" \
    --middleware "${TMP_DIR}/middleware.yaml" \
    --no-auto-providers \
    --no-tty \
    --detach \
    -- sh -c "exec sleep infinity" >/dev/null

ready=0
for _ in $(seq 1 60); do
    if "$OPENSHELL_BIN" sandbox exec --name "$SANDBOX" --no-tty -- true >/dev/null 2>&1 </dev/null; then
        ready=1
        break
    fi
    sleep 2
done
if [[ "$ready" != "1" ]]; then
    echo "sandbox ${SANDBOX} did not become ready" >&2
    "$OPENSHELL_BIN" logs "$SANDBOX" 2>&1 | tail -40 >&2 || true
    exit 1
fi

# ---------------------------------------------------------------------------
# Network: NetworkConnect and HttpRequest decisions
# ---------------------------------------------------------------------------

status() {
    capture_in_sandbox "curl -s -o /dev/null -w '%{http_code}' --max-time 20 $1 '${ECHO_URL}$2'" | tail -1
}

expect_eq "network: permitted GET reaches upstream" "$(status "" /allowed/ok)" "200"
expect_eq "network: path outside the permit is denied" "$(status "" /blocked)" "403"
expect_eq "network: method outside the permit is denied" "$(status "-X DELETE" /allowed/ok)" "403"
expect_eq "network: forbid overrides permit" "$(status "" /allowed/secret)" "403"

cat > "${TMP_DIR}/urllib.py" <<EOF
import urllib.error
import urllib.request

try:
    print(urllib.request.urlopen("${ECHO_URL}/allowed/ok", timeout=20).status)
except urllib.error.HTTPError as error:
    print(error.code)
except Exception as error:
    print(type(error).__name__)
EOF
python_status="$(python_in_sandbox "${TMP_DIR}/urllib.py")"
# A status code or exception name means python3 ran and was refused. Anything
# else, such as a missing interpreter, proves nothing about the policy.
if [[ "$python_status" =~ ^([0-9]{3}|[A-Za-z]+)$ && "$python_status" != "200" ]]; then
    pass "network: binary outside the permit is denied ($python_status)"
elif [[ "$python_status" != "200" ]]; then
    fail "network: binary outside the permit is denied" "python3 did not run: $python_status"
else
    fail "network: binary outside the permit is denied" "python3 reached the upstream"
fi

if in_sandbox "curl -s -o /dev/null --max-time 15 https://example.com" >/dev/null; then
    fail "network: host outside the policy is unreachable" "curl reached example.com"
else
    pass "network: host outside the policy is unreachable"
fi

# ---------------------------------------------------------------------------
# Middleware: configured with --middleware
# ---------------------------------------------------------------------------

echo_body="$(capture_in_sandbox "curl -s --max-time 20 -X POST -H 'Content-Type: text/plain' \
    --data 'key=sk-abcdefghijklmnopqrstuvwxyz' '${ECHO_URL}/allowed/echo'")"
expect_contains "middleware: request body is redacted before upstream" "$echo_body" "[REDACTED]"
if [[ "$echo_body" == *"sk-abcdefghijklmnopqrstuvwxyz"* ]]; then
    fail "middleware: secret never reaches upstream" "$echo_body"
else
    pass "middleware: secret never reaches upstream"
fi

# ---------------------------------------------------------------------------
# Filesystem: Landlock grants derived from the Cedar policy
# ---------------------------------------------------------------------------

for path in /sandbox /opt /srv; do
    if ! in_sandbox "test -d $path" >/dev/null; then
        echo "sandbox image has no $path directory; the filesystem checks need it" >&2
        exit 1
    fi
done

expect_eq "filesystem: WriteFile grant allows writing /sandbox" \
    "$(capture_in_sandbox "echo cedar > /sandbox/cedar-e2e && cat /sandbox/cedar-e2e" | tail -1)" "cedar"
if in_sandbox "ls /opt" >/dev/null; then
    pass "filesystem: ReadFile grant allows reading /opt"
else
    fail "filesystem: ReadFile grant allows reading /opt"
fi
expect_contains "filesystem: path without a grant is unreadable" \
    "$(in_sandbox "ls /srv" || true)" "Permission denied"

# ---------------------------------------------------------------------------
# Syscalls: seccomp restrictions apply under a Cedar policy
# ---------------------------------------------------------------------------

cat > "${TMP_DIR}/syscalls.py" <<'EOF'
import ctypes
import errno
import json
import platform
import socket

libc = ctypes.CDLL(None, use_errno=True)
# memfd_create syscall numbers, for C libraries without the wrapper.
MEMFD_CREATE = {"x86_64": 319, "aarch64": 279}
# io_uring_setup has the same number on every architecture.
IO_URING_SETUP = 425


def errno_name(code):
    return errno.errorcode.get(code, str(code))


def libc_probe(call):
    ctypes.set_errno(0)
    if call() >= 0:
        return "allowed"
    return errno_name(ctypes.get_errno())


def socket_probe(call):
    try:
        call()
        return "allowed"
    except OSError as error:
        return errno_name(error.errno)


def memfd_create():
    name = b"cedar-e2e"
    if hasattr(libc, "memfd_create"):
        return libc.memfd_create(name, 0)
    return libc.syscall(MEMFD_CREATE[platform.machine()], name, 0)


probes = {
    "memfd_create": lambda: libc_probe(memfd_create),
    "ptrace": lambda: libc_probe(lambda: libc.ptrace(0, 0, None, None)),  # PTRACE_TRACEME
    "unshare_user": lambda: libc_probe(lambda: libc.unshare(0x10000000)),  # CLONE_NEWUSER
    "mount": lambda: libc_probe(lambda: libc.mount(b"none", b"/tmp", b"tmpfs", 0, None)),
    "io_uring_setup": lambda: libc_probe(
        lambda: libc.syscall(IO_URING_SETUP, 1, ctypes.create_string_buffer(120))
    ),
    "netlink_uevent": lambda: socket_probe(
        lambda: socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 15).close()
    ),
    "direct_connect": lambda: socket_probe(
        lambda: socket.create_connection(("198.51.100.1", 80), timeout=10).close()
    ),
}
results = {}
for name, probe in probes.items():
    try:
        results[name] = probe()
    except Exception as error:  # A broken probe must not hide the others.
        results[name] = f"error:{type(error).__name__}:{error}"
print(json.dumps(results))
EOF
syscall_json="$(python_in_sandbox "${TMP_DIR}/syscalls.py")"

for syscall in memfd_create ptrace unshare_user mount io_uring_setup netlink_uevent; do
    result="$(printf '%s' "$syscall_json" | python3 -c "import json,sys; print(json.load(sys.stdin).get('$syscall','missing'))" 2>/dev/null || echo "unparsable")"
    expect_eq "syscall: $syscall is denied" "$result" "EPERM"
done
direct="$(printf '%s' "$syscall_json" | python3 -c "import json,sys; print(json.load(sys.stdin).get('direct_connect','missing'))" 2>/dev/null || echo "unparsable")"
if [[ "$direct" == "EPERM" || "$direct" == "EACCES" ]]; then
    pass "syscall: direct TCP connect bypassing the proxy is denied"
else
    fail "syscall: direct TCP connect bypassing the proxy is denied" "got $direct from $syscall_json"
fi

# ---------------------------------------------------------------------------
# Observability and policy view
# ---------------------------------------------------------------------------

expect_contains "logs: Cedar is recorded as the deciding engine" \
    "$("$OPENSHELL_BIN" logs "$SANDBOX" 2>&1 || true)" "engine:cedar"

policy_view="$("$OPENSHELL_BIN" policy get "$SANDBOX" --full 2>&1 || true)"
expect_contains "policy get: shows the Cedar policy" "$policy_view" 'Sandbox::Action::"NetworkConnect"'
expect_contains "policy get: shows middleware as its own section" "$policy_view" "# Middleware"

echo
if [[ "$FAILURES" -gt 0 ]]; then
    echo "${FAILURES} check(s) failed"
    exit 1
fi
echo "All Cedar e2e checks passed"
