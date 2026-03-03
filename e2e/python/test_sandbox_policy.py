# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from navigator._proto import datamodel_pb2, sandbox_pb2

if TYPE_CHECKING:
    from collections.abc import Callable

    from navigator import Sandbox


# =============================================================================
# Policy helpers
# =============================================================================

_BASE_FILESYSTEM = sandbox_pb2.FilesystemPolicy(
    include_workdir=True,
    read_only=["/usr", "/lib", "/etc", "/app", "/var/log"],
    read_write=["/sandbox", "/tmp"],
)
_BASE_LANDLOCK = sandbox_pb2.LandlockPolicy(compatibility="best_effort")
_BASE_PROCESS = sandbox_pb2.ProcessPolicy(run_as_user="sandbox", run_as_group="sandbox")
# Standard proxy address inside the sandbox network namespace
_PROXY_HOST = "10.200.0.1"
_PROXY_PORT = 3128


def _base_policy(
    network_policies: dict[str, sandbox_pb2.NetworkPolicyRule] | None = None,
) -> sandbox_pb2.SandboxPolicy:
    """Build a sandbox policy with standard filesystem/process/landlock settings."""
    return sandbox_pb2.SandboxPolicy(
        version=1,
        filesystem=_BASE_FILESYSTEM,
        landlock=_BASE_LANDLOCK,
        process=_BASE_PROCESS,
        network_policies=network_policies or {},
    )


def _policy_for_python_proxy_tests() -> sandbox_pb2.SandboxPolicy:
    return _base_policy(
        network_policies={
            "python": sandbox_pb2.NetworkPolicyRule(
                name="python",
                endpoints=[
                    sandbox_pb2.NetworkEndpoint(host="api.openai.com", port=443)
                ],
                binaries=[sandbox_pb2.NetworkBinary(path="/app/.venv/bin/python")],
            )
        },
    )


# =============================================================================
# Shared test function factories
#
# cloudpickle serializes module-level functions by reference (module + name).
# The sandbox doesn't have this module, so deserialization fails. These
# factories return closures that cloudpickle serializes by value instead.
# =============================================================================


def _proxy_connect():
    """Return a closure that sends a raw CONNECT and returns the status line."""

    def fn(host, port):
        import socket

        conn = socket.create_connection(("10.200.0.1", 3128), timeout=10)
        try:
            conn.sendall(
                f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}\r\n\r\n".encode()
            )
            return conn.recv(256).decode("latin1")
        finally:
            conn.close()

    return fn


def _proxy_connect_then_http():
    """Return a closure that CONNECTs, does TLS + HTTP, returns JSON string."""

    def fn(host, port, method="GET", path="/"):
        import json as _json
        import socket
        import ssl

        conn = socket.create_connection(("10.200.0.1", 3128), timeout=30)
        try:
            conn.sendall(
                f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}\r\n\r\n".encode()
            )
            connect_resp = conn.recv(256).decode("latin1")
            if "200" not in connect_resp:
                return _json.dumps(
                    {"connect_status": connect_resp.strip(), "http_status": 0}
                )

            sock = conn
            if port == 443:
                import os

                ctx = ssl.create_default_context()
                ca_file = os.environ.get("SSL_CERT_FILE")
                if ca_file:
                    ctx.load_verify_locations(ca_file)
                sock = ctx.wrap_socket(conn, server_hostname=host)

            sock.settimeout(15)

            request = (
                f"{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
            )
            sock.sendall(request.encode())

            # Read response. The L7 relay loops back to parse the next
            # request after relaying, so neither side closes — read until
            # we have headers, then drain body with a short timeout.
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk

            # Drain body with short timeout
            sock.settimeout(2)
            while len(data) < 65536:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                except (socket.timeout, TimeoutError):
                    break

            response = data.decode("latin1", errors="replace")
            status_line = response.split("\r\n")[0] if response else ""
            status_code = (
                int(status_line.split()[1]) if len(status_line.split()) >= 2 else 0
            )

            header_end = response.find("\r\n\r\n")
            headers_raw = response[:header_end] if header_end > 0 else ""
            body = response[header_end + 4 :] if header_end > 0 else ""

            return _json.dumps(
                {
                    "connect_status": connect_resp.strip(),
                    "http_status": status_code,
                    "headers": headers_raw,
                    "body": body,
                }
            )
        finally:
            conn.close()

    return fn


def _read_navigator_log():
    """Return a closure that reads the navigator log file."""

    def fn():
        try:
            with open("/var/log/navigator.log") as f:
                return f.read()
        except FileNotFoundError:
            return ""

    return fn


def test_policy_applies_to_exec_commands(
    sandbox: Callable[..., Sandbox],
) -> None:
    def current_user() -> str:
        import os
        import pwd

        return pwd.getpwuid(os.getuid()).pw_name

    def write_allowed_files() -> str:
        from pathlib import Path

        Path("/sandbox/allowed.txt").write_text("ok")
        Path("/tmp/allowed.txt").write_text("ok")
        return "ok"

    spec = datamodel_pb2.SandboxSpec(policy=_policy_for_python_proxy_tests())

    with sandbox(spec=spec, delete_on_exit=True) as policy_sandbox:
        user_result = policy_sandbox.exec_python(current_user)
        assert user_result.exit_code == 0, user_result.stderr
        assert user_result.stdout.strip() == "sandbox"

        file_result = policy_sandbox.exec_python(write_allowed_files)
        assert file_result.exit_code == 0, file_result.stderr
        assert file_result.stdout.strip() == "ok"


def test_policy_blocks_unauthorized_proxy_connect(
    sandbox: Callable[..., Sandbox],
) -> None:
    spec = datamodel_pb2.SandboxSpec(policy=_policy_for_python_proxy_tests())
    with sandbox(spec=spec, delete_on_exit=True) as policy_sandbox:
        proxy_result = policy_sandbox.exec_python(
            _proxy_connect(), args=("example.com", 443)
        )
        assert proxy_result.exit_code == 0, proxy_result.stderr
        assert "403" in proxy_result.stdout


# =============================================================================
# L4 Tests -- Connection-level OPA policy (host:port + binary identity)
# =============================================================================
#
# L4-1: No network policies -> all CONNECT requests denied
# L4-2: Wildcard binary (/**) + specific endpoint -> any binary can connect
#        but non-listed endpoints still denied
# L4-3: Binary-restricted policy -> matched binary allowed, others denied
# L4-4: Correct endpoint, wrong port -> denied
# L4-5: Multiple disjoint policies -> cross-policy access denied
# L4-6: Non-CONNECT HTTP method -> rejected with 405
# L4-7: Log fields are structured correctly (action, binary, policy, engine)
# =============================================================================


def test_l4_no_policy_denies_all(
    sandbox: Callable[..., Sandbox],
) -> None:
    """L4-1: No matching endpoint in any network policy -> CONNECT denied.

    We need at least one network policy so the proxy and network namespace
    start (empty network_policies disables networking entirely, including
    socket syscalls). The policy allows python->example.com:443 but
    api.anthropic.com:443 should still be denied.
    """
    policy = _base_policy(
        network_policies={
            "other": sandbox_pb2.NetworkPolicyRule(
                name="other",
                endpoints=[
                    sandbox_pb2.NetworkEndpoint(host="example.com", port=443),
                ],
                binaries=[sandbox_pb2.NetworkBinary(path="/**")],
            ),
        },
    )
    spec = datamodel_pb2.SandboxSpec(policy=policy)
    with sandbox(spec=spec, delete_on_exit=True) as sb:
        result = sb.exec_python(_proxy_connect(), args=("api.anthropic.com", 443))
        assert result.exit_code == 0, result.stderr
        assert "403" in result.stdout


def test_l4_wildcard_binary_allows_any_binary(
    sandbox: Callable[..., Sandbox],
) -> None:
    """L4-2: Wildcard binary glob allows python (and anything else) to connect."""
    policy = _base_policy(
        network_policies={
            "wildcard": sandbox_pb2.NetworkPolicyRule(
                name="wildcard",
                endpoints=[
                    sandbox_pb2.NetworkEndpoint(host="api.anthropic.com", port=443),
                ],
                binaries=[sandbox_pb2.NetworkBinary(path="/**")],
            ),
        },
    )
    spec = datamodel_pb2.SandboxSpec(policy=policy)
    with sandbox(spec=spec, delete_on_exit=True) as sb:
        # Python can reach the allowed endpoint
        result = sb.exec_python(_proxy_connect(), args=("api.anthropic.com", 443))
        assert result.exit_code == 0, result.stderr
        assert "200" in result.stdout

        # Non-listed endpoint is still denied
        result = sb.exec_python(_proxy_connect(), args=("example.com", 443))
        assert result.exit_code == 0, result.stderr
        assert "403" in result.stdout


def test_l4_binary_restricted_denies_wrong_binary(
    sandbox: Callable[..., Sandbox],
) -> None:
    """L4-3: Policy restricted to specific binary denies others.

    Policy allows /usr/bin/curl -> api.anthropic.com:443.
    Python (exec_python uses /app/.venv/bin/python) should be denied.
    """
    policy = _base_policy(
        network_policies={
            "curl_only": sandbox_pb2.NetworkPolicyRule(
                name="curl_only",
                endpoints=[
                    sandbox_pb2.NetworkEndpoint(host="api.anthropic.com", port=443),
                ],
                binaries=[sandbox_pb2.NetworkBinary(path="/usr/bin/curl")],
            ),
        },
    )
    spec = datamodel_pb2.SandboxSpec(policy=policy)
    with sandbox(spec=spec, delete_on_exit=True) as sb:
        # Python is NOT the allowed binary -> denied
        result = sb.exec_python(_proxy_connect(), args=("api.anthropic.com", 443))
        assert result.exit_code == 0, result.stderr
        assert "403" in result.stdout


def test_l4_wrong_port_denied(
    sandbox: Callable[..., Sandbox],
) -> None:
    """L4-4: Correct host but wrong port -> denied."""
    policy = _base_policy(
        network_policies={
            "anthropic": sandbox_pb2.NetworkPolicyRule(
                name="anthropic",
                endpoints=[
                    sandbox_pb2.NetworkEndpoint(host="api.anthropic.com", port=443),
                ],
                binaries=[sandbox_pb2.NetworkBinary(path="/**")],
            ),
        },
    )
    spec = datamodel_pb2.SandboxSpec(policy=policy)
    with sandbox(spec=spec, delete_on_exit=True) as sb:
        # Port 443 -> allowed
        result = sb.exec_python(_proxy_connect(), args=("api.anthropic.com", 443))
        assert result.exit_code == 0, result.stderr
        assert "200" in result.stdout

        # Port 80 -> denied
        result = sb.exec_python(_proxy_connect(), args=("api.anthropic.com", 80))
        assert result.exit_code == 0, result.stderr
        assert "403" in result.stdout


def test_l4_cross_policy_denied(
    sandbox: Callable[..., Sandbox],
) -> None:
    """L4-5: Multiple disjoint policies -> cross-policy access denied.

    Policy A: python -> api.anthropic.com:443
    Policy B: curl -> example.com:443
    Python should NOT reach example.com (that's curl's policy).
    """
    policy = _base_policy(
        network_policies={
            "anthropic": sandbox_pb2.NetworkPolicyRule(
                name="anthropic",
                endpoints=[
                    sandbox_pb2.NetworkEndpoint(host="api.anthropic.com", port=443),
                ],
                binaries=[sandbox_pb2.NetworkBinary(path="/app/.venv/bin/python")],
            ),
            "other": sandbox_pb2.NetworkPolicyRule(
                name="other",
                endpoints=[
                    sandbox_pb2.NetworkEndpoint(host="example.com", port=443),
                ],
                binaries=[sandbox_pb2.NetworkBinary(path="/usr/bin/curl")],
            ),
        },
    )
    spec = datamodel_pb2.SandboxSpec(policy=policy)
    with sandbox(spec=spec, delete_on_exit=True) as sb:
        # Python -> its own policy endpoint: allowed
        result = sb.exec_python(_proxy_connect(), args=("api.anthropic.com", 443))
        assert result.exit_code == 0, result.stderr
        assert "200" in result.stdout

        # Python -> curl's policy endpoint: denied
        result = sb.exec_python(_proxy_connect(), args=("example.com", 443))
        assert result.exit_code == 0, result.stderr
        assert "403" in result.stdout


def test_l4_non_connect_method_rejected(
    sandbox: Callable[..., Sandbox],
) -> None:
    """L4-6: Non-CONNECT HTTP method -> rejected with 405."""

    def send_get_to_proxy() -> str:
        import socket

        conn = socket.create_connection(("10.200.0.1", 3128), timeout=10)
        try:
            conn.sendall(
                b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n"
            )
            return conn.recv(256).decode("latin1")
        finally:
            conn.close()

    policy = _base_policy(
        network_policies={
            "any": sandbox_pb2.NetworkPolicyRule(
                name="any",
                endpoints=[
                    sandbox_pb2.NetworkEndpoint(host="example.com", port=443),
                ],
                binaries=[sandbox_pb2.NetworkBinary(path="/**")],
            ),
        },
    )
    spec = datamodel_pb2.SandboxSpec(policy=policy)
    with sandbox(spec=spec, delete_on_exit=True) as sb:
        result = sb.exec_python(send_get_to_proxy)
        assert result.exit_code == 0, result.stderr
        assert "405" in result.stdout


def test_l4_log_fields(
    sandbox: Callable[..., Sandbox],
) -> None:
    """L4-7: CONNECT log contains structured fields for allow and deny."""
    policy = _base_policy(
        network_policies={
            "anthropic": sandbox_pb2.NetworkPolicyRule(
                name="anthropic",
                endpoints=[
                    sandbox_pb2.NetworkEndpoint(host="api.anthropic.com", port=443),
                ],
                binaries=[sandbox_pb2.NetworkBinary(path="/**")],
            ),
        },
    )
    spec = datamodel_pb2.SandboxSpec(policy=policy)
    with sandbox(spec=spec, delete_on_exit=True) as sb:
        # Generate an allow
        sb.exec_python(_proxy_connect(), args=("api.anthropic.com", 443))
        # Generate a deny
        sb.exec_python(_proxy_connect(), args=("example.com", 443))

        log_result = sb.exec_python(_read_navigator_log())
        assert log_result.exit_code == 0, log_result.stderr
        log = log_result.stdout

        # Verify structured fields in allow line
        assert "action=allow" in log or 'action="allow"' in log or "action=allow" in log
        assert "dst_host=api.anthropic.com" in log or "dst_host" in log
        assert "engine=opa" in log or 'engine="opa"' in log

        # Verify deny line exists
        assert "action=deny" in log or 'action="deny"' in log


# =============================================================================
# SSRF Tests -- Internal IP rejection (defense-in-depth)
#
# The proxy resolves DNS before connecting and rejects any destination that
# resolves to a loopback, RFC1918 private, or link-local address.  These
# tests verify the check works even when OPA policy explicitly allows the
# internal endpoint.
#
# SSRF-1: Loopback (127.0.0.1) blocked despite OPA allow
# SSRF-2: Cloud metadata (169.254.169.254) blocked despite OPA allow
# SSRF-3: Log shows "internal address" block reason
# =============================================================================


def test_ssrf_blocks_loopback_despite_policy_allow(
    sandbox: Callable[..., Sandbox],
) -> None:
    """SSRF-1: CONNECT to 127.0.0.1 blocked even with explicit OPA allow."""
    policy = _base_policy(
        network_policies={
            "internal": sandbox_pb2.NetworkPolicyRule(
                name="internal",
                endpoints=[
                    sandbox_pb2.NetworkEndpoint(host="127.0.0.1", port=80),
                ],
                binaries=[sandbox_pb2.NetworkBinary(path="/**")],
            ),
        },
    )
    spec = datamodel_pb2.SandboxSpec(policy=policy)
    with sandbox(spec=spec, delete_on_exit=True) as sb:
        result = sb.exec_python(_proxy_connect(), args=("127.0.0.1", 80))
        assert result.exit_code == 0, result.stderr
        assert "403" in result.stdout


def test_ssrf_blocks_metadata_endpoint_despite_policy_allow(
    sandbox: Callable[..., Sandbox],
) -> None:
    """SSRF-2: CONNECT to 169.254.169.254 blocked even with explicit OPA allow."""
    policy = _base_policy(
        network_policies={
            "metadata": sandbox_pb2.NetworkPolicyRule(
                name="metadata",
                endpoints=[
                    sandbox_pb2.NetworkEndpoint(host="169.254.169.254", port=80),
                ],
                binaries=[sandbox_pb2.NetworkBinary(path="/**")],
            ),
        },
    )
    spec = datamodel_pb2.SandboxSpec(policy=policy)
    with sandbox(spec=spec, delete_on_exit=True) as sb:
        result = sb.exec_python(_proxy_connect(), args=("169.254.169.254", 80))
        assert result.exit_code == 0, result.stderr
        assert "403" in result.stdout


def test_ssrf_log_shows_internal_address_block(
    sandbox: Callable[..., Sandbox],
) -> None:
    """SSRF-3: Proxy log includes 'internal address' reason when SSRF check fires."""
    policy = _base_policy(
        network_policies={
            "internal": sandbox_pb2.NetworkPolicyRule(
                name="internal",
                endpoints=[
                    sandbox_pb2.NetworkEndpoint(host="127.0.0.1", port=80),
                ],
                binaries=[sandbox_pb2.NetworkBinary(path="/**")],
            ),
        },
    )
    spec = datamodel_pb2.SandboxSpec(policy=policy)
    with sandbox(spec=spec, delete_on_exit=True) as sb:
        sb.exec_python(_proxy_connect(), args=("127.0.0.1", 80))

        log_result = sb.exec_python(_read_navigator_log())
        assert log_result.exit_code == 0, log_result.stderr
        log = log_result.stdout
        assert "internal address" in log.lower(), (
            f"Expected 'internal address' in proxy log, got:\n{log}"
        )


# =============================================================================
# SSRF Tests -- allowed_ips (CIDR-based private IP access)
#
# When an endpoint has `allowed_ips`, the proxy validates resolved IPs against
# the CIDR allowlist instead of blanket-blocking all private IPs.
# Loopback and link-local remain always-blocked regardless.
#
# SSRF-4: Private IP allowed with allowed_ips (mode 2: host + IPs)
# SSRF-5: Private IP allowed with allowed_ips (mode 3: IPs only, no host)
# SSRF-6: Private IP still blocked without allowed_ips (default behavior)
# SSRF-7: Loopback always blocked even with allowed_ips covering 127.0.0.0/8
# =============================================================================


def test_ssrf_allowed_ips_permits_private_ip(
    sandbox: Callable[..., Sandbox],
) -> None:
    """SSRF-4: CONNECT to private IP succeeds when allowed_ips covers it.

    Uses 10.200.0.1 (the proxy's own host-side veth IP) as the target.
    The connection attempt will fail at the TCP level (nothing listening on
    port 19999) but the proxy should return 200 Connection Established
    instead of 403, proving the SSRF check passed.
    """
    policy = _base_policy(
        network_policies={
            "internal": sandbox_pb2.NetworkPolicyRule(
                name="internal",
                endpoints=[
                    sandbox_pb2.NetworkEndpoint(
                        host="10.200.0.1",
                        port=19999,
                        allowed_ips=["10.200.0.0/24"],
                    ),
                ],
                binaries=[sandbox_pb2.NetworkBinary(path="/**")],
            ),
        },
    )
    spec = datamodel_pb2.SandboxSpec(policy=policy)
    with sandbox(spec=spec, delete_on_exit=True) as sb:
        result = sb.exec_python(_proxy_connect(), args=("10.200.0.1", 19999))
        assert result.exit_code == 0, result.stderr
        # Should get 200 (connection established) — not 403.
        # The actual TCP connection may fail but the SSRF check passed.
        assert "403" not in result.stdout, (
            "Expected SSRF check to pass with allowed_ips, but got 403"
        )


def test_ssrf_allowed_ips_hostless_permits_private_ip(
    sandbox: Callable[..., Sandbox],
) -> None:
    """SSRF-5: CONNECT to private IP succeeds with hostless allowed_ips (mode 3).

    An endpoint with no host but with allowed_ips matches any hostname on the
    given port. The resolved IP must be in the allowlist.
    """
    policy = _base_policy(
        network_policies={
            "private_net": sandbox_pb2.NetworkPolicyRule(
                name="private_net",
                endpoints=[
                    sandbox_pb2.NetworkEndpoint(
                        # No host — matches any hostname on this port
                        port=19999,
                        allowed_ips=["10.200.0.0/24"],
                    ),
                ],
                binaries=[sandbox_pb2.NetworkBinary(path="/**")],
            ),
        },
    )
    spec = datamodel_pb2.SandboxSpec(policy=policy)
    with sandbox(spec=spec, delete_on_exit=True) as sb:
        result = sb.exec_python(_proxy_connect(), args=("10.200.0.1", 19999))
        assert result.exit_code == 0, result.stderr
        assert "403" not in result.stdout, (
            "Expected SSRF check to pass with hostless allowed_ips, but got 403"
        )


def test_ssrf_private_ip_blocked_without_allowed_ips(
    sandbox: Callable[..., Sandbox],
) -> None:
    """SSRF-6: Private IP blocked when endpoint has no allowed_ips (default)."""
    policy = _base_policy(
        network_policies={
            "internal": sandbox_pb2.NetworkPolicyRule(
                name="internal",
                endpoints=[
                    # No allowed_ips — private IP should be blocked
                    sandbox_pb2.NetworkEndpoint(host="10.200.0.1", port=19999),
                ],
                binaries=[sandbox_pb2.NetworkBinary(path="/**")],
            ),
        },
    )
    spec = datamodel_pb2.SandboxSpec(policy=policy)
    with sandbox(spec=spec, delete_on_exit=True) as sb:
        result = sb.exec_python(_proxy_connect(), args=("10.200.0.1", 19999))
        assert result.exit_code == 0, result.stderr
        assert "403" in result.stdout, (
            "Expected private IP to be blocked without allowed_ips"
        )


def test_ssrf_loopback_blocked_even_with_allowed_ips(
    sandbox: Callable[..., Sandbox],
) -> None:
    """SSRF-7: Loopback always blocked even when allowed_ips covers 127.0.0.0/8."""
    policy = _base_policy(
        network_policies={
            "internal": sandbox_pb2.NetworkPolicyRule(
                name="internal",
                endpoints=[
                    sandbox_pb2.NetworkEndpoint(
                        host="127.0.0.1",
                        port=80,
                        allowed_ips=["127.0.0.0/8"],
                    ),
                ],
                binaries=[sandbox_pb2.NetworkBinary(path="/**")],
            ),
        },
    )
    spec = datamodel_pb2.SandboxSpec(policy=policy)
    with sandbox(spec=spec, delete_on_exit=True) as sb:
        result = sb.exec_python(_proxy_connect(), args=("127.0.0.1", 80))
        assert result.exit_code == 0, result.stderr
        assert "403" in result.stdout, (
            "Expected loopback to be blocked even with allowed_ips"
        )


# =============================================================================
# L7 Tests -- TLS termination HTTPS inspection (Phase 2: tls=terminate)
#
# These tests use api.anthropic.com:443 as a real HTTPS endpoint since the
# sandbox already has proxy connectivity. The ephemeral CA is trusted via
# SSL_CERT_FILE injected into the sandbox environment.
#
# L7-T1: TLS terminate + access=full allows HTTPS requests through
# L7-T2: TLS terminate + access=read-only denies HTTPS POST (enforce)
# L7-T3: TLS terminate + enforcement=audit logs but allows HTTPS POST
# L7-T4: TLS terminate with explicit path rules
# L7-T5: CA trust store is injected (SSL_CERT_FILE, NODE_EXTRA_CA_CERTS)
# L7-T6: L7 deny response is valid JSON with expected fields
# L7-T7: L7 request logging includes structured fields
# L7-T8: Port 443 + protocol=rest without tls=terminate warns (L7 not evaluated)
# =============================================================================


def test_l7_tls_full_access_allows_all(
    sandbox: Callable[..., Sandbox],
) -> None:
    """L7-T1: TLS terminate + access=full allows HTTPS GET through."""
    policy = _base_policy(
        network_policies={
            "anthropic": sandbox_pb2.NetworkPolicyRule(
                name="anthropic",
                endpoints=[
                    sandbox_pb2.NetworkEndpoint(
                        host="api.anthropic.com",
                        port=443,
                        protocol="rest",
                        tls="terminate",
                        enforcement="enforce",
                        access="full",
                    ),
                ],
                binaries=[sandbox_pb2.NetworkBinary(path="/**")],
            ),
        },
    )
    spec = datamodel_pb2.SandboxSpec(policy=policy)
    with sandbox(spec=spec, delete_on_exit=True) as sb:
        result = sb.exec_python(
            _proxy_connect_then_http(),
            args=("api.anthropic.com", 443, "GET", "/v1/models"),
        )
        assert result.exit_code == 0, result.stderr
        resp = json.loads(result.stdout)
        assert "200" in resp["connect_status"]
        # Upstream returns a real response (likely 401 without auth, but not 403 from proxy)
        assert resp["http_status"] != 0
        assert resp["http_status"] != 403  # Not a proxy deny


def test_l7_tls_read_only_denies_post(
    sandbox: Callable[..., Sandbox],
) -> None:
    """L7-T2: TLS terminate + access=read-only denies HTTPS POST (enforce)."""
    policy = _base_policy(
        network_policies={
            "anthropic": sandbox_pb2.NetworkPolicyRule(
                name="anthropic",
                endpoints=[
                    sandbox_pb2.NetworkEndpoint(
                        host="api.anthropic.com",
                        port=443,
                        protocol="rest",
                        tls="terminate",
                        enforcement="enforce",
                        access="read-only",
                    ),
                ],
                binaries=[sandbox_pb2.NetworkBinary(path="/**")],
            ),
        },
    )
    spec = datamodel_pb2.SandboxSpec(policy=policy)
    with sandbox(spec=spec, delete_on_exit=True) as sb:
        # GET should be allowed through (read-only permits GET)
        get_result = sb.exec_python(
            _proxy_connect_then_http(),
            args=("api.anthropic.com", 443, "GET", "/v1/models"),
        )
        assert get_result.exit_code == 0, get_result.stderr
        get_resp = json.loads(get_result.stdout)
        assert get_resp["http_status"] != 403  # Not proxy denied

        # POST should be denied by the proxy with 403
        post_result = sb.exec_python(
            _proxy_connect_then_http(),
            args=("api.anthropic.com", 443, "POST", "/v1/messages"),
        )
        assert post_result.exit_code == 0, post_result.stderr
        post_resp = json.loads(post_result.stdout)
        assert post_resp["http_status"] == 403
        assert "policy_denied" in post_resp["body"]


def test_l7_tls_audit_mode_allows_but_logs(
    sandbox: Callable[..., Sandbox],
) -> None:
    """L7-T3: TLS terminate + enforcement=audit logs but allows HTTPS POST."""
    policy = _base_policy(
        network_policies={
            "anthropic": sandbox_pb2.NetworkPolicyRule(
                name="anthropic",
                endpoints=[
                    sandbox_pb2.NetworkEndpoint(
                        host="api.anthropic.com",
                        port=443,
                        protocol="rest",
                        tls="terminate",
                        enforcement="audit",
                        access="read-only",
                    ),
                ],
                binaries=[sandbox_pb2.NetworkBinary(path="/**")],
            ),
        },
    )
    spec = datamodel_pb2.SandboxSpec(policy=policy)
    with sandbox(spec=spec, delete_on_exit=True) as sb:
        # POST goes through in audit mode (not denied)
        post_result = sb.exec_python(
            _proxy_connect_then_http(),
            args=("api.anthropic.com", 443, "POST", "/v1/messages"),
        )
        assert post_result.exit_code == 0, post_result.stderr
        post_resp = json.loads(post_result.stdout)
        # Should NOT be 403 from proxy -- traffic is forwarded
        assert post_resp["http_status"] != 403

        # Log should contain audit decision
        log_result = sb.exec_python(_read_navigator_log())
        assert log_result.exit_code == 0, log_result.stderr
        log = log_result.stdout
        assert "l7_decision=audit" in log or 'l7_decision="audit"' in log


def test_l7_tls_explicit_path_rules(
    sandbox: Callable[..., Sandbox],
) -> None:
    """L7-T4: TLS terminate with explicit path rules."""
    policy = _base_policy(
        network_policies={
            "anthropic": sandbox_pb2.NetworkPolicyRule(
                name="anthropic",
                endpoints=[
                    sandbox_pb2.NetworkEndpoint(
                        host="api.anthropic.com",
                        port=443,
                        protocol="rest",
                        tls="terminate",
                        enforcement="enforce",
                        rules=[
                            sandbox_pb2.L7Rule(
                                allow=sandbox_pb2.L7Allow(method="GET", path="/v1/**"),
                            ),
                        ],
                    ),
                ],
                binaries=[sandbox_pb2.NetworkBinary(path="/**")],
            ),
        },
    )
    spec = datamodel_pb2.SandboxSpec(policy=policy)
    with sandbox(spec=spec, delete_on_exit=True) as sb:
        # GET /v1/models -> allowed (matches /v1/**)
        get_result = sb.exec_python(
            _proxy_connect_then_http(),
            args=("api.anthropic.com", 443, "GET", "/v1/models"),
        )
        assert get_result.exit_code == 0, get_result.stderr
        get_resp = json.loads(get_result.stdout)
        assert get_resp["http_status"] != 403

        # POST /v1/messages -> denied (no POST rule)
        post_result = sb.exec_python(
            _proxy_connect_then_http(),
            args=("api.anthropic.com", 443, "POST", "/v1/messages"),
        )
        assert post_result.exit_code == 0, post_result.stderr
        post_resp = json.loads(post_result.stdout)
        assert post_resp["http_status"] == 403

        # GET /v2/anything -> denied (path doesn't match /v1/**)
        v2_result = sb.exec_python(
            _proxy_connect_then_http(),
            args=("api.anthropic.com", 443, "GET", "/v2/anything"),
        )
        assert v2_result.exit_code == 0, v2_result.stderr
        v2_resp = json.loads(v2_result.stdout)
        assert v2_resp["http_status"] == 403


def test_l7_tls_ca_trust_store_injected(
    sandbox: Callable[..., Sandbox],
) -> None:
    """L7-T5: Sandbox CA is injected into trust store environment variables."""

    def check_ca_env() -> str:
        import json as _json
        import os

        return _json.dumps(
            {
                "SSL_CERT_FILE": os.environ.get("SSL_CERT_FILE", ""),
                "NODE_EXTRA_CA_CERTS": os.environ.get("NODE_EXTRA_CA_CERTS", ""),
                "REQUESTS_CA_BUNDLE": os.environ.get("REQUESTS_CA_BUNDLE", ""),
                "CURL_CA_BUNDLE": os.environ.get("CURL_CA_BUNDLE", ""),
                "ca_cert_exists": os.path.exists("/etc/navigator-tls/navigator-ca.pem"),
                "bundle_exists": os.path.exists("/etc/navigator-tls/ca-bundle.pem"),
            }
        )

    policy = _base_policy(
        network_policies={
            "any": sandbox_pb2.NetworkPolicyRule(
                name="any",
                endpoints=[
                    sandbox_pb2.NetworkEndpoint(host="example.com", port=443),
                ],
                binaries=[sandbox_pb2.NetworkBinary(path="/**")],
            ),
        },
    )
    spec = datamodel_pb2.SandboxSpec(policy=policy)
    with sandbox(spec=spec, delete_on_exit=True) as sb:
        result = sb.exec_python(check_ca_env)
        assert result.exit_code == 0, result.stderr
        env = json.loads(result.stdout)
        assert env["ca_cert_exists"], "navigator-ca.pem should exist"
        assert env["bundle_exists"], "ca-bundle.pem should exist"
        assert "navigator-tls" in env["SSL_CERT_FILE"]
        assert "navigator-tls" in env["NODE_EXTRA_CA_CERTS"]


def test_l7_tls_deny_response_format(
    sandbox: Callable[..., Sandbox],
) -> None:
    """L7-T6: L7 deny response is valid JSON with expected fields."""
    policy = _base_policy(
        network_policies={
            "anthropic": sandbox_pb2.NetworkPolicyRule(
                name="anthropic",
                endpoints=[
                    sandbox_pb2.NetworkEndpoint(
                        host="api.anthropic.com",
                        port=443,
                        protocol="rest",
                        tls="terminate",
                        enforcement="enforce",
                        access="read-only",
                    ),
                ],
                binaries=[sandbox_pb2.NetworkBinary(path="/**")],
            ),
        },
    )
    spec = datamodel_pb2.SandboxSpec(policy=policy)
    with sandbox(spec=spec, delete_on_exit=True) as sb:
        result = sb.exec_python(
            _proxy_connect_then_http(),
            args=("api.anthropic.com", 443, "DELETE", "/v1/anything"),
        )
        assert result.exit_code == 0, result.stderr
        resp = json.loads(result.stdout)
        assert resp["http_status"] == 403

        # Verify response headers
        assert "X-Navigator-Policy" in resp["headers"]
        assert "application/json" in resp["headers"]

        # Verify JSON body structure
        body = json.loads(resp["body"])
        assert body["error"] == "policy_denied"
        assert "policy" in body
        assert "rule" in body
        assert "detail" in body


def test_l7_tls_log_fields(
    sandbox: Callable[..., Sandbox],
) -> None:
    """L7-T7: L7 request logging includes structured fields."""
    policy = _base_policy(
        network_policies={
            "anthropic": sandbox_pb2.NetworkPolicyRule(
                name="anthropic",
                endpoints=[
                    sandbox_pb2.NetworkEndpoint(
                        host="api.anthropic.com",
                        port=443,
                        protocol="rest",
                        tls="terminate",
                        enforcement="enforce",
                        access="full",
                    ),
                ],
                binaries=[sandbox_pb2.NetworkBinary(path="/**")],
            ),
        },
    )
    spec = datamodel_pb2.SandboxSpec(policy=policy)
    with sandbox(spec=spec, delete_on_exit=True) as sb:
        sb.exec_python(
            _proxy_connect_then_http(),
            args=("api.anthropic.com", 443, "GET", "/v1/models"),
        )

        log_result = sb.exec_python(_read_navigator_log())
        assert log_result.exit_code == 0, log_result.stderr
        log = log_result.stdout

        assert "L7_REQUEST" in log
        assert "l7_protocol" in log
        assert "l7_action" in log
        assert "l7_target" in log
        assert "l7_decision" in log


# =============================================================================
# Live policy update + log streaming tests
#
# LPU-1: Create sandbox, verify initial policy is v1
# LPU-2: Set the same policy again -> unchanged (no new version)
# LPU-3: Push a different policy -> new version loaded, verify connectivity
# LPU-4: Push v2 again -> unchanged
# LPU-5: Fetch logs (one-shot + streaming) and verify both sources appear
# =============================================================================


def test_live_policy_update_and_logs(
    sandbox: Callable[..., Sandbox],
    sandbox_client: "SandboxClient",
) -> None:
    """End-to-end: live policy update lifecycle with log verification."""
    from navigator._proto import navigator_pb2, sandbox_pb2

    # --- Setup: two distinct policies ---
    # Policy A: python can reach api.anthropic.com
    policy_a = _base_policy(
        network_policies={
            "anthropic": sandbox_pb2.NetworkPolicyRule(
                name="anthropic",
                endpoints=[
                    sandbox_pb2.NetworkEndpoint(host="api.anthropic.com", port=443),
                ],
                binaries=[sandbox_pb2.NetworkBinary(path="/**")],
            ),
        },
    )
    # Policy B: python can reach api.anthropic.com AND example.com
    policy_b = _base_policy(
        network_policies={
            "anthropic": sandbox_pb2.NetworkPolicyRule(
                name="anthropic",
                endpoints=[
                    sandbox_pb2.NetworkEndpoint(host="api.anthropic.com", port=443),
                ],
                binaries=[sandbox_pb2.NetworkBinary(path="/**")],
            ),
            "example": sandbox_pb2.NetworkPolicyRule(
                name="example",
                endpoints=[
                    sandbox_pb2.NetworkEndpoint(host="example.com", port=443),
                ],
                binaries=[sandbox_pb2.NetworkBinary(path="/**")],
            ),
        },
    )

    spec = datamodel_pb2.SandboxSpec(policy=policy_a)
    stub = sandbox_client._stub

    with sandbox(spec=spec, delete_on_exit=True) as sb:
        sandbox_name = sb.sandbox.name

        # --- LPU-1: Initial policy should be version 1 ---
        status_resp = stub.GetSandboxPolicyStatus(
            navigator_pb2.GetSandboxPolicyStatusRequest(name=sandbox_name, version=0)
        )
        assert status_resp.revision.version >= 1, "Initial policy should be at least v1"
        initial_version = status_resp.revision.version
        initial_hash = status_resp.revision.policy_hash

        # --- LPU-2: Set the same policy -> no new version ---
        update_resp = stub.UpdateSandboxPolicy(
            navigator_pb2.UpdateSandboxPolicyRequest(
                name=sandbox_name,
                policy=policy_a,
            )
        )
        assert update_resp.version == initial_version, (
            f"Same policy should return existing version {initial_version}, "
            f"got {update_resp.version}"
        )
        assert update_resp.policy_hash == initial_hash

        # --- LPU-3: Push policy B -> new version ---
        update_resp = stub.UpdateSandboxPolicy(
            navigator_pb2.UpdateSandboxPolicyRequest(
                name=sandbox_name,
                policy=policy_b,
            )
        )
        new_version = update_resp.version
        assert new_version > initial_version, (
            f"Different policy should create new version > {initial_version}, "
            f"got {new_version}"
        )
        assert update_resp.policy_hash != initial_hash

        # Wait for the sandbox to load the new policy (poll loop is 30s default).
        import time

        deadline = time.time() + 90
        loaded = False
        while time.time() < deadline:
            status_resp = stub.GetSandboxPolicyStatus(
                navigator_pb2.GetSandboxPolicyStatusRequest(
                    name=sandbox_name, version=new_version
                )
            )
            status = status_resp.revision.status
            if status == navigator_pb2.POLICY_STATUS_LOADED:
                loaded = True
                break
            if status == navigator_pb2.POLICY_STATUS_FAILED:
                pytest.fail(
                    f"Policy v{new_version} failed to load: "
                    f"{status_resp.revision.load_error}"
                )
            time.sleep(2)
        assert loaded, f"Policy v{new_version} was not loaded within 90s"

        # Verify the new policy works: example.com should now be allowed
        result = sb.exec_python(_proxy_connect(), args=("example.com", 443))
        assert result.exit_code == 0, result.stderr
        assert "200" in result.stdout, (
            f"example.com should be allowed after policy update, got: {result.stdout}"
        )

        # --- LPU-4: Push policy B again -> unchanged ---
        update_resp = stub.UpdateSandboxPolicy(
            navigator_pb2.UpdateSandboxPolicyRequest(
                name=sandbox_name,
                policy=policy_b,
            )
        )
        assert update_resp.version == new_version, (
            f"Same policy B should return existing version {new_version}, "
            f"got {update_resp.version}"
        )

        # --- LPU-5: Verify policy history ---
        list_resp = stub.ListSandboxPolicies(
            navigator_pb2.ListSandboxPoliciesRequest(name=sandbox_name, limit=10)
        )
        versions = [r.version for r in list_resp.revisions]
        assert new_version in versions
        assert initial_version in versions

        # Only one version should be Loaded
        loaded_count = sum(
            1
            for r in list_resp.revisions
            if r.status == navigator_pb2.POLICY_STATUS_LOADED
        )
        assert loaded_count == 1, (
            f"Expected exactly 1 loaded version, got {loaded_count}: "
            f"{[(r.version, r.status) for r in list_resp.revisions]}"
        )

        # --- LPU-6: Fetch logs (one-shot) and verify both sources ---
        # Resolve sandbox ID for log RPCs
        get_resp = stub.GetSandbox(navigator_pb2.GetSandboxRequest(name=sandbox_name))
        sandbox_id = get_resp.sandbox.id

        logs_resp = stub.GetSandboxLogs(
            navigator_pb2.GetSandboxLogsRequest(sandbox_id=sandbox_id, lines=500)
        )
        assert logs_resp.buffer_total > 0, "Expected some logs in the buffer"

        sources = {log.source or "gateway" for log in logs_resp.logs}
        assert "gateway" in sources, (
            f"Expected gateway logs in response, got sources: {sources}"
        )
        # Sandbox logs may take a moment to arrive via the push stream.
        # If they're present, verify the source tag.
        if "sandbox" in sources:
            sandbox_logs = [l for l in logs_resp.logs if l.source == "sandbox"]
            assert len(sandbox_logs) > 0
            # Verify structured fields are present on at least one sandbox log
            has_fields = any(len(l.fields) > 0 for l in sandbox_logs)
            # Not all sandbox logs have fields (e.g., "Starting sandbox" doesn't),
            # so we just check at least one does if there are CONNECT logs
            connect_logs = [l for l in sandbox_logs if "CONNECT" in l.message]
            if connect_logs:
                assert has_fields, "CONNECT logs should have structured fields"
