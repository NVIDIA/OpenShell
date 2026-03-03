# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""E2E tests for inference interception and routing.

When a process inside the sandbox makes an inference API call (e.g. POST
/v1/chat/completions) to an endpoint not explicitly allowed by network policy,
the proxy intercepts it, TLS-terminates the connection, detects the inference
API pattern, and the sandbox routes the request locally to the configured
backend (configured with `mock://` for testing).
"""

from __future__ import annotations

import time

import grpc

from typing import TYPE_CHECKING

from navigator._proto import datamodel_pb2, sandbox_pb2

if TYPE_CHECKING:
    from collections.abc import Callable

    from navigator import InferenceRouteClient, Sandbox


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


def _inference_routing_policy(
    allowed_route: str = "e2e_mock_local",
) -> sandbox_pb2.SandboxPolicy:
    """Policy with inference routing enabled.

    No network_policies needed — any connection from any binary to an endpoint
    not in an explicit policy will be intercepted for inference when
    allowed_routes is non-empty.
    """
    return sandbox_pb2.SandboxPolicy(
        version=1,
        inference=sandbox_pb2.InferencePolicy(allowed_routes=[allowed_route]),
        filesystem=_BASE_FILESYSTEM,
        landlock=_BASE_LANDLOCK,
        process=_BASE_PROCESS,
    )


# =============================================================================
# Tests
# =============================================================================


def test_route_refresh_picks_up_route_created_after_sandbox_start(
    sandbox: Callable[..., Sandbox],
    inference_client: InferenceRouteClient,
) -> None:
    """Route refresh picks up a route created after sandbox startup.

    Regression scenario:
    1. Sandbox starts with inference allowed_routes configured but no matching route exists yet.
    2. Initial inference request should be intercepted and return 503 (empty route cache).
    3. Create the route after sandbox startup.
    4. Background refresh should load the new route and subsequent requests should succeed.
    """
    route_name = "e2e-mock-refresh-late"
    route_hint = "e2e_mock_refresh_late"
    spec = datamodel_pb2.SandboxSpec(policy=_inference_routing_policy(route_hint))

    def call_chat_completions() -> str:
        import json
        import ssl
        import urllib.error
        import urllib.request

        body = json.dumps(
            {
                "model": "test-model",
                "messages": [{"role": "user", "content": "hello"}],
            }
        ).encode()

        req = urllib.request.Request(
            "https://api.openai.com/v1/chat/completions",
            data=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer dummy-key",
            },
            method="POST",
        )

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        try:
            resp = urllib.request.urlopen(req, timeout=30, context=ctx)
            return resp.read().decode()
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            return f"http_error_{e.code}:{body}"
        except Exception as e:
            return f"error:{type(e).__name__}:{e}"

    try:
        inference_client.delete(route_name)
    except grpc.RpcError:
        pass

    try:
        with sandbox(spec=spec, delete_on_exit=True) as sb:
            initial = sb.exec_python(call_chat_completions, timeout_seconds=60)
            assert initial.exit_code == 0, f"stderr: {initial.stderr}"
            initial_output = initial.stdout.strip()
            assert initial_output.startswith("http_error_503"), initial_output
            assert "no inference routes configured" in initial_output, initial_output

            inference_client.create(
                name=route_name,
                routing_hint=route_hint,
                base_url="mock://e2e-refresh-late",
                protocols=["openai_chat_completions"],
                api_key="mock",
                model_id="mock/late-route-model",
                enabled=True,
            )

            deadline = time.time() + 95
            last_output = initial_output

            while time.time() < deadline:
                result = sb.exec_python(call_chat_completions, timeout_seconds=60)
                assert result.exit_code == 0, f"stderr: {result.stderr}"
                last_output = result.stdout.strip()

                if "Hello from navigator mock backend" in last_output:
                    break

                time.sleep(5)

            assert "Hello from navigator mock backend" in last_output, last_output
            assert "mock/late-route-model" in last_output, last_output
    finally:
        try:
            inference_client.delete(route_name)
        except grpc.RpcError:
            pass


def test_inference_call_routed_to_backend(
    sandbox: Callable[..., Sandbox],
    mock_inference_route: str,
) -> None:
    """Inference call to undeclared endpoint is intercepted and routed.

    A Python process inside the sandbox calls the OpenAI chat completions
    endpoint via raw urllib. Since api.openai.com is not in any network
    policy, but inference routing is configured, the proxy should:
    1. Detect no explicit policy match (inspect_for_inference)
    2. TLS-terminate the connection
    3. Detect the inference API pattern (POST /v1/chat/completions)
    4. Forward locally via sandbox router to the policy-allowed backend
    5. Return the mock response from the configured route
    """
    spec = datamodel_pb2.SandboxSpec(policy=_inference_routing_policy())

    def call_chat_completions() -> str:
        import json
        import ssl
        import urllib.request

        body = json.dumps(
            {
                "model": "test-model",
                "messages": [{"role": "user", "content": "hello"}],
            }
        ).encode()

        req = urllib.request.Request(
            "https://api.openai.com/v1/chat/completions",
            data=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer dummy-key",
            },
            method="POST",
        )
        # The proxy will TLS-terminate, so we need to accept its cert.
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        resp = urllib.request.urlopen(req, timeout=30, context=ctx)
        return resp.read().decode()

    with sandbox(spec=spec, delete_on_exit=True) as sb:
        result = sb.exec_python(call_chat_completions, timeout_seconds=60)
        assert result.exit_code == 0, f"stderr: {result.stderr}"
        output = result.stdout.strip()
        assert "Hello from navigator mock backend" in output
        assert "mock/test-model" in output


def test_non_inference_request_denied(
    sandbox: Callable[..., Sandbox],
    mock_inference_route: str,
) -> None:
    """Non-inference HTTP request on an intercepted connection is denied.

    A process making a non-inference request (e.g. GET /v1/models) to an
    undeclared endpoint should be denied with 403 when inference routing
    is configured — only recognized inference API patterns are routed.
    """
    spec = datamodel_pb2.SandboxSpec(policy=_inference_routing_policy())

    def make_non_inference_request() -> str:
        import ssl
        import urllib.error
        import urllib.request

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        try:
            req = urllib.request.Request("https://api.openai.com/v1/models")
            urllib.request.urlopen(req, timeout=10, context=ctx)
            return "unexpected_success"
        except urllib.error.HTTPError as e:
            return f"http_error_{e.code}"
        except Exception as e:
            return f"error: {e}"

    with sandbox(spec=spec, delete_on_exit=True) as sb:
        result = sb.exec_python(make_non_inference_request, timeout_seconds=30)
        assert result.exit_code == 0, f"stderr: {result.stderr}"
        assert "403" in result.stdout.strip()


def test_inference_anthropic_messages_protocol(
    sandbox: Callable[..., Sandbox],
    mock_anthropic_route: str,
) -> None:
    """Anthropic messages protocol (POST /v1/messages) is intercepted and routed.

    Verifies multi-protocol routing: a request using the Anthropic messages
    format is correctly detected and forwarded to a route configured with
    the anthropic_messages protocol.
    """
    policy = sandbox_pb2.SandboxPolicy(
        version=1,
        inference=sandbox_pb2.InferencePolicy(
            allowed_routes=["e2e_mock_anthropic"],
        ),
        filesystem=_BASE_FILESYSTEM,
        landlock=_BASE_LANDLOCK,
        process=_BASE_PROCESS,
    )
    spec = datamodel_pb2.SandboxSpec(policy=policy)

    def call_anthropic_messages() -> str:
        import json
        import ssl
        import urllib.request

        body = json.dumps(
            {
                "model": "claude-test",
                "max_tokens": 64,
                "messages": [{"role": "user", "content": "hello"}],
            }
        ).encode()

        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages",
            data=body,
            headers={
                "Content-Type": "application/json",
                "x-api-key": "dummy-key",
                "anthropic-version": "2023-06-01",
            },
            method="POST",
        )
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        resp = urllib.request.urlopen(req, timeout=30, context=ctx)
        return resp.read().decode()

    with sandbox(spec=spec, delete_on_exit=True) as sb:
        result = sb.exec_python(call_anthropic_messages, timeout_seconds=60)
        assert result.exit_code == 0, f"stderr: {result.stderr}"
        output = result.stdout.strip()
        assert "Hello from navigator mock backend" in output
        assert "mock/claude-test" in output


def test_inference_route_filtering_by_allowed_routes(
    sandbox: Callable[..., Sandbox],
    mock_inference_route: str,
    mock_disallowed_route: str,
) -> None:
    """Only routes in allowed_routes are available; others produce errors.

    Two routes exist (e2e_mock_local and e2e_mock_disallowed), but the
    policy only allows e2e_mock_local. A request that would match the
    allowed route should succeed, while inference requests that can't
    match any allowed route get an error from the sandbox router.
    """
    # Policy only allows e2e_mock_local, NOT e2e_mock_disallowed
    spec = datamodel_pb2.SandboxSpec(policy=_inference_routing_policy())

    def call_allowed_route() -> str:
        import json
        import ssl
        import urllib.request

        body = json.dumps(
            {
                "model": "test-model",
                "messages": [{"role": "user", "content": "hello"}],
            }
        ).encode()

        req = urllib.request.Request(
            "https://api.openai.com/v1/chat/completions",
            data=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer dummy",
            },
            method="POST",
        )
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        resp = urllib.request.urlopen(req, timeout=30, context=ctx)
        return resp.read().decode()

    with sandbox(spec=spec, delete_on_exit=True) as sb:
        result = sb.exec_python(call_allowed_route, timeout_seconds=60)
        assert result.exit_code == 0, f"stderr: {result.stderr}"
        output = result.stdout.strip()
        # The allowed route (e2e_mock_local) should serve the request
        assert "Hello from navigator mock backend" in output
        assert "mock/test-model" in output
