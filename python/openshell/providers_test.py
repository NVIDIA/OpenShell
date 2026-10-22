# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Curated provider retrieval through generated stubs and real gRPC error mapping."""

from concurrent import futures
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import grpc
import pytest

from openshell import ProviderClient, ProviderCredentialValue, SandboxClient, TlsConfig
from openshell._proto import openshell_pb2, openshell_pb2_grpc
from openshell.errors import GatewayError


@pytest.fixture
def provider_client():
    state = SimpleNamespace(calls=[], deadlines=[], code=None, response=None)

    def retrieve(request, context):
        state.calls.append(request)
        state.deadlines.append(context.time_remaining())
        if state.code is not None:
            context.set_trailing_metadata((("request-id", "provider-export"),))
            context.abort(state.code, "runtime credential retrieval failed")
        if state.response is not None:
            return state.response
        response = openshell_pb2.GetProviderCredentialsResponse()
        for key in request.credential_keys:
            response.credentials[key].value = f"secret-{key}"
            if key == "ACCESS_TOKEN":
                response.credentials[key].expiration_time.FromDatetime(
                    datetime(2030, 1, 1, tzinfo=UTC)
                )
            elif key == "EPOCH_KEY":
                response.credentials[key].expiration_time.FromNanoseconds(123_456_789)
        return response

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=1))
    server.add_generic_rpc_handlers(
        (
            grpc.method_handlers_generic_handler(
                "openshell.v1.OpenShell",
                {
                    "GetProviderCredentials": grpc.unary_unary_rpc_method_handler(
                        retrieve,
                        request_deserializer=openshell_pb2.GetProviderCredentialsRequest.FromString,
                        response_serializer=openshell_pb2.GetProviderCredentialsResponse.SerializeToString,
                    ),
                },
            ),
        )
    )
    port = server.add_insecure_port("127.0.0.1:0")
    server.start()
    with SandboxClient(f"127.0.0.1:{port}", timeout=3) as connection:
        try:
            yield ProviderClient.from_sandbox_client(connection), state
        finally:
            server.stop(0).wait()


def test_selected_values_and_expiration_are_curated_and_repr_safe(
    provider_client, caplog
):
    client, state = provider_client
    values = client.get_credentials(
        "my-provider",
        ["ACCESS_TOKEN", "STATIC_KEY", "EPOCH_KEY"],
        workspace="production",
        minimum_remaining_lifetime=timedelta(seconds=300, microseconds=123456),
    )
    assert set(values) == {"ACCESS_TOKEN", "STATIC_KEY", "EPOCH_KEY"}
    assert isinstance(values["ACCESS_TOKEN"], ProviderCredentialValue)
    assert values["ACCESS_TOKEN"].value == "secret-ACCESS_TOKEN"
    assert values["ACCESS_TOKEN"].expiration_time == datetime(2030, 1, 1, tzinfo=UTC)
    assert values["STATIC_KEY"].expiration_time is None
    assert values["EPOCH_KEY"].expiration_time == datetime(
        1970, 1, 1, microsecond=123456, tzinfo=UTC
    )
    assert "secret-" not in repr(values)
    assert "secret-" not in caplog.text
    request = state.calls[0]
    assert request.name == "my-provider"
    assert request.workspace_scope.WhichOneof("selection") == "workspace"
    assert request.workspace_scope.workspace == "production"
    assert list(request.credential_keys) == ["ACCESS_TOKEN", "STATIC_KEY", "EPOCH_KEY"]
    assert request.minimum_remaining_lifetime.seconds == 300
    assert request.minimum_remaining_lifetime.nanos == 123456000
    assert 0 < state.deadlines[0] <= 3.1


@pytest.mark.parametrize("lifetime", [None, timedelta(0), timedelta(days=1)])
def test_lifetime_default_zero_and_maximum(provider_client, lifetime):
    client, state = provider_client
    client.get_credentials(
        "provider",
        ["STATIC_KEY"],
        workspace="default",
        minimum_remaining_lifetime=lifetime,
    )
    request = state.calls[0]
    assert request.HasField("minimum_remaining_lifetime") == (lifetime is not None)
    if lifetime is not None:
        assert request.minimum_remaining_lifetime.ToTimedelta() == lifetime


@pytest.mark.parametrize(
    "name,keys,workspace,lifetime",
    [
        ("", ["KEY"], "default", None),
        (" provider", ["KEY"], "default", None),
        ("x" * 254, ["KEY"], "default", None),
        ("provider", [], "default", None),
        ("provider", ["KEY", "KEY"], "default", None),
        ("provider", [f"KEY_{i}" for i in range(33)], "default", None),
        ("provider", ["KEY=secret-input"], "default", None),
        ("provider", ["1KEY"], "default", None),
        ("provider", ["é"], "default", None),
        ("provider", ["K" * 257], "default", None),
        ("provider", "KEY", "default", None),
        ("provider", ["KEY"], "", None),
        ("provider", ["KEY"], " default", None),
        ("provider", ["KEY"], "default", timedelta(microseconds=-1)),
        ("provider", ["KEY"], "default", timedelta(days=1, microseconds=1)),
    ],
)
def test_invalid_requests_never_contact_gateway(
    provider_client, name, keys, workspace, lifetime
):
    client, state = provider_client
    with pytest.raises(ValueError) as error:
        client.get_credentials(
            name, keys, workspace=workspace, minimum_remaining_lifetime=lifetime
        )
    assert "secret-input" not in str(error.value)
    assert not state.calls


@pytest.mark.parametrize(
    "code",
    [
        grpc.StatusCode.UNAUTHENTICATED,
        grpc.StatusCode.PERMISSION_DENIED,
        grpc.StatusCode.NOT_FOUND,
        grpc.StatusCode.FAILED_PRECONDITION,
        grpc.StatusCode.UNAVAILABLE,
        grpc.StatusCode.ABORTED,
        grpc.StatusCode.DEADLINE_EXCEEDED,
    ],
)
def test_errors_preserve_status_and_metadata_without_retry(provider_client, code):
    client, state = provider_client
    state.code = code
    with pytest.raises(GatewayError) as error:
        client.get_credentials(
            "provider", ["ACCESS_TOKEN", "STATIC_KEY"], workspace="other"
        )
    assert error.value.code() == code
    assert ("request-id", "provider-export") in error.value.trailing_metadata()
    assert len(state.calls) == 1
    assert "secret-" not in str(error.value)


@pytest.mark.parametrize(
    "keys", [["ACCESS_TOKEN"], ["ACCESS_TOKEN", "STATIC_KEY", "PRIVATE_KEY"]]
)
def test_unexpected_or_partial_responses_are_not_delivered(provider_client, keys):
    client, state = provider_client
    state.response = openshell_pb2.GetProviderCredentialsResponse(
        credentials={
            key: openshell_pb2.ProviderCredentialValue(value="must-not-deliver")
            for key in keys
        }
    )
    with pytest.raises(ValueError, match="unexpected credential selection") as error:
        client.get_credentials(
            "provider", ["ACCESS_TOKEN", "STATIC_KEY"], workspace="other"
        )
    assert "must-not-deliver" not in str(error.value)


def test_shared_client_preserves_mtls_and_does_not_attach_bearer(monkeypatch, tmp_path):
    ca = tmp_path / "ca.crt"
    cert = tmp_path / "operator.crt"
    key = tmp_path / "operator.key"
    for path, value in [(ca, b"ca"), (cert, b"operator-cert"), (key, b"operator-key")]:
        path.write_bytes(value)
    seen = {}

    def credentials(**kwargs):
        seen.update(kwargs)
        return "tls-credentials"

    channel = SimpleNamespace(close=lambda: None)
    monkeypatch.setattr(grpc, "ssl_channel_credentials", credentials)

    def secure_channel(endpoint, creds):
        assert endpoint == "gateway.example.com:443"
        assert creds == "tls-credentials"
        return channel

    monkeypatch.setattr(grpc, "secure_channel", secure_channel)
    monkeypatch.setattr("openshell.sandbox._error_mapping_channel", lambda c: c)
    monkeypatch.setattr("openshell.providers._error_mapping_channel", lambda c: c)
    stub_channels = []

    def stub(c):
        stub_channels.append(c)
        return SimpleNamespace()

    monkeypatch.setattr(openshell_pb2_grpc, "OpenShellStub", stub)

    def reject_bearer(*_args):
        pytest.fail("operator connection must not attach a bearer interceptor")

    monkeypatch.setattr(grpc, "intercept_channel", reject_bearer)
    with SandboxClient(
        "gateway.example.com:443",
        tls=TlsConfig(ca_path=ca, cert_path=cert, key_path=key),
    ) as connection:
        assert isinstance(connection.providers(), ProviderClient)
        assert stub_channels == [channel, channel]
        assert seen == {
            "root_certificates": b"ca",
            "private_key": b"operator-key",
            "certificate_chain": b"operator-cert",
        }
