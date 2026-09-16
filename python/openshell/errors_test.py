# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Rich error decoding and preservation across unary and streaming calls."""

from concurrent import futures

import grpc
import pytest
from google.rpc import error_details_pb2, status_pb2

from openshell.errors import GatewayError, _error_mapping_channel, from_grpc_error


def rich_status():
    status = status_pb2.Status(
        code=grpc.StatusCode.UNAVAILABLE.value[0], message="try later"
    )
    retry = error_details_pb2.RetryInfo()
    retry.retry_delay.seconds = 1
    retry.retry_delay.nanos = 250_000_000
    for message in [
        error_details_pb2.BadRequest(
            field_violations=[
                error_details_pb2.BadRequest.FieldViolation(
                    field="name", description="invalid name"
                ),
            ]
        ),
        error_details_pb2.ErrorInfo(
            reason="GATEWAY_NOT_READY",
            domain="openshell.nvidia.com",
            metadata={"scope": "test"},
        ),
        retry,
    ]:
        detail = status.details.add()
        detail.Pack(message)
    status.details.add(
        type_url="type.googleapis.com/future.ErrorDetail", value=b"\x08\x01"
    )
    return status


@pytest.mark.parametrize("streaming", [False, True])
def test_maps_real_rpc_errors_without_losing_details(streaming):
    status = rich_status()

    def fail(_request, context):
        context.set_trailing_metadata(
            (
                ("grpc-status-details-bin", status.SerializeToString()),
                ("request-id", "test-correlation"),
            )
        )
        context.abort(grpc.StatusCode.UNAVAILABLE, "try later")

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=1))
    handler = (
        grpc.unary_stream_rpc_method_handler
        if streaming
        else grpc.unary_unary_rpc_method_handler
    )
    server.add_generic_rpc_handlers(
        (grpc.method_handlers_generic_handler("test.Errors", {"Fail": handler(fail)}),)
    )
    port = server.add_insecure_port("127.0.0.1:0")
    server.start()
    try:
        with _error_mapping_channel(
            grpc.insecure_channel(f"127.0.0.1:{port}")
        ) as channel:
            call = channel.unary_stream if streaming else channel.unary_unary
            with pytest.raises(GatewayError) as caught:
                response = call("/test.Errors/Fail")(b"", timeout=5)
                if streaming:
                    list(response)
            error = caught.value
            assert error.code() == grpc.StatusCode.UNAVAILABLE
            assert error.details() == "try later"
            assert error.field_violations[0].field == "name"
            assert error.error_info is not None
            assert error.error_info.reason == "GATEWAY_NOT_READY"
            assert error.retry_delay == 1.25
            assert error.raw_status == status
            assert ("request-id", "test-correlation") in error.trailing_metadata()
            assert from_grpc_error(error) is error
    finally:
        server.stop(0).wait()


class RawError(grpc.RpcError):
    def __init__(self, details):
        self._details = details

    def code(self):
        return grpc.StatusCode.UNAVAILABLE

    def details(self):
        return "try later"

    def trailing_metadata(self):
        return [("grpc-status-details-bin", self._details)]


def test_malformed_or_inconsistent_details_preserve_raw_error():
    for payload in [
        b"\xff",
        status_pb2.Status(code=3, message="different").SerializeToString(),
    ]:
        raw = RawError(payload)
        error = from_grpc_error(raw)
        assert error.raw_error is raw
        assert error.raw_status is None
        assert error.retry_delay is None
        assert error.trailing_metadata() == raw.trailing_metadata()


def test_malformed_known_detail_does_not_hide_other_details():
    status = rich_status()
    status.details.add(
        type_url="type.googleapis.com/google.rpc.BadRequest", value=b"\xff"
    )
    error = from_grpc_error(RawError(status.SerializeToString()))
    assert error.field_violations[0].field == "name"
    assert error.raw_status is not None
    assert len(error.raw_status.details) == 5
