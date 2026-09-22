# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Typed gateway errors that retain the original gRPC status and metadata."""

from __future__ import annotations

from dataclasses import dataclass

import grpc
from google.protobuf.message import DecodeError
from google.rpc import error_details_pb2, status_pb2


@dataclass(frozen=True)
class FieldViolation:
    """A request field rejected by the gateway."""

    field: str
    description: str


@dataclass(frozen=True)
class ErrorInfo:
    """A machine-readable error reason scoped to its producing service."""

    reason: str
    domain: str
    metadata: dict[str, str]


class GatewayError(grpc.RpcError):
    """A gRPC failure with decoded standard details.

    ``raw_error`` retains the complete original exception and metadata.
    ``raw_status`` retains all decoded Any messages, including unknown types.
    A retry delay is guidance only; it does not make a mutation safe to repeat.
    Existing ``except grpc.RpcError`` handlers continue to match this type.
    """

    def __init__(self, error: grpc.RpcError) -> None:
        super().__init__(str(error))
        self.raw_error = error
        self.raw_status: status_pb2.Status | None = None
        self.field_violations: tuple[FieldViolation, ...] = ()
        self.error_info: ErrorInfo | None = None
        self.retry_delay: float | None = None
        trailing = getattr(error, "trailing_metadata", lambda: None)() or ()
        for key, value in trailing:
            if key != "grpc-status-details-bin" or not isinstance(value, bytes):
                continue
            try:
                status = status_pb2.Status.FromString(value)
            except DecodeError:
                continue
            # The transport status is authoritative. Inconsistent rich status
            # must not provide misleading recovery guidance.
            code = self.code()
            if (
                code is None
                or status.code != code.value[0]
                or status.message != self.details()
            ):
                continue
            self.raw_status = status
            break
        if self.raw_status is None:
            return
        violations = []
        for detail in self.raw_status.details:
            try:
                if detail.Is(error_details_pb2.BadRequest.DESCRIPTOR):
                    bad_request = error_details_pb2.BadRequest()
                    detail.Unpack(bad_request)
                    violations.extend(
                        FieldViolation(v.field, v.description)
                        for v in bad_request.field_violations
                    )
                elif detail.Is(error_details_pb2.ErrorInfo.DESCRIPTOR):
                    info = error_details_pb2.ErrorInfo()
                    detail.Unpack(info)
                    self.error_info = ErrorInfo(
                        info.reason, info.domain, dict(info.metadata)
                    )
                elif detail.Is(error_details_pb2.RetryInfo.DESCRIPTOR):
                    retry = error_details_pb2.RetryInfo()
                    detail.Unpack(retry)
                    delay = retry.retry_delay
                    if (
                        retry.HasField("retry_delay")
                        and 0 <= delay.seconds <= 315_576_000_000
                        and 0 <= delay.nanos < 1_000_000_000
                    ):
                        self.retry_delay = delay.seconds + delay.nanos / 1_000_000_000
            except DecodeError:
                continue
        self.field_violations = tuple(violations)

    def code(self):
        """Return the original gRPC status code."""
        return getattr(self.raw_error, "code", lambda: None)()

    def details(self):
        """Return the original human-readable gRPC message."""
        return getattr(self.raw_error, "details", lambda: str(self.raw_error))()

    def __getattr__(self, name):
        return getattr(self.raw_error, name)


def from_grpc_error(error: grpc.RpcError) -> GatewayError:
    """Decode a raw RPC failure without discarding unrecognized details."""
    return error if isinstance(error, GatewayError) else GatewayError(error)


class _ErrorMappingStream:
    def __init__(self, call):
        self._call = call
        self._iterator = iter(call)

    def __iter__(self):
        return self

    def __next__(self):
        try:
            return next(self._iterator)
        except grpc.RpcError as error:
            raise from_grpc_error(error) from error

    def __getattr__(self, name):
        return getattr(self._call, name)


class _ErrorMappingInterceptor(
    grpc.UnaryUnaryClientInterceptor, grpc.UnaryStreamClientInterceptor
):
    def intercept_unary_unary(self, continuation, client_call_details, request):
        call = continuation(client_call_details, request)
        error = call.exception()
        if isinstance(error, grpc.RpcError):
            raise from_grpc_error(error) from error
        return call

    def intercept_unary_stream(self, continuation, client_call_details, request):
        return _ErrorMappingStream(continuation(client_call_details, request))


def _error_mapping_channel(channel):
    return grpc.intercept_channel(channel, _ErrorMappingInterceptor())
