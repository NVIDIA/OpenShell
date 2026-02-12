from __future__ import annotations

import os
from dataclasses import dataclass

import grpc

from navigator._proto import inference_pb2, inference_pb2_grpc

SANDBOX_ID_HEADER = "x-sandbox-id"
ENDPOINT_ENV = "NAVIGATOR_ENDPOINT"
SANDBOX_ID_ENV = "NAVIGATOR_SANDBOX_ID"


@dataclass
class Message:
    role: str
    content: str
    reasoning_content: str | None = None


@dataclass
class Choice:
    index: int
    message: Message
    finish_reason: str


@dataclass
class Usage:
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int


@dataclass
class CompletionResponse:
    id: str
    model: str
    created: int
    choices: list[Choice]
    usage: Usage | None


class Inference:
    """Client for the Navigator Inference gRPC service."""

    def __init__(
        self,
        endpoint: str | None = None,
        *,
        sandbox_id: str | None = None,
    ) -> None:
        endpoint = endpoint or os.environ.get(ENDPOINT_ENV, "")
        if not endpoint:
            raise ValueError(f"endpoint must be provided or set via ${ENDPOINT_ENV}")
        sandbox_id = (
            sandbox_id if sandbox_id is not None else os.environ.get(SANDBOX_ID_ENV, "")
        )

        # grpc.insecure_channel expects host:port, not a URL with scheme.
        # Strip http:// prefix if present to avoid malformed CONNECT targets
        # when gRPC routes through an HTTP proxy.
        target = endpoint
        for prefix in ("http://", "https://"):
            if target.startswith(prefix):
                target = target[len(prefix) :]
                break
        self._channel = grpc.insecure_channel(target)
        self._stub = inference_pb2_grpc.InferenceStub(self._channel)
        self._sandbox_id = sandbox_id

    def close(self) -> None:
        self._channel.close()

    def __enter__(self) -> Inference:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def completion(
        self,
        *,
        messages: list[dict[str, str]],
        routing_hint: str = "local",
        temperature: float | None = None,
        max_tokens: int | None = None,
        top_p: float | None = None,
    ) -> CompletionResponse:
        proto_messages = [
            inference_pb2.ChatMessage(role=m["role"], content=m["content"])
            for m in messages
        ]

        request = inference_pb2.CompletionRequest(
            routing_hint=routing_hint,
            messages=proto_messages,
        )
        if temperature is not None:
            request.temperature = temperature
        if max_tokens is not None:
            request.max_tokens = max_tokens
        if top_p is not None:
            request.top_p = top_p

        metadata = []
        if self._sandbox_id:
            metadata.append((SANDBOX_ID_HEADER, self._sandbox_id))

        response = self._stub.Completion(request, metadata=metadata or None)
        return _to_response(response)


def _to_response(proto: inference_pb2.CompletionResponse) -> CompletionResponse:
    choices = [
        Choice(
            index=c.index,
            message=Message(
                role=c.message.role,
                content=c.message.content,
                reasoning_content=(
                    c.message.reasoning_content
                    if c.message.HasField("reasoning_content")
                    else None
                ),
            ),
            finish_reason=c.finish_reason,
        )
        for c in proto.choices
    ]
    usage = None
    if proto.HasField("usage"):
        usage = Usage(
            prompt_tokens=proto.usage.prompt_tokens,
            completion_tokens=proto.usage.completion_tokens,
            total_tokens=proto.usage.total_tokens,
        )
    return CompletionResponse(
        id=proto.id,
        model=proto.model,
        created=proto.created,
        choices=choices,
        usage=usage,
    )
