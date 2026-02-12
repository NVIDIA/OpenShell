from __future__ import annotations

from concurrent import futures

import grpc
import pytest

from navigator._proto import inference_pb2, inference_pb2_grpc
from navigator.inference import Inference


class FakeInferenceServicer(inference_pb2_grpc.InferenceServicer):
    """Fake Inference gRPC servicer for testing."""

    def __init__(self) -> None:
        self.last_request: inference_pb2.CompletionRequest | None = None
        self.last_metadata: dict[str, str] = {}

    def Completion(self, request, context):
        self.last_request = request
        self.last_metadata = dict(context.invocation_metadata())
        return inference_pb2.CompletionResponse(
            id="test-completion-123",
            model="meta/llama-3.1-8b-instruct",
            created=1700000000,
            choices=[
                inference_pb2.CompletionChoice(
                    index=0,
                    message=inference_pb2.ChatMessage(
                        role="assistant",
                        content="Hello! How can I help?",
                        reasoning_content="testing reasoning",
                    ),
                    finish_reason="stop",
                )
            ],
            usage=inference_pb2.CompletionUsage(
                prompt_tokens=10,
                completion_tokens=7,
                total_tokens=17,
            ),
        )


@pytest.fixture()
def inference_server():
    """Start a fake gRPC server and return (endpoint, servicer)."""
    servicer = FakeInferenceServicer()
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=2))
    inference_pb2_grpc.add_InferenceServicer_to_server(servicer, server)
    port = server.add_insecure_port("[::]:0")
    server.start()
    yield f"localhost:{port}", servicer
    server.stop(grace=0)


def test_completion_returns_response(inference_server):
    endpoint, _ = inference_server
    with Inference(endpoint, sandbox_id="sandbox-abc") as client:
        response = client.completion(
            messages=[{"role": "user", "content": "Hello"}],
            routing_hint="local",
        )

    assert response.id == "test-completion-123"
    assert response.model == "meta/llama-3.1-8b-instruct"
    assert len(response.choices) == 1
    assert response.choices[0].message.content == "Hello! How can I help?"
    assert response.choices[0].message.reasoning_content == "testing reasoning"
    assert response.choices[0].finish_reason == "stop"
    assert response.usage is not None
    assert response.usage.prompt_tokens == 10
    assert response.usage.completion_tokens == 7
    assert response.usage.total_tokens == 17


def test_completion_sends_correct_request(inference_server):
    endpoint, servicer = inference_server
    with Inference(endpoint, sandbox_id="sandbox-abc") as client:
        client.completion(
            messages=[
                {"role": "system", "content": "You are helpful."},
                {"role": "user", "content": "Hi"},
            ],
            routing_hint="frontier",
            temperature=0.7,
            max_tokens=100,
        )

    assert servicer.last_request is not None
    assert servicer.last_request.routing_hint == "frontier"
    assert len(servicer.last_request.messages) == 2
    assert servicer.last_request.messages[0].role == "system"
    assert servicer.last_request.messages[1].content == "Hi"
    assert servicer.last_request.temperature == pytest.approx(0.7)
    assert servicer.last_request.max_tokens == 100


def test_completion_sends_sandbox_id_header(inference_server):
    endpoint, servicer = inference_server
    with Inference(endpoint, sandbox_id="sandbox-xyz") as client:
        client.completion(
            messages=[{"role": "user", "content": "Hello"}],
        )

    assert servicer.last_metadata.get("x-sandbox-id") == "sandbox-xyz"
