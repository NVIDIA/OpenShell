from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class InferenceRouteSpec(_message.Message):
    __slots__ = ("routing_hint", "base_url", "protocol", "api_key", "model_id", "enabled")
    ROUTING_HINT_FIELD_NUMBER: _ClassVar[int]
    BASE_URL_FIELD_NUMBER: _ClassVar[int]
    PROTOCOL_FIELD_NUMBER: _ClassVar[int]
    API_KEY_FIELD_NUMBER: _ClassVar[int]
    MODEL_ID_FIELD_NUMBER: _ClassVar[int]
    ENABLED_FIELD_NUMBER: _ClassVar[int]
    routing_hint: str
    base_url: str
    protocol: str
    api_key: str
    model_id: str
    enabled: bool
    def __init__(self, routing_hint: _Optional[str] = ..., base_url: _Optional[str] = ..., protocol: _Optional[str] = ..., api_key: _Optional[str] = ..., model_id: _Optional[str] = ..., enabled: bool = ...) -> None: ...

class InferenceRoute(_message.Message):
    __slots__ = ("id", "spec")
    ID_FIELD_NUMBER: _ClassVar[int]
    SPEC_FIELD_NUMBER: _ClassVar[int]
    id: str
    spec: InferenceRouteSpec
    def __init__(self, id: _Optional[str] = ..., spec: _Optional[_Union[InferenceRouteSpec, _Mapping]] = ...) -> None: ...

class CreateInferenceRouteRequest(_message.Message):
    __slots__ = ("route",)
    ROUTE_FIELD_NUMBER: _ClassVar[int]
    route: InferenceRouteSpec
    def __init__(self, route: _Optional[_Union[InferenceRouteSpec, _Mapping]] = ...) -> None: ...

class UpdateInferenceRouteRequest(_message.Message):
    __slots__ = ("id", "route")
    ID_FIELD_NUMBER: _ClassVar[int]
    ROUTE_FIELD_NUMBER: _ClassVar[int]
    id: str
    route: InferenceRouteSpec
    def __init__(self, id: _Optional[str] = ..., route: _Optional[_Union[InferenceRouteSpec, _Mapping]] = ...) -> None: ...

class DeleteInferenceRouteRequest(_message.Message):
    __slots__ = ("id",)
    ID_FIELD_NUMBER: _ClassVar[int]
    id: str
    def __init__(self, id: _Optional[str] = ...) -> None: ...

class DeleteInferenceRouteResponse(_message.Message):
    __slots__ = ("deleted",)
    DELETED_FIELD_NUMBER: _ClassVar[int]
    deleted: bool
    def __init__(self, deleted: bool = ...) -> None: ...

class ListInferenceRoutesRequest(_message.Message):
    __slots__ = ("limit", "offset")
    LIMIT_FIELD_NUMBER: _ClassVar[int]
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    limit: int
    offset: int
    def __init__(self, limit: _Optional[int] = ..., offset: _Optional[int] = ...) -> None: ...

class ListInferenceRoutesResponse(_message.Message):
    __slots__ = ("routes",)
    ROUTES_FIELD_NUMBER: _ClassVar[int]
    routes: _containers.RepeatedCompositeFieldContainer[InferenceRoute]
    def __init__(self, routes: _Optional[_Iterable[_Union[InferenceRoute, _Mapping]]] = ...) -> None: ...

class InferenceRouteResponse(_message.Message):
    __slots__ = ("route",)
    ROUTE_FIELD_NUMBER: _ClassVar[int]
    route: InferenceRoute
    def __init__(self, route: _Optional[_Union[InferenceRoute, _Mapping]] = ...) -> None: ...

class CompletionRequest(_message.Message):
    __slots__ = ("routing_hint", "messages", "temperature", "max_tokens", "top_p")
    ROUTING_HINT_FIELD_NUMBER: _ClassVar[int]
    MESSAGES_FIELD_NUMBER: _ClassVar[int]
    TEMPERATURE_FIELD_NUMBER: _ClassVar[int]
    MAX_TOKENS_FIELD_NUMBER: _ClassVar[int]
    TOP_P_FIELD_NUMBER: _ClassVar[int]
    routing_hint: str
    messages: _containers.RepeatedCompositeFieldContainer[ChatMessage]
    temperature: float
    max_tokens: int
    top_p: float
    def __init__(self, routing_hint: _Optional[str] = ..., messages: _Optional[_Iterable[_Union[ChatMessage, _Mapping]]] = ..., temperature: _Optional[float] = ..., max_tokens: _Optional[int] = ..., top_p: _Optional[float] = ...) -> None: ...

class ChatMessage(_message.Message):
    __slots__ = ("role", "content", "reasoning_content")
    ROLE_FIELD_NUMBER: _ClassVar[int]
    CONTENT_FIELD_NUMBER: _ClassVar[int]
    REASONING_CONTENT_FIELD_NUMBER: _ClassVar[int]
    role: str
    content: str
    reasoning_content: str
    def __init__(self, role: _Optional[str] = ..., content: _Optional[str] = ..., reasoning_content: _Optional[str] = ...) -> None: ...

class CompletionResponse(_message.Message):
    __slots__ = ("id", "model", "created", "choices", "usage")
    ID_FIELD_NUMBER: _ClassVar[int]
    MODEL_FIELD_NUMBER: _ClassVar[int]
    CREATED_FIELD_NUMBER: _ClassVar[int]
    CHOICES_FIELD_NUMBER: _ClassVar[int]
    USAGE_FIELD_NUMBER: _ClassVar[int]
    id: str
    model: str
    created: int
    choices: _containers.RepeatedCompositeFieldContainer[CompletionChoice]
    usage: CompletionUsage
    def __init__(self, id: _Optional[str] = ..., model: _Optional[str] = ..., created: _Optional[int] = ..., choices: _Optional[_Iterable[_Union[CompletionChoice, _Mapping]]] = ..., usage: _Optional[_Union[CompletionUsage, _Mapping]] = ...) -> None: ...

class CompletionChoice(_message.Message):
    __slots__ = ("index", "message", "finish_reason")
    INDEX_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    FINISH_REASON_FIELD_NUMBER: _ClassVar[int]
    index: int
    message: ChatMessage
    finish_reason: str
    def __init__(self, index: _Optional[int] = ..., message: _Optional[_Union[ChatMessage, _Mapping]] = ..., finish_reason: _Optional[str] = ...) -> None: ...

class CompletionUsage(_message.Message):
    __slots__ = ("prompt_tokens", "completion_tokens", "total_tokens")
    PROMPT_TOKENS_FIELD_NUMBER: _ClassVar[int]
    COMPLETION_TOKENS_FIELD_NUMBER: _ClassVar[int]
    TOTAL_TOKENS_FIELD_NUMBER: _ClassVar[int]
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int
    def __init__(self, prompt_tokens: _Optional[int] = ..., completion_tokens: _Optional[int] = ..., total_tokens: _Optional[int] = ...) -> None: ...
