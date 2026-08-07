import datamodel_pb2 as _datamodel_pb2
import options_pb2 as _options_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class InferenceRouteConfig(_message.Message):
    __slots__ = ("provider_name", "model_id", "timeout_secs")
    PROVIDER_NAME_FIELD_NUMBER: _ClassVar[int]
    MODEL_ID_FIELD_NUMBER: _ClassVar[int]
    TIMEOUT_SECS_FIELD_NUMBER: _ClassVar[int]
    provider_name: str
    model_id: str
    timeout_secs: int
    def __init__(self, provider_name: _Optional[str] = ..., model_id: _Optional[str] = ..., timeout_secs: _Optional[int] = ...) -> None: ...

class InferenceRoute(_message.Message):
    __slots__ = ("metadata", "config", "version")
    METADATA_FIELD_NUMBER: _ClassVar[int]
    CONFIG_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    metadata: _datamodel_pb2.ObjectMeta
    config: InferenceRouteConfig
    version: int
    def __init__(self, metadata: _Optional[_Union[_datamodel_pb2.ObjectMeta, _Mapping]] = ..., config: _Optional[_Union[InferenceRouteConfig, _Mapping]] = ..., version: _Optional[int] = ...) -> None: ...

class SetInferenceRouteRequest(_message.Message):
    __slots__ = ("provider_name", "model_id", "route_name", "verify", "no_verify", "timeout_secs", "workspace")
    PROVIDER_NAME_FIELD_NUMBER: _ClassVar[int]
    MODEL_ID_FIELD_NUMBER: _ClassVar[int]
    ROUTE_NAME_FIELD_NUMBER: _ClassVar[int]
    VERIFY_FIELD_NUMBER: _ClassVar[int]
    NO_VERIFY_FIELD_NUMBER: _ClassVar[int]
    TIMEOUT_SECS_FIELD_NUMBER: _ClassVar[int]
    WORKSPACE_FIELD_NUMBER: _ClassVar[int]
    provider_name: str
    model_id: str
    route_name: str
    verify: bool
    no_verify: bool
    timeout_secs: int
    workspace: str
    def __init__(self, provider_name: _Optional[str] = ..., model_id: _Optional[str] = ..., route_name: _Optional[str] = ..., verify: bool = ..., no_verify: bool = ..., timeout_secs: _Optional[int] = ..., workspace: _Optional[str] = ...) -> None: ...

class ValidatedEndpoint(_message.Message):
    __slots__ = ("url", "protocol")
    URL_FIELD_NUMBER: _ClassVar[int]
    PROTOCOL_FIELD_NUMBER: _ClassVar[int]
    url: str
    protocol: str
    def __init__(self, url: _Optional[str] = ..., protocol: _Optional[str] = ...) -> None: ...

class SetInferenceRouteResponse(_message.Message):
    __slots__ = ("provider_name", "model_id", "version", "route_name", "validation_performed", "validated_endpoints", "timeout_secs", "workspace")
    PROVIDER_NAME_FIELD_NUMBER: _ClassVar[int]
    MODEL_ID_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    ROUTE_NAME_FIELD_NUMBER: _ClassVar[int]
    VALIDATION_PERFORMED_FIELD_NUMBER: _ClassVar[int]
    VALIDATED_ENDPOINTS_FIELD_NUMBER: _ClassVar[int]
    TIMEOUT_SECS_FIELD_NUMBER: _ClassVar[int]
    WORKSPACE_FIELD_NUMBER: _ClassVar[int]
    provider_name: str
    model_id: str
    version: int
    route_name: str
    validation_performed: bool
    validated_endpoints: _containers.RepeatedCompositeFieldContainer[ValidatedEndpoint]
    timeout_secs: int
    workspace: str
    def __init__(self, provider_name: _Optional[str] = ..., model_id: _Optional[str] = ..., version: _Optional[int] = ..., route_name: _Optional[str] = ..., validation_performed: bool = ..., validated_endpoints: _Optional[_Iterable[_Union[ValidatedEndpoint, _Mapping]]] = ..., timeout_secs: _Optional[int] = ..., workspace: _Optional[str] = ...) -> None: ...

class GetInferenceRouteRequest(_message.Message):
    __slots__ = ("route_name", "workspace")
    ROUTE_NAME_FIELD_NUMBER: _ClassVar[int]
    WORKSPACE_FIELD_NUMBER: _ClassVar[int]
    route_name: str
    workspace: str
    def __init__(self, route_name: _Optional[str] = ..., workspace: _Optional[str] = ...) -> None: ...

class GetInferenceRouteResponse(_message.Message):
    __slots__ = ("provider_name", "model_id", "version", "route_name", "timeout_secs", "workspace")
    PROVIDER_NAME_FIELD_NUMBER: _ClassVar[int]
    MODEL_ID_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    ROUTE_NAME_FIELD_NUMBER: _ClassVar[int]
    TIMEOUT_SECS_FIELD_NUMBER: _ClassVar[int]
    WORKSPACE_FIELD_NUMBER: _ClassVar[int]
    provider_name: str
    model_id: str
    version: int
    route_name: str
    timeout_secs: int
    workspace: str
    def __init__(self, provider_name: _Optional[str] = ..., model_id: _Optional[str] = ..., version: _Optional[int] = ..., route_name: _Optional[str] = ..., timeout_secs: _Optional[int] = ..., workspace: _Optional[str] = ...) -> None: ...

class DeleteInferenceRouteRequest(_message.Message):
    __slots__ = ("route_name", "workspace")
    ROUTE_NAME_FIELD_NUMBER: _ClassVar[int]
    WORKSPACE_FIELD_NUMBER: _ClassVar[int]
    route_name: str
    workspace: str
    def __init__(self, route_name: _Optional[str] = ..., workspace: _Optional[str] = ...) -> None: ...

class DeleteInferenceRouteResponse(_message.Message):
    __slots__ = ("deleted",)
    DELETED_FIELD_NUMBER: _ClassVar[int]
    deleted: bool
    def __init__(self, deleted: bool = ...) -> None: ...

class GetInferenceBundleRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class ResolvedRoute(_message.Message):
    __slots__ = ("name", "base_url", "protocols", "api_key", "model_id", "provider_type", "timeout_secs", "model_in_path", "request_path_override")
    NAME_FIELD_NUMBER: _ClassVar[int]
    BASE_URL_FIELD_NUMBER: _ClassVar[int]
    PROTOCOLS_FIELD_NUMBER: _ClassVar[int]
    API_KEY_FIELD_NUMBER: _ClassVar[int]
    MODEL_ID_FIELD_NUMBER: _ClassVar[int]
    PROVIDER_TYPE_FIELD_NUMBER: _ClassVar[int]
    TIMEOUT_SECS_FIELD_NUMBER: _ClassVar[int]
    MODEL_IN_PATH_FIELD_NUMBER: _ClassVar[int]
    REQUEST_PATH_OVERRIDE_FIELD_NUMBER: _ClassVar[int]
    name: str
    base_url: str
    protocols: _containers.RepeatedScalarFieldContainer[str]
    api_key: str
    model_id: str
    provider_type: str
    timeout_secs: int
    model_in_path: bool
    request_path_override: str
    def __init__(self, name: _Optional[str] = ..., base_url: _Optional[str] = ..., protocols: _Optional[_Iterable[str]] = ..., api_key: _Optional[str] = ..., model_id: _Optional[str] = ..., provider_type: _Optional[str] = ..., timeout_secs: _Optional[int] = ..., model_in_path: bool = ..., request_path_override: _Optional[str] = ...) -> None: ...

class GetInferenceBundleResponse(_message.Message):
    __slots__ = ("routes", "revision", "generated_at_ms")
    ROUTES_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    GENERATED_AT_MS_FIELD_NUMBER: _ClassVar[int]
    routes: _containers.RepeatedCompositeFieldContainer[ResolvedRoute]
    revision: str
    generated_at_ms: int
    def __init__(self, routes: _Optional[_Iterable[_Union[ResolvedRoute, _Mapping]]] = ..., revision: _Optional[str] = ..., generated_at_ms: _Optional[int] = ...) -> None: ...
