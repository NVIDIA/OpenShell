import options_pb2 as _options_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class WorkspacePhase(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    WORKSPACE_PHASE_UNSPECIFIED: _ClassVar[WorkspacePhase]
    WORKSPACE_PHASE_ACTIVE: _ClassVar[WorkspacePhase]
    WORKSPACE_PHASE_TERMINATING: _ClassVar[WorkspacePhase]
WORKSPACE_PHASE_UNSPECIFIED: WorkspacePhase
WORKSPACE_PHASE_ACTIVE: WorkspacePhase
WORKSPACE_PHASE_TERMINATING: WorkspacePhase

class ObjectMeta(_message.Message):
    __slots__ = ("id", "name", "created_at_ms", "labels", "resource_version", "annotations", "workspace", "deletion_timestamp_ms")
    class LabelsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    class AnnotationsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    CREATED_AT_MS_FIELD_NUMBER: _ClassVar[int]
    LABELS_FIELD_NUMBER: _ClassVar[int]
    RESOURCE_VERSION_FIELD_NUMBER: _ClassVar[int]
    ANNOTATIONS_FIELD_NUMBER: _ClassVar[int]
    WORKSPACE_FIELD_NUMBER: _ClassVar[int]
    DELETION_TIMESTAMP_MS_FIELD_NUMBER: _ClassVar[int]
    id: str
    name: str
    created_at_ms: int
    labels: _containers.ScalarMap[str, str]
    resource_version: int
    annotations: _containers.ScalarMap[str, str]
    workspace: str
    deletion_timestamp_ms: int
    def __init__(self, id: _Optional[str] = ..., name: _Optional[str] = ..., created_at_ms: _Optional[int] = ..., labels: _Optional[_Mapping[str, str]] = ..., resource_version: _Optional[int] = ..., annotations: _Optional[_Mapping[str, str]] = ..., workspace: _Optional[str] = ..., deletion_timestamp_ms: _Optional[int] = ...) -> None: ...

class WorkspaceStatus(_message.Message):
    __slots__ = ("phase",)
    PHASE_FIELD_NUMBER: _ClassVar[int]
    phase: WorkspacePhase
    def __init__(self, phase: _Optional[_Union[WorkspacePhase, str]] = ...) -> None: ...

class Workspace(_message.Message):
    __slots__ = ("metadata", "status")
    METADATA_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    metadata: ObjectMeta
    status: WorkspaceStatus
    def __init__(self, metadata: _Optional[_Union[ObjectMeta, _Mapping]] = ..., status: _Optional[_Union[WorkspaceStatus, _Mapping]] = ...) -> None: ...

class Provider(_message.Message):
    __slots__ = ("metadata", "type", "credentials", "config", "credential_expires_at_ms", "profile_workspace")
    class CredentialsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    class ConfigEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    class CredentialExpiresAtMsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: int
        def __init__(self, key: _Optional[str] = ..., value: _Optional[int] = ...) -> None: ...
    METADATA_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    CREDENTIALS_FIELD_NUMBER: _ClassVar[int]
    CONFIG_FIELD_NUMBER: _ClassVar[int]
    CREDENTIAL_EXPIRES_AT_MS_FIELD_NUMBER: _ClassVar[int]
    PROFILE_WORKSPACE_FIELD_NUMBER: _ClassVar[int]
    metadata: ObjectMeta
    type: str
    credentials: _containers.ScalarMap[str, str]
    config: _containers.ScalarMap[str, str]
    credential_expires_at_ms: _containers.ScalarMap[str, int]
    profile_workspace: str
    def __init__(self, metadata: _Optional[_Union[ObjectMeta, _Mapping]] = ..., type: _Optional[str] = ..., credentials: _Optional[_Mapping[str, str]] = ..., config: _Optional[_Mapping[str, str]] = ..., credential_expires_at_ms: _Optional[_Mapping[str, int]] = ..., profile_workspace: _Optional[str] = ...) -> None: ...
