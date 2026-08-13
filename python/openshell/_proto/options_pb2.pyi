from google.protobuf import descriptor_pb2 as _descriptor_pb2
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Optional as _Optional

DESCRIPTOR: _descriptor.FileDescriptor
AUTHORIZATION_FIELD_NUMBER: _ClassVar[int]
authorization: _descriptor.FieldDescriptor
SECRET_FIELD_NUMBER: _ClassVar[int]
secret: _descriptor.FieldDescriptor

class AuthorizationRule(_message.Message):
    __slots__ = ("auth_mode", "workspace_role", "global_role", "scope")
    AUTH_MODE_FIELD_NUMBER: _ClassVar[int]
    WORKSPACE_ROLE_FIELD_NUMBER: _ClassVar[int]
    GLOBAL_ROLE_FIELD_NUMBER: _ClassVar[int]
    SCOPE_FIELD_NUMBER: _ClassVar[int]
    auth_mode: str
    workspace_role: str
    global_role: str
    scope: str
    def __init__(self, auth_mode: _Optional[str] = ..., workspace_role: _Optional[str] = ..., global_role: _Optional[str] = ..., scope: _Optional[str] = ...) -> None: ...
