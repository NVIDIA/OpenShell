from google.protobuf import struct_pb2 as _struct_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class SettingScope(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    SETTING_SCOPE_UNSPECIFIED: _ClassVar[SettingScope]
    SETTING_SCOPE_SANDBOX: _ClassVar[SettingScope]
    SETTING_SCOPE_GLOBAL: _ClassVar[SettingScope]

class PolicySource(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    POLICY_SOURCE_UNSPECIFIED: _ClassVar[PolicySource]
    POLICY_SOURCE_SANDBOX: _ClassVar[PolicySource]
    POLICY_SOURCE_GLOBAL: _ClassVar[PolicySource]
SETTING_SCOPE_UNSPECIFIED: SettingScope
SETTING_SCOPE_SANDBOX: SettingScope
SETTING_SCOPE_GLOBAL: SettingScope
POLICY_SOURCE_UNSPECIFIED: PolicySource
POLICY_SOURCE_SANDBOX: PolicySource
POLICY_SOURCE_GLOBAL: PolicySource

class SandboxPolicy(_message.Message):
    __slots__ = ("version", "filesystem", "landlock", "process", "network_policies", "network_middlewares")
    class NetworkPoliciesEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: NetworkPolicyRule
        def __init__(self, key: _Optional[str] = ..., value: _Optional[_Union[NetworkPolicyRule, _Mapping]] = ...) -> None: ...
    class NetworkMiddlewaresEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: NetworkMiddlewareConfig
        def __init__(self, key: _Optional[str] = ..., value: _Optional[_Union[NetworkMiddlewareConfig, _Mapping]] = ...) -> None: ...
    VERSION_FIELD_NUMBER: _ClassVar[int]
    FILESYSTEM_FIELD_NUMBER: _ClassVar[int]
    LANDLOCK_FIELD_NUMBER: _ClassVar[int]
    PROCESS_FIELD_NUMBER: _ClassVar[int]
    NETWORK_POLICIES_FIELD_NUMBER: _ClassVar[int]
    NETWORK_MIDDLEWARES_FIELD_NUMBER: _ClassVar[int]
    version: int
    filesystem: FilesystemPolicy
    landlock: LandlockPolicy
    process: ProcessPolicy
    network_policies: _containers.MessageMap[str, NetworkPolicyRule]
    network_middlewares: _containers.MessageMap[str, NetworkMiddlewareConfig]
    def __init__(self, version: _Optional[int] = ..., filesystem: _Optional[_Union[FilesystemPolicy, _Mapping]] = ..., landlock: _Optional[_Union[LandlockPolicy, _Mapping]] = ..., process: _Optional[_Union[ProcessPolicy, _Mapping]] = ..., network_policies: _Optional[_Mapping[str, NetworkPolicyRule]] = ..., network_middlewares: _Optional[_Mapping[str, NetworkMiddlewareConfig]] = ...) -> None: ...

class FilesystemPolicy(_message.Message):
    __slots__ = ("include_workdir", "read_only", "read_write")
    INCLUDE_WORKDIR_FIELD_NUMBER: _ClassVar[int]
    READ_ONLY_FIELD_NUMBER: _ClassVar[int]
    READ_WRITE_FIELD_NUMBER: _ClassVar[int]
    include_workdir: bool
    read_only: _containers.RepeatedScalarFieldContainer[str]
    read_write: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, include_workdir: bool = ..., read_only: _Optional[_Iterable[str]] = ..., read_write: _Optional[_Iterable[str]] = ...) -> None: ...

class LandlockPolicy(_message.Message):
    __slots__ = ("compatibility",)
    COMPATIBILITY_FIELD_NUMBER: _ClassVar[int]
    compatibility: str
    def __init__(self, compatibility: _Optional[str] = ...) -> None: ...

class ProcessPolicy(_message.Message):
    __slots__ = ("run_as_user", "run_as_group")
    RUN_AS_USER_FIELD_NUMBER: _ClassVar[int]
    RUN_AS_GROUP_FIELD_NUMBER: _ClassVar[int]
    run_as_user: str
    run_as_group: str
    def __init__(self, run_as_user: _Optional[str] = ..., run_as_group: _Optional[str] = ...) -> None: ...

class NetworkPolicyRule(_message.Message):
    __slots__ = ("name", "endpoints", "binaries")
    NAME_FIELD_NUMBER: _ClassVar[int]
    ENDPOINTS_FIELD_NUMBER: _ClassVar[int]
    BINARIES_FIELD_NUMBER: _ClassVar[int]
    name: str
    endpoints: _containers.RepeatedCompositeFieldContainer[NetworkEndpoint]
    binaries: _containers.RepeatedCompositeFieldContainer[NetworkBinary]
    def __init__(self, name: _Optional[str] = ..., endpoints: _Optional[_Iterable[_Union[NetworkEndpoint, _Mapping]]] = ..., binaries: _Optional[_Iterable[_Union[NetworkBinary, _Mapping]]] = ...) -> None: ...

class NetworkMiddlewareConfig(_message.Message):
    __slots__ = ("name", "middleware", "config", "on_error", "endpoints", "order")
    NAME_FIELD_NUMBER: _ClassVar[int]
    MIDDLEWARE_FIELD_NUMBER: _ClassVar[int]
    CONFIG_FIELD_NUMBER: _ClassVar[int]
    ON_ERROR_FIELD_NUMBER: _ClassVar[int]
    ENDPOINTS_FIELD_NUMBER: _ClassVar[int]
    ORDER_FIELD_NUMBER: _ClassVar[int]
    name: str
    middleware: str
    config: _struct_pb2.Struct
    on_error: str
    endpoints: MiddlewareEndpointSelector
    order: int
    def __init__(self, name: _Optional[str] = ..., middleware: _Optional[str] = ..., config: _Optional[_Union[_struct_pb2.Struct, _Mapping]] = ..., on_error: _Optional[str] = ..., endpoints: _Optional[_Union[MiddlewareEndpointSelector, _Mapping]] = ..., order: _Optional[int] = ...) -> None: ...

class MiddlewareEndpointSelector(_message.Message):
    __slots__ = ("include", "exclude")
    INCLUDE_FIELD_NUMBER: _ClassVar[int]
    EXCLUDE_FIELD_NUMBER: _ClassVar[int]
    include: _containers.RepeatedScalarFieldContainer[str]
    exclude: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, include: _Optional[_Iterable[str]] = ..., exclude: _Optional[_Iterable[str]] = ...) -> None: ...

class NetworkEndpoint(_message.Message):
    __slots__ = ("host", "port", "protocol", "tls", "enforcement", "access", "rules", "allowed_ips", "ports", "deny_rules", "allow_encoded_slash", "persisted_queries", "graphql_persisted_queries", "graphql_max_body_bytes", "path", "websocket_credential_rewrite", "request_body_credential_rewrite", "advisor_proposed", "credential_signing", "signing_service", "signing_region", "json_rpc_max_body_bytes", "mcp")
    class GraphqlPersistedQueriesEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: GraphqlOperation
        def __init__(self, key: _Optional[str] = ..., value: _Optional[_Union[GraphqlOperation, _Mapping]] = ...) -> None: ...
    HOST_FIELD_NUMBER: _ClassVar[int]
    PORT_FIELD_NUMBER: _ClassVar[int]
    PROTOCOL_FIELD_NUMBER: _ClassVar[int]
    TLS_FIELD_NUMBER: _ClassVar[int]
    ENFORCEMENT_FIELD_NUMBER: _ClassVar[int]
    ACCESS_FIELD_NUMBER: _ClassVar[int]
    RULES_FIELD_NUMBER: _ClassVar[int]
    ALLOWED_IPS_FIELD_NUMBER: _ClassVar[int]
    PORTS_FIELD_NUMBER: _ClassVar[int]
    DENY_RULES_FIELD_NUMBER: _ClassVar[int]
    ALLOW_ENCODED_SLASH_FIELD_NUMBER: _ClassVar[int]
    PERSISTED_QUERIES_FIELD_NUMBER: _ClassVar[int]
    GRAPHQL_PERSISTED_QUERIES_FIELD_NUMBER: _ClassVar[int]
    GRAPHQL_MAX_BODY_BYTES_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    WEBSOCKET_CREDENTIAL_REWRITE_FIELD_NUMBER: _ClassVar[int]
    REQUEST_BODY_CREDENTIAL_REWRITE_FIELD_NUMBER: _ClassVar[int]
    ADVISOR_PROPOSED_FIELD_NUMBER: _ClassVar[int]
    CREDENTIAL_SIGNING_FIELD_NUMBER: _ClassVar[int]
    SIGNING_SERVICE_FIELD_NUMBER: _ClassVar[int]
    SIGNING_REGION_FIELD_NUMBER: _ClassVar[int]
    JSON_RPC_MAX_BODY_BYTES_FIELD_NUMBER: _ClassVar[int]
    MCP_FIELD_NUMBER: _ClassVar[int]
    host: str
    port: int
    protocol: str
    tls: str
    enforcement: str
    access: str
    rules: _containers.RepeatedCompositeFieldContainer[L7Rule]
    allowed_ips: _containers.RepeatedScalarFieldContainer[str]
    ports: _containers.RepeatedScalarFieldContainer[int]
    deny_rules: _containers.RepeatedCompositeFieldContainer[L7DenyRule]
    allow_encoded_slash: bool
    persisted_queries: str
    graphql_persisted_queries: _containers.MessageMap[str, GraphqlOperation]
    graphql_max_body_bytes: int
    path: str
    websocket_credential_rewrite: bool
    request_body_credential_rewrite: bool
    advisor_proposed: bool
    credential_signing: str
    signing_service: str
    signing_region: str
    json_rpc_max_body_bytes: int
    mcp: McpOptions
    def __init__(self, host: _Optional[str] = ..., port: _Optional[int] = ..., protocol: _Optional[str] = ..., tls: _Optional[str] = ..., enforcement: _Optional[str] = ..., access: _Optional[str] = ..., rules: _Optional[_Iterable[_Union[L7Rule, _Mapping]]] = ..., allowed_ips: _Optional[_Iterable[str]] = ..., ports: _Optional[_Iterable[int]] = ..., deny_rules: _Optional[_Iterable[_Union[L7DenyRule, _Mapping]]] = ..., allow_encoded_slash: bool = ..., persisted_queries: _Optional[str] = ..., graphql_persisted_queries: _Optional[_Mapping[str, GraphqlOperation]] = ..., graphql_max_body_bytes: _Optional[int] = ..., path: _Optional[str] = ..., websocket_credential_rewrite: bool = ..., request_body_credential_rewrite: bool = ..., advisor_proposed: bool = ..., credential_signing: _Optional[str] = ..., signing_service: _Optional[str] = ..., signing_region: _Optional[str] = ..., json_rpc_max_body_bytes: _Optional[int] = ..., mcp: _Optional[_Union[McpOptions, _Mapping]] = ...) -> None: ...

class McpOptions(_message.Message):
    __slots__ = ("strict_tool_names", "allow_all_known_mcp_methods")
    STRICT_TOOL_NAMES_FIELD_NUMBER: _ClassVar[int]
    ALLOW_ALL_KNOWN_MCP_METHODS_FIELD_NUMBER: _ClassVar[int]
    strict_tool_names: bool
    allow_all_known_mcp_methods: bool
    def __init__(self, strict_tool_names: bool = ..., allow_all_known_mcp_methods: bool = ...) -> None: ...

class GraphqlOperation(_message.Message):
    __slots__ = ("operation_type", "operation_name", "fields")
    OPERATION_TYPE_FIELD_NUMBER: _ClassVar[int]
    OPERATION_NAME_FIELD_NUMBER: _ClassVar[int]
    FIELDS_FIELD_NUMBER: _ClassVar[int]
    operation_type: str
    operation_name: str
    fields: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, operation_type: _Optional[str] = ..., operation_name: _Optional[str] = ..., fields: _Optional[_Iterable[str]] = ...) -> None: ...

class L7DenyRule(_message.Message):
    __slots__ = ("method", "path", "command", "query", "operation_type", "operation_name", "fields", "params")
    class QueryEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: L7QueryMatcher
        def __init__(self, key: _Optional[str] = ..., value: _Optional[_Union[L7QueryMatcher, _Mapping]] = ...) -> None: ...
    class ParamsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: L7QueryMatcher
        def __init__(self, key: _Optional[str] = ..., value: _Optional[_Union[L7QueryMatcher, _Mapping]] = ...) -> None: ...
    METHOD_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    COMMAND_FIELD_NUMBER: _ClassVar[int]
    QUERY_FIELD_NUMBER: _ClassVar[int]
    OPERATION_TYPE_FIELD_NUMBER: _ClassVar[int]
    OPERATION_NAME_FIELD_NUMBER: _ClassVar[int]
    FIELDS_FIELD_NUMBER: _ClassVar[int]
    PARAMS_FIELD_NUMBER: _ClassVar[int]
    method: str
    path: str
    command: str
    query: _containers.MessageMap[str, L7QueryMatcher]
    operation_type: str
    operation_name: str
    fields: _containers.RepeatedScalarFieldContainer[str]
    params: _containers.MessageMap[str, L7QueryMatcher]
    def __init__(self, method: _Optional[str] = ..., path: _Optional[str] = ..., command: _Optional[str] = ..., query: _Optional[_Mapping[str, L7QueryMatcher]] = ..., operation_type: _Optional[str] = ..., operation_name: _Optional[str] = ..., fields: _Optional[_Iterable[str]] = ..., params: _Optional[_Mapping[str, L7QueryMatcher]] = ...) -> None: ...

class L7Rule(_message.Message):
    __slots__ = ("allow",)
    ALLOW_FIELD_NUMBER: _ClassVar[int]
    allow: L7Allow
    def __init__(self, allow: _Optional[_Union[L7Allow, _Mapping]] = ...) -> None: ...

class L7Allow(_message.Message):
    __slots__ = ("method", "path", "command", "query", "operation_type", "operation_name", "fields", "params")
    class QueryEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: L7QueryMatcher
        def __init__(self, key: _Optional[str] = ..., value: _Optional[_Union[L7QueryMatcher, _Mapping]] = ...) -> None: ...
    class ParamsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: L7QueryMatcher
        def __init__(self, key: _Optional[str] = ..., value: _Optional[_Union[L7QueryMatcher, _Mapping]] = ...) -> None: ...
    METHOD_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    COMMAND_FIELD_NUMBER: _ClassVar[int]
    QUERY_FIELD_NUMBER: _ClassVar[int]
    OPERATION_TYPE_FIELD_NUMBER: _ClassVar[int]
    OPERATION_NAME_FIELD_NUMBER: _ClassVar[int]
    FIELDS_FIELD_NUMBER: _ClassVar[int]
    PARAMS_FIELD_NUMBER: _ClassVar[int]
    method: str
    path: str
    command: str
    query: _containers.MessageMap[str, L7QueryMatcher]
    operation_type: str
    operation_name: str
    fields: _containers.RepeatedScalarFieldContainer[str]
    params: _containers.MessageMap[str, L7QueryMatcher]
    def __init__(self, method: _Optional[str] = ..., path: _Optional[str] = ..., command: _Optional[str] = ..., query: _Optional[_Mapping[str, L7QueryMatcher]] = ..., operation_type: _Optional[str] = ..., operation_name: _Optional[str] = ..., fields: _Optional[_Iterable[str]] = ..., params: _Optional[_Mapping[str, L7QueryMatcher]] = ...) -> None: ...

class L7QueryMatcher(_message.Message):
    __slots__ = ("glob", "any")
    GLOB_FIELD_NUMBER: _ClassVar[int]
    ANY_FIELD_NUMBER: _ClassVar[int]
    glob: str
    any: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, glob: _Optional[str] = ..., any: _Optional[_Iterable[str]] = ...) -> None: ...

class NetworkBinary(_message.Message):
    __slots__ = ("path", "harness")
    PATH_FIELD_NUMBER: _ClassVar[int]
    HARNESS_FIELD_NUMBER: _ClassVar[int]
    path: str
    harness: bool
    def __init__(self, path: _Optional[str] = ..., harness: bool = ...) -> None: ...

class GetSandboxConfigRequest(_message.Message):
    __slots__ = ("sandbox_id",)
    SANDBOX_ID_FIELD_NUMBER: _ClassVar[int]
    sandbox_id: str
    def __init__(self, sandbox_id: _Optional[str] = ...) -> None: ...

class GetGatewayConfigRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class GetGatewayConfigResponse(_message.Message):
    __slots__ = ("settings", "settings_revision")
    class SettingsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: SettingValue
        def __init__(self, key: _Optional[str] = ..., value: _Optional[_Union[SettingValue, _Mapping]] = ...) -> None: ...
    SETTINGS_FIELD_NUMBER: _ClassVar[int]
    SETTINGS_REVISION_FIELD_NUMBER: _ClassVar[int]
    settings: _containers.MessageMap[str, SettingValue]
    settings_revision: int
    def __init__(self, settings: _Optional[_Mapping[str, SettingValue]] = ..., settings_revision: _Optional[int] = ...) -> None: ...

class SettingValue(_message.Message):
    __slots__ = ("string_value", "bool_value", "int_value", "bytes_value")
    STRING_VALUE_FIELD_NUMBER: _ClassVar[int]
    BOOL_VALUE_FIELD_NUMBER: _ClassVar[int]
    INT_VALUE_FIELD_NUMBER: _ClassVar[int]
    BYTES_VALUE_FIELD_NUMBER: _ClassVar[int]
    string_value: str
    bool_value: bool
    int_value: int
    bytes_value: bytes
    def __init__(self, string_value: _Optional[str] = ..., bool_value: bool = ..., int_value: _Optional[int] = ..., bytes_value: _Optional[bytes] = ...) -> None: ...

class EffectiveSetting(_message.Message):
    __slots__ = ("value", "scope")
    VALUE_FIELD_NUMBER: _ClassVar[int]
    SCOPE_FIELD_NUMBER: _ClassVar[int]
    value: SettingValue
    scope: SettingScope
    def __init__(self, value: _Optional[_Union[SettingValue, _Mapping]] = ..., scope: _Optional[_Union[SettingScope, str]] = ...) -> None: ...

class GetSandboxConfigResponse(_message.Message):
    __slots__ = ("policy", "version", "policy_hash", "settings", "config_revision", "policy_source", "global_policy_version", "provider_env_revision", "supervisor_middleware_services", "workspace", "policy_validation_failure_mode")
    class SettingsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: EffectiveSetting
        def __init__(self, key: _Optional[str] = ..., value: _Optional[_Union[EffectiveSetting, _Mapping]] = ...) -> None: ...
    POLICY_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    POLICY_HASH_FIELD_NUMBER: _ClassVar[int]
    SETTINGS_FIELD_NUMBER: _ClassVar[int]
    CONFIG_REVISION_FIELD_NUMBER: _ClassVar[int]
    POLICY_SOURCE_FIELD_NUMBER: _ClassVar[int]
    GLOBAL_POLICY_VERSION_FIELD_NUMBER: _ClassVar[int]
    PROVIDER_ENV_REVISION_FIELD_NUMBER: _ClassVar[int]
    SUPERVISOR_MIDDLEWARE_SERVICES_FIELD_NUMBER: _ClassVar[int]
    WORKSPACE_FIELD_NUMBER: _ClassVar[int]
    POLICY_VALIDATION_FAILURE_MODE_FIELD_NUMBER: _ClassVar[int]
    policy: SandboxPolicy
    version: int
    policy_hash: str
    settings: _containers.MessageMap[str, EffectiveSetting]
    config_revision: int
    policy_source: PolicySource
    global_policy_version: int
    provider_env_revision: int
    supervisor_middleware_services: _containers.RepeatedCompositeFieldContainer[SupervisorMiddlewareService]
    workspace: str
    policy_validation_failure_mode: str
    def __init__(self, policy: _Optional[_Union[SandboxPolicy, _Mapping]] = ..., version: _Optional[int] = ..., policy_hash: _Optional[str] = ..., settings: _Optional[_Mapping[str, EffectiveSetting]] = ..., config_revision: _Optional[int] = ..., policy_source: _Optional[_Union[PolicySource, str]] = ..., global_policy_version: _Optional[int] = ..., provider_env_revision: _Optional[int] = ..., supervisor_middleware_services: _Optional[_Iterable[_Union[SupervisorMiddlewareService, _Mapping]]] = ..., workspace: _Optional[str] = ..., policy_validation_failure_mode: _Optional[str] = ...) -> None: ...

class SupervisorMiddlewareService(_message.Message):
    __slots__ = ("name", "grpc_endpoint", "max_body_bytes", "timeout")
    NAME_FIELD_NUMBER: _ClassVar[int]
    GRPC_ENDPOINT_FIELD_NUMBER: _ClassVar[int]
    MAX_BODY_BYTES_FIELD_NUMBER: _ClassVar[int]
    TIMEOUT_FIELD_NUMBER: _ClassVar[int]
    name: str
    grpc_endpoint: str
    max_body_bytes: int
    timeout: str
    def __init__(self, name: _Optional[str] = ..., grpc_endpoint: _Optional[str] = ..., max_body_bytes: _Optional[int] = ..., timeout: _Optional[str] = ...) -> None: ...
