import datamodel_pb2 as _datamodel_pb2
from google.protobuf import struct_pb2 as _struct_pb2
import options_pb2 as _options_pb2
import sandbox_pb2 as _sandbox_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class SandboxPhase(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    SANDBOX_PHASE_UNSPECIFIED: _ClassVar[SandboxPhase]
    SANDBOX_PHASE_PROVISIONING: _ClassVar[SandboxPhase]
    SANDBOX_PHASE_READY: _ClassVar[SandboxPhase]
    SANDBOX_PHASE_ERROR: _ClassVar[SandboxPhase]
    SANDBOX_PHASE_DELETING: _ClassVar[SandboxPhase]
    SANDBOX_PHASE_UNKNOWN: _ClassVar[SandboxPhase]

class ProviderCredentialRefreshStrategy(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    PROVIDER_CREDENTIAL_REFRESH_STRATEGY_UNSPECIFIED: _ClassVar[ProviderCredentialRefreshStrategy]
    PROVIDER_CREDENTIAL_REFRESH_STRATEGY_STATIC: _ClassVar[ProviderCredentialRefreshStrategy]
    PROVIDER_CREDENTIAL_REFRESH_STRATEGY_EXTERNAL: _ClassVar[ProviderCredentialRefreshStrategy]
    PROVIDER_CREDENTIAL_REFRESH_STRATEGY_OAUTH2_REFRESH_TOKEN: _ClassVar[ProviderCredentialRefreshStrategy]
    PROVIDER_CREDENTIAL_REFRESH_STRATEGY_OAUTH2_CLIENT_CREDENTIALS: _ClassVar[ProviderCredentialRefreshStrategy]
    PROVIDER_CREDENTIAL_REFRESH_STRATEGY_GOOGLE_SERVICE_ACCOUNT_JWT: _ClassVar[ProviderCredentialRefreshStrategy]
    PROVIDER_CREDENTIAL_REFRESH_STRATEGY_AWS_STS_ASSUME_ROLE: _ClassVar[ProviderCredentialRefreshStrategy]

class ProviderProfileCategory(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    PROVIDER_PROFILE_CATEGORY_UNSPECIFIED: _ClassVar[ProviderProfileCategory]
    PROVIDER_PROFILE_CATEGORY_OTHER: _ClassVar[ProviderProfileCategory]
    PROVIDER_PROFILE_CATEGORY_INFERENCE: _ClassVar[ProviderProfileCategory]
    PROVIDER_PROFILE_CATEGORY_AGENT: _ClassVar[ProviderProfileCategory]
    PROVIDER_PROFILE_CATEGORY_SOURCE_CONTROL: _ClassVar[ProviderProfileCategory]
    PROVIDER_PROFILE_CATEGORY_MESSAGING: _ClassVar[ProviderProfileCategory]
    PROVIDER_PROFILE_CATEGORY_DATA: _ClassVar[ProviderProfileCategory]
    PROVIDER_PROFILE_CATEGORY_KNOWLEDGE: _ClassVar[ProviderProfileCategory]

class PolicyStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    POLICY_STATUS_UNSPECIFIED: _ClassVar[PolicyStatus]
    POLICY_STATUS_PENDING: _ClassVar[PolicyStatus]
    POLICY_STATUS_LOADED: _ClassVar[PolicyStatus]
    POLICY_STATUS_FAILED: _ClassVar[PolicyStatus]
    POLICY_STATUS_SUPERSEDED: _ClassVar[PolicyStatus]

class ServiceStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    SERVICE_STATUS_UNSPECIFIED: _ClassVar[ServiceStatus]
    SERVICE_STATUS_HEALTHY: _ClassVar[ServiceStatus]
    SERVICE_STATUS_DEGRADED: _ClassVar[ServiceStatus]
    SERVICE_STATUS_UNHEALTHY: _ClassVar[ServiceStatus]

class WorkspaceRole(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    WORKSPACE_ROLE_UNSPECIFIED: _ClassVar[WorkspaceRole]
    WORKSPACE_ROLE_USER: _ClassVar[WorkspaceRole]
    WORKSPACE_ROLE_ADMIN: _ClassVar[WorkspaceRole]
SANDBOX_PHASE_UNSPECIFIED: SandboxPhase
SANDBOX_PHASE_PROVISIONING: SandboxPhase
SANDBOX_PHASE_READY: SandboxPhase
SANDBOX_PHASE_ERROR: SandboxPhase
SANDBOX_PHASE_DELETING: SandboxPhase
SANDBOX_PHASE_UNKNOWN: SandboxPhase
PROVIDER_CREDENTIAL_REFRESH_STRATEGY_UNSPECIFIED: ProviderCredentialRefreshStrategy
PROVIDER_CREDENTIAL_REFRESH_STRATEGY_STATIC: ProviderCredentialRefreshStrategy
PROVIDER_CREDENTIAL_REFRESH_STRATEGY_EXTERNAL: ProviderCredentialRefreshStrategy
PROVIDER_CREDENTIAL_REFRESH_STRATEGY_OAUTH2_REFRESH_TOKEN: ProviderCredentialRefreshStrategy
PROVIDER_CREDENTIAL_REFRESH_STRATEGY_OAUTH2_CLIENT_CREDENTIALS: ProviderCredentialRefreshStrategy
PROVIDER_CREDENTIAL_REFRESH_STRATEGY_GOOGLE_SERVICE_ACCOUNT_JWT: ProviderCredentialRefreshStrategy
PROVIDER_CREDENTIAL_REFRESH_STRATEGY_AWS_STS_ASSUME_ROLE: ProviderCredentialRefreshStrategy
PROVIDER_PROFILE_CATEGORY_UNSPECIFIED: ProviderProfileCategory
PROVIDER_PROFILE_CATEGORY_OTHER: ProviderProfileCategory
PROVIDER_PROFILE_CATEGORY_INFERENCE: ProviderProfileCategory
PROVIDER_PROFILE_CATEGORY_AGENT: ProviderProfileCategory
PROVIDER_PROFILE_CATEGORY_SOURCE_CONTROL: ProviderProfileCategory
PROVIDER_PROFILE_CATEGORY_MESSAGING: ProviderProfileCategory
PROVIDER_PROFILE_CATEGORY_DATA: ProviderProfileCategory
PROVIDER_PROFILE_CATEGORY_KNOWLEDGE: ProviderProfileCategory
POLICY_STATUS_UNSPECIFIED: PolicyStatus
POLICY_STATUS_PENDING: PolicyStatus
POLICY_STATUS_LOADED: PolicyStatus
POLICY_STATUS_FAILED: PolicyStatus
POLICY_STATUS_SUPERSEDED: PolicyStatus
SERVICE_STATUS_UNSPECIFIED: ServiceStatus
SERVICE_STATUS_HEALTHY: ServiceStatus
SERVICE_STATUS_DEGRADED: ServiceStatus
SERVICE_STATUS_UNHEALTHY: ServiceStatus
WORKSPACE_ROLE_UNSPECIFIED: WorkspaceRole
WORKSPACE_ROLE_USER: WorkspaceRole
WORKSPACE_ROLE_ADMIN: WorkspaceRole

class IssueSandboxTokenRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class IssueSandboxTokenResponse(_message.Message):
    __slots__ = ("token", "expires_at_ms")
    TOKEN_FIELD_NUMBER: _ClassVar[int]
    EXPIRES_AT_MS_FIELD_NUMBER: _ClassVar[int]
    token: str
    expires_at_ms: int
    def __init__(self, token: _Optional[str] = ..., expires_at_ms: _Optional[int] = ...) -> None: ...

class RefreshSandboxTokenRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class RefreshSandboxTokenResponse(_message.Message):
    __slots__ = ("token", "expires_at_ms")
    TOKEN_FIELD_NUMBER: _ClassVar[int]
    EXPIRES_AT_MS_FIELD_NUMBER: _ClassVar[int]
    token: str
    expires_at_ms: int
    def __init__(self, token: _Optional[str] = ..., expires_at_ms: _Optional[int] = ...) -> None: ...

class HealthRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class HealthResponse(_message.Message):
    __slots__ = ("status", "version")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    status: ServiceStatus
    version: str
    def __init__(self, status: _Optional[_Union[ServiceStatus, str]] = ..., version: _Optional[str] = ...) -> None: ...

class GetCurrentUserRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class GetCurrentUserResponse(_message.Message):
    __slots__ = ("subject", "display_name", "roles", "scopes", "identity_provider")
    SUBJECT_FIELD_NUMBER: _ClassVar[int]
    DISPLAY_NAME_FIELD_NUMBER: _ClassVar[int]
    ROLES_FIELD_NUMBER: _ClassVar[int]
    SCOPES_FIELD_NUMBER: _ClassVar[int]
    IDENTITY_PROVIDER_FIELD_NUMBER: _ClassVar[int]
    subject: str
    display_name: str
    roles: _containers.RepeatedScalarFieldContainer[str]
    scopes: _containers.RepeatedScalarFieldContainer[str]
    identity_provider: str
    def __init__(self, subject: _Optional[str] = ..., display_name: _Optional[str] = ..., roles: _Optional[_Iterable[str]] = ..., scopes: _Optional[_Iterable[str]] = ..., identity_provider: _Optional[str] = ...) -> None: ...

class GetGatewayInfoRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class GetGatewayInfoResponse(_message.Message):
    __slots__ = ("status", "gateway_version", "compute_drivers")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    GATEWAY_VERSION_FIELD_NUMBER: _ClassVar[int]
    COMPUTE_DRIVERS_FIELD_NUMBER: _ClassVar[int]
    status: ServiceStatus
    gateway_version: str
    compute_drivers: _containers.RepeatedCompositeFieldContainer[ComputeDriverInfo]
    def __init__(self, status: _Optional[_Union[ServiceStatus, str]] = ..., gateway_version: _Optional[str] = ..., compute_drivers: _Optional[_Iterable[_Union[ComputeDriverInfo, _Mapping]]] = ...) -> None: ...

class ComputeDriverInfo(_message.Message):
    __slots__ = ("name", "capabilities")
    NAME_FIELD_NUMBER: _ClassVar[int]
    CAPABILITIES_FIELD_NUMBER: _ClassVar[int]
    name: str
    capabilities: ComputeDriverCapabilities
    def __init__(self, name: _Optional[str] = ..., capabilities: _Optional[_Union[ComputeDriverCapabilities, _Mapping]] = ...) -> None: ...

class ComputeDriverCapabilities(_message.Message):
    __slots__ = ("driver_name", "driver_version")
    DRIVER_NAME_FIELD_NUMBER: _ClassVar[int]
    DRIVER_VERSION_FIELD_NUMBER: _ClassVar[int]
    driver_name: str
    driver_version: str
    def __init__(self, driver_name: _Optional[str] = ..., driver_version: _Optional[str] = ...) -> None: ...

class Sandbox(_message.Message):
    __slots__ = ("metadata", "spec", "status")
    METADATA_FIELD_NUMBER: _ClassVar[int]
    SPEC_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    metadata: _datamodel_pb2.ObjectMeta
    spec: SandboxSpec
    status: SandboxStatus
    def __init__(self, metadata: _Optional[_Union[_datamodel_pb2.ObjectMeta, _Mapping]] = ..., spec: _Optional[_Union[SandboxSpec, _Mapping]] = ..., status: _Optional[_Union[SandboxStatus, _Mapping]] = ...) -> None: ...

class SandboxSpec(_message.Message):
    __slots__ = ("log_level", "environment", "template", "policy", "providers", "resource_requirements")
    class EnvironmentEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    LOG_LEVEL_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_FIELD_NUMBER: _ClassVar[int]
    TEMPLATE_FIELD_NUMBER: _ClassVar[int]
    POLICY_FIELD_NUMBER: _ClassVar[int]
    PROVIDERS_FIELD_NUMBER: _ClassVar[int]
    RESOURCE_REQUIREMENTS_FIELD_NUMBER: _ClassVar[int]
    log_level: str
    environment: _containers.ScalarMap[str, str]
    template: SandboxTemplate
    policy: _sandbox_pb2.SandboxPolicy
    providers: _containers.RepeatedScalarFieldContainer[str]
    resource_requirements: ResourceRequirements
    def __init__(self, log_level: _Optional[str] = ..., environment: _Optional[_Mapping[str, str]] = ..., template: _Optional[_Union[SandboxTemplate, _Mapping]] = ..., policy: _Optional[_Union[_sandbox_pb2.SandboxPolicy, _Mapping]] = ..., providers: _Optional[_Iterable[str]] = ..., resource_requirements: _Optional[_Union[ResourceRequirements, _Mapping]] = ...) -> None: ...

class ResourceRequirements(_message.Message):
    __slots__ = ("gpu",)
    GPU_FIELD_NUMBER: _ClassVar[int]
    gpu: GpuResourceRequirements
    def __init__(self, gpu: _Optional[_Union[GpuResourceRequirements, _Mapping]] = ...) -> None: ...

class GpuResourceRequirements(_message.Message):
    __slots__ = ("count",)
    COUNT_FIELD_NUMBER: _ClassVar[int]
    count: int
    def __init__(self, count: _Optional[int] = ...) -> None: ...

class SandboxTemplate(_message.Message):
    __slots__ = ("image", "runtime_class_name", "agent_socket", "labels", "annotations", "environment", "resources", "user_namespaces", "driver_config")
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
    class EnvironmentEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    IMAGE_FIELD_NUMBER: _ClassVar[int]
    RUNTIME_CLASS_NAME_FIELD_NUMBER: _ClassVar[int]
    AGENT_SOCKET_FIELD_NUMBER: _ClassVar[int]
    LABELS_FIELD_NUMBER: _ClassVar[int]
    ANNOTATIONS_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_FIELD_NUMBER: _ClassVar[int]
    RESOURCES_FIELD_NUMBER: _ClassVar[int]
    USER_NAMESPACES_FIELD_NUMBER: _ClassVar[int]
    DRIVER_CONFIG_FIELD_NUMBER: _ClassVar[int]
    image: str
    runtime_class_name: str
    agent_socket: str
    labels: _containers.ScalarMap[str, str]
    annotations: _containers.ScalarMap[str, str]
    environment: _containers.ScalarMap[str, str]
    resources: _struct_pb2.Struct
    user_namespaces: bool
    driver_config: _struct_pb2.Struct
    def __init__(self, image: _Optional[str] = ..., runtime_class_name: _Optional[str] = ..., agent_socket: _Optional[str] = ..., labels: _Optional[_Mapping[str, str]] = ..., annotations: _Optional[_Mapping[str, str]] = ..., environment: _Optional[_Mapping[str, str]] = ..., resources: _Optional[_Union[_struct_pb2.Struct, _Mapping]] = ..., user_namespaces: bool = ..., driver_config: _Optional[_Union[_struct_pb2.Struct, _Mapping]] = ...) -> None: ...

class SandboxStatus(_message.Message):
    __slots__ = ("sandbox_name", "agent_pod", "agent_fd", "sandbox_fd", "conditions", "phase", "current_policy_version")
    SANDBOX_NAME_FIELD_NUMBER: _ClassVar[int]
    AGENT_POD_FIELD_NUMBER: _ClassVar[int]
    AGENT_FD_FIELD_NUMBER: _ClassVar[int]
    SANDBOX_FD_FIELD_NUMBER: _ClassVar[int]
    CONDITIONS_FIELD_NUMBER: _ClassVar[int]
    PHASE_FIELD_NUMBER: _ClassVar[int]
    CURRENT_POLICY_VERSION_FIELD_NUMBER: _ClassVar[int]
    sandbox_name: str
    agent_pod: str
    agent_fd: str
    sandbox_fd: str
    conditions: _containers.RepeatedCompositeFieldContainer[SandboxCondition]
    phase: SandboxPhase
    current_policy_version: int
    def __init__(self, sandbox_name: _Optional[str] = ..., agent_pod: _Optional[str] = ..., agent_fd: _Optional[str] = ..., sandbox_fd: _Optional[str] = ..., conditions: _Optional[_Iterable[_Union[SandboxCondition, _Mapping]]] = ..., phase: _Optional[_Union[SandboxPhase, str]] = ..., current_policy_version: _Optional[int] = ...) -> None: ...

class SandboxCondition(_message.Message):
    __slots__ = ("type", "status", "reason", "message", "last_transition_time")
    TYPE_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    REASON_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    LAST_TRANSITION_TIME_FIELD_NUMBER: _ClassVar[int]
    type: str
    status: str
    reason: str
    message: str
    last_transition_time: str
    def __init__(self, type: _Optional[str] = ..., status: _Optional[str] = ..., reason: _Optional[str] = ..., message: _Optional[str] = ..., last_transition_time: _Optional[str] = ...) -> None: ...

class PlatformEvent(_message.Message):
    __slots__ = ("timestamp_ms", "source", "type", "reason", "message", "metadata")
    class MetadataEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    TIMESTAMP_MS_FIELD_NUMBER: _ClassVar[int]
    SOURCE_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    REASON_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    METADATA_FIELD_NUMBER: _ClassVar[int]
    timestamp_ms: int
    source: str
    type: str
    reason: str
    message: str
    metadata: _containers.ScalarMap[str, str]
    def __init__(self, timestamp_ms: _Optional[int] = ..., source: _Optional[str] = ..., type: _Optional[str] = ..., reason: _Optional[str] = ..., message: _Optional[str] = ..., metadata: _Optional[_Mapping[str, str]] = ...) -> None: ...

class CreateSandboxRequest(_message.Message):
    __slots__ = ("spec", "name", "labels", "annotations", "workspace")
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
    SPEC_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    LABELS_FIELD_NUMBER: _ClassVar[int]
    ANNOTATIONS_FIELD_NUMBER: _ClassVar[int]
    WORKSPACE_FIELD_NUMBER: _ClassVar[int]
    spec: SandboxSpec
    name: str
    labels: _containers.ScalarMap[str, str]
    annotations: _containers.ScalarMap[str, str]
    workspace: str
    def __init__(self, spec: _Optional[_Union[SandboxSpec, _Mapping]] = ..., name: _Optional[str] = ..., labels: _Optional[_Mapping[str, str]] = ..., annotations: _Optional[_Mapping[str, str]] = ..., workspace: _Optional[str] = ...) -> None: ...

class GetSandboxRequest(_message.Message):
    __slots__ = ("name", "workspace")
    NAME_FIELD_NUMBER: _ClassVar[int]
    WORKSPACE_FIELD_NUMBER: _ClassVar[int]
    name: str
    workspace: str
    def __init__(self, name: _Optional[str] = ..., workspace: _Optional[str] = ...) -> None: ...

class ListSandboxesRequest(_message.Message):
    __slots__ = ("limit", "offset", "label_selector", "workspace", "all_workspaces")
    LIMIT_FIELD_NUMBER: _ClassVar[int]
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    LABEL_SELECTOR_FIELD_NUMBER: _ClassVar[int]
    WORKSPACE_FIELD_NUMBER: _ClassVar[int]
    ALL_WORKSPACES_FIELD_NUMBER: _ClassVar[int]
    limit: int
    offset: int
    label_selector: str
    workspace: str
    all_workspaces: bool
    def __init__(self, limit: _Optional[int] = ..., offset: _Optional[int] = ..., label_selector: _Optional[str] = ..., workspace: _Optional[str] = ..., all_workspaces: bool = ...) -> None: ...

class ListSandboxProvidersRequest(_message.Message):
    __slots__ = ("sandbox_name", "workspace")
    SANDBOX_NAME_FIELD_NUMBER: _ClassVar[int]
    WORKSPACE_FIELD_NUMBER: _ClassVar[int]
    sandbox_name: str
    workspace: str
    def __init__(self, sandbox_name: _Optional[str] = ..., workspace: _Optional[str] = ...) -> None: ...

class AttachSandboxProviderRequest(_message.Message):
    __slots__ = ("sandbox_name", "provider_name", "expected_resource_version", "workspace")
    SANDBOX_NAME_FIELD_NUMBER: _ClassVar[int]
    PROVIDER_NAME_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_RESOURCE_VERSION_FIELD_NUMBER: _ClassVar[int]
    WORKSPACE_FIELD_NUMBER: _ClassVar[int]
    sandbox_name: str
    provider_name: str
    expected_resource_version: int
    workspace: str
    def __init__(self, sandbox_name: _Optional[str] = ..., provider_name: _Optional[str] = ..., expected_resource_version: _Optional[int] = ..., workspace: _Optional[str] = ...) -> None: ...

class DetachSandboxProviderRequest(_message.Message):
    __slots__ = ("sandbox_name", "provider_name", "expected_resource_version", "workspace")
    SANDBOX_NAME_FIELD_NUMBER: _ClassVar[int]
    PROVIDER_NAME_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_RESOURCE_VERSION_FIELD_NUMBER: _ClassVar[int]
    WORKSPACE_FIELD_NUMBER: _ClassVar[int]
    sandbox_name: str
    provider_name: str
    expected_resource_version: int
    workspace: str
    def __init__(self, sandbox_name: _Optional[str] = ..., provider_name: _Optional[str] = ..., expected_resource_version: _Optional[int] = ..., workspace: _Optional[str] = ...) -> None: ...

class DeleteSandboxRequest(_message.Message):
    __slots__ = ("name", "workspace")
    NAME_FIELD_NUMBER: _ClassVar[int]
    WORKSPACE_FIELD_NUMBER: _ClassVar[int]
    name: str
    workspace: str
    def __init__(self, name: _Optional[str] = ..., workspace: _Optional[str] = ...) -> None: ...

class SandboxResponse(_message.Message):
    __slots__ = ("sandbox",)
    SANDBOX_FIELD_NUMBER: _ClassVar[int]
    sandbox: Sandbox
    def __init__(self, sandbox: _Optional[_Union[Sandbox, _Mapping]] = ...) -> None: ...

class ListSandboxesResponse(_message.Message):
    __slots__ = ("sandboxes",)
    SANDBOXES_FIELD_NUMBER: _ClassVar[int]
    sandboxes: _containers.RepeatedCompositeFieldContainer[Sandbox]
    def __init__(self, sandboxes: _Optional[_Iterable[_Union[Sandbox, _Mapping]]] = ...) -> None: ...

class ListSandboxProvidersResponse(_message.Message):
    __slots__ = ("providers",)
    PROVIDERS_FIELD_NUMBER: _ClassVar[int]
    providers: _containers.RepeatedCompositeFieldContainer[_datamodel_pb2.Provider]
    def __init__(self, providers: _Optional[_Iterable[_Union[_datamodel_pb2.Provider, _Mapping]]] = ...) -> None: ...

class AttachSandboxProviderResponse(_message.Message):
    __slots__ = ("sandbox", "attached")
    SANDBOX_FIELD_NUMBER: _ClassVar[int]
    ATTACHED_FIELD_NUMBER: _ClassVar[int]
    sandbox: Sandbox
    attached: bool
    def __init__(self, sandbox: _Optional[_Union[Sandbox, _Mapping]] = ..., attached: bool = ...) -> None: ...

class DetachSandboxProviderResponse(_message.Message):
    __slots__ = ("sandbox", "detached")
    SANDBOX_FIELD_NUMBER: _ClassVar[int]
    DETACHED_FIELD_NUMBER: _ClassVar[int]
    sandbox: Sandbox
    detached: bool
    def __init__(self, sandbox: _Optional[_Union[Sandbox, _Mapping]] = ..., detached: bool = ...) -> None: ...

class DeleteSandboxResponse(_message.Message):
    __slots__ = ("deleted",)
    DELETED_FIELD_NUMBER: _ClassVar[int]
    deleted: bool
    def __init__(self, deleted: bool = ...) -> None: ...

class CreateSshSessionRequest(_message.Message):
    __slots__ = ("sandbox_id",)
    SANDBOX_ID_FIELD_NUMBER: _ClassVar[int]
    sandbox_id: str
    def __init__(self, sandbox_id: _Optional[str] = ...) -> None: ...

class CreateSshSessionResponse(_message.Message):
    __slots__ = ("sandbox_id", "token", "gateway_host", "gateway_port", "gateway_scheme", "host_key_fingerprint", "expires_at_ms")
    SANDBOX_ID_FIELD_NUMBER: _ClassVar[int]
    TOKEN_FIELD_NUMBER: _ClassVar[int]
    GATEWAY_HOST_FIELD_NUMBER: _ClassVar[int]
    GATEWAY_PORT_FIELD_NUMBER: _ClassVar[int]
    GATEWAY_SCHEME_FIELD_NUMBER: _ClassVar[int]
    HOST_KEY_FINGERPRINT_FIELD_NUMBER: _ClassVar[int]
    EXPIRES_AT_MS_FIELD_NUMBER: _ClassVar[int]
    sandbox_id: str
    token: str
    gateway_host: str
    gateway_port: int
    gateway_scheme: str
    host_key_fingerprint: str
    expires_at_ms: int
    def __init__(self, sandbox_id: _Optional[str] = ..., token: _Optional[str] = ..., gateway_host: _Optional[str] = ..., gateway_port: _Optional[int] = ..., gateway_scheme: _Optional[str] = ..., host_key_fingerprint: _Optional[str] = ..., expires_at_ms: _Optional[int] = ...) -> None: ...

class ExposeServiceRequest(_message.Message):
    __slots__ = ("sandbox", "service", "target_port", "domain", "workspace")
    SANDBOX_FIELD_NUMBER: _ClassVar[int]
    SERVICE_FIELD_NUMBER: _ClassVar[int]
    TARGET_PORT_FIELD_NUMBER: _ClassVar[int]
    DOMAIN_FIELD_NUMBER: _ClassVar[int]
    WORKSPACE_FIELD_NUMBER: _ClassVar[int]
    sandbox: str
    service: str
    target_port: int
    domain: bool
    workspace: str
    def __init__(self, sandbox: _Optional[str] = ..., service: _Optional[str] = ..., target_port: _Optional[int] = ..., domain: bool = ..., workspace: _Optional[str] = ...) -> None: ...

class GetServiceRequest(_message.Message):
    __slots__ = ("sandbox", "service", "workspace")
    SANDBOX_FIELD_NUMBER: _ClassVar[int]
    SERVICE_FIELD_NUMBER: _ClassVar[int]
    WORKSPACE_FIELD_NUMBER: _ClassVar[int]
    sandbox: str
    service: str
    workspace: str
    def __init__(self, sandbox: _Optional[str] = ..., service: _Optional[str] = ..., workspace: _Optional[str] = ...) -> None: ...

class ListServicesRequest(_message.Message):
    __slots__ = ("sandbox", "limit", "offset", "workspace", "all_workspaces")
    SANDBOX_FIELD_NUMBER: _ClassVar[int]
    LIMIT_FIELD_NUMBER: _ClassVar[int]
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    WORKSPACE_FIELD_NUMBER: _ClassVar[int]
    ALL_WORKSPACES_FIELD_NUMBER: _ClassVar[int]
    sandbox: str
    limit: int
    offset: int
    workspace: str
    all_workspaces: bool
    def __init__(self, sandbox: _Optional[str] = ..., limit: _Optional[int] = ..., offset: _Optional[int] = ..., workspace: _Optional[str] = ..., all_workspaces: bool = ...) -> None: ...

class ListServicesResponse(_message.Message):
    __slots__ = ("services",)
    SERVICES_FIELD_NUMBER: _ClassVar[int]
    services: _containers.RepeatedCompositeFieldContainer[ServiceEndpointResponse]
    def __init__(self, services: _Optional[_Iterable[_Union[ServiceEndpointResponse, _Mapping]]] = ...) -> None: ...

class DeleteServiceRequest(_message.Message):
    __slots__ = ("sandbox", "service", "workspace")
    SANDBOX_FIELD_NUMBER: _ClassVar[int]
    SERVICE_FIELD_NUMBER: _ClassVar[int]
    WORKSPACE_FIELD_NUMBER: _ClassVar[int]
    sandbox: str
    service: str
    workspace: str
    def __init__(self, sandbox: _Optional[str] = ..., service: _Optional[str] = ..., workspace: _Optional[str] = ...) -> None: ...

class DeleteServiceResponse(_message.Message):
    __slots__ = ("deleted",)
    DELETED_FIELD_NUMBER: _ClassVar[int]
    deleted: bool
    def __init__(self, deleted: bool = ...) -> None: ...

class ServiceEndpoint(_message.Message):
    __slots__ = ("metadata", "sandbox_id", "sandbox_name", "service_name", "target_port", "domain")
    METADATA_FIELD_NUMBER: _ClassVar[int]
    SANDBOX_ID_FIELD_NUMBER: _ClassVar[int]
    SANDBOX_NAME_FIELD_NUMBER: _ClassVar[int]
    SERVICE_NAME_FIELD_NUMBER: _ClassVar[int]
    TARGET_PORT_FIELD_NUMBER: _ClassVar[int]
    DOMAIN_FIELD_NUMBER: _ClassVar[int]
    metadata: _datamodel_pb2.ObjectMeta
    sandbox_id: str
    sandbox_name: str
    service_name: str
    target_port: int
    domain: bool
    def __init__(self, metadata: _Optional[_Union[_datamodel_pb2.ObjectMeta, _Mapping]] = ..., sandbox_id: _Optional[str] = ..., sandbox_name: _Optional[str] = ..., service_name: _Optional[str] = ..., target_port: _Optional[int] = ..., domain: bool = ...) -> None: ...

class ServiceEndpointResponse(_message.Message):
    __slots__ = ("endpoint", "url")
    ENDPOINT_FIELD_NUMBER: _ClassVar[int]
    URL_FIELD_NUMBER: _ClassVar[int]
    endpoint: ServiceEndpoint
    url: str
    def __init__(self, endpoint: _Optional[_Union[ServiceEndpoint, _Mapping]] = ..., url: _Optional[str] = ...) -> None: ...

class RevokeSshSessionRequest(_message.Message):
    __slots__ = ("token",)
    TOKEN_FIELD_NUMBER: _ClassVar[int]
    token: str
    def __init__(self, token: _Optional[str] = ...) -> None: ...

class RevokeSshSessionResponse(_message.Message):
    __slots__ = ("revoked",)
    REVOKED_FIELD_NUMBER: _ClassVar[int]
    revoked: bool
    def __init__(self, revoked: bool = ...) -> None: ...

class ExecSandboxRequest(_message.Message):
    __slots__ = ("sandbox_id", "command", "workdir", "environment", "timeout_seconds", "stdin", "tty", "cols", "rows")
    class EnvironmentEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    SANDBOX_ID_FIELD_NUMBER: _ClassVar[int]
    COMMAND_FIELD_NUMBER: _ClassVar[int]
    WORKDIR_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_FIELD_NUMBER: _ClassVar[int]
    TIMEOUT_SECONDS_FIELD_NUMBER: _ClassVar[int]
    STDIN_FIELD_NUMBER: _ClassVar[int]
    TTY_FIELD_NUMBER: _ClassVar[int]
    COLS_FIELD_NUMBER: _ClassVar[int]
    ROWS_FIELD_NUMBER: _ClassVar[int]
    sandbox_id: str
    command: _containers.RepeatedScalarFieldContainer[str]
    workdir: str
    environment: _containers.ScalarMap[str, str]
    timeout_seconds: int
    stdin: bytes
    tty: bool
    cols: int
    rows: int
    def __init__(self, sandbox_id: _Optional[str] = ..., command: _Optional[_Iterable[str]] = ..., workdir: _Optional[str] = ..., environment: _Optional[_Mapping[str, str]] = ..., timeout_seconds: _Optional[int] = ..., stdin: _Optional[bytes] = ..., tty: bool = ..., cols: _Optional[int] = ..., rows: _Optional[int] = ...) -> None: ...

class ExecSandboxStdout(_message.Message):
    __slots__ = ("data",)
    DATA_FIELD_NUMBER: _ClassVar[int]
    data: bytes
    def __init__(self, data: _Optional[bytes] = ...) -> None: ...

class ExecSandboxStderr(_message.Message):
    __slots__ = ("data",)
    DATA_FIELD_NUMBER: _ClassVar[int]
    data: bytes
    def __init__(self, data: _Optional[bytes] = ...) -> None: ...

class ExecSandboxExit(_message.Message):
    __slots__ = ("exit_code",)
    EXIT_CODE_FIELD_NUMBER: _ClassVar[int]
    exit_code: int
    def __init__(self, exit_code: _Optional[int] = ...) -> None: ...

class ExecSandboxEvent(_message.Message):
    __slots__ = ("stdout", "stderr", "exit")
    STDOUT_FIELD_NUMBER: _ClassVar[int]
    STDERR_FIELD_NUMBER: _ClassVar[int]
    EXIT_FIELD_NUMBER: _ClassVar[int]
    stdout: ExecSandboxStdout
    stderr: ExecSandboxStderr
    exit: ExecSandboxExit
    def __init__(self, stdout: _Optional[_Union[ExecSandboxStdout, _Mapping]] = ..., stderr: _Optional[_Union[ExecSandboxStderr, _Mapping]] = ..., exit: _Optional[_Union[ExecSandboxExit, _Mapping]] = ...) -> None: ...

class TcpForwardInit(_message.Message):
    __slots__ = ("sandbox_id", "service_id", "ssh", "tcp", "authorization_token")
    SANDBOX_ID_FIELD_NUMBER: _ClassVar[int]
    SERVICE_ID_FIELD_NUMBER: _ClassVar[int]
    SSH_FIELD_NUMBER: _ClassVar[int]
    TCP_FIELD_NUMBER: _ClassVar[int]
    AUTHORIZATION_TOKEN_FIELD_NUMBER: _ClassVar[int]
    sandbox_id: str
    service_id: str
    ssh: SshRelayTarget
    tcp: TcpRelayTarget
    authorization_token: str
    def __init__(self, sandbox_id: _Optional[str] = ..., service_id: _Optional[str] = ..., ssh: _Optional[_Union[SshRelayTarget, _Mapping]] = ..., tcp: _Optional[_Union[TcpRelayTarget, _Mapping]] = ..., authorization_token: _Optional[str] = ...) -> None: ...

class TcpForwardFrame(_message.Message):
    __slots__ = ("init", "data")
    INIT_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    init: TcpForwardInit
    data: bytes
    def __init__(self, init: _Optional[_Union[TcpForwardInit, _Mapping]] = ..., data: _Optional[bytes] = ...) -> None: ...

class ExecSandboxInput(_message.Message):
    __slots__ = ("start", "stdin", "resize")
    START_FIELD_NUMBER: _ClassVar[int]
    STDIN_FIELD_NUMBER: _ClassVar[int]
    RESIZE_FIELD_NUMBER: _ClassVar[int]
    start: ExecSandboxRequest
    stdin: bytes
    resize: ExecSandboxWindowResize
    def __init__(self, start: _Optional[_Union[ExecSandboxRequest, _Mapping]] = ..., stdin: _Optional[bytes] = ..., resize: _Optional[_Union[ExecSandboxWindowResize, _Mapping]] = ...) -> None: ...

class ExecSandboxWindowResize(_message.Message):
    __slots__ = ("cols", "rows")
    COLS_FIELD_NUMBER: _ClassVar[int]
    ROWS_FIELD_NUMBER: _ClassVar[int]
    cols: int
    rows: int
    def __init__(self, cols: _Optional[int] = ..., rows: _Optional[int] = ...) -> None: ...

class SshSession(_message.Message):
    __slots__ = ("metadata", "sandbox_id", "token", "expires_at_ms", "revoked")
    METADATA_FIELD_NUMBER: _ClassVar[int]
    SANDBOX_ID_FIELD_NUMBER: _ClassVar[int]
    TOKEN_FIELD_NUMBER: _ClassVar[int]
    EXPIRES_AT_MS_FIELD_NUMBER: _ClassVar[int]
    REVOKED_FIELD_NUMBER: _ClassVar[int]
    metadata: _datamodel_pb2.ObjectMeta
    sandbox_id: str
    token: str
    expires_at_ms: int
    revoked: bool
    def __init__(self, metadata: _Optional[_Union[_datamodel_pb2.ObjectMeta, _Mapping]] = ..., sandbox_id: _Optional[str] = ..., token: _Optional[str] = ..., expires_at_ms: _Optional[int] = ..., revoked: bool = ...) -> None: ...

class WatchSandboxRequest(_message.Message):
    __slots__ = ("id", "follow_status", "follow_logs", "follow_events", "log_tail_lines", "event_tail", "stop_on_terminal", "log_since_ms", "log_sources", "log_min_level")
    ID_FIELD_NUMBER: _ClassVar[int]
    FOLLOW_STATUS_FIELD_NUMBER: _ClassVar[int]
    FOLLOW_LOGS_FIELD_NUMBER: _ClassVar[int]
    FOLLOW_EVENTS_FIELD_NUMBER: _ClassVar[int]
    LOG_TAIL_LINES_FIELD_NUMBER: _ClassVar[int]
    EVENT_TAIL_FIELD_NUMBER: _ClassVar[int]
    STOP_ON_TERMINAL_FIELD_NUMBER: _ClassVar[int]
    LOG_SINCE_MS_FIELD_NUMBER: _ClassVar[int]
    LOG_SOURCES_FIELD_NUMBER: _ClassVar[int]
    LOG_MIN_LEVEL_FIELD_NUMBER: _ClassVar[int]
    id: str
    follow_status: bool
    follow_logs: bool
    follow_events: bool
    log_tail_lines: int
    event_tail: int
    stop_on_terminal: bool
    log_since_ms: int
    log_sources: _containers.RepeatedScalarFieldContainer[str]
    log_min_level: str
    def __init__(self, id: _Optional[str] = ..., follow_status: bool = ..., follow_logs: bool = ..., follow_events: bool = ..., log_tail_lines: _Optional[int] = ..., event_tail: _Optional[int] = ..., stop_on_terminal: bool = ..., log_since_ms: _Optional[int] = ..., log_sources: _Optional[_Iterable[str]] = ..., log_min_level: _Optional[str] = ...) -> None: ...

class SandboxStreamEvent(_message.Message):
    __slots__ = ("sandbox", "log", "event", "warning", "draft_policy_update")
    SANDBOX_FIELD_NUMBER: _ClassVar[int]
    LOG_FIELD_NUMBER: _ClassVar[int]
    EVENT_FIELD_NUMBER: _ClassVar[int]
    WARNING_FIELD_NUMBER: _ClassVar[int]
    DRAFT_POLICY_UPDATE_FIELD_NUMBER: _ClassVar[int]
    sandbox: Sandbox
    log: SandboxLogLine
    event: PlatformEvent
    warning: SandboxStreamWarning
    draft_policy_update: DraftPolicyUpdate
    def __init__(self, sandbox: _Optional[_Union[Sandbox, _Mapping]] = ..., log: _Optional[_Union[SandboxLogLine, _Mapping]] = ..., event: _Optional[_Union[PlatformEvent, _Mapping]] = ..., warning: _Optional[_Union[SandboxStreamWarning, _Mapping]] = ..., draft_policy_update: _Optional[_Union[DraftPolicyUpdate, _Mapping]] = ...) -> None: ...

class SandboxLogLine(_message.Message):
    __slots__ = ("sandbox_id", "timestamp_ms", "level", "target", "message", "source", "fields")
    class FieldsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    SANDBOX_ID_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_MS_FIELD_NUMBER: _ClassVar[int]
    LEVEL_FIELD_NUMBER: _ClassVar[int]
    TARGET_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    SOURCE_FIELD_NUMBER: _ClassVar[int]
    FIELDS_FIELD_NUMBER: _ClassVar[int]
    sandbox_id: str
    timestamp_ms: int
    level: str
    target: str
    message: str
    source: str
    fields: _containers.ScalarMap[str, str]
    def __init__(self, sandbox_id: _Optional[str] = ..., timestamp_ms: _Optional[int] = ..., level: _Optional[str] = ..., target: _Optional[str] = ..., message: _Optional[str] = ..., source: _Optional[str] = ..., fields: _Optional[_Mapping[str, str]] = ...) -> None: ...

class SandboxStreamWarning(_message.Message):
    __slots__ = ("message",)
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    message: str
    def __init__(self, message: _Optional[str] = ...) -> None: ...

class CreateProviderRequest(_message.Message):
    __slots__ = ("provider", "workspace")
    PROVIDER_FIELD_NUMBER: _ClassVar[int]
    WORKSPACE_FIELD_NUMBER: _ClassVar[int]
    provider: _datamodel_pb2.Provider
    workspace: str
    def __init__(self, provider: _Optional[_Union[_datamodel_pb2.Provider, _Mapping]] = ..., workspace: _Optional[str] = ...) -> None: ...

class GetProviderRequest(_message.Message):
    __slots__ = ("name", "workspace")
    NAME_FIELD_NUMBER: _ClassVar[int]
    WORKSPACE_FIELD_NUMBER: _ClassVar[int]
    name: str
    workspace: str
    def __init__(self, name: _Optional[str] = ..., workspace: _Optional[str] = ...) -> None: ...

class ListProvidersRequest(_message.Message):
    __slots__ = ("limit", "offset", "workspace", "all_workspaces")
    LIMIT_FIELD_NUMBER: _ClassVar[int]
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    WORKSPACE_FIELD_NUMBER: _ClassVar[int]
    ALL_WORKSPACES_FIELD_NUMBER: _ClassVar[int]
    limit: int
    offset: int
    workspace: str
    all_workspaces: bool
    def __init__(self, limit: _Optional[int] = ..., offset: _Optional[int] = ..., workspace: _Optional[str] = ..., all_workspaces: bool = ...) -> None: ...

class UpdateProviderRequest(_message.Message):
    __slots__ = ("provider", "credential_expires_at_ms", "workspace")
    class CredentialExpiresAtMsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: int
        def __init__(self, key: _Optional[str] = ..., value: _Optional[int] = ...) -> None: ...
    PROVIDER_FIELD_NUMBER: _ClassVar[int]
    CREDENTIAL_EXPIRES_AT_MS_FIELD_NUMBER: _ClassVar[int]
    WORKSPACE_FIELD_NUMBER: _ClassVar[int]
    provider: _datamodel_pb2.Provider
    credential_expires_at_ms: _containers.ScalarMap[str, int]
    workspace: str
    def __init__(self, provider: _Optional[_Union[_datamodel_pb2.Provider, _Mapping]] = ..., credential_expires_at_ms: _Optional[_Mapping[str, int]] = ..., workspace: _Optional[str] = ...) -> None: ...

class DeleteProviderRequest(_message.Message):
    __slots__ = ("name", "workspace")
    NAME_FIELD_NUMBER: _ClassVar[int]
    WORKSPACE_FIELD_NUMBER: _ClassVar[int]
    name: str
    workspace: str
    def __init__(self, name: _Optional[str] = ..., workspace: _Optional[str] = ...) -> None: ...

class ProviderResponse(_message.Message):
    __slots__ = ("provider",)
    PROVIDER_FIELD_NUMBER: _ClassVar[int]
    provider: _datamodel_pb2.Provider
    def __init__(self, provider: _Optional[_Union[_datamodel_pb2.Provider, _Mapping]] = ...) -> None: ...

class ListProvidersResponse(_message.Message):
    __slots__ = ("providers",)
    PROVIDERS_FIELD_NUMBER: _ClassVar[int]
    providers: _containers.RepeatedCompositeFieldContainer[_datamodel_pb2.Provider]
    def __init__(self, providers: _Optional[_Iterable[_Union[_datamodel_pb2.Provider, _Mapping]]] = ...) -> None: ...

class ListProviderProfilesRequest(_message.Message):
    __slots__ = ("limit", "offset", "workspace")
    LIMIT_FIELD_NUMBER: _ClassVar[int]
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    WORKSPACE_FIELD_NUMBER: _ClassVar[int]
    limit: int
    offset: int
    workspace: str
    def __init__(self, limit: _Optional[int] = ..., offset: _Optional[int] = ..., workspace: _Optional[str] = ...) -> None: ...

class GetProviderProfileRequest(_message.Message):
    __slots__ = ("id", "workspace")
    ID_FIELD_NUMBER: _ClassVar[int]
    WORKSPACE_FIELD_NUMBER: _ClassVar[int]
    id: str
    workspace: str
    def __init__(self, id: _Optional[str] = ..., workspace: _Optional[str] = ...) -> None: ...

class ProviderProfileImportItem(_message.Message):
    __slots__ = ("profile", "source")
    PROFILE_FIELD_NUMBER: _ClassVar[int]
    SOURCE_FIELD_NUMBER: _ClassVar[int]
    profile: ProviderProfile
    source: str
    def __init__(self, profile: _Optional[_Union[ProviderProfile, _Mapping]] = ..., source: _Optional[str] = ...) -> None: ...

class ProviderProfileDiagnostic(_message.Message):
    __slots__ = ("source", "profile_id", "field", "message", "severity")
    SOURCE_FIELD_NUMBER: _ClassVar[int]
    PROFILE_ID_FIELD_NUMBER: _ClassVar[int]
    FIELD_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    SEVERITY_FIELD_NUMBER: _ClassVar[int]
    source: str
    profile_id: str
    field: str
    message: str
    severity: str
    def __init__(self, source: _Optional[str] = ..., profile_id: _Optional[str] = ..., field: _Optional[str] = ..., message: _Optional[str] = ..., severity: _Optional[str] = ...) -> None: ...

class ProviderCredentialTokenGrantAudienceOverride(_message.Message):
    __slots__ = ("host", "port", "path", "audience", "scopes")
    HOST_FIELD_NUMBER: _ClassVar[int]
    PORT_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    AUDIENCE_FIELD_NUMBER: _ClassVar[int]
    SCOPES_FIELD_NUMBER: _ClassVar[int]
    host: str
    port: int
    path: str
    audience: str
    scopes: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, host: _Optional[str] = ..., port: _Optional[int] = ..., path: _Optional[str] = ..., audience: _Optional[str] = ..., scopes: _Optional[_Iterable[str]] = ...) -> None: ...

class ProviderCredentialTokenGrant(_message.Message):
    __slots__ = ("token_endpoint", "audience", "jwt_svid_audience", "scopes", "cache_ttl_seconds", "audience_overrides", "client_assertion_type")
    TOKEN_ENDPOINT_FIELD_NUMBER: _ClassVar[int]
    AUDIENCE_FIELD_NUMBER: _ClassVar[int]
    JWT_SVID_AUDIENCE_FIELD_NUMBER: _ClassVar[int]
    SCOPES_FIELD_NUMBER: _ClassVar[int]
    CACHE_TTL_SECONDS_FIELD_NUMBER: _ClassVar[int]
    AUDIENCE_OVERRIDES_FIELD_NUMBER: _ClassVar[int]
    CLIENT_ASSERTION_TYPE_FIELD_NUMBER: _ClassVar[int]
    token_endpoint: str
    audience: str
    jwt_svid_audience: str
    scopes: _containers.RepeatedScalarFieldContainer[str]
    cache_ttl_seconds: int
    audience_overrides: _containers.RepeatedCompositeFieldContainer[ProviderCredentialTokenGrantAudienceOverride]
    client_assertion_type: str
    def __init__(self, token_endpoint: _Optional[str] = ..., audience: _Optional[str] = ..., jwt_svid_audience: _Optional[str] = ..., scopes: _Optional[_Iterable[str]] = ..., cache_ttl_seconds: _Optional[int] = ..., audience_overrides: _Optional[_Iterable[_Union[ProviderCredentialTokenGrantAudienceOverride, _Mapping]]] = ..., client_assertion_type: _Optional[str] = ...) -> None: ...

class ProviderProfileCredential(_message.Message):
    __slots__ = ("name", "description", "env_vars", "required", "auth_style", "header_name", "query_param", "refresh", "path_template", "token_grant")
    NAME_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    ENV_VARS_FIELD_NUMBER: _ClassVar[int]
    REQUIRED_FIELD_NUMBER: _ClassVar[int]
    AUTH_STYLE_FIELD_NUMBER: _ClassVar[int]
    HEADER_NAME_FIELD_NUMBER: _ClassVar[int]
    QUERY_PARAM_FIELD_NUMBER: _ClassVar[int]
    REFRESH_FIELD_NUMBER: _ClassVar[int]
    PATH_TEMPLATE_FIELD_NUMBER: _ClassVar[int]
    TOKEN_GRANT_FIELD_NUMBER: _ClassVar[int]
    name: str
    description: str
    env_vars: _containers.RepeatedScalarFieldContainer[str]
    required: bool
    auth_style: str
    header_name: str
    query_param: str
    refresh: ProviderCredentialRefresh
    path_template: str
    token_grant: ProviderCredentialTokenGrant
    def __init__(self, name: _Optional[str] = ..., description: _Optional[str] = ..., env_vars: _Optional[_Iterable[str]] = ..., required: bool = ..., auth_style: _Optional[str] = ..., header_name: _Optional[str] = ..., query_param: _Optional[str] = ..., refresh: _Optional[_Union[ProviderCredentialRefresh, _Mapping]] = ..., path_template: _Optional[str] = ..., token_grant: _Optional[_Union[ProviderCredentialTokenGrant, _Mapping]] = ...) -> None: ...

class ProviderCredentialRefreshMaterial(_message.Message):
    __slots__ = ("name", "description", "required", "secret")
    NAME_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    REQUIRED_FIELD_NUMBER: _ClassVar[int]
    SECRET_FIELD_NUMBER: _ClassVar[int]
    name: str
    description: str
    required: bool
    secret: bool
    def __init__(self, name: _Optional[str] = ..., description: _Optional[str] = ..., required: bool = ..., secret: bool = ...) -> None: ...

class ProviderCredentialRefreshOutput(_message.Message):
    __slots__ = ("output", "credential")
    OUTPUT_FIELD_NUMBER: _ClassVar[int]
    CREDENTIAL_FIELD_NUMBER: _ClassVar[int]
    output: str
    credential: str
    def __init__(self, output: _Optional[str] = ..., credential: _Optional[str] = ...) -> None: ...

class ProviderCredentialRefresh(_message.Message):
    __slots__ = ("strategy", "token_url", "scopes", "refresh_before_seconds", "max_lifetime_seconds", "material", "additional_outputs")
    STRATEGY_FIELD_NUMBER: _ClassVar[int]
    TOKEN_URL_FIELD_NUMBER: _ClassVar[int]
    SCOPES_FIELD_NUMBER: _ClassVar[int]
    REFRESH_BEFORE_SECONDS_FIELD_NUMBER: _ClassVar[int]
    MAX_LIFETIME_SECONDS_FIELD_NUMBER: _ClassVar[int]
    MATERIAL_FIELD_NUMBER: _ClassVar[int]
    ADDITIONAL_OUTPUTS_FIELD_NUMBER: _ClassVar[int]
    strategy: ProviderCredentialRefreshStrategy
    token_url: str
    scopes: _containers.RepeatedScalarFieldContainer[str]
    refresh_before_seconds: int
    max_lifetime_seconds: int
    material: _containers.RepeatedCompositeFieldContainer[ProviderCredentialRefreshMaterial]
    additional_outputs: _containers.RepeatedCompositeFieldContainer[ProviderCredentialRefreshOutput]
    def __init__(self, strategy: _Optional[_Union[ProviderCredentialRefreshStrategy, str]] = ..., token_url: _Optional[str] = ..., scopes: _Optional[_Iterable[str]] = ..., refresh_before_seconds: _Optional[int] = ..., max_lifetime_seconds: _Optional[int] = ..., material: _Optional[_Iterable[_Union[ProviderCredentialRefreshMaterial, _Mapping]]] = ..., additional_outputs: _Optional[_Iterable[_Union[ProviderCredentialRefreshOutput, _Mapping]]] = ...) -> None: ...

class ProviderCredentialRefreshStatus(_message.Message):
    __slots__ = ("provider_name", "provider_id", "credential_key", "strategy", "status", "expires_at_ms", "next_refresh_at_ms", "last_refresh_at_ms", "last_error")
    PROVIDER_NAME_FIELD_NUMBER: _ClassVar[int]
    PROVIDER_ID_FIELD_NUMBER: _ClassVar[int]
    CREDENTIAL_KEY_FIELD_NUMBER: _ClassVar[int]
    STRATEGY_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    EXPIRES_AT_MS_FIELD_NUMBER: _ClassVar[int]
    NEXT_REFRESH_AT_MS_FIELD_NUMBER: _ClassVar[int]
    LAST_REFRESH_AT_MS_FIELD_NUMBER: _ClassVar[int]
    LAST_ERROR_FIELD_NUMBER: _ClassVar[int]
    provider_name: str
    provider_id: str
    credential_key: str
    strategy: ProviderCredentialRefreshStrategy
    status: str
    expires_at_ms: int
    next_refresh_at_ms: int
    last_refresh_at_ms: int
    last_error: str
    def __init__(self, provider_name: _Optional[str] = ..., provider_id: _Optional[str] = ..., credential_key: _Optional[str] = ..., strategy: _Optional[_Union[ProviderCredentialRefreshStrategy, str]] = ..., status: _Optional[str] = ..., expires_at_ms: _Optional[int] = ..., next_refresh_at_ms: _Optional[int] = ..., last_refresh_at_ms: _Optional[int] = ..., last_error: _Optional[str] = ...) -> None: ...

class ProviderProfileDiscovery(_message.Message):
    __slots__ = ("credentials",)
    CREDENTIALS_FIELD_NUMBER: _ClassVar[int]
    credentials: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, credentials: _Optional[_Iterable[str]] = ...) -> None: ...

class StoredProviderCredentialRefreshState(_message.Message):
    __slots__ = ("metadata", "provider_id", "provider_name", "credential_key", "strategy", "material", "secret_material_keys", "expires_at_ms", "next_refresh_at_ms", "last_refresh_at_ms", "status", "last_error", "token_url", "scopes", "refresh_before_seconds", "max_lifetime_seconds", "additional_output_keys")
    class MaterialEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    class AdditionalOutputKeysEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    METADATA_FIELD_NUMBER: _ClassVar[int]
    PROVIDER_ID_FIELD_NUMBER: _ClassVar[int]
    PROVIDER_NAME_FIELD_NUMBER: _ClassVar[int]
    CREDENTIAL_KEY_FIELD_NUMBER: _ClassVar[int]
    STRATEGY_FIELD_NUMBER: _ClassVar[int]
    MATERIAL_FIELD_NUMBER: _ClassVar[int]
    SECRET_MATERIAL_KEYS_FIELD_NUMBER: _ClassVar[int]
    EXPIRES_AT_MS_FIELD_NUMBER: _ClassVar[int]
    NEXT_REFRESH_AT_MS_FIELD_NUMBER: _ClassVar[int]
    LAST_REFRESH_AT_MS_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    LAST_ERROR_FIELD_NUMBER: _ClassVar[int]
    TOKEN_URL_FIELD_NUMBER: _ClassVar[int]
    SCOPES_FIELD_NUMBER: _ClassVar[int]
    REFRESH_BEFORE_SECONDS_FIELD_NUMBER: _ClassVar[int]
    MAX_LIFETIME_SECONDS_FIELD_NUMBER: _ClassVar[int]
    ADDITIONAL_OUTPUT_KEYS_FIELD_NUMBER: _ClassVar[int]
    metadata: _datamodel_pb2.ObjectMeta
    provider_id: str
    provider_name: str
    credential_key: str
    strategy: ProviderCredentialRefreshStrategy
    material: _containers.ScalarMap[str, str]
    secret_material_keys: _containers.RepeatedScalarFieldContainer[str]
    expires_at_ms: int
    next_refresh_at_ms: int
    last_refresh_at_ms: int
    status: str
    last_error: str
    token_url: str
    scopes: _containers.RepeatedScalarFieldContainer[str]
    refresh_before_seconds: int
    max_lifetime_seconds: int
    additional_output_keys: _containers.ScalarMap[str, str]
    def __init__(self, metadata: _Optional[_Union[_datamodel_pb2.ObjectMeta, _Mapping]] = ..., provider_id: _Optional[str] = ..., provider_name: _Optional[str] = ..., credential_key: _Optional[str] = ..., strategy: _Optional[_Union[ProviderCredentialRefreshStrategy, str]] = ..., material: _Optional[_Mapping[str, str]] = ..., secret_material_keys: _Optional[_Iterable[str]] = ..., expires_at_ms: _Optional[int] = ..., next_refresh_at_ms: _Optional[int] = ..., last_refresh_at_ms: _Optional[int] = ..., status: _Optional[str] = ..., last_error: _Optional[str] = ..., token_url: _Optional[str] = ..., scopes: _Optional[_Iterable[str]] = ..., refresh_before_seconds: _Optional[int] = ..., max_lifetime_seconds: _Optional[int] = ..., additional_output_keys: _Optional[_Mapping[str, str]] = ...) -> None: ...

class GetProviderRefreshStatusRequest(_message.Message):
    __slots__ = ("provider", "credential_key", "workspace")
    PROVIDER_FIELD_NUMBER: _ClassVar[int]
    CREDENTIAL_KEY_FIELD_NUMBER: _ClassVar[int]
    WORKSPACE_FIELD_NUMBER: _ClassVar[int]
    provider: str
    credential_key: str
    workspace: str
    def __init__(self, provider: _Optional[str] = ..., credential_key: _Optional[str] = ..., workspace: _Optional[str] = ...) -> None: ...

class GetProviderRefreshStatusResponse(_message.Message):
    __slots__ = ("credentials",)
    CREDENTIALS_FIELD_NUMBER: _ClassVar[int]
    credentials: _containers.RepeatedCompositeFieldContainer[ProviderCredentialRefreshStatus]
    def __init__(self, credentials: _Optional[_Iterable[_Union[ProviderCredentialRefreshStatus, _Mapping]]] = ...) -> None: ...

class ConfigureProviderRefreshRequest(_message.Message):
    __slots__ = ("provider", "credential_key", "strategy", "material", "secret_material_keys", "expires_at_ms", "workspace")
    class MaterialEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    PROVIDER_FIELD_NUMBER: _ClassVar[int]
    CREDENTIAL_KEY_FIELD_NUMBER: _ClassVar[int]
    STRATEGY_FIELD_NUMBER: _ClassVar[int]
    MATERIAL_FIELD_NUMBER: _ClassVar[int]
    SECRET_MATERIAL_KEYS_FIELD_NUMBER: _ClassVar[int]
    EXPIRES_AT_MS_FIELD_NUMBER: _ClassVar[int]
    WORKSPACE_FIELD_NUMBER: _ClassVar[int]
    provider: str
    credential_key: str
    strategy: ProviderCredentialRefreshStrategy
    material: _containers.ScalarMap[str, str]
    secret_material_keys: _containers.RepeatedScalarFieldContainer[str]
    expires_at_ms: int
    workspace: str
    def __init__(self, provider: _Optional[str] = ..., credential_key: _Optional[str] = ..., strategy: _Optional[_Union[ProviderCredentialRefreshStrategy, str]] = ..., material: _Optional[_Mapping[str, str]] = ..., secret_material_keys: _Optional[_Iterable[str]] = ..., expires_at_ms: _Optional[int] = ..., workspace: _Optional[str] = ...) -> None: ...

class ConfigureProviderRefreshResponse(_message.Message):
    __slots__ = ("status",)
    STATUS_FIELD_NUMBER: _ClassVar[int]
    status: ProviderCredentialRefreshStatus
    def __init__(self, status: _Optional[_Union[ProviderCredentialRefreshStatus, _Mapping]] = ...) -> None: ...

class RotateProviderCredentialRequest(_message.Message):
    __slots__ = ("provider", "credential_key", "workspace")
    PROVIDER_FIELD_NUMBER: _ClassVar[int]
    CREDENTIAL_KEY_FIELD_NUMBER: _ClassVar[int]
    WORKSPACE_FIELD_NUMBER: _ClassVar[int]
    provider: str
    credential_key: str
    workspace: str
    def __init__(self, provider: _Optional[str] = ..., credential_key: _Optional[str] = ..., workspace: _Optional[str] = ...) -> None: ...

class RotateProviderCredentialResponse(_message.Message):
    __slots__ = ("status",)
    STATUS_FIELD_NUMBER: _ClassVar[int]
    status: ProviderCredentialRefreshStatus
    def __init__(self, status: _Optional[_Union[ProviderCredentialRefreshStatus, _Mapping]] = ...) -> None: ...

class DeleteProviderRefreshRequest(_message.Message):
    __slots__ = ("provider", "credential_key", "workspace")
    PROVIDER_FIELD_NUMBER: _ClassVar[int]
    CREDENTIAL_KEY_FIELD_NUMBER: _ClassVar[int]
    WORKSPACE_FIELD_NUMBER: _ClassVar[int]
    provider: str
    credential_key: str
    workspace: str
    def __init__(self, provider: _Optional[str] = ..., credential_key: _Optional[str] = ..., workspace: _Optional[str] = ...) -> None: ...

class DeleteProviderRefreshResponse(_message.Message):
    __slots__ = ("deleted",)
    DELETED_FIELD_NUMBER: _ClassVar[int]
    deleted: bool
    def __init__(self, deleted: bool = ...) -> None: ...

class ProviderProfile(_message.Message):
    __slots__ = ("id", "display_name", "description", "category", "credentials", "endpoints", "binaries", "inference_capable", "discovery", "resource_version", "annotations", "source", "scope")
    class AnnotationsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    ID_FIELD_NUMBER: _ClassVar[int]
    DISPLAY_NAME_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    CATEGORY_FIELD_NUMBER: _ClassVar[int]
    CREDENTIALS_FIELD_NUMBER: _ClassVar[int]
    ENDPOINTS_FIELD_NUMBER: _ClassVar[int]
    BINARIES_FIELD_NUMBER: _ClassVar[int]
    INFERENCE_CAPABLE_FIELD_NUMBER: _ClassVar[int]
    DISCOVERY_FIELD_NUMBER: _ClassVar[int]
    RESOURCE_VERSION_FIELD_NUMBER: _ClassVar[int]
    ANNOTATIONS_FIELD_NUMBER: _ClassVar[int]
    SOURCE_FIELD_NUMBER: _ClassVar[int]
    SCOPE_FIELD_NUMBER: _ClassVar[int]
    id: str
    display_name: str
    description: str
    category: ProviderProfileCategory
    credentials: _containers.RepeatedCompositeFieldContainer[ProviderProfileCredential]
    endpoints: _containers.RepeatedCompositeFieldContainer[_sandbox_pb2.NetworkEndpoint]
    binaries: _containers.RepeatedCompositeFieldContainer[_sandbox_pb2.NetworkBinary]
    inference_capable: bool
    discovery: ProviderProfileDiscovery
    resource_version: int
    annotations: _containers.ScalarMap[str, str]
    source: str
    scope: str
    def __init__(self, id: _Optional[str] = ..., display_name: _Optional[str] = ..., description: _Optional[str] = ..., category: _Optional[_Union[ProviderProfileCategory, str]] = ..., credentials: _Optional[_Iterable[_Union[ProviderProfileCredential, _Mapping]]] = ..., endpoints: _Optional[_Iterable[_Union[_sandbox_pb2.NetworkEndpoint, _Mapping]]] = ..., binaries: _Optional[_Iterable[_Union[_sandbox_pb2.NetworkBinary, _Mapping]]] = ..., inference_capable: bool = ..., discovery: _Optional[_Union[ProviderProfileDiscovery, _Mapping]] = ..., resource_version: _Optional[int] = ..., annotations: _Optional[_Mapping[str, str]] = ..., source: _Optional[str] = ..., scope: _Optional[str] = ...) -> None: ...

class StoredProviderProfile(_message.Message):
    __slots__ = ("metadata", "profile")
    METADATA_FIELD_NUMBER: _ClassVar[int]
    PROFILE_FIELD_NUMBER: _ClassVar[int]
    metadata: _datamodel_pb2.ObjectMeta
    profile: ProviderProfile
    def __init__(self, metadata: _Optional[_Union[_datamodel_pb2.ObjectMeta, _Mapping]] = ..., profile: _Optional[_Union[ProviderProfile, _Mapping]] = ...) -> None: ...

class ProviderProfileResponse(_message.Message):
    __slots__ = ("profile",)
    PROFILE_FIELD_NUMBER: _ClassVar[int]
    profile: ProviderProfile
    def __init__(self, profile: _Optional[_Union[ProviderProfile, _Mapping]] = ...) -> None: ...

class ListProviderProfilesResponse(_message.Message):
    __slots__ = ("profiles",)
    PROFILES_FIELD_NUMBER: _ClassVar[int]
    profiles: _containers.RepeatedCompositeFieldContainer[ProviderProfile]
    def __init__(self, profiles: _Optional[_Iterable[_Union[ProviderProfile, _Mapping]]] = ...) -> None: ...

class ImportProviderProfilesRequest(_message.Message):
    __slots__ = ("profiles", "workspace")
    PROFILES_FIELD_NUMBER: _ClassVar[int]
    WORKSPACE_FIELD_NUMBER: _ClassVar[int]
    profiles: _containers.RepeatedCompositeFieldContainer[ProviderProfileImportItem]
    workspace: str
    def __init__(self, profiles: _Optional[_Iterable[_Union[ProviderProfileImportItem, _Mapping]]] = ..., workspace: _Optional[str] = ...) -> None: ...

class ImportProviderProfilesResponse(_message.Message):
    __slots__ = ("diagnostics", "profiles", "imported")
    DIAGNOSTICS_FIELD_NUMBER: _ClassVar[int]
    PROFILES_FIELD_NUMBER: _ClassVar[int]
    IMPORTED_FIELD_NUMBER: _ClassVar[int]
    diagnostics: _containers.RepeatedCompositeFieldContainer[ProviderProfileDiagnostic]
    profiles: _containers.RepeatedCompositeFieldContainer[ProviderProfile]
    imported: bool
    def __init__(self, diagnostics: _Optional[_Iterable[_Union[ProviderProfileDiagnostic, _Mapping]]] = ..., profiles: _Optional[_Iterable[_Union[ProviderProfile, _Mapping]]] = ..., imported: bool = ...) -> None: ...

class UpdateProviderProfilesRequest(_message.Message):
    __slots__ = ("profile", "expected_resource_version", "id", "workspace")
    PROFILE_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_RESOURCE_VERSION_FIELD_NUMBER: _ClassVar[int]
    ID_FIELD_NUMBER: _ClassVar[int]
    WORKSPACE_FIELD_NUMBER: _ClassVar[int]
    profile: ProviderProfileImportItem
    expected_resource_version: int
    id: str
    workspace: str
    def __init__(self, profile: _Optional[_Union[ProviderProfileImportItem, _Mapping]] = ..., expected_resource_version: _Optional[int] = ..., id: _Optional[str] = ..., workspace: _Optional[str] = ...) -> None: ...

class UpdateProviderProfilesResponse(_message.Message):
    __slots__ = ("diagnostics", "profile", "updated")
    DIAGNOSTICS_FIELD_NUMBER: _ClassVar[int]
    PROFILE_FIELD_NUMBER: _ClassVar[int]
    UPDATED_FIELD_NUMBER: _ClassVar[int]
    diagnostics: _containers.RepeatedCompositeFieldContainer[ProviderProfileDiagnostic]
    profile: ProviderProfile
    updated: bool
    def __init__(self, diagnostics: _Optional[_Iterable[_Union[ProviderProfileDiagnostic, _Mapping]]] = ..., profile: _Optional[_Union[ProviderProfile, _Mapping]] = ..., updated: bool = ...) -> None: ...

class LintProviderProfilesRequest(_message.Message):
    __slots__ = ("profiles", "workspace")
    PROFILES_FIELD_NUMBER: _ClassVar[int]
    WORKSPACE_FIELD_NUMBER: _ClassVar[int]
    profiles: _containers.RepeatedCompositeFieldContainer[ProviderProfileImportItem]
    workspace: str
    def __init__(self, profiles: _Optional[_Iterable[_Union[ProviderProfileImportItem, _Mapping]]] = ..., workspace: _Optional[str] = ...) -> None: ...

class LintProviderProfilesResponse(_message.Message):
    __slots__ = ("diagnostics", "valid")
    DIAGNOSTICS_FIELD_NUMBER: _ClassVar[int]
    VALID_FIELD_NUMBER: _ClassVar[int]
    diagnostics: _containers.RepeatedCompositeFieldContainer[ProviderProfileDiagnostic]
    valid: bool
    def __init__(self, diagnostics: _Optional[_Iterable[_Union[ProviderProfileDiagnostic, _Mapping]]] = ..., valid: bool = ...) -> None: ...

class DeleteProviderResponse(_message.Message):
    __slots__ = ("deleted",)
    DELETED_FIELD_NUMBER: _ClassVar[int]
    deleted: bool
    def __init__(self, deleted: bool = ...) -> None: ...

class DeleteProviderProfileRequest(_message.Message):
    __slots__ = ("id", "workspace")
    ID_FIELD_NUMBER: _ClassVar[int]
    WORKSPACE_FIELD_NUMBER: _ClassVar[int]
    id: str
    workspace: str
    def __init__(self, id: _Optional[str] = ..., workspace: _Optional[str] = ...) -> None: ...

class DeleteProviderProfileResponse(_message.Message):
    __slots__ = ("deleted",)
    DELETED_FIELD_NUMBER: _ClassVar[int]
    deleted: bool
    def __init__(self, deleted: bool = ...) -> None: ...

class GetSandboxProviderEnvironmentRequest(_message.Message):
    __slots__ = ("sandbox_id",)
    SANDBOX_ID_FIELD_NUMBER: _ClassVar[int]
    sandbox_id: str
    def __init__(self, sandbox_id: _Optional[str] = ...) -> None: ...

class GetSandboxProviderEnvironmentResponse(_message.Message):
    __slots__ = ("environment", "provider_env_revision", "credential_expires_at_ms", "dynamic_credentials")
    class EnvironmentEntry(_message.Message):
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
    class DynamicCredentialsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: ProviderProfileCredential
        def __init__(self, key: _Optional[str] = ..., value: _Optional[_Union[ProviderProfileCredential, _Mapping]] = ...) -> None: ...
    ENVIRONMENT_FIELD_NUMBER: _ClassVar[int]
    PROVIDER_ENV_REVISION_FIELD_NUMBER: _ClassVar[int]
    CREDENTIAL_EXPIRES_AT_MS_FIELD_NUMBER: _ClassVar[int]
    DYNAMIC_CREDENTIALS_FIELD_NUMBER: _ClassVar[int]
    environment: _containers.ScalarMap[str, str]
    provider_env_revision: int
    credential_expires_at_ms: _containers.ScalarMap[str, int]
    dynamic_credentials: _containers.MessageMap[str, ProviderProfileCredential]
    def __init__(self, environment: _Optional[_Mapping[str, str]] = ..., provider_env_revision: _Optional[int] = ..., credential_expires_at_ms: _Optional[_Mapping[str, int]] = ..., dynamic_credentials: _Optional[_Mapping[str, ProviderProfileCredential]] = ...) -> None: ...

class UpdateConfigRequest(_message.Message):
    __slots__ = ("name", "policy", "setting_key", "setting_value", "delete_setting", "merge_operations", "expected_resource_version", "annotations", "workspace")
    class AnnotationsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    NAME_FIELD_NUMBER: _ClassVar[int]
    POLICY_FIELD_NUMBER: _ClassVar[int]
    SETTING_KEY_FIELD_NUMBER: _ClassVar[int]
    SETTING_VALUE_FIELD_NUMBER: _ClassVar[int]
    DELETE_SETTING_FIELD_NUMBER: _ClassVar[int]
    GLOBAL_FIELD_NUMBER: _ClassVar[int]
    MERGE_OPERATIONS_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_RESOURCE_VERSION_FIELD_NUMBER: _ClassVar[int]
    ANNOTATIONS_FIELD_NUMBER: _ClassVar[int]
    WORKSPACE_FIELD_NUMBER: _ClassVar[int]
    name: str
    policy: _sandbox_pb2.SandboxPolicy
    setting_key: str
    setting_value: _sandbox_pb2.SettingValue
    delete_setting: bool
    merge_operations: _containers.RepeatedCompositeFieldContainer[PolicyMergeOperation]
    expected_resource_version: int
    annotations: _containers.ScalarMap[str, str]
    workspace: str
    def __init__(self, name: _Optional[str] = ..., policy: _Optional[_Union[_sandbox_pb2.SandboxPolicy, _Mapping]] = ..., setting_key: _Optional[str] = ..., setting_value: _Optional[_Union[_sandbox_pb2.SettingValue, _Mapping]] = ..., delete_setting: bool = ..., merge_operations: _Optional[_Iterable[_Union[PolicyMergeOperation, _Mapping]]] = ..., expected_resource_version: _Optional[int] = ..., annotations: _Optional[_Mapping[str, str]] = ..., workspace: _Optional[str] = ..., **kwargs) -> None: ...

class PolicyMergeOperation(_message.Message):
    __slots__ = ("add_rule", "remove_endpoint", "remove_rule", "add_deny_rules", "add_allow_rules", "remove_binary")
    ADD_RULE_FIELD_NUMBER: _ClassVar[int]
    REMOVE_ENDPOINT_FIELD_NUMBER: _ClassVar[int]
    REMOVE_RULE_FIELD_NUMBER: _ClassVar[int]
    ADD_DENY_RULES_FIELD_NUMBER: _ClassVar[int]
    ADD_ALLOW_RULES_FIELD_NUMBER: _ClassVar[int]
    REMOVE_BINARY_FIELD_NUMBER: _ClassVar[int]
    add_rule: AddNetworkRule
    remove_endpoint: RemoveNetworkEndpoint
    remove_rule: RemoveNetworkRule
    add_deny_rules: AddDenyRules
    add_allow_rules: AddAllowRules
    remove_binary: RemoveNetworkBinary
    def __init__(self, add_rule: _Optional[_Union[AddNetworkRule, _Mapping]] = ..., remove_endpoint: _Optional[_Union[RemoveNetworkEndpoint, _Mapping]] = ..., remove_rule: _Optional[_Union[RemoveNetworkRule, _Mapping]] = ..., add_deny_rules: _Optional[_Union[AddDenyRules, _Mapping]] = ..., add_allow_rules: _Optional[_Union[AddAllowRules, _Mapping]] = ..., remove_binary: _Optional[_Union[RemoveNetworkBinary, _Mapping]] = ...) -> None: ...

class AddNetworkRule(_message.Message):
    __slots__ = ("rule_name", "rule")
    RULE_NAME_FIELD_NUMBER: _ClassVar[int]
    RULE_FIELD_NUMBER: _ClassVar[int]
    rule_name: str
    rule: _sandbox_pb2.NetworkPolicyRule
    def __init__(self, rule_name: _Optional[str] = ..., rule: _Optional[_Union[_sandbox_pb2.NetworkPolicyRule, _Mapping]] = ...) -> None: ...

class RemoveNetworkEndpoint(_message.Message):
    __slots__ = ("rule_name", "host", "port")
    RULE_NAME_FIELD_NUMBER: _ClassVar[int]
    HOST_FIELD_NUMBER: _ClassVar[int]
    PORT_FIELD_NUMBER: _ClassVar[int]
    rule_name: str
    host: str
    port: int
    def __init__(self, rule_name: _Optional[str] = ..., host: _Optional[str] = ..., port: _Optional[int] = ...) -> None: ...

class RemoveNetworkRule(_message.Message):
    __slots__ = ("rule_name",)
    RULE_NAME_FIELD_NUMBER: _ClassVar[int]
    rule_name: str
    def __init__(self, rule_name: _Optional[str] = ...) -> None: ...

class AddDenyRules(_message.Message):
    __slots__ = ("host", "port", "deny_rules")
    HOST_FIELD_NUMBER: _ClassVar[int]
    PORT_FIELD_NUMBER: _ClassVar[int]
    DENY_RULES_FIELD_NUMBER: _ClassVar[int]
    host: str
    port: int
    deny_rules: _containers.RepeatedCompositeFieldContainer[_sandbox_pb2.L7DenyRule]
    def __init__(self, host: _Optional[str] = ..., port: _Optional[int] = ..., deny_rules: _Optional[_Iterable[_Union[_sandbox_pb2.L7DenyRule, _Mapping]]] = ...) -> None: ...

class AddAllowRules(_message.Message):
    __slots__ = ("host", "port", "rules")
    HOST_FIELD_NUMBER: _ClassVar[int]
    PORT_FIELD_NUMBER: _ClassVar[int]
    RULES_FIELD_NUMBER: _ClassVar[int]
    host: str
    port: int
    rules: _containers.RepeatedCompositeFieldContainer[_sandbox_pb2.L7Rule]
    def __init__(self, host: _Optional[str] = ..., port: _Optional[int] = ..., rules: _Optional[_Iterable[_Union[_sandbox_pb2.L7Rule, _Mapping]]] = ...) -> None: ...

class RemoveNetworkBinary(_message.Message):
    __slots__ = ("rule_name", "binary_path")
    RULE_NAME_FIELD_NUMBER: _ClassVar[int]
    BINARY_PATH_FIELD_NUMBER: _ClassVar[int]
    rule_name: str
    binary_path: str
    def __init__(self, rule_name: _Optional[str] = ..., binary_path: _Optional[str] = ...) -> None: ...

class UpdateConfigResponse(_message.Message):
    __slots__ = ("version", "policy_hash", "settings_revision", "deleted", "annotations")
    class AnnotationsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    VERSION_FIELD_NUMBER: _ClassVar[int]
    POLICY_HASH_FIELD_NUMBER: _ClassVar[int]
    SETTINGS_REVISION_FIELD_NUMBER: _ClassVar[int]
    DELETED_FIELD_NUMBER: _ClassVar[int]
    ANNOTATIONS_FIELD_NUMBER: _ClassVar[int]
    version: int
    policy_hash: str
    settings_revision: int
    deleted: bool
    annotations: _containers.ScalarMap[str, str]
    def __init__(self, version: _Optional[int] = ..., policy_hash: _Optional[str] = ..., settings_revision: _Optional[int] = ..., deleted: bool = ..., annotations: _Optional[_Mapping[str, str]] = ...) -> None: ...

class GetSandboxPolicyStatusRequest(_message.Message):
    __slots__ = ("name", "version", "workspace")
    NAME_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    GLOBAL_FIELD_NUMBER: _ClassVar[int]
    WORKSPACE_FIELD_NUMBER: _ClassVar[int]
    name: str
    version: int
    workspace: str
    def __init__(self, name: _Optional[str] = ..., version: _Optional[int] = ..., workspace: _Optional[str] = ..., **kwargs) -> None: ...

class GetSandboxPolicyStatusResponse(_message.Message):
    __slots__ = ("revision", "active_version")
    REVISION_FIELD_NUMBER: _ClassVar[int]
    ACTIVE_VERSION_FIELD_NUMBER: _ClassVar[int]
    revision: SandboxPolicyRevision
    active_version: int
    def __init__(self, revision: _Optional[_Union[SandboxPolicyRevision, _Mapping]] = ..., active_version: _Optional[int] = ...) -> None: ...

class ListSandboxPoliciesRequest(_message.Message):
    __slots__ = ("name", "limit", "offset", "workspace")
    NAME_FIELD_NUMBER: _ClassVar[int]
    LIMIT_FIELD_NUMBER: _ClassVar[int]
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    GLOBAL_FIELD_NUMBER: _ClassVar[int]
    WORKSPACE_FIELD_NUMBER: _ClassVar[int]
    name: str
    limit: int
    offset: int
    workspace: str
    def __init__(self, name: _Optional[str] = ..., limit: _Optional[int] = ..., offset: _Optional[int] = ..., workspace: _Optional[str] = ..., **kwargs) -> None: ...

class ListSandboxPoliciesResponse(_message.Message):
    __slots__ = ("revisions",)
    REVISIONS_FIELD_NUMBER: _ClassVar[int]
    revisions: _containers.RepeatedCompositeFieldContainer[SandboxPolicyRevision]
    def __init__(self, revisions: _Optional[_Iterable[_Union[SandboxPolicyRevision, _Mapping]]] = ...) -> None: ...

class ReportPolicyStatusRequest(_message.Message):
    __slots__ = ("sandbox_id", "version", "status", "load_error")
    SANDBOX_ID_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    LOAD_ERROR_FIELD_NUMBER: _ClassVar[int]
    sandbox_id: str
    version: int
    status: PolicyStatus
    load_error: str
    def __init__(self, sandbox_id: _Optional[str] = ..., version: _Optional[int] = ..., status: _Optional[_Union[PolicyStatus, str]] = ..., load_error: _Optional[str] = ...) -> None: ...

class ReportPolicyStatusResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class SandboxPolicyRevision(_message.Message):
    __slots__ = ("version", "policy_hash", "status", "load_error", "created_at_ms", "loaded_at_ms", "policy", "provenance")
    class ProvenanceEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    VERSION_FIELD_NUMBER: _ClassVar[int]
    POLICY_HASH_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    LOAD_ERROR_FIELD_NUMBER: _ClassVar[int]
    CREATED_AT_MS_FIELD_NUMBER: _ClassVar[int]
    LOADED_AT_MS_FIELD_NUMBER: _ClassVar[int]
    POLICY_FIELD_NUMBER: _ClassVar[int]
    PROVENANCE_FIELD_NUMBER: _ClassVar[int]
    version: int
    policy_hash: str
    status: PolicyStatus
    load_error: str
    created_at_ms: int
    loaded_at_ms: int
    policy: _sandbox_pb2.SandboxPolicy
    provenance: _containers.ScalarMap[str, str]
    def __init__(self, version: _Optional[int] = ..., policy_hash: _Optional[str] = ..., status: _Optional[_Union[PolicyStatus, str]] = ..., load_error: _Optional[str] = ..., created_at_ms: _Optional[int] = ..., loaded_at_ms: _Optional[int] = ..., policy: _Optional[_Union[_sandbox_pb2.SandboxPolicy, _Mapping]] = ..., provenance: _Optional[_Mapping[str, str]] = ...) -> None: ...

class GetSandboxLogsRequest(_message.Message):
    __slots__ = ("sandbox_id", "lines", "since_ms", "sources", "min_level", "workspace")
    SANDBOX_ID_FIELD_NUMBER: _ClassVar[int]
    LINES_FIELD_NUMBER: _ClassVar[int]
    SINCE_MS_FIELD_NUMBER: _ClassVar[int]
    SOURCES_FIELD_NUMBER: _ClassVar[int]
    MIN_LEVEL_FIELD_NUMBER: _ClassVar[int]
    WORKSPACE_FIELD_NUMBER: _ClassVar[int]
    sandbox_id: str
    lines: int
    since_ms: int
    sources: _containers.RepeatedScalarFieldContainer[str]
    min_level: str
    workspace: str
    def __init__(self, sandbox_id: _Optional[str] = ..., lines: _Optional[int] = ..., since_ms: _Optional[int] = ..., sources: _Optional[_Iterable[str]] = ..., min_level: _Optional[str] = ..., workspace: _Optional[str] = ...) -> None: ...

class PushSandboxLogsRequest(_message.Message):
    __slots__ = ("sandbox_id", "logs")
    SANDBOX_ID_FIELD_NUMBER: _ClassVar[int]
    LOGS_FIELD_NUMBER: _ClassVar[int]
    sandbox_id: str
    logs: _containers.RepeatedCompositeFieldContainer[SandboxLogLine]
    def __init__(self, sandbox_id: _Optional[str] = ..., logs: _Optional[_Iterable[_Union[SandboxLogLine, _Mapping]]] = ...) -> None: ...

class PushSandboxLogsResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class GetSandboxLogsResponse(_message.Message):
    __slots__ = ("logs", "buffer_total")
    LOGS_FIELD_NUMBER: _ClassVar[int]
    BUFFER_TOTAL_FIELD_NUMBER: _ClassVar[int]
    logs: _containers.RepeatedCompositeFieldContainer[SandboxLogLine]
    buffer_total: int
    def __init__(self, logs: _Optional[_Iterable[_Union[SandboxLogLine, _Mapping]]] = ..., buffer_total: _Optional[int] = ...) -> None: ...

class SupervisorMessage(_message.Message):
    __slots__ = ("hello", "heartbeat", "relay_open_result", "relay_close")
    HELLO_FIELD_NUMBER: _ClassVar[int]
    HEARTBEAT_FIELD_NUMBER: _ClassVar[int]
    RELAY_OPEN_RESULT_FIELD_NUMBER: _ClassVar[int]
    RELAY_CLOSE_FIELD_NUMBER: _ClassVar[int]
    hello: SupervisorHello
    heartbeat: SupervisorHeartbeat
    relay_open_result: RelayOpenResult
    relay_close: RelayClose
    def __init__(self, hello: _Optional[_Union[SupervisorHello, _Mapping]] = ..., heartbeat: _Optional[_Union[SupervisorHeartbeat, _Mapping]] = ..., relay_open_result: _Optional[_Union[RelayOpenResult, _Mapping]] = ..., relay_close: _Optional[_Union[RelayClose, _Mapping]] = ...) -> None: ...

class GatewayMessage(_message.Message):
    __slots__ = ("session_accepted", "session_rejected", "heartbeat", "relay_open", "relay_close")
    SESSION_ACCEPTED_FIELD_NUMBER: _ClassVar[int]
    SESSION_REJECTED_FIELD_NUMBER: _ClassVar[int]
    HEARTBEAT_FIELD_NUMBER: _ClassVar[int]
    RELAY_OPEN_FIELD_NUMBER: _ClassVar[int]
    RELAY_CLOSE_FIELD_NUMBER: _ClassVar[int]
    session_accepted: SessionAccepted
    session_rejected: SessionRejected
    heartbeat: GatewayHeartbeat
    relay_open: RelayOpen
    relay_close: RelayClose
    def __init__(self, session_accepted: _Optional[_Union[SessionAccepted, _Mapping]] = ..., session_rejected: _Optional[_Union[SessionRejected, _Mapping]] = ..., heartbeat: _Optional[_Union[GatewayHeartbeat, _Mapping]] = ..., relay_open: _Optional[_Union[RelayOpen, _Mapping]] = ..., relay_close: _Optional[_Union[RelayClose, _Mapping]] = ...) -> None: ...

class SupervisorHello(_message.Message):
    __slots__ = ("sandbox_id", "instance_id")
    SANDBOX_ID_FIELD_NUMBER: _ClassVar[int]
    INSTANCE_ID_FIELD_NUMBER: _ClassVar[int]
    sandbox_id: str
    instance_id: str
    def __init__(self, sandbox_id: _Optional[str] = ..., instance_id: _Optional[str] = ...) -> None: ...

class SessionAccepted(_message.Message):
    __slots__ = ("session_id", "heartbeat_interval_secs")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    HEARTBEAT_INTERVAL_SECS_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    heartbeat_interval_secs: int
    def __init__(self, session_id: _Optional[str] = ..., heartbeat_interval_secs: _Optional[int] = ...) -> None: ...

class SessionRejected(_message.Message):
    __slots__ = ("reason",)
    REASON_FIELD_NUMBER: _ClassVar[int]
    reason: str
    def __init__(self, reason: _Optional[str] = ...) -> None: ...

class SupervisorHeartbeat(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class GatewayHeartbeat(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class RelayOpen(_message.Message):
    __slots__ = ("channel_id", "ssh", "tcp", "service_id")
    CHANNEL_ID_FIELD_NUMBER: _ClassVar[int]
    SSH_FIELD_NUMBER: _ClassVar[int]
    TCP_FIELD_NUMBER: _ClassVar[int]
    SERVICE_ID_FIELD_NUMBER: _ClassVar[int]
    channel_id: str
    ssh: SshRelayTarget
    tcp: TcpRelayTarget
    service_id: str
    def __init__(self, channel_id: _Optional[str] = ..., ssh: _Optional[_Union[SshRelayTarget, _Mapping]] = ..., tcp: _Optional[_Union[TcpRelayTarget, _Mapping]] = ..., service_id: _Optional[str] = ...) -> None: ...

class SshRelayTarget(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class TcpRelayTarget(_message.Message):
    __slots__ = ("host", "port")
    HOST_FIELD_NUMBER: _ClassVar[int]
    PORT_FIELD_NUMBER: _ClassVar[int]
    host: str
    port: int
    def __init__(self, host: _Optional[str] = ..., port: _Optional[int] = ...) -> None: ...

class RelayInit(_message.Message):
    __slots__ = ("channel_id",)
    CHANNEL_ID_FIELD_NUMBER: _ClassVar[int]
    channel_id: str
    def __init__(self, channel_id: _Optional[str] = ...) -> None: ...

class RelayFrame(_message.Message):
    __slots__ = ("init", "data")
    INIT_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    init: RelayInit
    data: bytes
    def __init__(self, init: _Optional[_Union[RelayInit, _Mapping]] = ..., data: _Optional[bytes] = ...) -> None: ...

class RelayOpenResult(_message.Message):
    __slots__ = ("channel_id", "success", "error")
    CHANNEL_ID_FIELD_NUMBER: _ClassVar[int]
    SUCCESS_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    channel_id: str
    success: bool
    error: str
    def __init__(self, channel_id: _Optional[str] = ..., success: bool = ..., error: _Optional[str] = ...) -> None: ...

class RelayClose(_message.Message):
    __slots__ = ("channel_id", "reason")
    CHANNEL_ID_FIELD_NUMBER: _ClassVar[int]
    REASON_FIELD_NUMBER: _ClassVar[int]
    channel_id: str
    reason: str
    def __init__(self, channel_id: _Optional[str] = ..., reason: _Optional[str] = ...) -> None: ...

class L7RequestSample(_message.Message):
    __slots__ = ("method", "path", "decision", "count")
    METHOD_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    DECISION_FIELD_NUMBER: _ClassVar[int]
    COUNT_FIELD_NUMBER: _ClassVar[int]
    method: str
    path: str
    decision: str
    count: int
    def __init__(self, method: _Optional[str] = ..., path: _Optional[str] = ..., decision: _Optional[str] = ..., count: _Optional[int] = ...) -> None: ...

class DenialSummary(_message.Message):
    __slots__ = ("sandbox_id", "host", "port", "binary", "ancestors", "deny_reason", "first_seen_ms", "last_seen_ms", "count", "suppressed_count", "total_count", "sample_cmdlines", "binary_sha256", "persistent", "denial_stage", "l7_request_samples", "l7_inspection_active")
    SANDBOX_ID_FIELD_NUMBER: _ClassVar[int]
    HOST_FIELD_NUMBER: _ClassVar[int]
    PORT_FIELD_NUMBER: _ClassVar[int]
    BINARY_FIELD_NUMBER: _ClassVar[int]
    ANCESTORS_FIELD_NUMBER: _ClassVar[int]
    DENY_REASON_FIELD_NUMBER: _ClassVar[int]
    FIRST_SEEN_MS_FIELD_NUMBER: _ClassVar[int]
    LAST_SEEN_MS_FIELD_NUMBER: _ClassVar[int]
    COUNT_FIELD_NUMBER: _ClassVar[int]
    SUPPRESSED_COUNT_FIELD_NUMBER: _ClassVar[int]
    TOTAL_COUNT_FIELD_NUMBER: _ClassVar[int]
    SAMPLE_CMDLINES_FIELD_NUMBER: _ClassVar[int]
    BINARY_SHA256_FIELD_NUMBER: _ClassVar[int]
    PERSISTENT_FIELD_NUMBER: _ClassVar[int]
    DENIAL_STAGE_FIELD_NUMBER: _ClassVar[int]
    L7_REQUEST_SAMPLES_FIELD_NUMBER: _ClassVar[int]
    L7_INSPECTION_ACTIVE_FIELD_NUMBER: _ClassVar[int]
    sandbox_id: str
    host: str
    port: int
    binary: str
    ancestors: _containers.RepeatedScalarFieldContainer[str]
    deny_reason: str
    first_seen_ms: int
    last_seen_ms: int
    count: int
    suppressed_count: int
    total_count: int
    sample_cmdlines: _containers.RepeatedScalarFieldContainer[str]
    binary_sha256: str
    persistent: bool
    denial_stage: str
    l7_request_samples: _containers.RepeatedCompositeFieldContainer[L7RequestSample]
    l7_inspection_active: bool
    def __init__(self, sandbox_id: _Optional[str] = ..., host: _Optional[str] = ..., port: _Optional[int] = ..., binary: _Optional[str] = ..., ancestors: _Optional[_Iterable[str]] = ..., deny_reason: _Optional[str] = ..., first_seen_ms: _Optional[int] = ..., last_seen_ms: _Optional[int] = ..., count: _Optional[int] = ..., suppressed_count: _Optional[int] = ..., total_count: _Optional[int] = ..., sample_cmdlines: _Optional[_Iterable[str]] = ..., binary_sha256: _Optional[str] = ..., persistent: bool = ..., denial_stage: _Optional[str] = ..., l7_request_samples: _Optional[_Iterable[_Union[L7RequestSample, _Mapping]]] = ..., l7_inspection_active: bool = ...) -> None: ...

class DenialGroupCount(_message.Message):
    __slots__ = ("deny_group", "denied_count")
    DENY_GROUP_FIELD_NUMBER: _ClassVar[int]
    DENIED_COUNT_FIELD_NUMBER: _ClassVar[int]
    deny_group: str
    denied_count: int
    def __init__(self, deny_group: _Optional[str] = ..., denied_count: _Optional[int] = ...) -> None: ...

class NetworkActivitySummary(_message.Message):
    __slots__ = ("network_activity_count", "denied_action_count", "denials_by_group")
    NETWORK_ACTIVITY_COUNT_FIELD_NUMBER: _ClassVar[int]
    DENIED_ACTION_COUNT_FIELD_NUMBER: _ClassVar[int]
    DENIALS_BY_GROUP_FIELD_NUMBER: _ClassVar[int]
    network_activity_count: int
    denied_action_count: int
    denials_by_group: _containers.RepeatedCompositeFieldContainer[DenialGroupCount]
    def __init__(self, network_activity_count: _Optional[int] = ..., denied_action_count: _Optional[int] = ..., denials_by_group: _Optional[_Iterable[_Union[DenialGroupCount, _Mapping]]] = ...) -> None: ...

class PolicyChunk(_message.Message):
    __slots__ = ("id", "status", "rule_name", "proposed_rule", "rationale", "security_notes", "confidence", "denial_summary_ids", "created_at_ms", "decided_at_ms", "stage", "supersedes_chunk_id", "hit_count", "first_seen_ms", "last_seen_ms", "binary", "validation_result", "rejection_reason")
    ID_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    RULE_NAME_FIELD_NUMBER: _ClassVar[int]
    PROPOSED_RULE_FIELD_NUMBER: _ClassVar[int]
    RATIONALE_FIELD_NUMBER: _ClassVar[int]
    SECURITY_NOTES_FIELD_NUMBER: _ClassVar[int]
    CONFIDENCE_FIELD_NUMBER: _ClassVar[int]
    DENIAL_SUMMARY_IDS_FIELD_NUMBER: _ClassVar[int]
    CREATED_AT_MS_FIELD_NUMBER: _ClassVar[int]
    DECIDED_AT_MS_FIELD_NUMBER: _ClassVar[int]
    STAGE_FIELD_NUMBER: _ClassVar[int]
    SUPERSEDES_CHUNK_ID_FIELD_NUMBER: _ClassVar[int]
    HIT_COUNT_FIELD_NUMBER: _ClassVar[int]
    FIRST_SEEN_MS_FIELD_NUMBER: _ClassVar[int]
    LAST_SEEN_MS_FIELD_NUMBER: _ClassVar[int]
    BINARY_FIELD_NUMBER: _ClassVar[int]
    VALIDATION_RESULT_FIELD_NUMBER: _ClassVar[int]
    REJECTION_REASON_FIELD_NUMBER: _ClassVar[int]
    id: str
    status: str
    rule_name: str
    proposed_rule: _sandbox_pb2.NetworkPolicyRule
    rationale: str
    security_notes: str
    confidence: float
    denial_summary_ids: _containers.RepeatedScalarFieldContainer[str]
    created_at_ms: int
    decided_at_ms: int
    stage: str
    supersedes_chunk_id: str
    hit_count: int
    first_seen_ms: int
    last_seen_ms: int
    binary: str
    validation_result: str
    rejection_reason: str
    def __init__(self, id: _Optional[str] = ..., status: _Optional[str] = ..., rule_name: _Optional[str] = ..., proposed_rule: _Optional[_Union[_sandbox_pb2.NetworkPolicyRule, _Mapping]] = ..., rationale: _Optional[str] = ..., security_notes: _Optional[str] = ..., confidence: _Optional[float] = ..., denial_summary_ids: _Optional[_Iterable[str]] = ..., created_at_ms: _Optional[int] = ..., decided_at_ms: _Optional[int] = ..., stage: _Optional[str] = ..., supersedes_chunk_id: _Optional[str] = ..., hit_count: _Optional[int] = ..., first_seen_ms: _Optional[int] = ..., last_seen_ms: _Optional[int] = ..., binary: _Optional[str] = ..., validation_result: _Optional[str] = ..., rejection_reason: _Optional[str] = ...) -> None: ...

class DraftPolicyUpdate(_message.Message):
    __slots__ = ("draft_version", "new_chunks", "total_pending", "summary")
    DRAFT_VERSION_FIELD_NUMBER: _ClassVar[int]
    NEW_CHUNKS_FIELD_NUMBER: _ClassVar[int]
    TOTAL_PENDING_FIELD_NUMBER: _ClassVar[int]
    SUMMARY_FIELD_NUMBER: _ClassVar[int]
    draft_version: int
    new_chunks: int
    total_pending: int
    summary: str
    def __init__(self, draft_version: _Optional[int] = ..., new_chunks: _Optional[int] = ..., total_pending: _Optional[int] = ..., summary: _Optional[str] = ...) -> None: ...

class SubmitPolicyAnalysisRequest(_message.Message):
    __slots__ = ("summaries", "proposed_chunks", "analysis_mode", "name", "network_activity_summaries", "workspace")
    SUMMARIES_FIELD_NUMBER: _ClassVar[int]
    PROPOSED_CHUNKS_FIELD_NUMBER: _ClassVar[int]
    ANALYSIS_MODE_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    NETWORK_ACTIVITY_SUMMARIES_FIELD_NUMBER: _ClassVar[int]
    WORKSPACE_FIELD_NUMBER: _ClassVar[int]
    summaries: _containers.RepeatedCompositeFieldContainer[DenialSummary]
    proposed_chunks: _containers.RepeatedCompositeFieldContainer[PolicyChunk]
    analysis_mode: str
    name: str
    network_activity_summaries: _containers.RepeatedCompositeFieldContainer[NetworkActivitySummary]
    workspace: str
    def __init__(self, summaries: _Optional[_Iterable[_Union[DenialSummary, _Mapping]]] = ..., proposed_chunks: _Optional[_Iterable[_Union[PolicyChunk, _Mapping]]] = ..., analysis_mode: _Optional[str] = ..., name: _Optional[str] = ..., network_activity_summaries: _Optional[_Iterable[_Union[NetworkActivitySummary, _Mapping]]] = ..., workspace: _Optional[str] = ...) -> None: ...

class SubmitPolicyAnalysisResponse(_message.Message):
    __slots__ = ("accepted_chunks", "rejected_chunks", "rejection_reasons", "accepted_chunk_ids")
    ACCEPTED_CHUNKS_FIELD_NUMBER: _ClassVar[int]
    REJECTED_CHUNKS_FIELD_NUMBER: _ClassVar[int]
    REJECTION_REASONS_FIELD_NUMBER: _ClassVar[int]
    ACCEPTED_CHUNK_IDS_FIELD_NUMBER: _ClassVar[int]
    accepted_chunks: int
    rejected_chunks: int
    rejection_reasons: _containers.RepeatedScalarFieldContainer[str]
    accepted_chunk_ids: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, accepted_chunks: _Optional[int] = ..., rejected_chunks: _Optional[int] = ..., rejection_reasons: _Optional[_Iterable[str]] = ..., accepted_chunk_ids: _Optional[_Iterable[str]] = ...) -> None: ...

class GetDraftPolicyRequest(_message.Message):
    __slots__ = ("name", "status_filter", "workspace")
    NAME_FIELD_NUMBER: _ClassVar[int]
    STATUS_FILTER_FIELD_NUMBER: _ClassVar[int]
    WORKSPACE_FIELD_NUMBER: _ClassVar[int]
    name: str
    status_filter: str
    workspace: str
    def __init__(self, name: _Optional[str] = ..., status_filter: _Optional[str] = ..., workspace: _Optional[str] = ...) -> None: ...

class GetDraftPolicyResponse(_message.Message):
    __slots__ = ("chunks", "rolling_summary", "draft_version", "last_analyzed_at_ms")
    CHUNKS_FIELD_NUMBER: _ClassVar[int]
    ROLLING_SUMMARY_FIELD_NUMBER: _ClassVar[int]
    DRAFT_VERSION_FIELD_NUMBER: _ClassVar[int]
    LAST_ANALYZED_AT_MS_FIELD_NUMBER: _ClassVar[int]
    chunks: _containers.RepeatedCompositeFieldContainer[PolicyChunk]
    rolling_summary: str
    draft_version: int
    last_analyzed_at_ms: int
    def __init__(self, chunks: _Optional[_Iterable[_Union[PolicyChunk, _Mapping]]] = ..., rolling_summary: _Optional[str] = ..., draft_version: _Optional[int] = ..., last_analyzed_at_ms: _Optional[int] = ...) -> None: ...

class ApproveDraftChunkRequest(_message.Message):
    __slots__ = ("name", "chunk_id", "workspace")
    NAME_FIELD_NUMBER: _ClassVar[int]
    CHUNK_ID_FIELD_NUMBER: _ClassVar[int]
    WORKSPACE_FIELD_NUMBER: _ClassVar[int]
    name: str
    chunk_id: str
    workspace: str
    def __init__(self, name: _Optional[str] = ..., chunk_id: _Optional[str] = ..., workspace: _Optional[str] = ...) -> None: ...

class ApproveDraftChunkResponse(_message.Message):
    __slots__ = ("policy_version", "policy_hash")
    POLICY_VERSION_FIELD_NUMBER: _ClassVar[int]
    POLICY_HASH_FIELD_NUMBER: _ClassVar[int]
    policy_version: int
    policy_hash: str
    def __init__(self, policy_version: _Optional[int] = ..., policy_hash: _Optional[str] = ...) -> None: ...

class RejectDraftChunkRequest(_message.Message):
    __slots__ = ("name", "chunk_id", "reason", "workspace")
    NAME_FIELD_NUMBER: _ClassVar[int]
    CHUNK_ID_FIELD_NUMBER: _ClassVar[int]
    REASON_FIELD_NUMBER: _ClassVar[int]
    WORKSPACE_FIELD_NUMBER: _ClassVar[int]
    name: str
    chunk_id: str
    reason: str
    workspace: str
    def __init__(self, name: _Optional[str] = ..., chunk_id: _Optional[str] = ..., reason: _Optional[str] = ..., workspace: _Optional[str] = ...) -> None: ...

class RejectDraftChunkResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class ApproveAllDraftChunksRequest(_message.Message):
    __slots__ = ("name", "include_security_flagged", "workspace")
    NAME_FIELD_NUMBER: _ClassVar[int]
    INCLUDE_SECURITY_FLAGGED_FIELD_NUMBER: _ClassVar[int]
    WORKSPACE_FIELD_NUMBER: _ClassVar[int]
    name: str
    include_security_flagged: bool
    workspace: str
    def __init__(self, name: _Optional[str] = ..., include_security_flagged: bool = ..., workspace: _Optional[str] = ...) -> None: ...

class ApproveAllDraftChunksResponse(_message.Message):
    __slots__ = ("policy_version", "policy_hash", "chunks_approved", "chunks_skipped")
    POLICY_VERSION_FIELD_NUMBER: _ClassVar[int]
    POLICY_HASH_FIELD_NUMBER: _ClassVar[int]
    CHUNKS_APPROVED_FIELD_NUMBER: _ClassVar[int]
    CHUNKS_SKIPPED_FIELD_NUMBER: _ClassVar[int]
    policy_version: int
    policy_hash: str
    chunks_approved: int
    chunks_skipped: int
    def __init__(self, policy_version: _Optional[int] = ..., policy_hash: _Optional[str] = ..., chunks_approved: _Optional[int] = ..., chunks_skipped: _Optional[int] = ...) -> None: ...

class EditDraftChunkRequest(_message.Message):
    __slots__ = ("name", "chunk_id", "proposed_rule", "workspace")
    NAME_FIELD_NUMBER: _ClassVar[int]
    CHUNK_ID_FIELD_NUMBER: _ClassVar[int]
    PROPOSED_RULE_FIELD_NUMBER: _ClassVar[int]
    WORKSPACE_FIELD_NUMBER: _ClassVar[int]
    name: str
    chunk_id: str
    proposed_rule: _sandbox_pb2.NetworkPolicyRule
    workspace: str
    def __init__(self, name: _Optional[str] = ..., chunk_id: _Optional[str] = ..., proposed_rule: _Optional[_Union[_sandbox_pb2.NetworkPolicyRule, _Mapping]] = ..., workspace: _Optional[str] = ...) -> None: ...

class EditDraftChunkResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class UndoDraftChunkRequest(_message.Message):
    __slots__ = ("name", "chunk_id", "workspace")
    NAME_FIELD_NUMBER: _ClassVar[int]
    CHUNK_ID_FIELD_NUMBER: _ClassVar[int]
    WORKSPACE_FIELD_NUMBER: _ClassVar[int]
    name: str
    chunk_id: str
    workspace: str
    def __init__(self, name: _Optional[str] = ..., chunk_id: _Optional[str] = ..., workspace: _Optional[str] = ...) -> None: ...

class UndoDraftChunkResponse(_message.Message):
    __slots__ = ("policy_version", "policy_hash")
    POLICY_VERSION_FIELD_NUMBER: _ClassVar[int]
    POLICY_HASH_FIELD_NUMBER: _ClassVar[int]
    policy_version: int
    policy_hash: str
    def __init__(self, policy_version: _Optional[int] = ..., policy_hash: _Optional[str] = ...) -> None: ...

class ClearDraftChunksRequest(_message.Message):
    __slots__ = ("name", "workspace")
    NAME_FIELD_NUMBER: _ClassVar[int]
    WORKSPACE_FIELD_NUMBER: _ClassVar[int]
    name: str
    workspace: str
    def __init__(self, name: _Optional[str] = ..., workspace: _Optional[str] = ...) -> None: ...

class ClearDraftChunksResponse(_message.Message):
    __slots__ = ("chunks_cleared",)
    CHUNKS_CLEARED_FIELD_NUMBER: _ClassVar[int]
    chunks_cleared: int
    def __init__(self, chunks_cleared: _Optional[int] = ...) -> None: ...

class GetDraftHistoryRequest(_message.Message):
    __slots__ = ("name", "workspace")
    NAME_FIELD_NUMBER: _ClassVar[int]
    WORKSPACE_FIELD_NUMBER: _ClassVar[int]
    name: str
    workspace: str
    def __init__(self, name: _Optional[str] = ..., workspace: _Optional[str] = ...) -> None: ...

class DraftHistoryEntry(_message.Message):
    __slots__ = ("timestamp_ms", "event_type", "description", "chunk_id")
    TIMESTAMP_MS_FIELD_NUMBER: _ClassVar[int]
    EVENT_TYPE_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    CHUNK_ID_FIELD_NUMBER: _ClassVar[int]
    timestamp_ms: int
    event_type: str
    description: str
    chunk_id: str
    def __init__(self, timestamp_ms: _Optional[int] = ..., event_type: _Optional[str] = ..., description: _Optional[str] = ..., chunk_id: _Optional[str] = ...) -> None: ...

class GetDraftHistoryResponse(_message.Message):
    __slots__ = ("entries",)
    ENTRIES_FIELD_NUMBER: _ClassVar[int]
    entries: _containers.RepeatedCompositeFieldContainer[DraftHistoryEntry]
    def __init__(self, entries: _Optional[_Iterable[_Union[DraftHistoryEntry, _Mapping]]] = ...) -> None: ...

class PolicyRevisionPayload(_message.Message):
    __slots__ = ("policy", "hash", "load_error", "loaded_at_ms", "provenance")
    class ProvenanceEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    POLICY_FIELD_NUMBER: _ClassVar[int]
    HASH_FIELD_NUMBER: _ClassVar[int]
    LOAD_ERROR_FIELD_NUMBER: _ClassVar[int]
    LOADED_AT_MS_FIELD_NUMBER: _ClassVar[int]
    PROVENANCE_FIELD_NUMBER: _ClassVar[int]
    policy: _sandbox_pb2.SandboxPolicy
    hash: str
    load_error: str
    loaded_at_ms: int
    provenance: _containers.ScalarMap[str, str]
    def __init__(self, policy: _Optional[_Union[_sandbox_pb2.SandboxPolicy, _Mapping]] = ..., hash: _Optional[str] = ..., load_error: _Optional[str] = ..., loaded_at_ms: _Optional[int] = ..., provenance: _Optional[_Mapping[str, str]] = ...) -> None: ...

class DraftChunkPayload(_message.Message):
    __slots__ = ("rule_name", "proposed_rule", "rationale", "security_notes", "confidence", "decided_at_ms", "host", "port", "binary", "draft_version", "validation_result", "rejection_reason")
    RULE_NAME_FIELD_NUMBER: _ClassVar[int]
    PROPOSED_RULE_FIELD_NUMBER: _ClassVar[int]
    RATIONALE_FIELD_NUMBER: _ClassVar[int]
    SECURITY_NOTES_FIELD_NUMBER: _ClassVar[int]
    CONFIDENCE_FIELD_NUMBER: _ClassVar[int]
    DECIDED_AT_MS_FIELD_NUMBER: _ClassVar[int]
    HOST_FIELD_NUMBER: _ClassVar[int]
    PORT_FIELD_NUMBER: _ClassVar[int]
    BINARY_FIELD_NUMBER: _ClassVar[int]
    DRAFT_VERSION_FIELD_NUMBER: _ClassVar[int]
    VALIDATION_RESULT_FIELD_NUMBER: _ClassVar[int]
    REJECTION_REASON_FIELD_NUMBER: _ClassVar[int]
    rule_name: str
    proposed_rule: _sandbox_pb2.NetworkPolicyRule
    rationale: str
    security_notes: str
    confidence: float
    decided_at_ms: int
    host: str
    port: int
    binary: str
    draft_version: int
    validation_result: str
    rejection_reason: str
    def __init__(self, rule_name: _Optional[str] = ..., proposed_rule: _Optional[_Union[_sandbox_pb2.NetworkPolicyRule, _Mapping]] = ..., rationale: _Optional[str] = ..., security_notes: _Optional[str] = ..., confidence: _Optional[float] = ..., decided_at_ms: _Optional[int] = ..., host: _Optional[str] = ..., port: _Optional[int] = ..., binary: _Optional[str] = ..., draft_version: _Optional[int] = ..., validation_result: _Optional[str] = ..., rejection_reason: _Optional[str] = ...) -> None: ...

class StoredPolicyRevision(_message.Message):
    __slots__ = ("id", "sandbox_id", "version", "policy_payload", "policy_hash", "status", "load_error", "created_at_ms", "loaded_at_ms", "provenance")
    class ProvenanceEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    ID_FIELD_NUMBER: _ClassVar[int]
    SANDBOX_ID_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    POLICY_PAYLOAD_FIELD_NUMBER: _ClassVar[int]
    POLICY_HASH_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    LOAD_ERROR_FIELD_NUMBER: _ClassVar[int]
    CREATED_AT_MS_FIELD_NUMBER: _ClassVar[int]
    LOADED_AT_MS_FIELD_NUMBER: _ClassVar[int]
    PROVENANCE_FIELD_NUMBER: _ClassVar[int]
    id: str
    sandbox_id: str
    version: int
    policy_payload: bytes
    policy_hash: str
    status: str
    load_error: str
    created_at_ms: int
    loaded_at_ms: int
    provenance: _containers.ScalarMap[str, str]
    def __init__(self, id: _Optional[str] = ..., sandbox_id: _Optional[str] = ..., version: _Optional[int] = ..., policy_payload: _Optional[bytes] = ..., policy_hash: _Optional[str] = ..., status: _Optional[str] = ..., load_error: _Optional[str] = ..., created_at_ms: _Optional[int] = ..., loaded_at_ms: _Optional[int] = ..., provenance: _Optional[_Mapping[str, str]] = ...) -> None: ...

class StoredDraftChunk(_message.Message):
    __slots__ = ("id", "sandbox_id", "draft_version", "status", "rule_name", "proposed_rule", "rationale", "security_notes", "confidence", "created_at_ms", "decided_at_ms", "host", "port", "binary", "hit_count", "first_seen_ms", "last_seen_ms", "validation_result", "rejection_reason")
    ID_FIELD_NUMBER: _ClassVar[int]
    SANDBOX_ID_FIELD_NUMBER: _ClassVar[int]
    DRAFT_VERSION_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    RULE_NAME_FIELD_NUMBER: _ClassVar[int]
    PROPOSED_RULE_FIELD_NUMBER: _ClassVar[int]
    RATIONALE_FIELD_NUMBER: _ClassVar[int]
    SECURITY_NOTES_FIELD_NUMBER: _ClassVar[int]
    CONFIDENCE_FIELD_NUMBER: _ClassVar[int]
    CREATED_AT_MS_FIELD_NUMBER: _ClassVar[int]
    DECIDED_AT_MS_FIELD_NUMBER: _ClassVar[int]
    HOST_FIELD_NUMBER: _ClassVar[int]
    PORT_FIELD_NUMBER: _ClassVar[int]
    BINARY_FIELD_NUMBER: _ClassVar[int]
    HIT_COUNT_FIELD_NUMBER: _ClassVar[int]
    FIRST_SEEN_MS_FIELD_NUMBER: _ClassVar[int]
    LAST_SEEN_MS_FIELD_NUMBER: _ClassVar[int]
    VALIDATION_RESULT_FIELD_NUMBER: _ClassVar[int]
    REJECTION_REASON_FIELD_NUMBER: _ClassVar[int]
    id: str
    sandbox_id: str
    draft_version: int
    status: str
    rule_name: str
    proposed_rule: bytes
    rationale: str
    security_notes: str
    confidence: float
    created_at_ms: int
    decided_at_ms: int
    host: str
    port: int
    binary: str
    hit_count: int
    first_seen_ms: int
    last_seen_ms: int
    validation_result: str
    rejection_reason: str
    def __init__(self, id: _Optional[str] = ..., sandbox_id: _Optional[str] = ..., draft_version: _Optional[int] = ..., status: _Optional[str] = ..., rule_name: _Optional[str] = ..., proposed_rule: _Optional[bytes] = ..., rationale: _Optional[str] = ..., security_notes: _Optional[str] = ..., confidence: _Optional[float] = ..., created_at_ms: _Optional[int] = ..., decided_at_ms: _Optional[int] = ..., host: _Optional[str] = ..., port: _Optional[int] = ..., binary: _Optional[str] = ..., hit_count: _Optional[int] = ..., first_seen_ms: _Optional[int] = ..., last_seen_ms: _Optional[int] = ..., validation_result: _Optional[str] = ..., rejection_reason: _Optional[str] = ...) -> None: ...

class CreateWorkspaceRequest(_message.Message):
    __slots__ = ("name", "labels")
    class LabelsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    NAME_FIELD_NUMBER: _ClassVar[int]
    LABELS_FIELD_NUMBER: _ClassVar[int]
    name: str
    labels: _containers.ScalarMap[str, str]
    def __init__(self, name: _Optional[str] = ..., labels: _Optional[_Mapping[str, str]] = ...) -> None: ...

class CreateWorkspaceResponse(_message.Message):
    __slots__ = ("workspace",)
    WORKSPACE_FIELD_NUMBER: _ClassVar[int]
    workspace: _datamodel_pb2.Workspace
    def __init__(self, workspace: _Optional[_Union[_datamodel_pb2.Workspace, _Mapping]] = ...) -> None: ...

class GetWorkspaceRequest(_message.Message):
    __slots__ = ("name",)
    NAME_FIELD_NUMBER: _ClassVar[int]
    name: str
    def __init__(self, name: _Optional[str] = ...) -> None: ...

class GetWorkspaceResponse(_message.Message):
    __slots__ = ("workspace",)
    WORKSPACE_FIELD_NUMBER: _ClassVar[int]
    workspace: _datamodel_pb2.Workspace
    def __init__(self, workspace: _Optional[_Union[_datamodel_pb2.Workspace, _Mapping]] = ...) -> None: ...

class ListWorkspacesRequest(_message.Message):
    __slots__ = ("limit", "offset", "label_selector")
    LIMIT_FIELD_NUMBER: _ClassVar[int]
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    LABEL_SELECTOR_FIELD_NUMBER: _ClassVar[int]
    limit: int
    offset: int
    label_selector: str
    def __init__(self, limit: _Optional[int] = ..., offset: _Optional[int] = ..., label_selector: _Optional[str] = ...) -> None: ...

class ListWorkspacesResponse(_message.Message):
    __slots__ = ("workspaces",)
    WORKSPACES_FIELD_NUMBER: _ClassVar[int]
    workspaces: _containers.RepeatedCompositeFieldContainer[_datamodel_pb2.Workspace]
    def __init__(self, workspaces: _Optional[_Iterable[_Union[_datamodel_pb2.Workspace, _Mapping]]] = ...) -> None: ...

class DeleteWorkspaceRequest(_message.Message):
    __slots__ = ("name",)
    NAME_FIELD_NUMBER: _ClassVar[int]
    name: str
    def __init__(self, name: _Optional[str] = ...) -> None: ...

class DeleteWorkspaceResponse(_message.Message):
    __slots__ = ("deleted",)
    DELETED_FIELD_NUMBER: _ClassVar[int]
    deleted: bool
    def __init__(self, deleted: bool = ...) -> None: ...

class WorkspaceMember(_message.Message):
    __slots__ = ("metadata", "principal_subject", "role")
    METADATA_FIELD_NUMBER: _ClassVar[int]
    PRINCIPAL_SUBJECT_FIELD_NUMBER: _ClassVar[int]
    ROLE_FIELD_NUMBER: _ClassVar[int]
    metadata: _datamodel_pb2.ObjectMeta
    principal_subject: str
    role: WorkspaceRole
    def __init__(self, metadata: _Optional[_Union[_datamodel_pb2.ObjectMeta, _Mapping]] = ..., principal_subject: _Optional[str] = ..., role: _Optional[_Union[WorkspaceRole, str]] = ...) -> None: ...

class AddWorkspaceMemberRequest(_message.Message):
    __slots__ = ("workspace", "principal_subject", "role")
    WORKSPACE_FIELD_NUMBER: _ClassVar[int]
    PRINCIPAL_SUBJECT_FIELD_NUMBER: _ClassVar[int]
    ROLE_FIELD_NUMBER: _ClassVar[int]
    workspace: str
    principal_subject: str
    role: WorkspaceRole
    def __init__(self, workspace: _Optional[str] = ..., principal_subject: _Optional[str] = ..., role: _Optional[_Union[WorkspaceRole, str]] = ...) -> None: ...

class AddWorkspaceMemberResponse(_message.Message):
    __slots__ = ("member",)
    MEMBER_FIELD_NUMBER: _ClassVar[int]
    member: WorkspaceMember
    def __init__(self, member: _Optional[_Union[WorkspaceMember, _Mapping]] = ...) -> None: ...

class RemoveWorkspaceMemberRequest(_message.Message):
    __slots__ = ("workspace", "principal_subject")
    WORKSPACE_FIELD_NUMBER: _ClassVar[int]
    PRINCIPAL_SUBJECT_FIELD_NUMBER: _ClassVar[int]
    workspace: str
    principal_subject: str
    def __init__(self, workspace: _Optional[str] = ..., principal_subject: _Optional[str] = ...) -> None: ...

class RemoveWorkspaceMemberResponse(_message.Message):
    __slots__ = ("removed",)
    REMOVED_FIELD_NUMBER: _ClassVar[int]
    removed: bool
    def __init__(self, removed: bool = ...) -> None: ...

class ListWorkspaceMembersRequest(_message.Message):
    __slots__ = ("workspace", "limit", "offset")
    WORKSPACE_FIELD_NUMBER: _ClassVar[int]
    LIMIT_FIELD_NUMBER: _ClassVar[int]
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    workspace: str
    limit: int
    offset: int
    def __init__(self, workspace: _Optional[str] = ..., limit: _Optional[int] = ..., offset: _Optional[int] = ...) -> None: ...

class ListWorkspaceMembersResponse(_message.Message):
    __slots__ = ("members",)
    MEMBERS_FIELD_NUMBER: _ClassVar[int]
    members: _containers.RepeatedCompositeFieldContainer[WorkspaceMember]
    def __init__(self, members: _Optional[_Iterable[_Union[WorkspaceMember, _Mapping]]] = ...) -> None: ...
