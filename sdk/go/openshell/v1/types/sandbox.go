// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package types

import "time"

// Sandbox represents a sandbox instance.
type Sandbox struct {
	// HostKeyFingerprint is the stable SSH identity; empty on older runtimes.
	HostKeyFingerprint          string
	ID                          string
	Name                        string
	CreatedAt                   time.Time
	Labels                      map[string]string
	Annotations                 map[string]string
	ResourceVersion             uint64
	Workspace                   string
	DeletionTimestamp           *time.Time
	CreatedFromWorkloadTemplate *SandboxWorkloadTemplateProvenance
	Spec                        SandboxSpec
	Status                      SandboxStatus
	// ServiceURLs is populated by create operations and keyed by service name.
	// The empty key identifies the unnamed service.
	ServiceURLs map[string]string
}

// SandboxSpec holds the desired state of a sandbox.
type SandboxSpec struct {
	// Frozen preserves the effective policy after initialization for this sandbox's lifetime.
	Frozen      bool
	LogLevel    string
	Environment map[string]string
	Template    *SandboxTemplate
	Providers   []string
	// GPU requests GPU resources using the active driver's default GPU assignment
	// when GPUCount is nil. GPUCount implies GPU for backward compatibility.
	GPU      bool
	GPUCount *uint32
	// Policy is the security policy for the sandbox. Nil means no policy specified.
	Policy        *SandboxPolicy
	Command       []string
	TTY           bool
	RestartPolicy SandboxRestartPolicy
}

// SandboxTemplate defines the container template for a sandbox.
type SandboxTemplate struct {
	Image            string
	RuntimeClassName string
	AgentSocket      string
	Labels           map[string]string
	Annotations      map[string]string
	Environment      map[string]string
	UserNamespaces   *bool
	Resources        map[string]any
	DriverConfig     map[string]any
}

// SandboxWorkloadTemplate is a reusable workspace-scoped sandbox template resource.
type SandboxWorkloadTemplate struct {
	ID                string
	Name              string
	CreatedAt         time.Time
	Labels            map[string]string
	Annotations       map[string]string
	ResourceVersion   uint64
	Workspace         string
	DeletionTimestamp *time.Time
	Spec              SandboxWorkloadTemplateSpec
}

// SandboxWorkloadTemplateSpec holds reusable sandbox template settings.
type SandboxWorkloadTemplateSpec struct {
	Workload            *SandboxWorkloadConfig
	DriverConfig        map[string]any
	DesiredServiceLevel *SandboxServiceLevel
}

// SandboxWorkloadConfig defines the portable workload for a reusable template.
type SandboxWorkloadConfig struct {
	Image       string
	Environment map[string]string
	Resources   *SandboxResources
}

// SandboxResources defines portable sandbox resource requirements.
type SandboxResources struct {
	CPU    string
	Memory string
	// GPU requests GPU resources for template-backed sandboxes. A non-nil GPU
	// with nil Count requests the active driver's default GPU assignment.
	GPU *SandboxGPURequirements
}

// SandboxGPURequirements defines template GPU requirements.
type SandboxGPURequirements struct {
	Count *uint32
}

// SandboxServiceLevel describes desired operational characteristics.
type SandboxServiceLevel struct {
	Startup *SandboxStartup
}

// SandboxStartup describes desired startup characteristics.
type SandboxStartup struct {
	ReadyWithin time.Duration
	MaxBurst    uint32
}

// SandboxWorkloadTemplateProvenance identifies the reusable template revision used to create a sandbox.
type SandboxWorkloadTemplateProvenance struct {
	Name            string
	ResourceVersion string
}

// SandboxStatus holds the observed state of a sandbox.
type SandboxStatus struct {
	// FrozenPolicy is nil until a requested freeze has initialized successfully.
	FrozenPolicy         *FrozenSandboxPolicy
	AgentPod             string
	AgentFd              string
	SandboxFd            string
	Phase                SandboxPhase
	Conditions           []SandboxCondition
	CurrentPolicyVersion uint32
	ExitCode             *int32
	// EndpointStatuses describes configured external tool endpoints and their
	// last accepted network results, independently of sandbox readiness.
	EndpointStatuses []EndpointStatus
	// LastTokenGrantFailure is the latest classified grant refusal for any
	// destination, including requests outside the MCP endpoint inventory.
	// A successful grant for the same destination and provider/credential clears
	// it. Before credential selection, any successful grant to that destination
	// clears it. Policy, provider, and session resets also clear it.
	// Nil means no retained cause.
	LastTokenGrantFailure  *TokenGrantFailureObservation
	ConfigurationAdmission *SandboxConfigurationAdmission
	RestartCount           uint32
	NextRestartAtMs        int64
	MainProcessStartedAtMs int64
}

// FrozenSandboxPolicy is the accepted effective policy and its immutable identity.
// Gateway-owned provider authorization snapshots remain available through the raw API.
type FrozenSandboxPolicy struct {
	Policy              *SandboxPolicy
	Version             uint32
	PolicyHash          string
	FrozenAt            time.Time
	PolicySource        PolicySource
	GlobalPolicyVersion uint32
}

// TokenGrantFailureObservation records a refused grant's destination and cause.
// It describes the attempted call, not the remote server's current health.
type TokenGrantFailureObservation struct {
	DestinationHost string
	DestinationPort uint32
	Failure         *EndpointFailure
}

// ConfigurationAdmissionState describes validation of an effective configuration.
type ConfigurationAdmissionState string

// Configuration admission states reported by the gateway.
const (
	ConfigurationAdmissionUnknown  ConfigurationAdmissionState = "unknown"
	ConfigurationAdmissionPending  ConfigurationAdmissionState = "pending"
	ConfigurationAdmissionAccepted ConfigurationAdmissionState = "accepted"
	ConfigurationAdmissionRejected ConfigurationAdmissionState = "rejected"
)

// SandboxConfigurationAdmission identifies a validated or rejected configuration.
// Supervisor instance fencing remains available through the raw protobuf API.
type SandboxConfigurationAdmission struct {
	State               ConfigurationAdmissionState
	PolicyVersion       uint32
	PolicyHash          string
	ConfigRevision      uint64
	ProviderEnvRevision uint64
	Error               string
}

// EndpointStatus holds a configured tool endpoint and its last accepted network result.
// Observations aggregate configured callers across the listed ports; the result
// does not establish present availability or successful tool execution.
type EndpointStatus struct {
	// EndpointID selects this endpoint without parsing its address or display text.
	EndpointID string
	Host       string
	Ports      []uint32
	Path       string
	LastResult EndpointResult
	// LastReportedAt is the RFC 3339 UTC rendering of the time when the gateway accepted the
	// observation, not the request time. Retained evidence can be accepted after
	// a reset. NoObservedExchange has no report timestamp.
	LastReportedAt string
	// LastFailure is the bounded cause of LastResult, when the supervisor
	// classified it. Each failure domain names the results it explains; token
	// grant failures accompany EndpointCredentialUnavailable. Each later
	// observation replaces or clears it, and the resets that clear LastResult
	// also clear it. Nil means no classified cause.
	LastFailure *EndpointFailure
}

// EndpointFailure explains why an observed exchange failed. It does not
// establish that the endpoint is unhealthy. No field carries remote text.
type EndpointFailure struct {
	// Domain names the subsystem whose closed code set explains the failure.
	Domain EndpointFailureDomain
	// Code is a stable lower_snake_case code from the domain's closed set,
	// such as provider_authorization_required.
	Code string
	// RecoveryAction is the action documented for Code.
	RecoveryAction RefreshRecoveryAction
	// Provider is the configured provider whose credential failed. It is empty
	// when the failure happened before a credential was selected.
	Provider string
	// CredentialKey is the configured credential name within Provider, never a
	// credential value. It is empty when Provider is empty.
	CredentialKey string
	// Stage is the step that observed the failure, from the domain's closed
	// set, such as gateway_rpc.
	Stage string
	// UpstreamHTTPStatus is the HTTP status a token service returned. Nil means
	// no status was received.
	UpstreamHTTPStatus *uint32
	// RequestID is the supervisor-minted UUID of the refused exchange. The
	// workload receives the same value in the x-openshell-request-id response
	// header.
	RequestID string
}

// EndpointFailureDomain names the subsystem that explains an endpoint failure.
type EndpointFailureDomain string

// EndpointFailureDomain values select the closed set that Code and Stage come from.
const (
	// EndpointFailureDomainUnspecified means the domain was absent or was not recognized.
	EndpointFailureDomainUnspecified EndpointFailureDomain = "Unspecified"
	// EndpointFailureDomainTokenGrant means a dynamic token grant for a provider
	// credential failed, so OpenShell refused the request before any of it
	// reached the endpoint.
	EndpointFailureDomainTokenGrant EndpointFailureDomain = "TokenGrant"
)

// EndpointResult classifies the last accepted network result for a tool endpoint.
type EndpointResult string

// EndpointResult values describe passive observations of actual traffic.
const (
	// EndpointUnspecified means the result was absent or was not recognized.
	EndpointUnspecified EndpointResult = "Unspecified"
	// EndpointNoObservedExchange means the active configuration and supervisor
	// session have no applicable observation.
	EndpointNoObservedExchange EndpointResult = "NoObservedExchange"
	// EndpointHTTPResponseReceived means an HTTP status below 400 was received.
	// The response body can still contain a tool error.
	EndpointHTTPResponseReceived EndpointResult = "HttpResponseReceived"
	// EndpointPolicyDenied means OpenShell policy denied the request locally.
	EndpointPolicyDenied EndpointResult = "PolicyDenied"
	// EndpointCredentialUnavailable means a required managed credential was unavailable.
	EndpointCredentialUnavailable EndpointResult = "CredentialUnavailable"
	// EndpointTLSFailed means TLS setup for the upstream connection failed.
	EndpointTLSFailed EndpointResult = "TlsFailed"
	// EndpointTransportFailed means the transport failed before an HTTP response arrived.
	EndpointTransportFailed EndpointResult = "TransportFailed"
	// EndpointUpstreamRejected means the server returned an HTTP status of 400 or higher.
	EndpointUpstreamRejected EndpointResult = "UpstreamRejected"
)

// SandboxCondition describes an observed condition of a sandbox.
type SandboxCondition struct {
	Type               string
	Status             string
	Reason             string
	Message            string
	LastTransitionTime string
}

// AttachProviderResult holds the result of attaching a provider to a sandbox.
type AttachProviderResult struct {
	Sandbox  *Sandbox
	Attached bool
}

// DetachProviderResult holds the result of detaching a provider from a sandbox.
type DetachProviderResult struct {
	Sandbox  *Sandbox
	Detached bool
}
