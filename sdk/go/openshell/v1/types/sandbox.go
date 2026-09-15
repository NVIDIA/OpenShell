// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package types

import "time"

// Sandbox represents a sandbox instance.
type Sandbox struct {
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
}

// SandboxSpec holds the desired state of a sandbox.
type SandboxSpec struct {
	LogLevel    string
	Environment map[string]string
	Template    *SandboxTemplate
	Providers   []string
	// ResourceRequirements are the portable GPU, CPU, and memory requirements
	// for the sandbox workload. Nil means no resource requirements specified.
	ResourceRequirements *ResourceRequirements
	// Policy is the security policy for the sandbox. Nil means no policy specified.
	Policy  *SandboxPolicy
	Command []string
	TTY     bool
}

// ResourceRequirements holds portable compute resource requirements for a
// sandbox workload, mirroring the proto ResourceRequirements message.
type ResourceRequirements struct {
	// GPU requirements for the sandbox. Presence indicates a GPU request.
	GPU *GPUResourceRequirements
	// CPU requirements for the sandbox workload.
	CPU *CPUResourceRequirements
	// Memory requirements for the sandbox workload.
	Memory *MemoryResourceRequirements
}

// GPUResourceRequirements holds GPU resource requirements for a sandbox.
type GPUResourceRequirements struct {
	// Count is the number of GPUs requested. Nil means the driver's default
	// GPU assignment count semantics apply.
	Count *uint32
}

// CPUResourceRequirements holds CPU resource requirements for a sandbox.
type CPUResourceRequirements struct {
	// Limit is the CPU limit for the sandbox workload, using a
	// Kubernetes-style CPU quantity string such as "500m", "1", or "2.5".
	Limit string
	// Request is the CPU request for the sandbox workload, independent of its
	// limit. An empty value omits the request.
	Request string
}

// MemoryResourceRequirements holds memory resource requirements for a sandbox.
type MemoryResourceRequirements struct {
	// Limit is the memory limit for the sandbox workload, using a
	// Kubernetes-style memory quantity string such as "512Mi", "4Gi", or "8G".
	Limit string
	// Request is the memory request for the sandbox workload, independent of
	// its limit. An empty value omits the request.
	Request string
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
	Resources   *ResourceRequirements
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
	SandboxName          string
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
	// LastReportedAt is the RFC 3339 UTC time when the gateway accepted the
	// observation, not the request time. Retained evidence can be accepted after
	// a reset. NoObservedExchange has no report timestamp.
	LastReportedAt string
}

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
