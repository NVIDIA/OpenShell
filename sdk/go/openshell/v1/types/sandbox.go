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
	// GPU requests GPU resources using the active driver's default GPU assignment
	// when GPUCount is nil. GPUCount implies GPU for backward compatibility.
	GPU      bool
	GPUCount *uint32
	// Policy is the security policy for the sandbox. Nil means no policy specified.
	Policy  *SandboxPolicy
	Command []string
	TTY     bool
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
