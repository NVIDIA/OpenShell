// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package types

import "time"

// Sandbox represents a sandbox instance.
type Sandbox struct {
	ID                string
	Name              string
	CreatedAt         time.Time
	Labels            map[string]string
	Annotations       map[string]string
	ResourceVersion   uint64
	Workspace         string
	DeletionTimestamp *time.Time
	Spec              SandboxSpec
	Status            SandboxStatus
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
}

// MemoryResourceRequirements holds memory resource requirements for a sandbox.
type MemoryResourceRequirements struct {
	// Limit is the memory limit for the sandbox workload, using a
	// Kubernetes-style memory quantity string such as "512Mi", "4Gi", or "8G".
	Limit string
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
}

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
