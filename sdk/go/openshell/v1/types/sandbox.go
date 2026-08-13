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
	GPUCount    *uint32
	// Policy is the security policy for the sandbox. Nil means no policy specified.
	Policy *SandboxPolicy
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
