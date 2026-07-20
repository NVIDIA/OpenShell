// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package types

import "time"

// Sandbox represents a sandbox instance.
type Sandbox struct {
	ID                  string
	Name                string
	CreatedAt           time.Time
	Labels              map[string]string
	Annotations         map[string]string
	ResourceVersion     uint64
	Workspace           string
	DeletionTimestamp   *time.Time
	CreatedFromTemplate *SandboxTemplateProvenance
	Spec                SandboxSpec
	Status              SandboxStatus
}

// SandboxSpec holds the desired state of a sandbox.
type SandboxSpec struct {
	Workload     *SandboxWorkloadConfig
	DriverConfig map[string]any
	Providers    []string
	// Policy is the security policy for the sandbox. Nil means no policy specified.
	Policy *SandboxPolicy
}

// SandboxWorkloadConfig defines the portable workload for a sandbox.
type SandboxWorkloadConfig struct {
	Image       string
	Environment map[string]string
	Resources   *SandboxResources
}

// SandboxResources defines portable sandbox resource requirements.
type SandboxResources struct {
	CPU      string
	Memory   string
	GPUCount *uint32
}

// SandboxTemplate is a reusable workspace-scoped sandbox template resource.
type SandboxTemplate struct {
	ID                string
	Name              string
	CreatedAt         time.Time
	Labels            map[string]string
	Annotations       map[string]string
	ResourceVersion   uint64
	Workspace         string
	DeletionTimestamp *time.Time
	Spec              SandboxTemplateSpec
}

// SandboxTemplateSpec holds reusable sandbox template settings.
type SandboxTemplateSpec struct {
	Workload            *SandboxWorkloadConfig
	DriverConfig        map[string]any
	DesiredServiceLevel *SandboxServiceLevel
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

// SandboxTemplateProvenance identifies the template revision used to create a sandbox.
type SandboxTemplateProvenance struct {
	ID              string
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
