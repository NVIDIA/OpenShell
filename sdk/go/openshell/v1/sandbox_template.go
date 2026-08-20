// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
)

// SandboxWorkloadTemplate is a reusable workspace-scoped sandbox template resource.
type SandboxWorkloadTemplate = types.SandboxWorkloadTemplate

// SandboxWorkloadTemplateSpec holds reusable sandbox template settings.
type SandboxWorkloadTemplateSpec = types.SandboxWorkloadTemplateSpec

// SandboxWorkloadConfig defines the portable workload for a reusable template.
type SandboxWorkloadConfig = types.SandboxWorkloadConfig

// SandboxResources defines portable sandbox resource requirements.
type SandboxResources = types.SandboxResources

// SandboxGPURequirements defines template GPU requirements.
type SandboxGPURequirements = types.SandboxGPURequirements

// SandboxServiceLevel describes desired operational characteristics.
type SandboxServiceLevel = types.SandboxServiceLevel

// SandboxStartup describes desired startup characteristics.
type SandboxStartup = types.SandboxStartup

// SandboxWorkloadTemplateProvenance identifies the reusable template revision used to create a sandbox.
type SandboxWorkloadTemplateProvenance = types.SandboxWorkloadTemplateProvenance

// SandboxTemplateInterface defines CRUD operations on reusable sandbox templates.
//
// The resource type is named SandboxWorkloadTemplate in the v1 Go SDK so it does
// not collide with the legacy inline SandboxTemplate field on SandboxSpec.
type SandboxTemplateInterface interface {
	Create(ctx context.Context, workspace string, template *SandboxWorkloadTemplate) (*SandboxWorkloadTemplate, error)
	Get(ctx context.Context, workspace, name string) (*SandboxWorkloadTemplate, error)
	List(ctx context.Context, workspace string, opts ...ListOptions) ([]*SandboxWorkloadTemplate, error)
	Delete(ctx context.Context, workspace, name string) (bool, error)
}
