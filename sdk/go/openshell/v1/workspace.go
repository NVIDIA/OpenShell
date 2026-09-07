// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
)

// Workspace represents a logical grouping of resources.
type Workspace = types.Workspace

// WorkspaceMember represents a user's membership in a workspace.
type WorkspaceMember = types.WorkspaceMember

// WorkspacePhase describes the lifecycle state of a workspace.
type WorkspacePhase = types.WorkspacePhase

// WorkspaceRole describes a member's role within a workspace.
type WorkspaceRole = types.WorkspaceRole

// WorkspacePhase constants.
const (
	WorkspaceActive      = types.WorkspaceActive
	WorkspaceTerminating = types.WorkspaceTerminating
	WorkspaceUnknown     = types.WorkspaceUnknown
)

// WorkspaceRole constants.
const (
	WorkspaceRoleAdmin   = types.WorkspaceRoleAdmin
	WorkspaceRoleUser    = types.WorkspaceRoleUser
	WorkspaceRoleUnknown = types.WorkspaceRoleUnknown
)

// WorkspaceInterface defines workspace and member management operations.
type WorkspaceInterface interface {
	Create(ctx context.Context, name string, labels map[string]string) (*Workspace, error)
	Get(ctx context.Context, name string) (*Workspace, error)
	List(ctx context.Context, opts ...ListOptions) ([]*Workspace, error)
	Delete(ctx context.Context, name string) error
	AddMember(ctx context.Context, workspace, principalSubject string, role WorkspaceRole) (*WorkspaceMember, error)
	RemoveMember(ctx context.Context, workspace, principalSubject string) error
	ListMembers(ctx context.Context, workspace string, opts ...ListOptions) ([]*WorkspaceMember, error)
}
