// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package types

import "time"

// WorkspacePhase describes the lifecycle state of a workspace.
type WorkspacePhase string

// WorkspacePhase constants.
const (
	WorkspaceActive      WorkspacePhase = "Active"
	WorkspaceTerminating WorkspacePhase = "Terminating"
	WorkspaceUnknown     WorkspacePhase = "Unknown"
)

// WorkspaceRole describes a member's role within a workspace.
type WorkspaceRole string

// WorkspaceRole constants.
const (
	WorkspaceRoleAdmin   WorkspaceRole = "Admin"
	WorkspaceRoleUser    WorkspaceRole = "User"
	WorkspaceRoleUnknown WorkspaceRole = "Unknown"
)

// Workspace represents a logical grouping of resources.
type Workspace struct {
	ID                string
	Name              string
	CreatedAt         time.Time
	Labels            map[string]string
	Annotations       map[string]string
	ResourceVersion   uint64
	Workspace         string
	DeletionTimestamp *time.Time
	Phase             WorkspacePhase
}

// WorkspaceMember represents a user's membership in a workspace.
type WorkspaceMember struct {
	ID               string
	Name             string
	CreatedAt        time.Time
	Labels           map[string]string
	Annotations      map[string]string
	ResourceVersion  uint64
	PrincipalSubject string
	Role             WorkspaceRole
}
