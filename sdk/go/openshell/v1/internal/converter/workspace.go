// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package converter

import (
	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
	dm "github.com/NVIDIA/OpenShell/sdk/go/proto/datamodelv1"
	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
)

// WorkspaceFromProto converts a proto Workspace to an SDK Workspace.
func WorkspaceFromProto(w *dm.Workspace) *types.Workspace {
	if w == nil {
		return nil
	}

	result := &types.Workspace{}

	if m := w.GetMetadata(); m != nil {
		result.ID = m.GetId()
		result.Name = m.GetName()
		result.CreatedAt = TimeFromMillis(m.GetCreatedAtMs())
		result.Labels = CopyStringMap(m.GetLabels())
		result.Annotations = CopyStringMap(m.GetAnnotations())
		result.ResourceVersion = m.GetResourceVersion()
		result.Workspace = m.GetWorkspace()
		result.DeletionTimestamp = TimeFromMillisPtr(m.GetDeletionTimestampMs())
	}

	if status := w.GetStatus(); status != nil {
		result.Phase = WorkspacePhaseFromProto(status.GetPhase())
	} else {
		result.Phase = types.WorkspaceUnknown
	}

	return result
}

// WorkspacePhaseFromProto converts a proto WorkspacePhase to an SDK WorkspacePhase.
func WorkspacePhaseFromProto(phase dm.WorkspacePhase) types.WorkspacePhase {
	switch phase {
	case dm.WorkspacePhase_WORKSPACE_PHASE_ACTIVE:
		return types.WorkspaceActive
	case dm.WorkspacePhase_WORKSPACE_PHASE_TERMINATING:
		return types.WorkspaceTerminating
	default:
		return types.WorkspaceUnknown
	}
}

// WorkspaceMemberFromProto converts a proto WorkspaceMember to an SDK WorkspaceMember.
func WorkspaceMemberFromProto(m *pb.WorkspaceMember) *types.WorkspaceMember {
	if m == nil {
		return nil
	}

	result := &types.WorkspaceMember{
		PrincipalSubject: m.GetPrincipalSubject(),
		Role:             WorkspaceRoleFromProto(m.GetRole()),
	}

	if meta := m.GetMetadata(); meta != nil {
		result.ID = meta.GetId()
		result.Name = meta.GetName()
		result.CreatedAt = TimeFromMillis(meta.GetCreatedAtMs())
		result.Labels = CopyStringMap(meta.GetLabels())
		result.Annotations = CopyStringMap(meta.GetAnnotations())
		result.ResourceVersion = meta.GetResourceVersion()
	}

	return result
}

// WorkspaceRoleFromProto converts a proto WorkspaceRole to an SDK WorkspaceRole.
func WorkspaceRoleFromProto(role pb.WorkspaceRole) types.WorkspaceRole {
	switch role {
	case pb.WorkspaceRole_WORKSPACE_ROLE_ADMIN:
		return types.WorkspaceRoleAdmin
	case pb.WorkspaceRole_WORKSPACE_ROLE_USER:
		return types.WorkspaceRoleUser
	default:
		return types.WorkspaceRoleUnknown
	}
}

// WorkspaceRoleToProto converts an SDK WorkspaceRole to a proto WorkspaceRole.
func WorkspaceRoleToProto(role types.WorkspaceRole) pb.WorkspaceRole {
	switch role {
	case types.WorkspaceRoleAdmin:
		return pb.WorkspaceRole_WORKSPACE_ROLE_ADMIN
	case types.WorkspaceRoleUser:
		return pb.WorkspaceRole_WORKSPACE_ROLE_USER
	default:
		return pb.WorkspaceRole_WORKSPACE_ROLE_UNSPECIFIED
	}
}
