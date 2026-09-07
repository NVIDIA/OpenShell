// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package converter

import (
	"testing"
	"time"

	v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
	dm "github.com/NVIDIA/OpenShell/sdk/go/proto/datamodelv1"
	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWorkspaceFromProto(t *testing.T) {
	proto := &dm.Workspace{
		Metadata: &dm.ObjectMeta{
			Id:                  "ws-1",
			Name:                "my-workspace",
			CreatedAtMs:         1700000000000,
			Labels:              map[string]string{"team": "platform"},
			Annotations:         map[string]string{"managed-by": "sdk"},
			ResourceVersion:     3,
			Workspace:           "",
			DeletionTimestampMs: 1700000060000,
		},
		Status: &dm.WorkspaceStatus{
			Phase: dm.WorkspacePhase_WORKSPACE_PHASE_ACTIVE,
		},
	}

	ws := WorkspaceFromProto(proto)

	require.NotNil(t, ws)
	assert.Equal(t, "ws-1", ws.ID)
	assert.Equal(t, "my-workspace", ws.Name)
	assert.Equal(t, time.UnixMilli(1700000000000).UTC(), ws.CreatedAt)
	assert.Equal(t, map[string]string{"team": "platform"}, ws.Labels)
	assert.Equal(t, map[string]string{"managed-by": "sdk"}, ws.Annotations)
	assert.Equal(t, uint64(3), ws.ResourceVersion)
	assert.Equal(t, "", ws.Workspace)
	require.NotNil(t, ws.DeletionTimestamp)
	assert.Equal(t, time.UnixMilli(1700000060000).UTC(), *ws.DeletionTimestamp)
	assert.Equal(t, v1.WorkspaceActive, ws.Phase)
}

func TestWorkspaceFromProto_DeepCopy(t *testing.T) {
	labels := map[string]string{"env": "test"}
	proto := &dm.Workspace{
		Metadata: &dm.ObjectMeta{
			Name:   "ws-copy",
			Labels: labels,
		},
		Status: &dm.WorkspaceStatus{
			Phase: dm.WorkspacePhase_WORKSPACE_PHASE_ACTIVE,
		},
	}

	ws := WorkspaceFromProto(proto)
	labels["env"] = "mutated"

	assert.Equal(t, "test", ws.Labels["env"])
}

func TestWorkspaceFromProto_NilMetadata(t *testing.T) {
	proto := &dm.Workspace{
		Status: &dm.WorkspaceStatus{
			Phase: dm.WorkspacePhase_WORKSPACE_PHASE_TERMINATING,
		},
	}

	ws := WorkspaceFromProto(proto)

	require.NotNil(t, ws)
	assert.Empty(t, ws.ID)
	assert.Equal(t, v1.WorkspaceTerminating, ws.Phase)
}

func TestWorkspaceFromProto_NilStatus(t *testing.T) {
	proto := &dm.Workspace{
		Metadata: &dm.ObjectMeta{Name: "ws-nostatus"},
	}

	ws := WorkspaceFromProto(proto)

	require.NotNil(t, ws)
	assert.Equal(t, v1.WorkspaceUnknown, ws.Phase)
}

func TestWorkspaceFromProto_Nil(t *testing.T) {
	ws := WorkspaceFromProto(nil)
	assert.Nil(t, ws)
}

func TestWorkspacePhaseFromProto(t *testing.T) {
	tests := []struct {
		proto    dm.WorkspacePhase
		expected v1.WorkspacePhase
	}{
		{dm.WorkspacePhase_WORKSPACE_PHASE_ACTIVE, v1.WorkspaceActive},
		{dm.WorkspacePhase_WORKSPACE_PHASE_TERMINATING, v1.WorkspaceTerminating},
		{dm.WorkspacePhase_WORKSPACE_PHASE_UNSPECIFIED, v1.WorkspaceUnknown},
		{dm.WorkspacePhase(99), v1.WorkspaceUnknown},
	}

	for _, tt := range tests {
		assert.Equal(t, tt.expected, WorkspacePhaseFromProto(tt.proto))
	}
}

func TestWorkspaceMemberFromProto(t *testing.T) {
	proto := &pb.WorkspaceMember{
		Metadata: &dm.ObjectMeta{
			Id:              "mem-1",
			Name:            "member-auto-name",
			CreatedAtMs:     1700000000000,
			Annotations:     map[string]string{"source": "cli"},
			ResourceVersion: 2,
		},
		PrincipalSubject: "user@example.com",
		Role:             pb.WorkspaceRole_WORKSPACE_ROLE_ADMIN,
	}

	m := WorkspaceMemberFromProto(proto)

	require.NotNil(t, m)
	assert.Equal(t, "mem-1", m.ID)
	assert.Equal(t, "member-auto-name", m.Name)
	assert.Equal(t, time.UnixMilli(1700000000000).UTC(), m.CreatedAt)
	assert.Equal(t, map[string]string{"source": "cli"}, m.Annotations)
	assert.Equal(t, uint64(2), m.ResourceVersion)
	assert.Equal(t, "user@example.com", m.PrincipalSubject)
	assert.Equal(t, v1.WorkspaceRoleAdmin, m.Role)
}

func TestWorkspaceMemberFromProto_DeepCopy(t *testing.T) {
	annotations := map[string]string{"key": "original"}
	proto := &pb.WorkspaceMember{
		Metadata: &dm.ObjectMeta{
			Annotations: annotations,
		},
		PrincipalSubject: "user@test.com",
		Role:             pb.WorkspaceRole_WORKSPACE_ROLE_USER,
	}

	m := WorkspaceMemberFromProto(proto)
	annotations["key"] = "mutated"

	assert.Equal(t, "original", m.Annotations["key"])
}

func TestWorkspaceMemberFromProto_NilMetadata(t *testing.T) {
	proto := &pb.WorkspaceMember{
		PrincipalSubject: "user@test.com",
		Role:             pb.WorkspaceRole_WORKSPACE_ROLE_USER,
	}

	m := WorkspaceMemberFromProto(proto)

	require.NotNil(t, m)
	assert.Empty(t, m.ID)
	assert.Equal(t, "user@test.com", m.PrincipalSubject)
	assert.Equal(t, v1.WorkspaceRoleUser, m.Role)
}

func TestWorkspaceMemberFromProto_Nil(t *testing.T) {
	m := WorkspaceMemberFromProto(nil)
	assert.Nil(t, m)
}

func TestWorkspaceRoleFromProto(t *testing.T) {
	tests := []struct {
		proto    pb.WorkspaceRole
		expected v1.WorkspaceRole
	}{
		{pb.WorkspaceRole_WORKSPACE_ROLE_ADMIN, v1.WorkspaceRoleAdmin},
		{pb.WorkspaceRole_WORKSPACE_ROLE_USER, v1.WorkspaceRoleUser},
		{pb.WorkspaceRole_WORKSPACE_ROLE_UNSPECIFIED, v1.WorkspaceRoleUnknown},
		{pb.WorkspaceRole(99), v1.WorkspaceRoleUnknown},
	}

	for _, tt := range tests {
		assert.Equal(t, tt.expected, WorkspaceRoleFromProto(tt.proto))
	}
}

func TestWorkspaceRoleToProto(t *testing.T) {
	tests := []struct {
		sdk      v1.WorkspaceRole
		expected pb.WorkspaceRole
	}{
		{v1.WorkspaceRoleAdmin, pb.WorkspaceRole_WORKSPACE_ROLE_ADMIN},
		{v1.WorkspaceRoleUser, pb.WorkspaceRole_WORKSPACE_ROLE_USER},
		{v1.WorkspaceRole("invalid"), pb.WorkspaceRole_WORKSPACE_ROLE_UNSPECIFIED},
	}

	for _, tt := range tests {
		assert.Equal(t, tt.expected, WorkspaceRoleToProto(tt.sdk))
	}
}

func TestWorkspaceRoleRoundTrip(t *testing.T) {
	roles := []v1.WorkspaceRole{v1.WorkspaceRoleAdmin, v1.WorkspaceRoleUser}
	for _, role := range roles {
		assert.Equal(t, role, WorkspaceRoleFromProto(WorkspaceRoleToProto(role)))
	}
}
