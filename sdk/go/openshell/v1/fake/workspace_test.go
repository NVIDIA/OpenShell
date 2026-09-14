// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package fake

import (
	"context"
	"testing"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWorkspaceDelete_RemovesMembers(t *testing.T) {
	fc := NewClient()
	ctx := context.Background()
	_, err := fc.Workspaces().Create(ctx, "team", nil)
	require.NoError(t, err)
	_, err = fc.Workspaces().AddMember(ctx, "team", "alice", types.WorkspaceRoleUser)
	require.NoError(t, err)
	require.NoError(t, fc.Workspaces().Delete(ctx, "team"))

	members, err := fc.Workspaces().ListMembers(ctx, "team")
	require.NoError(t, err)
	assert.Empty(t, members)
}

func TestFakeWorkspace_Create(t *testing.T) {
	fc := NewClient()
	ws, err := fc.Workspaces().Create(context.Background(), "test-ws", map[string]string{"team": "platform"})

	require.NoError(t, err)
	require.NotNil(t, ws)
	assert.Equal(t, "test-ws", ws.Name)
	assert.Equal(t, map[string]string{"team": "platform"}, ws.Labels)
	assert.Equal(t, types.WorkspaceActive, ws.Phase)
	assert.Equal(t, uint64(1), ws.ResourceVersion)
}

func TestFakeWorkspace_Create_EmptyName(t *testing.T) {
	fc := NewClient()
	_, err := fc.Workspaces().Create(context.Background(), "", nil)

	require.Error(t, err)
	assert.True(t, types.IsInvalidArgument(err))
}

func TestFakeWorkspace_Create_AlreadyExists(t *testing.T) {
	fc := NewClient()
	_, err := fc.Workspaces().Create(context.Background(), "dup-ws", nil)
	require.NoError(t, err)

	_, err = fc.Workspaces().Create(context.Background(), "dup-ws", nil)
	require.Error(t, err)
	assert.True(t, types.IsAlreadyExists(err))
}

func TestFakeWorkspace_Create_DeepCopy(t *testing.T) {
	fc := NewClient()
	labels := map[string]string{"env": "test"}
	ws, err := fc.Workspaces().Create(context.Background(), "ws", labels)
	require.NoError(t, err)

	labels["env"] = "mutated"
	assert.Equal(t, "test", ws.Labels["env"])

	got, err := fc.Workspaces().Get(context.Background(), "ws")
	require.NoError(t, err)
	assert.Equal(t, "test", got.Labels["env"])
}

func TestFakeWorkspace_Get(t *testing.T) {
	fc := NewClient()
	_, err := fc.Workspaces().Create(context.Background(), "my-ws", nil)
	require.NoError(t, err)

	ws, err := fc.Workspaces().Get(context.Background(), "my-ws")
	require.NoError(t, err)
	assert.Equal(t, "my-ws", ws.Name)
}

func TestFakeWorkspace_Get_EmptyName(t *testing.T) {
	fc := NewClient()
	_, err := fc.Workspaces().Get(context.Background(), "")

	require.Error(t, err)
	assert.True(t, types.IsInvalidArgument(err))
}

func TestFakeWorkspace_Get_NotFound(t *testing.T) {
	fc := NewClient()
	_, err := fc.Workspaces().Get(context.Background(), "missing")

	require.Error(t, err)
	assert.True(t, types.IsNotFound(err))
}

func TestFakeWorkspace_List(t *testing.T) {
	fc := NewClient()
	_, _ = fc.Workspaces().Create(context.Background(), "ws-1", nil)
	_, _ = fc.Workspaces().Create(context.Background(), "ws-2", nil)

	workspaces, err := fc.Workspaces().List(context.Background())
	require.NoError(t, err)
	assert.Len(t, workspaces, 2)
}

func TestFakeWorkspace_List_Empty(t *testing.T) {
	fc := NewClient()
	workspaces, err := fc.Workspaces().List(context.Background())
	require.NoError(t, err)
	assert.Empty(t, workspaces)
}

func TestFakeWorkspace_Delete(t *testing.T) {
	fc := NewClient()
	_, _ = fc.Workspaces().Create(context.Background(), "del-ws", nil)

	err := fc.Workspaces().Delete(context.Background(), "del-ws")
	require.NoError(t, err)

	_, err = fc.Workspaces().Get(context.Background(), "del-ws")
	assert.True(t, types.IsNotFound(err))
}

func TestFakeWorkspace_Delete_EmptyName(t *testing.T) {
	fc := NewClient()
	err := fc.Workspaces().Delete(context.Background(), "")

	require.Error(t, err)
	assert.True(t, types.IsInvalidArgument(err))
}

func TestFakeWorkspace_Delete_NotFound(t *testing.T) {
	fc := NewClient()
	err := fc.Workspaces().Delete(context.Background(), "missing")

	require.Error(t, err)
	assert.True(t, types.IsNotFound(err))
}

func TestFakeWorkspace_AddMember(t *testing.T) {
	fc := NewClient()
	m, err := fc.Workspaces().AddMember(context.Background(), "ws", "user@example.com", types.WorkspaceRoleAdmin)

	require.NoError(t, err)
	require.NotNil(t, m)
	assert.Equal(t, "user@example.com", m.PrincipalSubject)
	assert.Equal(t, types.WorkspaceRoleAdmin, m.Role)
}

func TestFakeWorkspace_AddMember_EmptyWorkspace(t *testing.T) {
	fc := NewClient()
	_, err := fc.Workspaces().AddMember(context.Background(), "", "user@example.com", types.WorkspaceRoleAdmin)

	require.Error(t, err)
	assert.True(t, types.IsInvalidArgument(err))
}

func TestFakeWorkspace_AddMember_EmptySubject(t *testing.T) {
	fc := NewClient()
	_, err := fc.Workspaces().AddMember(context.Background(), "ws", "", types.WorkspaceRoleAdmin)

	require.Error(t, err)
	assert.True(t, types.IsInvalidArgument(err))
}

func TestFakeWorkspace_AddMember_InvalidRole(t *testing.T) {
	fc := NewClient()
	_, err := fc.Workspaces().AddMember(context.Background(), "ws", "user@example.com", types.WorkspaceRole("invalid"))

	require.Error(t, err)
	assert.True(t, types.IsInvalidArgument(err))
}

func TestFakeWorkspace_AddMember_AlreadyExists(t *testing.T) {
	fc := NewClient()
	_, err := fc.Workspaces().AddMember(context.Background(), "ws", "user@example.com", types.WorkspaceRoleAdmin)
	require.NoError(t, err)

	_, err = fc.Workspaces().AddMember(context.Background(), "ws", "user@example.com", types.WorkspaceRoleUser)
	require.Error(t, err)
	assert.True(t, types.IsAlreadyExists(err))
}

func TestFakeWorkspace_RemoveMember(t *testing.T) {
	fc := NewClient()
	_, _ = fc.Workspaces().AddMember(context.Background(), "ws", "user@example.com", types.WorkspaceRoleAdmin)

	err := fc.Workspaces().RemoveMember(context.Background(), "ws", "user@example.com")
	require.NoError(t, err)

	members, err := fc.Workspaces().ListMembers(context.Background(), "ws")
	require.NoError(t, err)
	assert.Empty(t, members)
}

func TestFakeWorkspace_RemoveMember_EmptyWorkspace(t *testing.T) {
	fc := NewClient()
	err := fc.Workspaces().RemoveMember(context.Background(), "", "user@example.com")

	require.Error(t, err)
	assert.True(t, types.IsInvalidArgument(err))
}

func TestFakeWorkspace_RemoveMember_EmptySubject(t *testing.T) {
	fc := NewClient()
	err := fc.Workspaces().RemoveMember(context.Background(), "ws", "")

	require.Error(t, err)
	assert.True(t, types.IsInvalidArgument(err))
}

func TestFakeWorkspace_RemoveMember_NotFound(t *testing.T) {
	fc := NewClient()
	err := fc.Workspaces().RemoveMember(context.Background(), "ws", "missing@example.com")

	require.Error(t, err)
	assert.True(t, types.IsNotFound(err))
}

func TestFakeWorkspace_ListMembers(t *testing.T) {
	fc := NewClient()
	_, _ = fc.Workspaces().AddMember(context.Background(), "ws", "user1@example.com", types.WorkspaceRoleAdmin)
	_, _ = fc.Workspaces().AddMember(context.Background(), "ws", "user2@example.com", types.WorkspaceRoleUser)

	members, err := fc.Workspaces().ListMembers(context.Background(), "ws")
	require.NoError(t, err)
	assert.Len(t, members, 2)
}

func TestFakeWorkspace_ListMembers_EmptyWorkspace(t *testing.T) {
	fc := NewClient()
	_, err := fc.Workspaces().ListMembers(context.Background(), "")

	require.Error(t, err)
	assert.True(t, types.IsInvalidArgument(err))
}

func TestFakeWorkspace_ListMembers_Isolation(t *testing.T) {
	fc := NewClient()
	_, _ = fc.Workspaces().AddMember(context.Background(), "ws-a", "user@example.com", types.WorkspaceRoleAdmin)
	_, _ = fc.Workspaces().AddMember(context.Background(), "ws-b", "other@example.com", types.WorkspaceRoleUser)

	membersA, err := fc.Workspaces().ListMembers(context.Background(), "ws-a")
	require.NoError(t, err)
	assert.Len(t, membersA, 1)
	assert.Equal(t, "user@example.com", membersA[0].PrincipalSubject)

	membersB, err := fc.Workspaces().ListMembers(context.Background(), "ws-b")
	require.NoError(t, err)
	assert.Len(t, membersB, 1)
	assert.Equal(t, "other@example.com", membersB[0].PrincipalSubject)
}

func TestFakeWorkspace_Closed(t *testing.T) {
	fc := NewClient()
	_ = fc.Close()

	_, err := fc.Workspaces().Create(context.Background(), "ws", nil)
	assert.True(t, types.IsUnavailable(err))

	_, err = fc.Workspaces().Get(context.Background(), "ws")
	assert.True(t, types.IsUnavailable(err))

	_, err = fc.Workspaces().List(context.Background())
	assert.True(t, types.IsUnavailable(err))

	err = fc.Workspaces().Delete(context.Background(), "ws")
	assert.True(t, types.IsUnavailable(err))

	_, err = fc.Workspaces().AddMember(context.Background(), "ws", "user", types.WorkspaceRoleAdmin)
	assert.True(t, types.IsUnavailable(err))

	err = fc.Workspaces().RemoveMember(context.Background(), "ws", "user")
	assert.True(t, types.IsUnavailable(err))

	_, err = fc.Workspaces().ListMembers(context.Background(), "ws")
	assert.True(t, types.IsUnavailable(err))
}

func TestFakeWorkspace_AddWorkspace(t *testing.T) {
	fc := NewClient()
	fc.AddWorkspace(&types.Workspace{
		Name:  "preseeded",
		Phase: types.WorkspaceActive,
	})

	ws, err := fc.Workspaces().Get(context.Background(), "preseeded")
	require.NoError(t, err)
	assert.Equal(t, "preseeded", ws.Name)
}
