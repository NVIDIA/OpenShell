// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build e2e

package e2e

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1"
)

func requireWorkspaceResponse(t *testing.T, workspace *v1.Workspace, name string) {
	t.Helper()
	require.NotNil(t, workspace)
	require.NotEmpty(t, workspace.ID)
	require.Equal(t, name, workspace.Name)
	require.False(t, workspace.CreatedAt.IsZero())
	require.NotZero(t, workspace.ResourceVersion)
}

func TestWorkspaceCRUD(t *testing.T) {
	client := requireClient(t)
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	name := uniqueName("ws-crud")
	ws, err := client.Workspaces().Create(ctx, name, nil)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		_, err := client.Workspaces().Delete(cleanupCtx, name)
		require.NoError(t, err)
	})
	require.Equal(t, name, ws.Name)
	require.Equal(t, v1.WorkspaceActive, ws.Phase)
	requireWorkspaceResponse(t, ws, name)

	fetched, err := client.Workspaces().Get(ctx, name)
	require.NoError(t, err)
	require.Equal(t, name, fetched.Name)
	require.Equal(t, v1.WorkspaceActive, fetched.Phase)
	requireWorkspaceResponse(t, fetched, name)
	require.Equal(t, ws.ID, fetched.ID)
}

func TestWorkspaceCreateWithLabels(t *testing.T) {
	client := requireClient(t)
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	name := uniqueName("ws-lbl")
	ws, err := client.Workspaces().Create(ctx, name, map[string]string{"env": "test", "team": "infra"})
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		_, err := client.Workspaces().Delete(cleanupCtx, name)
		require.NoError(t, err)
	})
	require.Equal(t, "test", ws.Labels["env"])
	require.Equal(t, "infra", ws.Labels["team"])
	requireWorkspaceResponse(t, ws, name)

	fetched, err := client.Workspaces().Get(ctx, name)
	require.NoError(t, err)
	require.Equal(t, "test", fetched.Labels["env"])
	require.Equal(t, "infra", fetched.Labels["team"])
	requireWorkspaceResponse(t, fetched, name)
	require.Equal(t, ws.ID, fetched.ID)
}

func TestWorkspaceListIncludesCreated(t *testing.T) {
	client := requireClient(t)
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	name := uniqueName("ws-list")
	_, err := client.Workspaces().Create(ctx, name, nil)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		_, err := client.Workspaces().Delete(cleanupCtx, name)
		require.NoError(t, err)
	})

	workspaces, err := client.Workspaces().ListAll(ctx)
	require.NoError(t, err)

	found := false
	hasDefault := false
	for _, ws := range workspaces {
		if ws.Name == name {
			found = true
		}
		if ws.Name == "default" {
			hasDefault = true
		}
	}
	require.True(t, found, "expected created workspace %q in list", name)
	require.True(t, hasDefault, "expected \"default\" workspace in list")
}

func TestWorkspaceDeleteNonexistentNotFound(t *testing.T) {
	client := requireClient(t)
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := client.Workspaces().Delete(ctx, uniqueName("no-such-ws"))
	require.True(t, v1.IsNotFound(err), "expected NotFound, got %v", err)
}

func TestWorkspaceGetNonexistentNotFound(t *testing.T) {
	client := requireClient(t)
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := client.Workspaces().Get(ctx, uniqueName("no-such-ws"))
	require.True(t, v1.IsNotFound(err), "expected NotFound, got %v", err)
}
