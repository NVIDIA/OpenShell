// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package fake

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
)

// --- T031: fakePolicyClient stub tests ---

func TestFakePolicy_GetDraft_ReturnsUnimplemented(t *testing.T) {
	c := newFakePolicyClient(func() bool { return false })
	_, err := c.GetDraft(context.Background(), "default", "sb-1")
	require.Error(t, err)
	assert.True(t, types.IsUnimplemented(err))
}

func TestFakePolicy_ApproveDraftChunk_ReturnsUnimplemented(t *testing.T) {
	c := newFakePolicyClient(func() bool { return false })
	_, err := c.ApproveDraftChunk(context.Background(), "default", "sb-1", "chunk-1")
	require.Error(t, err)
	assert.True(t, types.IsUnimplemented(err))
}

func TestFakePolicy_RejectDraftChunk_ReturnsUnimplemented(t *testing.T) {
	c := newFakePolicyClient(func() bool { return false })
	err := c.RejectDraftChunk(context.Background(), "default", "sb-1", "chunk-1", "bad rule")
	require.Error(t, err)
	assert.True(t, types.IsUnimplemented(err))
}

func TestFakePolicy_ApproveAllDraftChunks_ReturnsUnimplemented(t *testing.T) {
	c := newFakePolicyClient(func() bool { return false })
	_, err := c.ApproveAllDraftChunks(context.Background(), "default", "sb-1")
	require.Error(t, err)
	assert.True(t, types.IsUnimplemented(err))
}

func TestFakePolicy_ClearDraftChunks_ReturnsUnimplemented(t *testing.T) {
	c := newFakePolicyClient(func() bool { return false })
	_, err := c.ClearDraftChunks(context.Background(), "default", "sb-1")
	require.Error(t, err)
	assert.True(t, types.IsUnimplemented(err))
}

func TestFakePolicy_GetDraftHistory_ReturnsUnimplemented(t *testing.T) {
	c := newFakePolicyClient(func() bool { return false })
	_, err := c.GetDraftHistory(context.Background(), "default", "sb-1")
	require.Error(t, err)
	assert.True(t, types.IsUnimplemented(err))
}

func TestFakePolicy_GetStatus_EmptyReturnsNotFound(t *testing.T) {
	c := newFakePolicyClient(func() bool { return false })
	_, err := c.GetStatus(context.Background(), "default", "sb-1")
	require.Error(t, err)
	assert.True(t, types.IsNotFound(err))
}

func TestFakePolicy_List_EmptyReturnsNil(t *testing.T) {
	c := newFakePolicyClient(func() bool { return false })
	revisions, err := c.List(context.Background(), "default")
	require.NoError(t, err)
	assert.Nil(t, revisions)
}

func TestFakePolicy_EditDraftChunk_ReturnsUnimplemented(t *testing.T) {
	c := newFakePolicyClient(func() bool { return false })
	err := c.EditDraftChunk(context.Background(), "default", "sb-1", "chunk-1", &types.NetworkPolicyRule{Name: "test"})
	require.Error(t, err)
	assert.True(t, types.IsUnimplemented(err))
}

func TestFakePolicy_UndoDraftChunk_ReturnsUnimplemented(t *testing.T) {
	c := newFakePolicyClient(func() bool { return false })
	_, err := c.UndoDraftChunk(context.Background(), "default", "sb-1", "chunk-1")
	require.Error(t, err)
	assert.True(t, types.IsUnimplemented(err))
}

// --- T007: Global policy List and GetStatus tests ---

func TestFakePolicy_List_Global(t *testing.T) {
	c := newFakePolicyClient(func() bool { return false })

	// Seed global and sandbox-scoped revisions.
	c.AddGlobalRevision(types.SandboxPolicyRevision{Version: 1, PolicyHash: "sha256:global-v1", Status: types.PolicyLoadStatusLoaded})
	c.AddGlobalRevision(types.SandboxPolicyRevision{Version: 2, PolicyHash: "sha256:global-v2", Status: types.PolicyLoadStatusPending})
	c.AddRevision("default", "sb-1", types.SandboxPolicyRevision{Version: 1, PolicyHash: "sha256:sb-v1", Status: types.PolicyLoadStatusLoaded})

	// List global revisions.
	revisions, err := c.List(context.Background(), "", types.WithListGlobal(true))
	require.NoError(t, err)
	require.Len(t, revisions, 2)
	assert.Equal(t, uint32(1), revisions[0].Version)
	assert.Equal(t, "sha256:global-v1", revisions[0].PolicyHash)
	assert.Equal(t, uint32(2), revisions[1].Version)
}

func TestFakePolicy_List_Sandbox(t *testing.T) {
	c := newFakePolicyClient(func() bool { return false })

	// Seed global and sandbox-scoped revisions.
	c.AddGlobalRevision(types.SandboxPolicyRevision{Version: 1, PolicyHash: "sha256:global-v1"})
	c.AddRevision("default", "sb-1", types.SandboxPolicyRevision{Version: 1, PolicyHash: "sha256:sb-v1", Status: types.PolicyLoadStatusLoaded})
	c.AddRevision("default", "sb-1", types.SandboxPolicyRevision{Version: 2, PolicyHash: "sha256:sb-v2", Status: types.PolicyLoadStatusPending})

	// List sandbox-scoped revisions (no global flag).
	revisions, err := c.List(context.Background(), "default")
	require.NoError(t, err)
	require.Len(t, revisions, 2)
	assert.Equal(t, "sha256:sb-v1", revisions[0].PolicyHash)
	assert.Equal(t, "sha256:sb-v2", revisions[1].PolicyHash)
}

func TestFakePolicy_List_NoIsolationCrossContamination(t *testing.T) {
	c := newFakePolicyClient(func() bool { return false })

	// Only seed sandbox-scoped revisions.
	c.AddRevision("default", "sb-1", types.SandboxPolicyRevision{Version: 1, PolicyHash: "sha256:sb-v1"})

	// Global list returns empty (no global revisions seeded).
	revisions, err := c.List(context.Background(), "", types.WithListGlobal(true))
	require.NoError(t, err)
	assert.Nil(t, revisions)
}

func TestFakePolicy_List_GlobalWithPagination(t *testing.T) {
	c := newFakePolicyClient(func() bool { return false })

	c.AddGlobalRevision(types.SandboxPolicyRevision{Version: 1})
	c.AddGlobalRevision(types.SandboxPolicyRevision{Version: 2})
	c.AddGlobalRevision(types.SandboxPolicyRevision{Version: 3})

	// Limit to 2.
	revisions, err := c.List(context.Background(), "", types.WithListGlobal(true), types.WithLimit(2))
	require.NoError(t, err)
	require.Len(t, revisions, 2)
	assert.Equal(t, uint32(1), revisions[0].Version)
	assert.Equal(t, uint32(2), revisions[1].Version)

	// Offset by 1, limit 2.
	revisions, err = c.List(context.Background(), "", types.WithListGlobal(true), types.WithLimit(2), types.WithOffset(1))
	require.NoError(t, err)
	require.Len(t, revisions, 2)
	assert.Equal(t, uint32(2), revisions[0].Version)
	assert.Equal(t, uint32(3), revisions[1].Version)
}

func TestFakePolicy_GetStatus_Sandbox(t *testing.T) {
	c := newFakePolicyClient(func() bool { return false })

	c.AddRevision("default", "sb-1", types.SandboxPolicyRevision{Version: 1, PolicyHash: "sha256:sb-v1", Status: types.PolicyLoadStatusLoaded})
	c.AddRevision("default", "sb-1", types.SandboxPolicyRevision{Version: 2, PolicyHash: "sha256:sb-v2", Status: types.PolicyLoadStatusPending})

	result, err := c.GetStatus(context.Background(), "default", "sb-1")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, uint32(2), result.Revision.Version)
	assert.Equal(t, "sha256:sb-v2", result.Revision.PolicyHash)
	assert.Equal(t, uint32(1), result.ActiveVersion)
}

func TestFakePolicy_GetStatus_Global(t *testing.T) {
	c := newFakePolicyClient(func() bool { return false })

	c.AddGlobalRevision(types.SandboxPolicyRevision{Version: 1, PolicyHash: "sha256:global-v1", Status: types.PolicyLoadStatusSuperseded})
	c.AddGlobalRevision(types.SandboxPolicyRevision{Version: 2, PolicyHash: "sha256:global-v2", Status: types.PolicyLoadStatusLoaded})

	// Get global status (latest).
	result, err := c.GetStatus(context.Background(), "", "", types.WithStatusGlobal(true))
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, uint32(2), result.Revision.Version)
	assert.Equal(t, "sha256:global-v2", result.Revision.PolicyHash)
	assert.Equal(t, uint32(2), result.ActiveVersion)
}

func TestFakePolicy_GetStatus_GlobalWithVersion(t *testing.T) {
	c := newFakePolicyClient(func() bool { return false })

	c.AddGlobalRevision(types.SandboxPolicyRevision{Version: 1, PolicyHash: "sha256:global-v1", Status: types.PolicyLoadStatusSuperseded})
	c.AddGlobalRevision(types.SandboxPolicyRevision{Version: 2, PolicyHash: "sha256:global-v2", Status: types.PolicyLoadStatusLoaded})

	// Get specific global version.
	result, err := c.GetStatus(context.Background(), "", "", types.WithStatusGlobal(true), types.WithVersion(1))
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, uint32(1), result.Revision.Version)
	assert.Equal(t, types.PolicyLoadStatusSuperseded, result.Revision.Status)
	assert.Equal(t, uint32(2), result.ActiveVersion)
}

func TestFakePolicy_GetStatus_GlobalNotFound(t *testing.T) {
	c := newFakePolicyClient(func() bool { return false })

	// No global revisions seeded.
	_, err := c.GetStatus(context.Background(), "", "", types.WithStatusGlobal(true))
	require.Error(t, err)
	assert.True(t, types.IsNotFound(err))
}

func TestFakePolicy_DeepCopyWithPolicy(t *testing.T) {
	fc := NewClient()
	defer fc.Close() //nolint:errcheck

	fc.AddGlobalRevision(types.SandboxPolicyRevision{
		Version:    1,
		PolicyHash: "sha256:with-policy",
		Status:     types.PolicyLoadStatusLoaded,
		Policy: &types.SandboxPolicy{
			NetworkPolicies: map[string]types.NetworkPolicyRule{
				"rule-1": {Name: "rule-1"},
			},
		},
	})

	fc.AddRevision("default", "sb-1", types.SandboxPolicyRevision{
		Version:    1,
		PolicyHash: "sha256:sb-policy",
		Status:     types.PolicyLoadStatusLoaded,
		Policy: &types.SandboxPolicy{
			NetworkPolicies: map[string]types.NetworkPolicyRule{
				"rule-2": {Name: "rule-2"},
			},
		},
	})

	ctx := context.Background()

	// Get global revision and mutate it.
	revisions, err := fc.Policy().List(ctx, "", types.WithListGlobal(true))
	require.NoError(t, err)
	require.Len(t, revisions, 1)
	require.NotNil(t, revisions[0].Policy)
	revisions[0].Policy.NetworkPolicies["rule-1"] = types.NetworkPolicyRule{Name: "mutated"}

	// Verify internal state is not corrupted.
	revisions2, err := fc.Policy().List(ctx, "", types.WithListGlobal(true))
	require.NoError(t, err)
	assert.Equal(t, "rule-1", revisions2[0].Policy.NetworkPolicies["rule-1"].Name)

	// Get sandbox revision via GetStatus and verify deep copy.
	status, err := fc.Policy().GetStatus(ctx, "default", "sb-1")
	require.NoError(t, err)
	require.NotNil(t, status.Revision.Policy)
	assert.Equal(t, "rule-2", status.Revision.Policy.NetworkPolicies["rule-2"].Name)
}

func TestFakePolicy_List_ClosedReturnsUnavailable(t *testing.T) {
	c := newFakePolicyClient(func() bool { return true })
	_, err := c.List(context.Background(), "", types.WithListGlobal(true))
	require.Error(t, err)
	assert.True(t, types.IsUnavailable(err))
}

func TestFakePolicy_GetStatus_ClosedReturnsUnavailable(t *testing.T) {
	c := newFakePolicyClient(func() bool { return true })
	_, err := c.GetStatus(context.Background(), "", "", types.WithStatusGlobal(true))
	require.Error(t, err)
	assert.True(t, types.IsUnavailable(err))
}

// --- Closed client tests ---

func TestFakePolicy_GetDraft_ClosedReturnsUnavailable(t *testing.T) {
	c := newFakePolicyClient(func() bool { return true })
	_, err := c.GetDraft(context.Background(), "default", "sb-1")
	require.Error(t, err)
	assert.True(t, types.IsUnavailable(err))
}

func TestFakePolicy_ApproveDraftChunk_ClosedReturnsUnavailable(t *testing.T) {
	c := newFakePolicyClient(func() bool { return true })
	_, err := c.ApproveDraftChunk(context.Background(), "default", "sb-1", "chunk-1")
	require.Error(t, err)
	assert.True(t, types.IsUnavailable(err))
}

func TestFakePolicy_RejectDraftChunk_ClosedReturnsUnavailable(t *testing.T) {
	c := newFakePolicyClient(func() bool { return true })
	err := c.RejectDraftChunk(context.Background(), "default", "sb-1", "chunk-1", "reason")
	require.Error(t, err)
	assert.True(t, types.IsUnavailable(err))
}
