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
	_, err := c.GetDraft(context.Background(), "sb-1")
	require.Error(t, err)
	assert.True(t, types.IsUnimplemented(err))
}

func TestFakePolicy_ApproveDraftChunk_ReturnsUnimplemented(t *testing.T) {
	c := newFakePolicyClient(func() bool { return false })
	_, err := c.ApproveDraftChunk(context.Background(), "sb-1", "chunk-1")
	require.Error(t, err)
	assert.True(t, types.IsUnimplemented(err))
}

func TestFakePolicy_RejectDraftChunk_ReturnsUnimplemented(t *testing.T) {
	c := newFakePolicyClient(func() bool { return false })
	err := c.RejectDraftChunk(context.Background(), "sb-1", "chunk-1", "bad rule")
	require.Error(t, err)
	assert.True(t, types.IsUnimplemented(err))
}

func TestFakePolicy_ApproveAllDraftChunks_ReturnsUnimplemented(t *testing.T) {
	c := newFakePolicyClient(func() bool { return false })
	_, err := c.ApproveAllDraftChunks(context.Background(), "sb-1")
	require.Error(t, err)
	assert.True(t, types.IsUnimplemented(err))
}

func TestFakePolicy_ClearDraftChunks_ReturnsUnimplemented(t *testing.T) {
	c := newFakePolicyClient(func() bool { return false })
	_, err := c.ClearDraftChunks(context.Background(), "sb-1")
	require.Error(t, err)
	assert.True(t, types.IsUnimplemented(err))
}

func TestFakePolicy_GetDraftHistory_ReturnsUnimplemented(t *testing.T) {
	c := newFakePolicyClient(func() bool { return false })
	_, err := c.GetDraftHistory(context.Background(), "sb-1")
	require.Error(t, err)
	assert.True(t, types.IsUnimplemented(err))
}

func TestFakePolicy_GetStatus_ReturnsUnimplemented(t *testing.T) {
	c := newFakePolicyClient(func() bool { return false })
	_, err := c.GetStatus(context.Background(), "sb-1")
	require.Error(t, err)
	assert.True(t, types.IsUnimplemented(err))
}

func TestFakePolicy_List_ReturnsUnimplemented(t *testing.T) {
	c := newFakePolicyClient(func() bool { return false })
	_, err := c.List(context.Background(), "sb-1")
	require.Error(t, err)
	assert.True(t, types.IsUnimplemented(err))
}

func TestFakePolicy_EditDraftChunk_ReturnsUnimplemented(t *testing.T) {
	c := newFakePolicyClient(func() bool { return false })
	err := c.EditDraftChunk(context.Background(), "sb-1", "chunk-1", &types.NetworkPolicyRule{Name: "test"})
	require.Error(t, err)
	assert.True(t, types.IsUnimplemented(err))
}

func TestFakePolicy_UndoDraftChunk_ReturnsUnimplemented(t *testing.T) {
	c := newFakePolicyClient(func() bool { return false })
	_, err := c.UndoDraftChunk(context.Background(), "sb-1", "chunk-1")
	require.Error(t, err)
	assert.True(t, types.IsUnimplemented(err))
}

// --- Closed client tests ---

func TestFakePolicy_GetDraft_ClosedReturnsUnavailable(t *testing.T) {
	c := newFakePolicyClient(func() bool { return true })
	_, err := c.GetDraft(context.Background(), "sb-1")
	require.Error(t, err)
	assert.True(t, types.IsUnavailable(err))
}

func TestFakePolicy_ApproveDraftChunk_ClosedReturnsUnavailable(t *testing.T) {
	c := newFakePolicyClient(func() bool { return true })
	_, err := c.ApproveDraftChunk(context.Background(), "sb-1", "chunk-1")
	require.Error(t, err)
	assert.True(t, types.IsUnavailable(err))
}

func TestFakePolicy_RejectDraftChunk_ClosedReturnsUnavailable(t *testing.T) {
	c := newFakePolicyClient(func() bool { return true })
	err := c.RejectDraftChunk(context.Background(), "sb-1", "chunk-1", "reason")
	require.Error(t, err)
	assert.True(t, types.IsUnavailable(err))
}
