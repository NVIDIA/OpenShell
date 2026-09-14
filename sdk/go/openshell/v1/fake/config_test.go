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

// --- T020: fakeConfigClient stub tests ---

func TestFakeConfig_GetSandbox_ReturnsUnimplemented(t *testing.T) {
	c := newFakeConfigClient(func() bool { return false })
	_, err := c.GetSandbox(context.Background(), "default", "sandbox-1")
	require.Error(t, err)
	assert.True(t, types.IsUnimplemented(err))
}

func TestFakeConfig_GetGateway_ReturnsUnimplemented(t *testing.T) {
	c := newFakeConfigClient(func() bool { return false })
	_, err := c.GetGateway(context.Background())
	require.Error(t, err)
	assert.True(t, types.IsUnimplemented(err))
}

func TestFakeConfig_Update_ReturnsUnimplemented(t *testing.T) {
	c := newFakeConfigClient(func() bool { return false })
	_, err := c.Update(context.Background(), "default", &types.ConfigUpdate{
		Name:       "sandbox-1",
		SettingKey: "key",
	})
	require.Error(t, err)
	assert.True(t, types.IsUnimplemented(err))
}

func TestFakeConfig_GetSandbox_ClosedReturnsUnavailable(t *testing.T) {
	c := newFakeConfigClient(func() bool { return true })
	_, err := c.GetSandbox(context.Background(), "default", "sandbox-1")
	require.Error(t, err)
	assert.True(t, types.IsUnavailable(err))
}

func TestFakeConfig_GetGateway_ClosedReturnsUnavailable(t *testing.T) {
	c := newFakeConfigClient(func() bool { return true })
	_, err := c.GetGateway(context.Background())
	require.Error(t, err)
	assert.True(t, types.IsUnavailable(err))
}

func TestFakeConfig_Update_ClosedReturnsUnavailable(t *testing.T) {
	c := newFakeConfigClient(func() bool { return true })
	_, err := c.Update(context.Background(), "default", &types.ConfigUpdate{
		Name:       "sandbox-1",
		SettingKey: "key",
	})
	require.Error(t, err)
	assert.True(t, types.IsUnavailable(err))
}

// --- T033: MergeOperations acceptance test ---

func TestFakeConfig_Update_MergeOperationsAccepted(t *testing.T) {
	c := newFakeConfigClient(func() bool { return false })
	_, err := c.Update(context.Background(), "default", &types.ConfigUpdate{
		Name:            "sandbox-1",
		MergeOperations: []types.PolicyMergeOperation{{RemoveRule: &types.RemoveNetworkRule{RuleName: "test"}}},
	})
	require.Error(t, err)
	// Should return Unimplemented (not InvalidArgument) — MergeOperations are now accepted
	assert.True(t, types.IsUnimplemented(err))
	assert.False(t, types.IsInvalidArgument(err))
}
