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

// --- T028: fakeRefreshClient stub tests ---

func TestFakeRefresh_GetStatus_ReturnsUnimplemented(t *testing.T) {
	c := newFakeRefreshClient(func() bool { return false })
	_, err := c.GetStatus(context.Background(), "default", "provider-1", "cred-1")
	require.Error(t, err)
	assert.True(t, types.IsUnimplemented(err))
}

func TestFakeRefresh_Configure_ReturnsUnimplemented(t *testing.T) {
	c := newFakeRefreshClient(func() bool { return false })
	_, err := c.Configure(context.Background(), "default", &types.RefreshConfig{
		Provider:      "provider-1",
		CredentialKey: "cred-1",
	})
	require.Error(t, err)
	assert.True(t, types.IsUnimplemented(err))
}

func TestFakeRefresh_Rotate_ReturnsUnimplemented(t *testing.T) {
	c := newFakeRefreshClient(func() bool { return false })
	_, err := c.Rotate(context.Background(), "default", "provider-1", "cred-1")
	require.Error(t, err)
	assert.True(t, types.IsUnimplemented(err))
}

func TestFakeRefresh_Delete_ReturnsUnimplemented(t *testing.T) {
	c := newFakeRefreshClient(func() bool { return false })
	_, err := c.Delete(context.Background(), "default", "provider-1", "cred-1")
	require.Error(t, err)
	assert.True(t, types.IsUnimplemented(err))
}

func TestFakeRefresh_GetStatus_ClosedReturnsUnavailable(t *testing.T) {
	c := newFakeRefreshClient(func() bool { return true })
	_, err := c.GetStatus(context.Background(), "default", "provider-1", "cred-1")
	require.Error(t, err)
	assert.True(t, types.IsUnavailable(err))
}

func TestFakeRefresh_Configure_ClosedReturnsUnavailable(t *testing.T) {
	c := newFakeRefreshClient(func() bool { return true })
	_, err := c.Configure(context.Background(), "default", &types.RefreshConfig{
		Provider:      "provider-1",
		CredentialKey: "cred-1",
	})
	require.Error(t, err)
	assert.True(t, types.IsUnavailable(err))
}

func TestFakeRefresh_Rotate_ClosedReturnsUnavailable(t *testing.T) {
	c := newFakeRefreshClient(func() bool { return true })
	_, err := c.Rotate(context.Background(), "default", "provider-1", "cred-1")
	require.Error(t, err)
	assert.True(t, types.IsUnavailable(err))
}

func TestFakeRefresh_Delete_ClosedReturnsUnavailable(t *testing.T) {
	c := newFakeRefreshClient(func() bool { return true })
	_, err := c.Delete(context.Background(), "default", "provider-1", "cred-1")
	require.Error(t, err)
	assert.True(t, types.IsUnavailable(err))
}
