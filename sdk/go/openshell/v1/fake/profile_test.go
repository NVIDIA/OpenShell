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

// --- T027: fakeProfileClient stub tests ---

func TestFakeProfile_List_ReturnsUnimplemented(t *testing.T) {
	c := newFakeProfileClient(func() bool { return false })
	_, err := c.List(context.Background(), "default")
	require.Error(t, err)
	assert.True(t, types.IsUnimplemented(err))
}

func TestFakeProfile_Get_ReturnsUnimplemented(t *testing.T) {
	c := newFakeProfileClient(func() bool { return false })
	_, err := c.Get(context.Background(), "default", "profile-1")
	require.Error(t, err)
	assert.True(t, types.IsUnimplemented(err))
}

func TestFakeProfile_Import_ReturnsUnimplemented(t *testing.T) {
	c := newFakeProfileClient(func() bool { return false })
	_, err := c.Import(context.Background(), "default", []types.ProfileImportItem{{Source: "test"}})
	require.Error(t, err)
	assert.True(t, types.IsUnimplemented(err))
}

func TestFakeProfile_Update_ReturnsUnimplemented(t *testing.T) {
	c := newFakeProfileClient(func() bool { return false })
	_, err := c.Update(context.Background(), "default", "profile-1", 1, types.ProfileImportItem{Source: "test"})
	require.Error(t, err)
	assert.True(t, types.IsUnimplemented(err))
}

func TestFakeProfile_Lint_ReturnsUnimplemented(t *testing.T) {
	c := newFakeProfileClient(func() bool { return false })
	_, err := c.Lint(context.Background(), "default", []types.ProfileImportItem{{Source: "test"}})
	require.Error(t, err)
	assert.True(t, types.IsUnimplemented(err))
}

func TestFakeProfile_Delete_ReturnsUnimplemented(t *testing.T) {
	c := newFakeProfileClient(func() bool { return false })
	_, err := c.Delete(context.Background(), "default", "profile-1")
	require.Error(t, err)
	assert.True(t, types.IsUnimplemented(err))
}

func TestFakeProfile_List_ClosedReturnsUnavailable(t *testing.T) {
	c := newFakeProfileClient(func() bool { return true })
	_, err := c.List(context.Background(), "default")
	require.Error(t, err)
	assert.True(t, types.IsUnavailable(err))
}

func TestFakeProfile_Get_ClosedReturnsUnavailable(t *testing.T) {
	c := newFakeProfileClient(func() bool { return true })
	_, err := c.Get(context.Background(), "default", "profile-1")
	require.Error(t, err)
	assert.True(t, types.IsUnavailable(err))
}

func TestFakeProfile_Import_ClosedReturnsUnavailable(t *testing.T) {
	c := newFakeProfileClient(func() bool { return true })
	_, err := c.Import(context.Background(), "default", []types.ProfileImportItem{{Source: "test"}})
	require.Error(t, err)
	assert.True(t, types.IsUnavailable(err))
}

func TestFakeProfile_Update_ClosedReturnsUnavailable(t *testing.T) {
	c := newFakeProfileClient(func() bool { return true })
	_, err := c.Update(context.Background(), "default", "profile-1", 1, types.ProfileImportItem{Source: "test"})
	require.Error(t, err)
	assert.True(t, types.IsUnavailable(err))
}

func TestFakeProfile_Lint_ClosedReturnsUnavailable(t *testing.T) {
	c := newFakeProfileClient(func() bool { return true })
	_, err := c.Lint(context.Background(), "default", []types.ProfileImportItem{{Source: "test"}})
	require.Error(t, err)
	assert.True(t, types.IsUnavailable(err))
}

func TestFakeProfile_Delete_ClosedReturnsUnavailable(t *testing.T) {
	c := newFakeProfileClient(func() bool { return true })
	_, err := c.Delete(context.Background(), "default", "profile-1")
	require.Error(t, err)
	assert.True(t, types.IsUnavailable(err))
}
