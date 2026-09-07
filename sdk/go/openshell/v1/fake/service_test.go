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

// --- T026: fakeServiceClient stub tests ---

func TestFakeService_Expose_ReturnsUnimplemented(t *testing.T) {
	c := newFakeServiceClient(func() bool { return false })
	_, err := c.Expose(context.Background(), "default", "sb1", "svc1", 8080, false)
	require.Error(t, err)
	assert.True(t, types.IsUnimplemented(err))
}

func TestFakeService_Get_ReturnsUnimplemented(t *testing.T) {
	c := newFakeServiceClient(func() bool { return false })
	_, err := c.Get(context.Background(), "default", "sb1", "svc1")
	require.Error(t, err)
	assert.True(t, types.IsUnimplemented(err))
}

func TestFakeService_List_ReturnsUnimplemented(t *testing.T) {
	c := newFakeServiceClient(func() bool { return false })
	_, err := c.List(context.Background(), "default", "sb1")
	require.Error(t, err)
	assert.True(t, types.IsUnimplemented(err))
}

func TestFakeService_Delete_ReturnsUnimplemented(t *testing.T) {
	c := newFakeServiceClient(func() bool { return false })
	err := c.Delete(context.Background(), "default", "sb1", "svc1")
	require.Error(t, err)
	assert.True(t, types.IsUnimplemented(err))
}

func TestFakeService_Expose_ClosedReturnsUnavailable(t *testing.T) {
	c := newFakeServiceClient(func() bool { return true })
	_, err := c.Expose(context.Background(), "default", "sb1", "svc1", 8080, false)
	require.Error(t, err)
	assert.True(t, types.IsUnavailable(err))
}

func TestFakeService_Get_ClosedReturnsUnavailable(t *testing.T) {
	c := newFakeServiceClient(func() bool { return true })
	_, err := c.Get(context.Background(), "default", "sb1", "svc1")
	require.Error(t, err)
	assert.True(t, types.IsUnavailable(err))
}

func TestFakeService_List_ClosedReturnsUnavailable(t *testing.T) {
	c := newFakeServiceClient(func() bool { return true })
	_, err := c.List(context.Background(), "default", "sb1")
	require.Error(t, err)
	assert.True(t, types.IsUnavailable(err))
}

func TestFakeService_Delete_ClosedReturnsUnavailable(t *testing.T) {
	c := newFakeServiceClient(func() bool { return true })
	err := c.Delete(context.Background(), "default", "sb1", "svc1")
	require.Error(t, err)
	assert.True(t, types.IsUnavailable(err))
}
