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

func TestFakeInference_SetRoute_Success(t *testing.T) {
	fc := NewClient()
	defer fc.Close() //nolint:errcheck

	route, err := fc.Inference().SetRoute(context.Background(), "ws", &types.InferenceRouteConfig{
		ProviderName: "openai",
		ModelID:      "gpt-4",
		RouteName:    "my-route",
		TimeoutSecs:  120,
	})

	require.NoError(t, err)
	require.NotNil(t, route)
	assert.Equal(t, "openai", route.ProviderName)
	assert.Equal(t, "gpt-4", route.ModelID)
	assert.Equal(t, uint64(1), route.Version)
	assert.Equal(t, "my-route", route.RouteName)
	assert.Equal(t, uint64(120), route.TimeoutSecs)
	assert.Equal(t, "ws", route.Workspace)
}

func TestFakeInference_SetRoute_UpdateIncrementsVersion(t *testing.T) {
	fc := NewClient()
	defer fc.Close() //nolint:errcheck

	ctx := context.Background()

	route1, err := fc.Inference().SetRoute(ctx, "ws", &types.InferenceRouteConfig{
		ProviderName: "openai",
		ModelID:      "gpt-4",
		RouteName:    "my-route",
	})
	require.NoError(t, err)
	assert.Equal(t, uint64(1), route1.Version)

	route2, err := fc.Inference().SetRoute(ctx, "ws", &types.InferenceRouteConfig{
		ProviderName: "anthropic",
		ModelID:      "claude-4",
		RouteName:    "my-route",
	})
	require.NoError(t, err)
	assert.Equal(t, uint64(2), route2.Version)
	assert.Equal(t, "anthropic", route2.ProviderName)
}

func TestFakeInference_SetRoute_EmptyWorkspace(t *testing.T) {
	fc := NewClient()
	defer fc.Close() //nolint:errcheck

	_, err := fc.Inference().SetRoute(context.Background(), "", &types.InferenceRouteConfig{
		ProviderName: "openai",
		ModelID:      "gpt-4",
	})

	require.Error(t, err)
	assert.True(t, types.IsInvalidArgument(err))
}

func TestFakeInference_SetRoute_NilConfig(t *testing.T) {
	fc := NewClient()
	defer fc.Close() //nolint:errcheck

	_, err := fc.Inference().SetRoute(context.Background(), "ws", nil)

	require.Error(t, err)
	assert.True(t, types.IsInvalidArgument(err))
}

func TestFakeInference_SetRoute_EmptyProviderName(t *testing.T) {
	fc := NewClient()
	defer fc.Close() //nolint:errcheck

	_, err := fc.Inference().SetRoute(context.Background(), "ws", &types.InferenceRouteConfig{
		ProviderName: "",
		ModelID:      "gpt-4",
	})

	require.Error(t, err)
	assert.True(t, types.IsInvalidArgument(err))
}

func TestFakeInference_SetRoute_EmptyModelID(t *testing.T) {
	fc := NewClient()
	defer fc.Close() //nolint:errcheck

	_, err := fc.Inference().SetRoute(context.Background(), "ws", &types.InferenceRouteConfig{
		ProviderName: "openai",
		ModelID:      "",
	})

	require.Error(t, err)
	assert.True(t, types.IsInvalidArgument(err))
}

func TestFakeInference_SetRoute_EmptyRouteName(t *testing.T) {
	fc := NewClient()
	defer fc.Close() //nolint:errcheck

	route, err := fc.Inference().SetRoute(context.Background(), "ws", &types.InferenceRouteConfig{
		ProviderName: "openai",
		ModelID:      "gpt-4",
		RouteName:    "",
	})

	require.NoError(t, err)
	require.NotNil(t, route)
	assert.Empty(t, route.RouteName)
}

func TestFakeInference_GetRoute_Success(t *testing.T) {
	fc := NewClient()
	defer fc.Close() //nolint:errcheck

	ctx := context.Background()

	_, err := fc.Inference().SetRoute(ctx, "ws", &types.InferenceRouteConfig{
		ProviderName: "openai",
		ModelID:      "gpt-4",
		RouteName:    "my-route",
		TimeoutSecs:  120,
	})
	require.NoError(t, err)

	route, err := fc.Inference().GetRoute(ctx, "ws", "my-route")

	require.NoError(t, err)
	require.NotNil(t, route)
	assert.Equal(t, "openai", route.ProviderName)
	assert.Equal(t, "gpt-4", route.ModelID)
	assert.Equal(t, "my-route", route.RouteName)
	assert.Equal(t, uint64(120), route.TimeoutSecs)
	assert.Equal(t, "ws", route.Workspace)
}

func TestFakeInference_GetRoute_EmptyWorkspace(t *testing.T) {
	fc := NewClient()
	defer fc.Close() //nolint:errcheck

	_, err := fc.Inference().GetRoute(context.Background(), "", "my-route")

	require.Error(t, err)
	assert.True(t, types.IsInvalidArgument(err))
}

func TestFakeInference_GetRoute_NotFound(t *testing.T) {
	fc := NewClient()
	defer fc.Close() //nolint:errcheck

	_, err := fc.Inference().GetRoute(context.Background(), "ws", "nonexistent")

	require.Error(t, err)
	assert.True(t, types.IsNotFound(err))
}

func TestFakeInference_GetRoute_DeepCopy(t *testing.T) {
	fc := NewClient()
	defer fc.Close() //nolint:errcheck

	ctx := context.Background()

	_, err := fc.Inference().SetRoute(ctx, "ws", &types.InferenceRouteConfig{
		ProviderName: "openai",
		ModelID:      "gpt-4",
		RouteName:    "my-route",
	})
	require.NoError(t, err)

	route1, err := fc.Inference().GetRoute(ctx, "ws", "my-route")
	require.NoError(t, err)

	// Mutate the returned route; it should not affect the stored copy.
	route1.ProviderName = "mutated"

	route2, err := fc.Inference().GetRoute(ctx, "ws", "my-route")
	require.NoError(t, err)
	assert.Equal(t, "openai", route2.ProviderName)
}

func TestFakeInference_DeleteRoute_Success(t *testing.T) {
	fc := NewClient()
	defer fc.Close() //nolint:errcheck

	ctx := context.Background()

	_, err := fc.Inference().SetRoute(ctx, "ws", &types.InferenceRouteConfig{
		ProviderName: "openai",
		ModelID:      "gpt-4",
		RouteName:    "my-route",
	})
	require.NoError(t, err)

	err = fc.Inference().DeleteRoute(ctx, "ws", "my-route")
	require.NoError(t, err)

	// Subsequent get should return NotFound.
	_, err = fc.Inference().GetRoute(ctx, "ws", "my-route")
	require.Error(t, err)
	assert.True(t, types.IsNotFound(err))
}

func TestFakeInference_DeleteRoute_EmptyWorkspace(t *testing.T) {
	fc := NewClient()
	defer fc.Close() //nolint:errcheck

	err := fc.Inference().DeleteRoute(context.Background(), "", "my-route")

	require.Error(t, err)
	assert.True(t, types.IsInvalidArgument(err))
}

func TestFakeInference_DeleteRoute_Idempotent(t *testing.T) {
	fc := NewClient()
	defer fc.Close() //nolint:errcheck

	// Deleting a non-existent route should not error.
	err := fc.Inference().DeleteRoute(context.Background(), "ws", "nonexistent")
	require.NoError(t, err)
}

func TestFakeInference_WorkspaceIsolation(t *testing.T) {
	fc := NewClient()
	defer fc.Close() //nolint:errcheck

	ctx := context.Background()

	_, err := fc.Inference().SetRoute(ctx, "ws1", &types.InferenceRouteConfig{
		ProviderName: "openai",
		ModelID:      "gpt-4",
		RouteName:    "shared-name",
	})
	require.NoError(t, err)

	// Different workspace should not see the route.
	_, err = fc.Inference().GetRoute(ctx, "ws2", "shared-name")
	require.Error(t, err)
	assert.True(t, types.IsNotFound(err))
}

func TestFakeInference_ClosedClient(t *testing.T) {
	fc := NewClient()
	_ = fc.Close()

	ctx := context.Background()

	_, err := fc.Inference().SetRoute(ctx, "ws", &types.InferenceRouteConfig{
		ProviderName: "openai",
		ModelID:      "gpt-4",
	})
	require.Error(t, err)
	assert.True(t, types.IsUnavailable(err))

	_, err = fc.Inference().GetRoute(ctx, "ws", "route")
	require.Error(t, err)
	assert.True(t, types.IsUnavailable(err))

	err = fc.Inference().DeleteRoute(ctx, "ws", "route")
	require.Error(t, err)
	assert.True(t, types.IsUnavailable(err))
}
