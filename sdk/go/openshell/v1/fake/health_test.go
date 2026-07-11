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

// --- T017: Health check tests ---

func TestHealth_DefaultHealthy(t *testing.T) {
	hc := newFakeHealthClient(nil, func() bool { return false })
	ctx := context.Background()

	result, err := hc.Check(ctx)
	require.NoError(t, err)
	assert.True(t, result.Healthy)
	assert.Equal(t, "fake", result.Version)
}

func TestHealth_ConfigurableResult(t *testing.T) {
	custom := &types.HealthResult{
		Healthy: false,
		Version: "v0.0.0-broken",
	}
	hc := newFakeHealthClient(custom, func() bool { return false })
	ctx := context.Background()

	result, err := hc.Check(ctx)
	require.NoError(t, err)
	assert.False(t, result.Healthy)
	assert.Equal(t, "v0.0.0-broken", result.Version)
}

func TestHealth_ClosedClient(t *testing.T) {
	hc := newFakeHealthClient(nil, func() bool { return true })
	ctx := context.Background()

	_, err := hc.Check(ctx)
	require.Error(t, err)
	assert.True(t, types.IsUnavailable(err))
}
