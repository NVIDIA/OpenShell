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

func TestHealth_GetGatewayInfo_Default(t *testing.T) {
	fc := NewClient()
	info, err := fc.Health().GetGatewayInfo(context.Background())

	require.NoError(t, err)
	require.NotNil(t, info)
	assert.Equal(t, types.ServiceStatusHealthy, info.Status)
	assert.Equal(t, "fake", info.Version)
}

func TestHealth_GetGatewayInfo_Custom(t *testing.T) {
	fc := NewClient(WithGatewayInfo(&types.GatewayInfo{
		Status:  types.ServiceStatusDegraded,
		Version: "1.2.3",
		ComputeDrivers: []types.ComputeDriverInfo{
			{Name: "k8s", DriverName: "kubernetes", DriverVersion: "2.0.0"},
		},
	}))

	info, err := fc.Health().GetGatewayInfo(context.Background())

	require.NoError(t, err)
	require.NotNil(t, info)
	assert.Equal(t, types.ServiceStatusDegraded, info.Status)
	assert.Equal(t, "1.2.3", info.Version)
	require.Len(t, info.ComputeDrivers, 1)
	assert.Equal(t, "k8s", info.ComputeDrivers[0].Name)
}

func TestHealth_GetGatewayInfo_DeepCopy(t *testing.T) {
	fc := NewClient(WithGatewayInfo(&types.GatewayInfo{
		Status:  types.ServiceStatusHealthy,
		Version: "1.0.0",
		ComputeDrivers: []types.ComputeDriverInfo{
			{Name: "k8s"},
		},
	}))

	info1, _ := fc.Health().GetGatewayInfo(context.Background())
	info1.ComputeDrivers[0].Name = "mutated"

	info2, _ := fc.Health().GetGatewayInfo(context.Background())
	assert.Equal(t, "k8s", info2.ComputeDrivers[0].Name)
}

func TestHealth_GetCurrentUser_Default(t *testing.T) {
	fc := NewClient()
	user, err := fc.Health().GetCurrentUser(context.Background())

	require.NoError(t, err)
	require.NotNil(t, user)
	assert.Equal(t, "fake-user", user.Subject)
	assert.Equal(t, "Fake User", user.DisplayName)
}

func TestHealth_GetCurrentUser_Custom(t *testing.T) {
	fc := NewClient(WithCurrentUser(&types.CurrentUser{
		Subject:          "real-user",
		DisplayName:      "Real User",
		Roles:            []string{"admin"},
		Scopes:           []string{"read", "write"},
		IdentityProvider: "oidc",
	}))

	user, err := fc.Health().GetCurrentUser(context.Background())

	require.NoError(t, err)
	require.NotNil(t, user)
	assert.Equal(t, "real-user", user.Subject)
	assert.Equal(t, "Real User", user.DisplayName)
	assert.Equal(t, []string{"admin"}, user.Roles)
	assert.Equal(t, []string{"read", "write"}, user.Scopes)
	assert.Equal(t, "oidc", user.IdentityProvider)
}

func TestHealth_GetCurrentUser_DeepCopy(t *testing.T) {
	fc := NewClient(WithCurrentUser(&types.CurrentUser{
		Subject: "user",
		Roles:   []string{"admin"},
	}))

	user1, _ := fc.Health().GetCurrentUser(context.Background())
	user1.Roles[0] = "mutated"

	user2, _ := fc.Health().GetCurrentUser(context.Background())
	assert.Equal(t, "admin", user2.Roles[0])
}

func TestHealth_GetGatewayInfo_Closed(t *testing.T) {
	fc := NewClient()
	_ = fc.Close()

	_, err := fc.Health().GetGatewayInfo(context.Background())
	assert.True(t, types.IsUnavailable(err))
}

func TestHealth_GetCurrentUser_Closed(t *testing.T) {
	fc := NewClient()
	_ = fc.Close()

	_, err := fc.Health().GetCurrentUser(context.Background())
	assert.True(t, types.IsUnavailable(err))
}
