// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package fake

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
)

func TestClientOption_NilIgnored(t *testing.T) {
	hr := &types.HealthResult{Healthy: false, Version: "1.2.3"}
	cu := &types.CurrentUser{Subject: "user-42", DisplayName: "Test User"}

	fc := NewClient(
		WithHealthResult(hr),
		nil,
		WithCurrentUser(cu),
	)
	require.NotNil(t, fc)

	healthClient := fc.health.(*fakeHealthClient)
	assert.Equal(t, false, healthClient.result.Healthy)
	assert.Equal(t, "1.2.3", healthClient.result.Version)
	assert.Equal(t, "Test User", healthClient.currentUser.DisplayName)
}
