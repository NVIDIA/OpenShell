// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"context"
	"testing"

	v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCloudflareAccess_ValidToken(t *testing.T) {
	base := v1.StaticToken("my-token")
	auth, err := CloudflareAccess(base, "cf-edge-jwt-xxx")
	require.NoError(t, err)

	md, err := auth.GetRequestMetadata(context.Background())
	require.NoError(t, err)

	// Base auth header preserved.
	assert.Equal(t, "Bearer my-token", md["authorization"])

	// Cloudflare-specific headers present.
	assert.Equal(t, "cf-edge-jwt-xxx", md["cf-access-jwt-assertion"])
	assert.Equal(t, "CF_Authorization=cf-edge-jwt-xxx", md["cookie"])
}

func TestCloudflareAccess_EmptyToken(t *testing.T) {
	base := v1.StaticToken("my-token")
	_, err := CloudflareAccess(base, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "edge token")
}

func TestCloudflareAccess_NilBase(t *testing.T) {
	_, err := CloudflareAccess(nil, "cf-edge-jwt-xxx")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "base")
}

func TestCloudflareAccess_WithNoAuth(t *testing.T) {
	auth, err := CloudflareAccess(v1.NoAuth(), "cf-edge-jwt-xxx")
	require.NoError(t, err)

	md, err := auth.GetRequestMetadata(context.Background())
	require.NoError(t, err)

	// NoAuth provides no base metadata; only CF headers should appear.
	assert.Equal(t, "cf-edge-jwt-xxx", md["cf-access-jwt-assertion"])
	assert.Equal(t, "CF_Authorization=cf-edge-jwt-xxx", md["cookie"])
}

func TestCloudflareAccess_RequireTransportSecurity_Delegates(t *testing.T) {
	tests := []struct {
		name     string
		base     v1.AuthProvider
		expected bool
	}{
		{
			name:     "delegates to NoAuth (false)",
			base:     v1.NoAuth(),
			expected: false,
		},
		{
			name:     "delegates to StaticToken (true)",
			base:     v1.StaticToken("tok"),
			expected: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth, err := CloudflareAccess(tt.base, "cf-edge-jwt-xxx")
			require.NoError(t, err)
			assert.Equal(t, tt.expected, auth.RequireTransportSecurity())
		})
	}
}

func TestCloudflareAccess_TokenNotInError(t *testing.T) {
	// Verify the error for empty token does not leak actual token values.
	_, err := CloudflareAccess(v1.StaticToken("s3cr3t-val"), "")
	require.Error(t, err)
	// The error should mention the parameter name, not any token value.
	assert.NotContains(t, err.Error(), "s3cr3t-val")
}
