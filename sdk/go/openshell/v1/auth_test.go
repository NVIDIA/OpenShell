// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNoAuth_GetRequestMetadata(t *testing.T) {
	auth := NoAuth()
	md, err := auth.GetRequestMetadata(context.Background())
	require.NoError(t, err)
	assert.Empty(t, md)
}

func TestNoAuth_RequireTransportSecurity(t *testing.T) {
	auth := NoAuth()
	assert.False(t, auth.RequireTransportSecurity())
}

func TestStaticToken_GetRequestMetadata(t *testing.T) {
	auth := StaticToken("my-secret-token")
	md, err := auth.GetRequestMetadata(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "Bearer my-secret-token", md["authorization"])
}

func TestStaticToken_RequireTransportSecurity(t *testing.T) {
	auth := StaticToken("token")
	assert.True(t, auth.RequireTransportSecurity())
}
