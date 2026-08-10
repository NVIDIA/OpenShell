// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWithExtraHeaders_NilBase(t *testing.T) {
	_, err := WithExtraHeaders(nil, map[string]string{"x-key": "val"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "base")
}

func TestWithExtraHeaders_NilHeaders(t *testing.T) {
	_, err := WithExtraHeaders(NoAuth(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "headers")
}

func TestWithExtraHeaders_EmptyHeaders(t *testing.T) {
	_, err := WithExtraHeaders(NoAuth(), map[string]string{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "headers")
}

func TestWithExtraHeaders_AllEmptyValues(t *testing.T) {
	// All values are empty strings, so after filtering, headers map is empty.
	_, err := WithExtraHeaders(NoAuth(), map[string]string{"x-key": ""})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "headers")
}

func TestWithExtraHeaders_MergesWithBase(t *testing.T) {
	base := StaticToken("my-token")
	auth, err := WithExtraHeaders(base, map[string]string{
		"x-proxy-key": "proxy-secret",
		"x-tenant-id": "acme-corp",
	})
	require.NoError(t, err)

	md, err := auth.GetRequestMetadata(context.Background())
	require.NoError(t, err)

	assert.Equal(t, "Bearer my-token", md["authorization"])
	assert.Equal(t, "proxy-secret", md["x-proxy-key"])
	assert.Equal(t, "acme-corp", md["x-tenant-id"])
}

func TestWithExtraHeaders_ExtraPrecedenceOnCollision(t *testing.T) {
	base := StaticToken("my-token")
	auth, err := WithExtraHeaders(base, map[string]string{
		"authorization": "Custom override-token",
	})
	require.NoError(t, err)

	md, err := auth.GetRequestMetadata(context.Background())
	require.NoError(t, err)

	// Extra header wins over base.
	assert.Equal(t, "Custom override-token", md["authorization"])
}

func TestWithExtraHeaders_CaseInsensitiveCollision(t *testing.T) {
	base := StaticToken("my-token")
	// "Authorization" with uppercase should still override "authorization".
	auth, err := WithExtraHeaders(base, map[string]string{
		"Authorization": "Custom override-token",
	})
	require.NoError(t, err)

	md, err := auth.GetRequestMetadata(context.Background())
	require.NoError(t, err)

	assert.Equal(t, "Custom override-token", md["authorization"])
}

func TestWithExtraHeaders_EmptyValueSkipped(t *testing.T) {
	base := StaticToken("my-token")
	auth, err := WithExtraHeaders(base, map[string]string{
		"x-proxy-key": "proxy-secret",
		"x-empty":     "", // Should be silently skipped.
	})
	require.NoError(t, err)

	md, err := auth.GetRequestMetadata(context.Background())
	require.NoError(t, err)

	assert.Equal(t, "proxy-secret", md["x-proxy-key"])
	_, hasEmpty := md["x-empty"]
	assert.False(t, hasEmpty, "empty-string header values should be skipped")
}

func TestWithExtraHeaders_RequireTransportSecurity_Delegates(t *testing.T) {
	tests := []struct {
		name     string
		base     AuthProvider
		expected bool
	}{
		{
			name:     "delegates to NoAuth (false)",
			base:     NoAuth(),
			expected: false,
		},
		{
			name:     "delegates to StaticToken (true)",
			base:     StaticToken("tok"),
			expected: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth, err := WithExtraHeaders(tt.base, map[string]string{"x-key": "val"})
			require.NoError(t, err)
			assert.Equal(t, tt.expected, auth.RequireTransportSecurity())
		})
	}
}

func TestWithExtraHeaders_WithNoAuth(t *testing.T) {
	auth, err := WithExtraHeaders(NoAuth(), map[string]string{
		"x-proxy-key": "proxy-secret",
	})
	require.NoError(t, err)

	md, err := auth.GetRequestMetadata(context.Background())
	require.NoError(t, err)

	// NoAuth returns nil metadata, extra headers should still appear.
	assert.Equal(t, "proxy-secret", md["x-proxy-key"])
}

func TestWithExtraHeaders_BaseError_Propagated(t *testing.T) {
	base := &errAuth{err: errors.New("auth failure")}
	auth, err := WithExtraHeaders(base, map[string]string{"x-key": "val"})
	require.NoError(t, err)

	_, err = auth.GetRequestMetadata(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "auth failure")
}

func TestWithExtraHeaders_DeepCopiesHeaders(t *testing.T) {
	original := map[string]string{
		"x-key": "original-value",
	}
	auth, err := WithExtraHeaders(NoAuth(), original)
	require.NoError(t, err)

	// Mutate the original map after construction.
	original["x-key"] = "mutated-value"

	md, err := auth.GetRequestMetadata(context.Background())
	require.NoError(t, err)

	// The wrapper should use the value at construction time, not the mutated value.
	assert.Equal(t, "original-value", md["x-key"])
}

// errAuth is a test helper that always returns an error.
type errAuth struct {
	err error
}

func (e *errAuth) GetRequestMetadata(_ context.Context, _ ...string) (map[string]string, error) {
	return nil, e.err
}

func (e *errAuth) RequireTransportSecurity() bool {
	return false
}
