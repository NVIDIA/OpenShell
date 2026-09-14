// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- T014: Edge token loading tests ---

func TestReadEdgeToken_PrimaryFile(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, edgeTokenFile, "my-edge-token-123")

	token, err := readEdgeToken(dir)
	require.NoError(t, err)
	assert.Equal(t, "my-edge-token-123", token)
}

func TestReadEdgeToken_PrimaryFileWithWhitespace(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, edgeTokenFile, "  token-with-whitespace  \n")

	token, err := readEdgeToken(dir)
	require.NoError(t, err)
	assert.Equal(t, "token-with-whitespace", token)
}

func TestReadEdgeToken_CfTokenFallback(t *testing.T) {
	dir := t.TempDir()
	// No edge_token file, only cf_token.
	writeFile(t, dir, cfTokenFile, "legacy-cf-token")

	token, err := readEdgeToken(dir)
	require.NoError(t, err)
	assert.Equal(t, "legacy-cf-token", token)
}

func TestReadEdgeToken_PrimaryTakesPrecedence(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, edgeTokenFile, "primary-token")
	writeFile(t, dir, cfTokenFile, "legacy-token")

	token, err := readEdgeToken(dir)
	require.NoError(t, err)
	assert.Equal(t, "primary-token", token)
}

func TestReadEdgeToken_MissingBothFiles(t *testing.T) {
	dir := t.TempDir()

	_, err := readEdgeToken(dir)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTokenLoad)
	assert.Contains(t, err.Error(), "neither edge_token nor cf_token")
}

func TestReadEdgeToken_EmptyPrimaryFile(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, edgeTokenFile, "   \n")

	_, err := readEdgeToken(dir)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTokenLoad)
	assert.Contains(t, err.Error(), "empty")
}

func TestReadEdgeToken_EmptyFallbackFile(t *testing.T) {
	dir := t.TempDir()
	// No edge_token, only empty cf_token.
	writeFile(t, dir, cfTokenFile, "")

	_, err := readEdgeToken(dir)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTokenLoad)
	assert.Contains(t, err.Error(), "empty")
}

func TestEdgeTokenLoader_Lazy(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, edgeTokenFile, "lazy-token")

	loader := &edgeTokenLoader{dir: dir}

	// First call reads from disk.
	token1, err := loader.load()
	require.NoError(t, err)
	assert.Equal(t, "lazy-token", token1)

	// Remove the file. Second call should return cached value.
	require.NoError(t, os.Remove(filepath.Join(dir, edgeTokenFile)))

	token2, err := loader.load()
	require.NoError(t, err)
	assert.Equal(t, "lazy-token", token2, "should return cached token")
}

func TestEdgeTokenLoader_LazyError(t *testing.T) {
	dir := t.TempDir()
	// No token files exist.

	loader := &edgeTokenLoader{dir: dir}

	// First call fails.
	_, err1 := loader.load()
	require.Error(t, err1)

	// Write the file now. A transient load failure must not be cached.
	writeFile(t, dir, edgeTokenFile, "late-token")

	token, err2 := loader.load()
	require.NoError(t, err2)
	assert.Equal(t, "late-token", token)
}

// --- T015: diskTokenSource tests ---

func TestDiskTokenSource_ValidBundle(t *testing.T) {
	dir := t.TempDir()
	expiry := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	writeFile(t, dir, oidcTokenFile, `{
		"access_token": "access-123",
		"refresh_token": "refresh-456",
		"expiry": "`+expiry+`"
	}`)

	src := newDiskTokenSource(dir)
	tok, err := src.Token()
	require.NoError(t, err)
	assert.Equal(t, "access-123", tok.AccessToken)
	assert.Equal(t, "refresh-456", tok.RefreshToken)
	assert.Equal(t, "Bearer", tok.TokenType)
	assert.False(t, tok.Expiry.IsZero())
}

func TestDiskTokenSource_ExpiresInIgnored(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, oidcTokenFile, `{
		"access_token": "access-789",
		"expires_in": 3600
	}`)

	src := newDiskTokenSource(dir)
	tok, err := src.Token()
	require.NoError(t, err)
	assert.Equal(t, "access-789", tok.AccessToken)
	// expires_in without an absolute expiry field is ignored because
	// there is no written_at timestamp to compute absolute expiry from.
	assert.True(t, tok.Expiry.IsZero(), "expiry should be zero when only expires_in is present")
}

func TestDiskTokenSource_ExpiryPrecedence(t *testing.T) {
	dir := t.TempDir()
	expiry := time.Now().Add(2 * time.Hour).UTC().Format(time.RFC3339)
	writeFile(t, dir, oidcTokenFile, `{
		"access_token": "access-abc",
		"expiry": "`+expiry+`",
		"expires_in": 60
	}`)

	src := newDiskTokenSource(dir)
	tok, err := src.Token()
	require.NoError(t, err)
	// "expiry" field takes precedence over "expires_in".
	assert.WithinDuration(t, time.Now().Add(2*time.Hour), tok.Expiry, 5*time.Second)
}

func TestDiskTokenSource_NoExpiry(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, oidcTokenFile, `{"access_token": "no-expiry-token"}`)

	src := newDiskTokenSource(dir)
	tok, err := src.Token()
	require.NoError(t, err)
	assert.Equal(t, "no-expiry-token", tok.AccessToken)
	assert.True(t, tok.Expiry.IsZero(), "should have zero expiry when not set")
}

func TestDiskTokenSource_ExpiredToken(t *testing.T) {
	dir := t.TempDir()
	expiry := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	writeFile(t, dir, oidcTokenFile, `{
		"access_token": "expired-token",
		"expiry": "`+expiry+`"
	}`)

	src := newDiskTokenSource(dir)
	_, err := src.Token()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTokenLoad)
	assert.Contains(t, err.Error(), "expired")
	assert.Contains(t, err.Error(), "re-authenticate")
}

func TestDiskTokenSource_MissingFile(t *testing.T) {
	dir := t.TempDir()

	src := newDiskTokenSource(dir)
	_, err := src.Token()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTokenLoad)
}

func TestDiskTokenSource_MalformedJSON(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, oidcTokenFile, `{not valid json}`)

	src := newDiskTokenSource(dir)
	_, err := src.Token()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTokenLoad)
	assert.Contains(t, err.Error(), "invalid JSON")
}

func TestDiskTokenSource_MissingAccessToken(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, oidcTokenFile, `{"refresh_token": "only-refresh"}`)

	src := newDiskTokenSource(dir)
	_, err := src.Token()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTokenLoad)
	assert.Contains(t, err.Error(), "missing access_token")
}

func TestDiskTokenSource_ReReadsOnEachCall(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, oidcTokenFile, `{"access_token": "token-v1"}`)

	src := newDiskTokenSource(dir)
	tok1, err := src.Token()
	require.NoError(t, err)
	assert.Equal(t, "token-v1", tok1.AccessToken)

	// Update the file. Next call should read the new value.
	writeFile(t, dir, oidcTokenFile, `{"access_token": "token-v2"}`)

	tok2, err := src.Token()
	require.NoError(t, err)
	assert.Equal(t, "token-v2", tok2.AccessToken)
}

func TestDiskTokenSource_InvalidExpiryFormat(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, oidcTokenFile, `{
		"access_token": "token-xyz",
		"expiry": "not-a-date"
	}`)

	src := newDiskTokenSource(dir)
	_, err := src.Token()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTokenLoad)
}

// writeFile is a test helper that writes a file with the given content.
func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644)
	require.NoError(t, err)
}
