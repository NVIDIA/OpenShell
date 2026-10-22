// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/internal/oidctoken"
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

const loginHint = "run `openshell gateway login prod`"

func TestDiskTokenSource_ValidBundle(t *testing.T) {
	dir := t.TempDir()
	fixture, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "conformance", "oidc-token-bundle.json"))
	require.NoError(t, err)
	writeFile(t, dir, oidctoken.FileName, string(fixture))

	src := newDiskTokenSource(dir, "prod")
	tok, err := src.Token()
	require.NoError(t, err)
	assert.Equal(t, "conformance-access-token", tok.AccessToken)
	assert.Equal(t, "conformance-refresh-token", tok.RefreshToken)
	assert.Equal(t, "Bearer", tok.TokenType)
	assert.Equal(t, time.Unix(4102444800, 0), tok.Expiry)
}

func TestDiskTokenSource_NoExpiry(t *testing.T) {
	for _, expiresAt := range []string{"", "null"} {
		dir := t.TempDir()
		writeFile(t, dir, oidctoken.FileName, oidcBundleJSON("no-expiry-token", expiresAt))

		src := newDiskTokenSource(dir, "prod")
		tok, err := src.Token()
		require.NoError(t, err, "expires_at=%q", expiresAt)
		assert.Equal(t, "no-expiry-token", tok.AccessToken)
		assert.True(t, tok.Expiry.IsZero(), "should have zero expiry for expires_at=%q", expiresAt)
	}
}

func TestDiskTokenSource_ExpiredToken(t *testing.T) {
	for _, expiresAt := range []string{fmt.Sprint(time.Now().Add(-time.Hour).Unix()), "0"} {
		dir := t.TempDir()
		writeFile(t, dir, oidctoken.FileName, oidcBundleJSON("expired-token", expiresAt))

		src := newDiskTokenSource(dir, "prod")
		_, err := src.Token()
		require.ErrorIs(t, err, ErrTokenLoad, "expires_at=%s", expiresAt)
		assert.Contains(t, err.Error(), "expired at")
		assert.Contains(t, err.Error(), loginHint)
	}
}

func TestDiskTokenSource_MissingIssuerOrClientID(t *testing.T) {
	expiry := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	bundles := map[string]string{
		"earlier Go SDK format": `{"access_token": "a", "refresh_token": "r", "expiry": "` + expiry + `", "expires_in": 3600}`,
		"no issuer":             `{"access_token": "a", "client_id": "openshell-cli"}`,
		"no client_id":          `{"access_token": "a", "issuer": "https://issuer.example.com"}`,
		"empty issuer":          `{"access_token": "a", "issuer": "", "client_id": "openshell-cli"}`,
	}
	for name, content := range bundles {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeFile(t, dir, oidctoken.FileName, content)

			src := newDiskTokenSource(dir, "prod")
			_, err := src.Token()
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrTokenLoad)
			assert.Contains(t, err.Error(), `OIDC token for gateway "prod" is missing issuer or client_id`)
			assert.Contains(t, err.Error(), loginHint)
		})
	}
}

func TestDiskTokenSource_MissingFile(t *testing.T) {
	dir := t.TempDir()

	src := newDiskTokenSource(dir, "prod")
	_, err := src.Token()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTokenLoad)
	assert.Contains(t, err.Error(), loginHint)
}

func TestDiskTokenSource_MalformedJSON(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, oidctoken.FileName, `{not valid json}`)

	src := newDiskTokenSource(dir, "prod")
	_, err := src.Token()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTokenLoad)
	assert.Contains(t, err.Error(), "invalid JSON")
	assert.Contains(t, err.Error(), loginHint)
}

func TestDiskTokenSource_MissingAccessToken(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, oidctoken.FileName, `{"refresh_token": "only-refresh"}`)

	src := newDiskTokenSource(dir, "prod")
	_, err := src.Token()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTokenLoad)
	assert.Contains(t, err.Error(), "missing access_token")
}

func TestDiskTokenSource_ReReadsOnEachCall(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, oidctoken.FileName, oidcBundleJSON("token-v1", ""))

	src := newDiskTokenSource(dir, "prod")
	tok1, err := src.Token()
	require.NoError(t, err)
	assert.Equal(t, "token-v1", tok1.AccessToken)

	// Update the file. Next call should read the new value.
	writeFile(t, dir, oidctoken.FileName, oidcBundleJSON("token-v2", ""))

	tok2, err := src.Token()
	require.NoError(t, err)
	assert.Equal(t, "token-v2", tok2.AccessToken)
}

func TestDiskTokenSource_InvalidExpiryFormat(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, oidctoken.FileName, oidcBundleJSON("token-xyz", "-1"))

	src := newDiskTokenSource(dir, "prod")
	_, err := src.Token()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTokenLoad)
	assert.Contains(t, err.Error(), "invalid JSON")
}

// writeFile is a test helper that writes a file with the given content.
func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644)
	require.NoError(t, err)
}

// oidcBundleJSON returns a CLI-format oidc_token.json body. expiresAt is
// the raw JSON value of expires_at; an empty string omits the field.
func oidcBundleJSON(accessToken, expiresAt string) string {
	expiry := ""
	if expiresAt != "" {
		expiry = `"expires_at": ` + expiresAt + `, `
	}
	return `{"access_token": "` + accessToken + `", ` + expiry +
		`"issuer": "https://issuer.example.com", "client_id": "openshell-cli"}`
}
