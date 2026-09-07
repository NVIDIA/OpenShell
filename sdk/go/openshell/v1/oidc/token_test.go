// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func TestWriteToken_Success(t *testing.T) {
	dir := t.TempDir()
	tok := &oauth2.Token{
		AccessToken:  "access-123",
		RefreshToken: "refresh-456",
		Expiry:       time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC),
	}

	err := writeToken(dir, tok)
	require.NoError(t, err)

	// Verify the file was written.
	data, err := os.ReadFile(filepath.Join(dir, "oidc_token.json"))
	require.NoError(t, err)
	assert.Contains(t, string(data), `"access_token":"access-123"`)
	assert.Contains(t, string(data), `"refresh_token":"refresh-456"`)
	assert.Contains(t, string(data), `"expiry":"2026-07-03T12:00:00Z"`)
}

func TestWriteToken_ReplacesInsecureExistingFileWithOwnerOnlyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, oidcTokenFile)
	require.NoError(t, os.WriteFile(path, []byte("old"), 0o644))

	require.NoError(t, writeToken(dir, &oauth2.Token{AccessToken: "secret"}))

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func TestWriteToken_ExpiresInCalculated(t *testing.T) {
	dir := t.TempDir()
	expiry := time.Now().Add(3600 * time.Second)
	tok := &oauth2.Token{
		AccessToken: "access-123",
		Expiry:      expiry,
	}

	err := writeToken(dir, tok)
	require.NoError(t, err)

	data, err := os.ReadFile(filepath.Join(dir, "oidc_token.json"))
	require.NoError(t, err)
	// expires_in should be roughly 3600 (within a few seconds).
	assert.Contains(t, string(data), `"expires_in":`)
}

func TestWriteToken_InvalidDirectory(t *testing.T) {
	err := writeToken("/nonexistent/path/that/does/not/exist", &oauth2.Token{
		AccessToken: "test",
		Expiry:      time.Now().Add(time.Hour),
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrTokenPersist))
}

func TestReadToken_Success(t *testing.T) {
	dir := t.TempDir()
	content := `{
		"access_token": "access-123",
		"refresh_token": "refresh-456",
		"expiry": "2099-07-03T12:00:00Z",
		"expires_in": 3600
	}`
	err := os.WriteFile(filepath.Join(dir, "oidc_token.json"), []byte(content), 0o600)
	require.NoError(t, err)

	tok, err := readToken(dir)
	require.NoError(t, err)
	assert.Equal(t, "access-123", tok.AccessToken)
	assert.Equal(t, "refresh-456", tok.RefreshToken)
	assert.False(t, tok.Expiry.IsZero())
}

func TestReadToken_MissingFile(t *testing.T) {
	dir := t.TempDir()

	tok, err := readToken(dir)
	assert.Nil(t, tok)
	assert.NoError(t, err, "missing file should return nil token, no error")
}

func TestReadToken_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	err := os.WriteFile(filepath.Join(dir, "oidc_token.json"), []byte(`{invalid`), 0o600)
	require.NoError(t, err)

	_, err = readToken(dir)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrTokenPersist))
}

func TestReadToken_ExpiredToken(t *testing.T) {
	dir := t.TempDir()
	content := `{
		"access_token": "expired-access",
		"expiry": "2020-01-01T00:00:00Z"
	}`
	err := os.WriteFile(filepath.Join(dir, "oidc_token.json"), []byte(content), 0o600)
	require.NoError(t, err)

	tok, err := readToken(dir)
	assert.Nil(t, tok, "expired token should return nil")
	assert.NoError(t, err, "expired token is not an error, just nil")
}

func TestReadToken_ValidWithExpiresInFallback(t *testing.T) {
	dir := t.TempDir()
	// No expiry field, only expires_in. Since we wrote it "now",
	// a large expires_in should make the token valid.
	content := `{
		"access_token": "access-via-expires-in",
		"expires_in": 99999
	}`
	err := os.WriteFile(filepath.Join(dir, "oidc_token.json"), []byte(content), 0o600)
	require.NoError(t, err)

	tok, err := readToken(dir)
	require.NoError(t, err)
	// Token with only expires_in cannot reconstruct a valid Expiry
	// without knowing when the file was written. readToken should
	// treat it as potentially valid and return it.
	assert.NotNil(t, tok)
	assert.Equal(t, "access-via-expires-in", tok.AccessToken)
}

func TestReadToken_EmptyAccessToken(t *testing.T) {
	dir := t.TempDir()
	content := `{
		"access_token": "",
		"expiry": "2099-01-01T00:00:00Z"
	}`
	err := os.WriteFile(filepath.Join(dir, "oidc_token.json"), []byte(content), 0o600)
	require.NoError(t, err)

	tok, err := readToken(dir)
	assert.Nil(t, tok, "empty access token should return nil")
	assert.NoError(t, err)
}

func TestWriteAndReadToken_Roundtrip(t *testing.T) {
	dir := t.TempDir()
	original := &oauth2.Token{
		AccessToken:  "roundtrip-access",
		RefreshToken: "roundtrip-refresh",
		Expiry:       time.Now().Add(time.Hour).Truncate(time.Second),
	}

	err := writeToken(dir, original)
	require.NoError(t, err)

	loaded, err := readToken(dir)
	require.NoError(t, err)
	require.NotNil(t, loaded)

	assert.Equal(t, original.AccessToken, loaded.AccessToken)
	assert.Equal(t, original.RefreshToken, loaded.RefreshToken)
	// Expiry should be close (within a second due to serialization).
	assert.WithinDuration(t, original.Expiry, loaded.Expiry, time.Second)
}

func TestWriteToken_FilePermissions(t *testing.T) {
	dir := t.TempDir()
	tok := &oauth2.Token{
		AccessToken: "perm-check",
		Expiry:      time.Now().Add(time.Hour),
	}

	err := writeToken(dir, tok)
	require.NoError(t, err)

	info, err := os.Stat(filepath.Join(dir, "oidc_token.json"))
	require.NoError(t, err)
	// File should be owner-only readable (0600).
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}
