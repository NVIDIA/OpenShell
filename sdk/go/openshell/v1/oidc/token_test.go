// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/internal/oidctoken"
)

func loadOIDCTokenFixture(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "conformance", "oidc-token-bundle.json"))
	require.NoError(t, err)
	return data
}

func TestReadToken_ConformanceFixture(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, oidctoken.FileName), loadOIDCTokenFixture(t), 0o600))

	b, err := readToken(dir)
	require.NoError(t, err)
	require.NotNil(t, b)
	assert.Equal(t, "conformance-access-token", b.AccessToken)
	assert.Equal(t, "conformance-refresh-token", b.RefreshToken)
	require.NotNil(t, b.ExpiresAt)
	assert.Equal(t, uint64(4102444800), *b.ExpiresAt)
	assert.Equal(t, "https://issuer.example.com", b.Issuer)
	assert.Equal(t, "openshell-cli", b.ClientID)
}

func TestWriteToken_MatchesConformanceFixture(t *testing.T) {
	dir := t.TempDir()
	tok := &oauth2.Token{
		AccessToken:  "conformance-access-token",
		RefreshToken: "conformance-refresh-token",
		Expiry:       time.Unix(4102444800, 0),
	}

	require.NoError(t, writeToken(dir, oidctoken.FromToken(tok, "https://issuer.example.com", "openshell-cli")))

	data, err := os.ReadFile(filepath.Join(dir, oidctoken.FileName))
	require.NoError(t, err)
	assert.JSONEq(t, string(loadOIDCTokenFixture(t)), string(data))
}

func TestWriteToken_OmitsEmptyOptionalFields(t *testing.T) {
	dir := t.TempDir()
	tok := &oauth2.Token{AccessToken: "access-only"}

	require.NoError(t, writeToken(dir, oidctoken.FromToken(tok, "https://issuer.example.com", "openshell-cli")))

	data, err := os.ReadFile(filepath.Join(dir, oidctoken.FileName))
	require.NoError(t, err)
	assert.JSONEq(t,
		`{"access_token": "access-only", "issuer": "https://issuer.example.com", "client_id": "openshell-cli"}`,
		string(data))
}

func TestWriteToken_ReplacesInsecureExistingFileWithOwnerOnlyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, oidctoken.FileName)
	require.NoError(t, os.WriteFile(path, []byte("old"), 0o644))

	require.NoError(t, writeToken(dir, oidctoken.Bundle{AccessToken: "secret"}))

	assertOwnerOnlyFilePermissions(t, path)
}

func TestWriteToken_InvalidDirectory(t *testing.T) {
	err := writeToken("/nonexistent/path/that/does/not/exist", oidctoken.Bundle{AccessToken: "test"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrTokenPersist))
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

func TestWriteToken_FilePermissions(t *testing.T) {
	dir := t.TempDir()

	err := writeToken(dir, oidctoken.Bundle{AccessToken: "perm-check"})
	require.NoError(t, err)

	assertOwnerOnlyFilePermissions(t, filepath.Join(dir, "oidc_token.json"))
}

func assertOwnerOnlyFilePermissions(t *testing.T, path string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file permission bits are not supported on Windows")
	}

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}
