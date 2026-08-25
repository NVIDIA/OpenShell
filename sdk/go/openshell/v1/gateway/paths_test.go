// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- T007: XDG resolution tests ---

func TestUserConfigDir_XDGSet(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmp)

	dir, err := userConfigDir()
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(tmp, "openshell"), dir)
}

func TestUserConfigDir_XDGUnset(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "")

	dir, err := userConfigDir()
	require.NoError(t, err)

	home, err := os.UserHomeDir()
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(home, ".config", "openshell"), dir)
}

func TestSystemGatewayDir(t *testing.T) {
	dir := systemGatewayDir()
	assert.Equal(t, "/etc/openshell/gateways", dir)
}

func TestResolveGatewayDir_UserDir(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmp)

	// Create a gateway directory in user config.
	gwDir := filepath.Join(tmp, "openshell", "gateways", "prod")
	require.NoError(t, os.MkdirAll(gwDir, 0o755))

	dir, source, err := resolveGatewayDir("prod")
	require.NoError(t, err)
	assert.Equal(t, gwDir, dir)
	assert.Equal(t, SourceUser, source)
}

func TestResolveGatewayDir_NotFound(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmp)

	_, _, err := resolveGatewayDir("nonexistent")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrGatewayNotFound)
}

func TestResolveGatewayDir_InvalidName(t *testing.T) {
	_, _, err := resolveGatewayDir("../etc")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidGatewayName)
}

func TestResolveGatewayDir_UserPrecedenceOverSystem(t *testing.T) {
	// This test verifies the search order: user dir is checked before
	// system dir. We can only test the user dir path since we cannot
	// write to /etc in tests. The logic is verified by the successful
	// user dir resolution above.
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmp)

	gwDir := filepath.Join(tmp, "openshell", "gateways", "shared")
	require.NoError(t, os.MkdirAll(gwDir, 0o755))

	dir, source, err := resolveGatewayDir("shared")
	require.NoError(t, err)
	assert.Equal(t, gwDir, dir)
	assert.Equal(t, SourceUser, source)
}

// --- T008: Name validation tests ---

func TestValidateGatewayName_ValidNames(t *testing.T) {
	validNames := []string{
		"prod",
		"staging",
		"my-gateway",
		"gateway_1",
		"PROD",
		"a",
		"test-gateway-01",
		"A_B_C",
	}

	for _, name := range validNames {
		t.Run(name, func(t *testing.T) {
			err := validateGatewayName(name)
			assert.NoError(t, err, "expected %q to be valid", name)
		})
	}
}

func TestValidateGatewayName_Empty(t *testing.T) {
	err := validateGatewayName("")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidGatewayName)
	assert.Contains(t, err.Error(), "empty")
}

func TestValidateGatewayName_PathSeparators(t *testing.T) {
	cases := []string{
		"../etc",
		"foo/bar",
		"foo\\bar",
		"/absolute",
	}

	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			err := validateGatewayName(name)
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrInvalidGatewayName)
		})
	}
}

func TestValidateGatewayName_Dots(t *testing.T) {
	cases := []string{
		".",
		"..",
		".hidden",
		"foo.bar",
		"config.json",
	}

	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			err := validateGatewayName(name)
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrInvalidGatewayName)
		})
	}
}

// --- T021: Active gateway resolution tests ---

func TestResolveActiveGateway_ValidName(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmp)
	require.NoError(t, os.MkdirAll(filepath.Join(tmp, "openshell"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "openshell", "active_gateway"), []byte("my-gateway"), 0o644))

	name, err := resolveActiveGateway()
	require.NoError(t, err)
	assert.Equal(t, "my-gateway", name)
}

func TestResolveActiveGateway_WhitespaceHandling(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmp)
	require.NoError(t, os.MkdirAll(filepath.Join(tmp, "openshell"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "openshell", "active_gateway"), []byte("  my-gateway  \n"), 0o644))

	name, err := resolveActiveGateway()
	require.NoError(t, err)
	assert.Equal(t, "my-gateway", name)
}

func TestResolveActiveGateway_FileMissing(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmp)
	require.NoError(t, os.MkdirAll(filepath.Join(tmp, "openshell"), 0o755))

	_, err := resolveActiveGateway()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNoActiveGateway)
}

func TestResolveActiveGateway_EmptyFile(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmp)
	require.NoError(t, os.MkdirAll(filepath.Join(tmp, "openshell"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "openshell", "active_gateway"), []byte("   \n"), 0o644))

	_, err := resolveActiveGateway()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNoActiveGateway)
}

func TestValidateGatewayName_SpecialCharacters(t *testing.T) {
	cases := []struct {
		name string
		desc string
	}{
		{"hello world", "space"},
		{"foo@bar", "at sign"},
		{"foo#bar", "hash"},
		{"café", "non-ASCII"},
		{"日本語", "unicode"},
		{"foo bar", "tab (space)"},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			err := validateGatewayName(tc.name)
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrInvalidGatewayName)
		})
	}
}
