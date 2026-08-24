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

// --- T010: metadata.json parsing tests ---

func TestParseMetadata_ValidConfig(t *testing.T) {
	dir := t.TempDir()
	writeJSON(t, dir, `{"gateway_endpoint":"localhost:8080","auth_mode":"none","name":"prod"}`)

	cfg, err := parseMetadata(dir)
	require.NoError(t, err)
	assert.Equal(t, "prod", cfg.Name)
	assert.Equal(t, "localhost:8080", cfg.Endpoint)
	assert.Equal(t, AuthModeNone, cfg.AuthMode)
	assert.Equal(t, dir, cfg.Dir)
}

func TestParseMetadata_EmptyAuthMode(t *testing.T) {
	dir := t.TempDir()
	writeJSON(t, dir, `{"gateway_endpoint":"host:443"}`)

	cfg, err := parseMetadata(dir)
	require.NoError(t, err)
	assert.Equal(t, AuthModeNone, cfg.AuthMode)
}

func TestParseMetadata_AllAuthModes(t *testing.T) {
	cases := []struct {
		mode     string
		expected AuthMode
	}{
		{"", AuthModeNone},
		{"none", AuthModeNone},
		{"plaintext", AuthModePlaintext},
		{"cloudflare_jwt", AuthModeCloudflareJWT},
		{"oidc", AuthModeOIDC},
		{"mtls", AuthModeMTLS},
	}

	for _, tc := range cases {
		t.Run("mode_"+tc.mode, func(t *testing.T) {
			dir := t.TempDir()
			if tc.mode == "" {
				writeJSON(t, dir, `{"gateway_endpoint":"host:443"}`)
			} else {
				writeJSON(t, dir, `{"gateway_endpoint":"host:443","auth_mode":"`+tc.mode+`"}`)
			}

			cfg, err := parseMetadata(dir)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, cfg.AuthMode)
		})
	}
}

func TestParseMetadata_MissingEndpoint(t *testing.T) {
	dir := t.TempDir()
	writeJSON(t, dir, `{"auth_mode":"none","name":"prod"}`)

	_, err := parseMetadata(dir)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrConfigParse)
	assert.Contains(t, err.Error(), "missing gateway_endpoint")
}

func TestParseMetadata_MissingFile(t *testing.T) {
	dir := t.TempDir()

	_, err := parseMetadata(dir)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrConfigParse)
}

func TestParseMetadata_MalformedJSON(t *testing.T) {
	dir := t.TempDir()
	writeJSON(t, dir, `{invalid json}`)

	_, err := parseMetadata(dir)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrConfigParse)
	assert.Contains(t, err.Error(), "invalid JSON")
}

func TestParseMetadata_UnknownFieldsIgnored(t *testing.T) {
	dir := t.TempDir()
	writeJSON(t, dir, `{
		"gateway_endpoint":"host:443",
		"auth_mode":"none",
		"name":"prod",
		"future_field":"some_value",
		"another_new_thing": 42
	}`)

	cfg, err := parseMetadata(dir)
	require.NoError(t, err)
	assert.Equal(t, "prod", cfg.Name)
	assert.Equal(t, "host:443", cfg.Endpoint)
}

func TestParseMetadata_UnsupportedAuthMode(t *testing.T) {
	dir := t.TempDir()
	writeJSON(t, dir, `{"gateway_endpoint":"host:443","auth_mode":"kerberos"}`)

	_, err := parseMetadata(dir)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnsupportedAuthMode)
	assert.Contains(t, err.Error(), "kerberos")
}

func TestParseAuthMode(t *testing.T) {
	cases := []struct {
		input    string
		expected AuthMode
		wantErr  bool
	}{
		{"", AuthModeNone, false},
		{"none", AuthModeNone, false},
		{"plaintext", AuthModePlaintext, false},
		{"cloudflare_jwt", AuthModeCloudflareJWT, false},
		{"oidc", AuthModeOIDC, false},
		{"mtls", AuthModeMTLS, false},
		{"unknown", "", true},
		{"NONE", "", true}, // case-sensitive
	}

	for _, tc := range cases {
		t.Run("input_"+tc.input, func(t *testing.T) {
			mode, err := parseAuthMode(tc.input)
			if tc.wantErr {
				require.Error(t, err)
				assert.ErrorIs(t, err, ErrUnsupportedAuthMode)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expected, mode)
			}
		})
	}
}

// --- T010: OIDC config field tests ---

func TestParseMetadata_OIDCFields(t *testing.T) {
	dir := t.TempDir()
	writeJSON(t, dir, `{
		"gateway_endpoint":"host:443",
		"auth_mode":"oidc",
		"name":"oidc-gw",
		"oidc_issuer":"https://auth.example.com",
		"oidc_client_id":"my-client-id"
		,"oidc_audience":"openshell-api",
		"oidc_scopes":"sandbox:read sandbox:write"
	}`)

	cfg, err := parseMetadata(dir)
	require.NoError(t, err)
	assert.Equal(t, "oidc-gw", cfg.Name)
	assert.Equal(t, AuthModeOIDC, cfg.AuthMode)
	assert.Equal(t, "https://auth.example.com", cfg.OIDCIssuer)
	assert.Equal(t, "my-client-id", cfg.OIDCClientID)
	assert.Equal(t, "openshell-api", cfg.OIDCAudience)
	assert.Equal(t, "sandbox:read sandbox:write", cfg.OIDCScopes)
}

func TestParseMetadata_OIDCFieldsMissing(t *testing.T) {
	// When OIDC fields are absent (older gateway or non-OIDC mode),
	// the Config should have empty strings for OIDCIssuer/OIDCClientID.
	dir := t.TempDir()
	writeJSON(t, dir, `{
		"gateway_endpoint":"host:443",
		"auth_mode":"cloudflare_jwt",
		"name":"legacy-gw"
	}`)

	cfg, err := parseMetadata(dir)
	require.NoError(t, err)
	assert.Equal(t, "", cfg.OIDCIssuer)
	assert.Equal(t, "", cfg.OIDCClientID)
}

func TestParseMetadata_OIDCFieldsEmpty(t *testing.T) {
	// Explicit empty strings for OIDC fields should be handled
	// gracefully (backward compatibility).
	dir := t.TempDir()
	writeJSON(t, dir, `{
		"gateway_endpoint":"host:443",
		"auth_mode":"oidc",
		"oidc_issuer":"",
		"oidc_client_id":""
	}`)

	cfg, err := parseMetadata(dir)
	require.NoError(t, err)
	assert.Equal(t, "", cfg.OIDCIssuer)
	assert.Equal(t, "", cfg.OIDCClientID)
}

// writeJSON is a test helper that writes a metadata.json file.
func writeJSON(t *testing.T, dir, content string) {
	t.Helper()
	err := os.WriteFile(filepath.Join(dir, "metadata.json"), []byte(content), 0o644)
	require.NoError(t, err)
}
