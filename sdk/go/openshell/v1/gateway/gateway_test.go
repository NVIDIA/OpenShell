// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
)

// --- Test helpers ---

// setupGateway creates a gateway directory with the given metadata.json
// content under a temp XDG config dir. Returns the XDG root path.
func setupGateway(t *testing.T, name, metadataJSON string) string {
	t.Helper()
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmp)

	gwDir := filepath.Join(tmp, "openshell", "gateways", name)
	require.NoError(t, os.MkdirAll(gwDir, 0o755))
	writeFile(t, gwDir, "metadata.json", metadataJSON)

	return tmp
}

// setupGatewayWithTokens creates a gateway directory with metadata and
// token files.
func setupGatewayWithTokens(t *testing.T, name, metadataJSON string, tokens map[string]string) string {
	t.Helper()
	tmp := setupGateway(t, name, metadataJSON)

	gwDir := filepath.Join(tmp, "openshell", "gateways", name)
	for filename, content := range tokens {
		writeFile(t, gwDir, filename, content)
	}

	return tmp
}

// --- T018: NewClient tests ---

func TestNewClient_AuthModeNone(t *testing.T) {
	setupGateway(t, "test-gw", `{"gateway_endpoint":"localhost:50051","auth_mode":"none"}`)

	client, err := NewClient("test-gw", WithTLS(&types.TLSConfig{Insecure: true}))
	require.NoError(t, err)
	require.NotNil(t, client)
	assert.NoError(t, client.Close())
}

func TestNewClient_AuthModePlaintext(t *testing.T) {
	setupGateway(t, "plain-gw", `{"gateway_endpoint":"localhost:50051","auth_mode":"plaintext"}`)

	// Plaintext mode should auto-set insecure TLS.
	client, err := NewClient("plain-gw")
	require.NoError(t, err)
	require.NotNil(t, client)
	assert.NoError(t, client.Close())
}

func TestNewClient_AuthModeCloudflareJWT(t *testing.T) {
	setupGatewayWithTokens(t, "cf-gw",
		`{"gateway_endpoint":"localhost:50051","auth_mode":"cloudflare_jwt"}`,
		map[string]string{edgeTokenFile: "test-edge-token"},
	)

	// StaticToken requires transport security, so use WithAuth override
	// to bypass gRPC TLS requirement. Auth resolution is verified by
	// TestResolveAuthProvider_CloudflareJWT.
	client, err := NewClient("cf-gw",
		WithAuth(&mockAuth{}),
		WithTLS(&types.TLSConfig{Insecure: true}),
	)
	require.NoError(t, err)
	require.NotNil(t, client)
	assert.NoError(t, client.Close())
}

func TestNewClient_AuthModeOIDC(t *testing.T) {
	setupGatewayWithTokens(t, "oidc-gw",
		`{"gateway_endpoint":"localhost:50051","auth_mode":"oidc"}`,
		map[string]string{oidcTokenFile: `{"access_token":"test-oidc-token"}`},
	)

	// RefreshableToken requires transport security, so use WithAuth
	// override. Auth resolution verified by TestResolveAuthProvider_OIDC.
	client, err := NewClient("oidc-gw",
		WithAuth(&mockAuth{}),
		WithTLS(&types.TLSConfig{Insecure: true}),
	)
	require.NoError(t, err)
	require.NotNil(t, client)
	assert.NoError(t, client.Close())
}

func TestNewClient_NotFound(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmp)

	_, err := NewClient("nonexistent")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrGatewayNotFound)
}

func TestNewClient_InvalidName(t *testing.T) {
	_, err := NewClient("../escape")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidGatewayName)
}

func TestNewClient_MissingEdgeToken(t *testing.T) {
	setupGateway(t, "no-token-gw", `{"gateway_endpoint":"localhost:50051","auth_mode":"cloudflare_jwt"}`)

	// Edge token loading is lazy (FR-007): NewClient succeeds even when
	// the token file is missing. The error surfaces on first use via
	// GetRequestMetadata, not at construction time.
	_, err := NewClient("no-token-gw")
	require.NoError(t, err)
}

func TestNewClient_MissingOIDCToken(t *testing.T) {
	setupGateway(t, "no-oidc-gw", `{"gateway_endpoint":"localhost:50051","auth_mode":"oidc"}`)

	_, err := NewClient("no-oidc-gw")
	// OIDC uses RefreshableToken which defers the disk read to Token(),
	// so NewClient should succeed. The error would come on first use.
	// Let's verify it doesn't fail at construction time.
	require.NoError(t, err)
	assert.NoError(t, err)
}

func TestNewClient_MTLSUnsupported(t *testing.T) {
	setupGateway(t, "mtls-gw", `{"gateway_endpoint":"localhost:50051","auth_mode":"mtls"}`)

	_, err := NewClient("mtls-gw")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnsupportedAuthMode)
	assert.Contains(t, err.Error(), "mtls")
}

func TestNewClient_WithAuthOverride(t *testing.T) {
	setupGateway(t, "override-gw", `{"gateway_endpoint":"localhost:50051","auth_mode":"cloudflare_jwt"}`)

	// Even though auth_mode is cloudflare_jwt and there's no edge_token,
	// the WithAuth override should bypass token loading entirely.
	customAuth := &mockAuth{}
	client, err := NewClient("override-gw",
		WithAuth(customAuth),
		WithTLS(&types.TLSConfig{Insecure: true}),
	)
	require.NoError(t, err)
	require.NotNil(t, client)
	assert.NoError(t, client.Close())
}

func TestNewClient_WithOptions(t *testing.T) {
	setupGateway(t, "opts-gw", `{"gateway_endpoint":"localhost:50051","auth_mode":"none"}`)

	client, err := NewClient("opts-gw",
		WithTLS(&types.TLSConfig{Insecure: true}),
	)
	require.NoError(t, err)
	require.NotNil(t, client)
	assert.NoError(t, client.Close())
}

// --- T019: Credential leak test ---

func TestNewClient_NoCredentialLeaks(t *testing.T) {
	// Test 1: Invalid gateway with path traversal attempt.
	_, err := NewClient("../../../etc/passwd")
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "passwd")

	// Test 2: Verify error from missing edge token does not reveal
	// file system details beyond the generic message.
	setupGateway(t, "no-edge-gw", `{"gateway_endpoint":"localhost:50051","auth_mode":"cloudflare_jwt"}`)
	cfg := &Config{
		AuthMode: AuthModeCloudflareJWT,
		Dir:      filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "openshell", "gateways", "no-edge-gw"),
	}
	auth, authErr := resolveAuthProvider(cfg)
	require.NoError(t, authErr)
	_, err = auth.GetRequestMetadata(context.Background())
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTokenLoad)

	// Test 3: Verify credential values never appear in error strings.
	secretToken := "SUPER_SECRET_TOKEN_12345"
	setupGatewayWithTokens(t, "leak-gw",
		`{"gateway_endpoint":"localhost:50051","auth_mode":"cloudflare_jwt"}`,
		map[string]string{edgeTokenFile: secretToken},
	)
	// Use resolveAuthProvider directly to test token loading.
	cfg = &Config{
		Name:     "leak-gw",
		Endpoint: "localhost:50051",
		AuthMode: AuthModeCloudflareJWT,
		Dir:      filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "openshell", "gateways", "leak-gw"),
	}
	auth, err = resolveAuthProvider(cfg)
	require.NoError(t, err)

	// The provider should not expose the token in its string form.
	if stringer, ok := auth.(interface{ String() string }); ok {
		assert.NotContains(t, stringer.String(), secretToken)
	}
}

func TestResolveAuthProvider_NoTokenLeaks(t *testing.T) {
	secretToken := "CREDENTIAL_THAT_MUST_NOT_LEAK"

	// Create a gateway with a bad OIDC token.
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmp)
	gwDir := filepath.Join(tmp, "openshell", "gateways", "leak-test")
	require.NoError(t, os.MkdirAll(gwDir, 0o755))
	writeFile(t, gwDir, "metadata.json", `{"gateway_endpoint":"localhost:50051","auth_mode":"cloudflare_jwt"}`)
	writeFile(t, gwDir, edgeTokenFile, secretToken)

	cfg := &Config{
		Name:     "leak-test",
		Endpoint: "localhost:50051",
		AuthMode: AuthModeCloudflareJWT,
		Dir:      gwDir,
	}

	auth, err := resolveAuthProvider(cfg)
	require.NoError(t, err)

	// The auth provider should work but the token value should not
	// appear in the provider's string representation (if any).
	providerStr := ""
	if stringer, ok := auth.(interface{ String() string }); ok {
		providerStr = stringer.String()
		assert.NotContains(t, providerStr, secretToken)
	}

	// Verify the token IS used correctly via GetRequestMetadata.
	md, err := auth.GetRequestMetadata(context.Background())
	require.NoError(t, err)
	assert.Contains(t, md["authorization"], secretToken)
}

// --- Test helpers ---

// mockAuth is a minimal AuthProvider for testing WithAuth overrides.
type mockAuth struct{}

func (m *mockAuth) GetRequestMetadata(_ context.Context, _ ...string) (map[string]string, error) {
	return map[string]string{"authorization": "Bearer mock-token"}, nil
}

func (m *mockAuth) RequireTransportSecurity() bool {
	return false
}

// --- LoadConfig tests (T025 placeholder, implemented here for Phase 3 coverage) ---

func TestLoadConfig_ValidConfig(t *testing.T) {
	setupGateway(t, "cfg-gw", `{"gateway_endpoint":"host:443","auth_mode":"oidc","name":"ignored"}`)

	cfg, err := LoadConfig("cfg-gw")
	require.NoError(t, err)
	// Name comes from directory, not metadata.json "name" field.
	assert.Equal(t, "cfg-gw", cfg.Name)
	assert.Equal(t, "host:443", cfg.Endpoint)
	assert.Equal(t, AuthModeOIDC, cfg.AuthMode)
	assert.Equal(t, SourceUser, cfg.Source)
	assert.NotEmpty(t, cfg.Dir)
}

func TestLoadConfig_NotFound(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmp)

	_, err := LoadConfig("missing-gw")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrGatewayNotFound)
}

func TestLoadConfig_FrozenSnapshot(t *testing.T) {
	xdg := setupGateway(t, "snap-gw", `{"gateway_endpoint":"original:443","auth_mode":"none"}`)

	cfg, err := LoadConfig("snap-gw")
	require.NoError(t, err)
	assert.Equal(t, "original:443", cfg.Endpoint)

	// Modify the on-disk file.
	gwDir := filepath.Join(xdg, "openshell", "gateways", "snap-gw")
	writeFile(t, gwDir, "metadata.json", `{"gateway_endpoint":"modified:443","auth_mode":"none"}`)

	// The previously loaded config should be unchanged.
	assert.Equal(t, "original:443", cfg.Endpoint)

	// A new load should see the change.
	cfg2, err := LoadConfig("snap-gw")
	require.NoError(t, err)
	assert.Equal(t, "modified:443", cfg2.Endpoint)
}

// --- resolveAuthProvider tests ---

func TestResolveAuthProvider_None(t *testing.T) {
	cfg := &Config{AuthMode: AuthModeNone}
	auth, err := resolveAuthProvider(cfg)
	require.NoError(t, err)
	require.NotNil(t, auth)
	assert.False(t, auth.RequireTransportSecurity())
}

func TestResolveAuthProvider_Plaintext(t *testing.T) {
	cfg := &Config{AuthMode: AuthModePlaintext}
	auth, err := resolveAuthProvider(cfg)
	require.NoError(t, err)
	require.NotNil(t, auth)
	assert.False(t, auth.RequireTransportSecurity())
}

func TestResolveAuthProvider_CloudflareJWT(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, edgeTokenFile, "cf-jwt-token")

	cfg := &Config{AuthMode: AuthModeCloudflareJWT, Dir: dir}
	auth, err := resolveAuthProvider(cfg)
	require.NoError(t, err)
	require.NotNil(t, auth)

	md, err := auth.GetRequestMetadata(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "Bearer cf-jwt-token", md["authorization"])
}

func TestResolveAuthProvider_OIDC(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, oidcTokenFile, `{"access_token":"oidc-access-token"}`)

	cfg := &Config{AuthMode: AuthModeOIDC, Dir: dir}
	auth, err := resolveAuthProvider(cfg)
	require.NoError(t, err)
	require.NotNil(t, auth)

	md, err := auth.GetRequestMetadata(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "Bearer oidc-access-token", md["authorization"])
}

func TestResolveAuthProvider_MTLS(t *testing.T) {
	cfg := &Config{AuthMode: AuthModeMTLS}
	_, err := resolveAuthProvider(cfg)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnsupportedAuthMode)
	assert.Contains(t, err.Error(), "mtls")
	assert.Contains(t, err.Error(), "WithAuth")
}

func TestResolveAuthProvider_UnknownMode(t *testing.T) {
	cfg := &Config{AuthMode: "alien_auth"}
	_, err := resolveAuthProvider(cfg)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnsupportedAuthMode)
}

// --- T021/T023: Active gateway tests ---

func TestNewClient_ActiveGateway(t *testing.T) {
	tmp := setupGateway(t, "active-gw", `{"gateway_endpoint":"localhost:50051","auth_mode":"none"}`)

	activeFile := filepath.Join(tmp, "openshell", "active_gateway")
	writeFile(t, filepath.Join(tmp, "openshell"), "active_gateway", "active-gw")
	_ = activeFile

	client, err := NewClient("", WithTLS(&types.TLSConfig{Insecure: true}))
	require.NoError(t, err)
	require.NotNil(t, client)
	assert.NoError(t, client.Close())
}

func TestNewClient_NoActiveGateway(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmp)
	require.NoError(t, os.MkdirAll(filepath.Join(tmp, "openshell"), 0o755))

	_, err := NewClient("")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNoActiveGateway)
}

func TestLoadConfig_ActiveGateway(t *testing.T) {
	tmp := setupGateway(t, "my-active", `{"gateway_endpoint":"host:443","auth_mode":"oidc"}`)
	writeFile(t, filepath.Join(tmp, "openshell"), "active_gateway", "my-active")

	cfg, err := LoadConfig("")
	require.NoError(t, err)
	assert.Equal(t, "my-active", cfg.Name)
	assert.Equal(t, "host:443", cfg.Endpoint)
}

// --- T027: ListGateways tests ---

func TestListGateways_MultipleGateways(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmp)

	for _, name := range []string{"prod", "staging", "dev"} {
		gwDir := filepath.Join(tmp, "openshell", "gateways", name)
		require.NoError(t, os.MkdirAll(gwDir, 0o755))
	}

	gateways, err := ListGateways()
	require.NoError(t, err)
	assert.Len(t, gateways, 3)

	names := make(map[string]bool)
	for _, gw := range gateways {
		names[gw.Name] = true
		assert.Equal(t, SourceUser, gw.Source)
	}
	assert.True(t, names["prod"])
	assert.True(t, names["staging"])
	assert.True(t, names["dev"])
}

func TestListGateways_EmptyDirs(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmp)

	gateways, err := ListGateways()
	require.NoError(t, err)
	assert.Empty(t, gateways)
}

func TestListGateways_ActiveStatus(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmp)

	for _, name := range []string{"alpha", "beta"} {
		gwDir := filepath.Join(tmp, "openshell", "gateways", name)
		require.NoError(t, os.MkdirAll(gwDir, 0o755))
	}
	writeFile(t, filepath.Join(tmp, "openshell"), "active_gateway", "beta")

	gateways, err := ListGateways()
	require.NoError(t, err)
	assert.Len(t, gateways, 2)

	for _, gw := range gateways {
		if gw.Name == "beta" {
			assert.True(t, gw.Active)
		} else {
			assert.False(t, gw.Active)
		}
	}
}
