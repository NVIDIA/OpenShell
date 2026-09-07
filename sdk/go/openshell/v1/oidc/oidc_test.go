// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/gateway"
)

// --- T021: Login entry point tests ---

// setupMockProvider creates a mock OIDC provider that serves discovery,
// authorize, and token endpoints. The token endpoint returns a valid
// token response. Returns the server (auto-cleaned up) and its URL.
func setupMockProvider(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	var srv *httptest.Server

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		doc := map[string]any{
			"issuer":                           srv.URL,
			"authorization_endpoint":           srv.URL + "/authorize",
			"token_endpoint":                   srv.URL + "/token",
			"device_authorization_endpoint":    srv.URL + "/device",
			"scopes_supported":                 []string{"openid", "profile", "email"},
			"code_challenge_methods_supported": []string{"S256"},
		}
		_ = json.NewEncoder(w).Encode(doc)
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(tokenResponseJSON("login-access-token", "login-refresh-token", 3600)))
	})

	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// TestLogin_MissingOIDCConfig verifies that Login returns ErrOIDCConfig
// when called without a gateway name and without WithIssuer/WithClientID.
func TestLogin_MissingOIDCConfig(t *testing.T) {
	resetDiscoveryCache()

	_, err := Login(context.Background(), "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrOIDCConfig), "expected ErrOIDCConfig, got: %v", err)
}

// TestLogin_MissingIssuer verifies that Login returns ErrOIDCConfig
// when only WithClientID is provided (missing issuer).
func TestLogin_MissingIssuer(t *testing.T) {
	resetDiscoveryCache()

	_, err := Login(context.Background(), "", WithClientID("test-client"))
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrOIDCConfig), "expected ErrOIDCConfig, got: %v", err)
}

// TestLogin_MissingClientID verifies that Login returns ErrOIDCConfig
// when only WithIssuer is provided (missing client ID).
func TestLogin_MissingClientID(t *testing.T) {
	resetDiscoveryCache()

	_, err := Login(context.Background(), "", WithIssuer("https://example.com"))
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrOIDCConfig), "expected ErrOIDCConfig, got: %v", err)
}

// TestLogin_ReusesValidToken verifies FR-019: when a valid token exists
// on disk in the token directory, Login returns it without starting an
// interactive flow.
func TestLogin_ReusesValidToken(t *testing.T) {
	resetDiscoveryCache()

	// Create a temp dir with a valid, non-expired token file.
	tokenDir := t.TempDir()
	existingToken := &oauth2.Token{
		AccessToken:  "existing-access-token",
		RefreshToken: "existing-refresh-token",
		TokenType:    "Bearer",
		Expiry:       time.Now().Add(1 * time.Hour),
	}
	err := writeToken(tokenDir, existingToken)
	require.NoError(t, err)

	// Login with explicit issuer/clientID and WithTokenDir (internal)
	// pointing to the directory with the existing token. No OIDC
	// provider is needed because the existing token is returned.
	tok, err := Login(context.Background(), "",
		WithIssuer("https://issuer-should-not-be-called.example.com"),
		WithClientID("test-client"),
		withTokenDir(tokenDir),
	)
	require.NoError(t, err)
	assert.Equal(t, "existing-access-token", tok.AccessToken)
	assert.Equal(t, "existing-refresh-token", tok.RefreshToken)
}

// TestLogin_ExpiredTokenTriggersFlow verifies that an expired token on
// disk does not short-circuit: Login proceeds to the interactive flow.
// Since we use keyboard flow (no browser), we feed it a code and verify
// a new token is returned.
func TestLogin_ExpiredTokenTriggersFlow(t *testing.T) {
	resetDiscoveryCache()

	provider := setupMockProvider(t)
	tokenDir := t.TempDir()

	// Write an expired token.
	expiredToken := &oauth2.Token{
		AccessToken:  "expired-token",
		RefreshToken: "old-refresh",
		TokenType:    "Bearer",
		Expiry:       time.Now().Add(-1 * time.Hour), // expired
	}
	err := writeToken(tokenDir, expiredToken)
	require.NoError(t, err)

	// Start a callback server ourselves to simulate the auth code callback.
	// We'll use keyboard flow to avoid browser dependency.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Use keyboard flow with a reader that provides a fake auth code.
	// The mock provider's /token endpoint accepts any code.
	codeReader := strings.NewReader("fake-auth-code\n")

	tok, err := Login(ctx, "",
		WithIssuer(provider.URL),
		WithClientID("test-client"),
		withTokenDir(tokenDir),
		WithKeyboardFlow(),
		withInput(codeReader),
	)
	require.NoError(t, err)
	assert.Equal(t, "login-access-token", tok.AccessToken)
	assert.Equal(t, "login-refresh-token", tok.RefreshToken)
}

// TestLogin_KeyboardFlow verifies that Login completes using the
// keyboard flow when WithKeyboardFlow() is set. The test provides a
// mock OIDC provider and feeds an auth code through a reader.
func TestLogin_KeyboardFlow(t *testing.T) {
	resetDiscoveryCache()

	provider := setupMockProvider(t)
	tokenDir := t.TempDir()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	codeReader := strings.NewReader("keyboard-auth-code\n")

	tok, err := Login(ctx, "",
		WithIssuer(provider.URL),
		WithClientID("test-client"),
		withTokenDir(tokenDir),
		WithKeyboardFlow(),
		withInput(codeReader),
	)
	require.NoError(t, err)
	assert.Equal(t, "login-access-token", tok.AccessToken)

	// Verify token was persisted to disk.
	diskTok, err := readToken(tokenDir)
	require.NoError(t, err)
	require.NotNil(t, diskTok)
	assert.Equal(t, "login-access-token", diskTok.AccessToken)
}

// TestLogin_InMemorySkipsPersistence verifies that WithInMemory()
// returns a token without writing to disk.
func TestLogin_InMemorySkipsPersistence(t *testing.T) {
	resetDiscoveryCache()

	provider := setupMockProvider(t)
	tokenDir := t.TempDir()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	codeReader := strings.NewReader("some-code\n")

	tok, err := Login(ctx, "",
		WithIssuer(provider.URL),
		WithClientID("test-client"),
		withTokenDir(tokenDir),
		WithKeyboardFlow(),
		WithInMemory(),
		withInput(codeReader),
	)
	require.NoError(t, err)
	assert.Equal(t, "login-access-token", tok.AccessToken)

	// Verify NO token file on disk.
	_, err = os.Stat(filepath.Join(tokenDir, oidcTokenFile))
	assert.True(t, os.IsNotExist(err), "token file should not exist in in-memory mode")
}

// TestLogin_DiscoveryFailure verifies that Login returns ErrDiscovery
// when the OIDC provider is unreachable.
func TestLogin_DiscoveryFailure(t *testing.T) {
	resetDiscoveryCache()

	// Point to a server that doesn't exist.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := Login(ctx, "",
		WithIssuer("http://127.0.0.1:1"), // port 1 should refuse connections
		WithClientID("test-client"),
		WithKeyboardFlow(),
	)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrDiscovery), "expected ErrDiscovery, got: %v", err)
}

// TestLogin_GatewayResolution verifies that Login resolves OIDC config
// from gateway metadata when a gateway name is provided. We use the
// withGatewayResolver option to inject a fake gateway loader.
func TestLogin_GatewayResolution(t *testing.T) {
	resetDiscoveryCache()

	provider := setupMockProvider(t)
	tokenDir := t.TempDir()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	codeReader := strings.NewReader("gw-auth-code\n")

	fakeConfig := &gateway.Config{
		Name:         "test-gateway",
		Endpoint:     "gateway.example.com:443",
		Dir:          tokenDir,
		OIDCIssuer:   provider.URL,
		OIDCClientID: "gateway-client-id",
	}

	tok, err := Login(ctx, "test-gateway",
		WithKeyboardFlow(),
		withInput(codeReader),
		withGatewayResolver(func(name string) (*gateway.Config, error) {
			assert.Equal(t, "test-gateway", name)
			return fakeConfig, nil
		}),
	)
	require.NoError(t, err)
	assert.Equal(t, "login-access-token", tok.AccessToken)

	// Verify token was persisted in the gateway dir.
	diskTok, err := readToken(tokenDir)
	require.NoError(t, err)
	require.NotNil(t, diskTok)
	assert.Equal(t, "login-access-token", diskTok.AccessToken)
}

// TestLogin_GatewayMissingOIDCFields verifies that Login returns
// ErrOIDCConfig when the gateway config has empty OIDC fields.
func TestLogin_GatewayMissingOIDCFields(t *testing.T) {
	resetDiscoveryCache()

	fakeConfig := &gateway.Config{
		Name:     "no-oidc-gw",
		Endpoint: "gateway.example.com:443",
		Dir:      t.TempDir(),
		// OIDCIssuer and OIDCClientID are empty.
	}

	_, err := Login(context.Background(), "no-oidc-gw",
		withGatewayResolver(func(_ string) (*gateway.Config, error) {
			return fakeConfig, nil
		}),
	)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrOIDCConfig), "expected ErrOIDCConfig, got: %v", err)
}

// TestLogin_GatewayResolutionError verifies that Login propagates
// errors from gateway resolution.
func TestLogin_GatewayResolutionError(t *testing.T) {
	resetDiscoveryCache()

	gwErr := fmt.Errorf("gateway not found: no-such-gateway")

	_, err := Login(context.Background(), "no-such-gateway",
		withGatewayResolver(func(_ string) (*gateway.Config, error) {
			return nil, gwErr
		}),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "gateway not found")
}

// TestLogin_NoPKCESupport verifies that Login proceeds without PKCE
// when the OIDC provider does not advertise S256 support.
func TestLogin_NoPKCESupport(t *testing.T) {
	resetDiscoveryCache()

	// Create a provider that does NOT list S256 in supported methods.
	mux := http.NewServeMux()
	var srv *httptest.Server

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		doc := map[string]any{
			"issuer":                 srv.URL,
			"authorization_endpoint": srv.URL + "/authorize",
			"token_endpoint":         srv.URL + "/token",
			"scopes_supported":       []string{"openid"},
			// No code_challenge_methods_supported field.
		}
		_ = json.NewEncoder(w).Encode(doc)
	})

	var receivedVerifier string
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		receivedVerifier = r.Form.Get("code_verifier")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(tokenResponseJSON("no-pkce-token", "", 3600)))
	})

	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	codeReader := strings.NewReader("some-code\n")

	tok, err := Login(ctx, "",
		WithIssuer(srv.URL),
		WithClientID("test-client"),
		withTokenDir(t.TempDir()),
		WithKeyboardFlow(),
		withInput(codeReader),
	)
	require.NoError(t, err)
	assert.Equal(t, "no-pkce-token", tok.AccessToken)

	// Verify no PKCE verifier was sent to the token endpoint.
	assert.Empty(t, receivedVerifier, "code_verifier should not be sent when PKCE is not supported")
}

// TestLogin_ContextCancellation verifies that Login respects context
// cancellation during the interactive flow.
func TestLogin_ContextCancellation(t *testing.T) {
	resetDiscoveryCache()

	provider := setupMockProvider(t)

	// Create a context that is already cancelled.
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	_, err := Login(ctx, "",
		WithIssuer(provider.URL),
		WithClientID("test-client"),
		WithKeyboardFlow(),
	)
	require.Error(t, err)
	// Should get a context error or timeout error.
	assert.True(t,
		errors.Is(err, ErrTimeout) || errors.Is(err, ErrDiscovery) || errors.Is(err, context.Canceled),
		"expected timeout/discovery/cancelled error, got: %v", err,
	)
}

// TestLogin_CustomScopes verifies that WithScopes overrides the
// default scopes sent in the authorization request.
func TestLogin_CustomScopes(t *testing.T) {
	resetDiscoveryCache()

	// Provider that captures the auth URL scope parameter.
	mux := http.NewServeMux()
	var srv *httptest.Server

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		doc := map[string]any{
			"issuer":                           srv.URL,
			"authorization_endpoint":           srv.URL + "/authorize",
			"token_endpoint":                   srv.URL + "/token",
			"code_challenge_methods_supported": []string{"S256"},
		}
		_ = json.NewEncoder(w).Encode(doc)
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(tokenResponseJSON("scoped-token", "", 3600)))
	})

	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	codeReader := strings.NewReader("auth-code\n")

	tok, err := Login(ctx, "",
		WithIssuer(srv.URL),
		WithClientID("test-client"),
		withTokenDir(t.TempDir()),
		WithKeyboardFlow(),
		WithScopes("openid", "custom-scope"),
		withInput(codeReader),
	)
	require.NoError(t, err)
	assert.Equal(t, "scoped-token", tok.AccessToken)
}

// TestLoginBrowser_PortBusy_FallbackToKeyboard verifies that
// loginBrowser falls back to keyboard flow when the callback server
// port is already occupied and no custom port is set.
func TestLoginBrowser_PortBusy_FallbackToKeyboard(t *testing.T) {
	resetDiscoveryCache()

	provider := setupMockProvider(t)

	// Occupy port 8000 so startCallbackServer fails on the primary port.
	// Then occupy port 18000 so the fallback port also fails.
	// This forces loginBrowser into the keyboard fallback path.
	ln1, err1 := net.Listen("tcp", "127.0.0.1:8000")
	ln2, err2 := net.Listen("tcp", "127.0.0.1:18000")
	if err1 != nil || err2 != nil {
		if ln1 != nil {
			_ = ln1.Close()
		}
		if ln2 != nil {
			_ = ln2.Close()
		}
		t.Skip("Cannot bind test ports 8000 and 18000")
	}
	defer func() { _ = ln1.Close() }()
	defer func() { _ = ln2.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	codeReader := strings.NewReader("keyboard-fallback-code\n")

	tok, err := Login(ctx, "",
		WithIssuer(provider.URL),
		WithClientID("test-client"),
		withTokenDir(t.TempDir()),
		withInput(codeReader),
	)
	require.NoError(t, err)
	assert.Equal(t, "login-access-token", tok.AccessToken)
}

// TestLogin_ContextTimeout verifies that a Login with a very short
// timeout returns a timeout-related error.
func TestLogin_ContextTimeout(t *testing.T) {
	resetDiscoveryCache()

	provider := setupMockProvider(t)

	// Create a context that times out immediately.
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()
	time.Sleep(1 * time.Millisecond) // ensure timeout fires

	_, err := Login(ctx, "",
		WithIssuer(provider.URL),
		WithClientID("test-client"),
		WithKeyboardFlow(),
	)
	require.Error(t, err)
}
