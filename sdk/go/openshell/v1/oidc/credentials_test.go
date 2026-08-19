// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/gateway"
)

// --- T023: Client credentials tests ---

// setupCredentialsMockProvider creates a mock OIDC provider for client
// credentials testing. The token endpoint validates Basic Auth and
// returns a token response. Returns the server and the expected
// client ID / client secret pair.
func setupCredentialsMockProvider(t *testing.T, expectedClientID, expectedSecret string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	var srv *httptest.Server

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		doc := map[string]any{
			"issuer":                 srv.URL,
			"authorization_endpoint": srv.URL + "/authorize",
			"token_endpoint":         srv.URL + "/token",
		}
		_ = json.NewEncoder(w).Encode(doc)
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()

		// Validate grant type.
		if r.Form.Get("grant_type") != "client_credentials" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"unsupported_grant_type","error_description":"expected client_credentials"}`))
			return
		}

		// Check credentials from form body (client_id + client_secret)
		// or Basic Auth header.
		clientID := r.Form.Get("client_id")
		clientSecret := r.Form.Get("client_secret")
		if clientID == "" || clientSecret == "" {
			// Try Basic Auth.
			var ok bool
			clientID, clientSecret, ok = r.BasicAuth()
			if !ok {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"invalid_client","error_description":"missing credentials"}`))
				return
			}
		}

		if clientID != expectedClientID || clientSecret != expectedSecret {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"invalid_client","error_description":"invalid credentials"}`))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(tokenResponseJSON("cc-access-token", "", 3600)))
	})

	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// TestClientCredentials_Success verifies the happy path: valid client
// ID, secret, and issuer produce a valid access token.
func TestClientCredentials_Success(t *testing.T) {
	resetDiscoveryCache()

	provider := setupCredentialsMockProvider(t, "my-client", "my-secret")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tok, err := ClientCredentials(ctx,
		WithIssuer(provider.URL),
		WithClientID("my-client"),
		WithClientSecret("my-secret"),
	)
	require.NoError(t, err)
	assert.Equal(t, "cc-access-token", tok.AccessToken)
	assert.Empty(t, tok.RefreshToken, "client credentials should not return a refresh token")
}

// TestClientCredentials_MissingIssuer verifies that ClientCredentials
// returns ErrOIDCConfig when the issuer is not set.
func TestClientCredentials_MissingIssuer(t *testing.T) {
	resetDiscoveryCache()

	_, err := ClientCredentials(context.Background(),
		WithClientID("my-client"),
		WithClientSecret("my-secret"),
	)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrOIDCConfig), "expected ErrOIDCConfig, got: %v", err)
}

// TestClientCredentials_MissingClientID verifies that ClientCredentials
// returns ErrOIDCConfig when the client ID is not set.
func TestClientCredentials_MissingClientID(t *testing.T) {
	resetDiscoveryCache()

	_, err := ClientCredentials(context.Background(),
		WithIssuer("https://example.com"),
		WithClientSecret("my-secret"),
	)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrOIDCConfig), "expected ErrOIDCConfig, got: %v", err)
}

// TestClientCredentials_MissingClientSecret verifies that
// ClientCredentials returns ErrClientCredentials when the secret is
// missing.
func TestClientCredentials_MissingClientSecret(t *testing.T) {
	resetDiscoveryCache()

	_, err := ClientCredentials(context.Background(),
		WithIssuer("https://example.com"),
		WithClientID("my-client"),
	)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrClientCredentials), "expected ErrClientCredentials, got: %v", err)
}

// TestClientCredentials_InvalidCredentials verifies that
// ClientCredentials returns ErrClientCredentials when the provider
// rejects the credentials, and that the secret is not leaked in the
// error message.
func TestClientCredentials_InvalidCredentials(t *testing.T) {
	resetDiscoveryCache()

	provider := setupCredentialsMockProvider(t, "good-client", "good-secret")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := ClientCredentials(ctx,
		WithIssuer(provider.URL),
		WithClientID("good-client"),
		WithClientSecret("wrong-secret"),
	)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrClientCredentials), "expected ErrClientCredentials, got: %v", err)

	// FR-014: The secret must NEVER appear in error messages.
	assert.NotContains(t, err.Error(), "wrong-secret", "secret must not leak in error message")
	assert.NotContains(t, err.Error(), "good-secret", "secret must not leak in error message")
}

// TestClientCredentials_DiscoveryFailure verifies that
// ClientCredentials returns ErrDiscovery when the provider is
// unreachable.
func TestClientCredentials_DiscoveryFailure(t *testing.T) {
	resetDiscoveryCache()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := ClientCredentials(ctx,
		WithIssuer("http://127.0.0.1:1"),
		WithClientID("my-client"),
		WithClientSecret("my-secret"),
	)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrDiscovery), "expected ErrDiscovery, got: %v", err)
}

// TestClientCredentials_WithGateway verifies that ClientCredentials
// resolves OIDC config from gateway metadata when WithGateway is set.
func TestClientCredentials_WithGateway(t *testing.T) {
	resetDiscoveryCache()

	provider := setupCredentialsMockProvider(t, "gw-client", "gw-secret")

	fakeConfig := &gateway.Config{
		Name:         "cc-gateway",
		Endpoint:     "gateway.example.com:443",
		Dir:          t.TempDir(),
		OIDCIssuer:   provider.URL,
		OIDCClientID: "gw-client",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tok, err := ClientCredentials(ctx,
		WithGateway("cc-gateway"),
		WithClientSecret("gw-secret"),
		withGatewayResolver(func(name string) (*gateway.Config, error) {
			assert.Equal(t, "cc-gateway", name)
			return fakeConfig, nil
		}),
	)
	require.NoError(t, err)
	assert.Equal(t, "cc-access-token", tok.AccessToken)
}

// TestClientCredentials_CustomScopes verifies that WithScopes overrides
// default scopes in the client credentials request.
func TestClientCredentials_CustomScopes(t *testing.T) {
	resetDiscoveryCache()

	var receivedScope string
	mux := http.NewServeMux()
	var srv *httptest.Server

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		doc := map[string]any{
			"issuer":                 srv.URL,
			"authorization_endpoint": srv.URL + "/authorize",
			"token_endpoint":         srv.URL + "/token",
		}
		_ = json.NewEncoder(w).Encode(doc)
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		receivedScope = r.Form.Get("scope")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(tokenResponseJSON("scoped-cc-token", "", 3600)))
	})

	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tok, err := ClientCredentials(ctx,
		WithIssuer(srv.URL),
		WithClientID("my-client"),
		WithClientSecret("my-secret"),
		WithScopes("api:read", "api:write"),
	)
	require.NoError(t, err)
	assert.Equal(t, "scoped-cc-token", tok.AccessToken)
	assert.Equal(t, "api:read api:write", receivedScope)
}

// TestClientCredentials_ContextCancellation verifies that
// ClientCredentials respects context cancellation.
func TestClientCredentials_ContextCancellation(t *testing.T) {
	resetDiscoveryCache()

	provider := setupCredentialsMockProvider(t, "my-client", "my-secret")

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	_, err := ClientCredentials(ctx,
		WithIssuer(provider.URL),
		WithClientID("my-client"),
		WithClientSecret("my-secret"),
	)
	require.Error(t, err)
}
