// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/gateway"
)

type clientCredentialsFixture struct {
	Request struct {
		GrantType    string   `json:"grant_type"`
		ClientID     string   `json:"client_id"`
		ClientSecret string   `json:"client_secret"`
		Scopes       []string `json:"scopes"`
		Scope        string   `json:"scope"`
		Audience     string   `json:"audience"`
	} `json:"request"`
	Expiry struct {
		LeewaySeconds    int               `json:"leeway_seconds"`
		ValidExpiresIn   int64             `json:"valid_expires_in"`
		InvalidExpiresIn []json.RawMessage `json:"invalid_expires_in"`
	} `json:"expiry"`
	Discovery struct {
		ConfiguredIssuer string `json:"configured_issuer"`
		MatchingIssuer   string `json:"matching_issuer"`
		MismatchedIssuer string `json:"mismatched_issuer"`
		RedirectStatuses []int  `json:"redirect_statuses"`
	} `json:"discovery"`
	Limits struct {
		MaxResponseBytes int `json:"max_response_bytes"`
	} `json:"limits"`
	URLs struct {
		Allowed  []string `json:"allowed"`
		Rejected []string `json:"rejected"`
	} `json:"urls"`
}

func loadClientCredentialsFixture(t *testing.T) clientCredentialsFixture {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "conformance", "oauth-client-credentials.json"))
	require.NoError(t, err)
	var fixture clientCredentialsFixture
	require.NoError(t, json.Unmarshal(data, &fixture))
	return fixture
}

func TestClientCredentialsConformanceFixture(t *testing.T) {
	fixture := loadClientCredentialsFixture(t)
	assert.Equal(t, int(clientCredentialsLeeway/time.Second), fixture.Expiry.LeewaySeconds)
	for _, raw := range fixture.URLs.Allowed {
		assert.NoError(t, validateSecureURL("issuer", raw), raw)
	}
	for _, raw := range fixture.URLs.Rejected {
		assert.Error(t, validateSecureURL("issuer", raw), raw)
	}
}

func TestClientCredentialsRejectsInvalidExpiryConformance(t *testing.T) {
	fixture := loadClientCredentialsFixture(t)
	for _, raw := range fixture.Expiry.InvalidExpiresIn {
		raw := raw
		t.Run(string(raw), func(t *testing.T) {
			resetDiscoveryCache()
			var server *httptest.Server
			server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/.well-known/openid-configuration" {
					_ = json.NewEncoder(w).Encode(map[string]string{
						"issuer":                 server.URL,
						"authorization_endpoint": server.URL + "/authorize",
						"token_endpoint":         server.URL + "/token",
					})
					return
				}
				_, _ = fmt.Fprintf(w, `{"access_token":"sensitive-access-token","expires_in":%s}`, raw)
			}))
			t.Cleanup(server.Close)

			_, err := ClientCredentials(
				context.Background(),
				WithIssuer(server.URL),
				WithClientID("client"),
				WithClientSecret("secret"),
			)
			require.Error(t, err)
			assert.NotContains(t, err.Error(), "sensitive-access-token")
		})
	}
}

func TestClientCredentialsMissingExpiryCompatibility(t *testing.T) {
	resetDiscoveryCache()
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			_ = json.NewEncoder(w).Encode(map[string]string{
				"issuer":                 server.URL,
				"authorization_endpoint": server.URL + "/authorize",
				"token_endpoint":         server.URL + "/token",
			})
			return
		}
		_, _ = w.Write([]byte(`{"access_token":"token","token_type":"Bearer"}`))
	}))
	t.Cleanup(server.Close)

	opts := []LoginOption{
		WithIssuer(server.URL),
		WithClientID("client"),
		WithClientSecret("secret"),
	}
	token, err := ClientCredentials(context.Background(), opts...)
	require.NoError(t, err)
	assert.True(t, token.Expiry.IsZero())

	auth, err := NewClientCredentialsAuth(opts...)
	require.NoError(t, err)
	metadata, err := auth.GetRequestMetadata(context.Background())
	require.Error(t, err)
	assert.Nil(t, metadata)
	assert.Contains(t, err.Error(), "positive expires_in")
}

func TestClientCredentialsRefusesRedirectsConformance(t *testing.T) {
	fixture := loadClientCredentialsFixture(t)
	for _, status := range fixture.Discovery.RedirectStatuses {
		status := status
		for _, endpoint := range []string{"discovery", "token"} {
			endpoint := endpoint
			t.Run(fmt.Sprintf("%s_%d", endpoint, status), func(t *testing.T) {
				resetDiscoveryCache()
				var server *httptest.Server
				var redirected atomic.Bool
				server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					switch r.URL.Path {
					case "/.well-known/openid-configuration":
						if endpoint == "discovery" {
							w.Header().Set("Location", server.URL+"/redirected")
							w.WriteHeader(status)
							return
						}
						_ = json.NewEncoder(w).Encode(map[string]string{
							"issuer":                 server.URL,
							"authorization_endpoint": server.URL + "/authorize",
							"token_endpoint":         server.URL + "/token",
						})
					case "/token":
						w.Header().Set("Location", server.URL+"/redirected")
						w.WriteHeader(status)
					case "/redirected":
						redirected.Store(true)
					}
				}))
				t.Cleanup(server.Close)

				_, err := ClientCredentials(
					context.Background(),
					WithIssuer(server.URL),
					WithClientID("client"),
					WithClientSecret("secret"),
				)
				require.Error(t, err)
				assert.False(t, redirected.Load())
			})
		}
	}
}

func TestClientCredentialsRejectsMismatchedIssuerConformance(t *testing.T) {
	resetDiscoveryCache()
	fixture := loadClientCredentialsFixture(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 fixture.Discovery.MismatchedIssuer,
			"authorization_endpoint": fixture.Discovery.MismatchedIssuer + "/authorize",
			"token_endpoint":         fixture.Discovery.MismatchedIssuer + "/token",
		})
	}))
	t.Cleanup(server.Close)

	_, err := ClientCredentials(
		context.Background(),
		WithIssuer(server.URL),
		WithClientID("client"),
		WithClientSecret("secret"),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "issuer")
}

func TestClientCredentialsRejectsOversizedResponseConformance(t *testing.T) {
	resetDiscoveryCache()
	fixture := loadClientCredentialsFixture(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(make([]byte, fixture.Limits.MaxResponseBytes+1))
	}))
	t.Cleanup(server.Close)

	_, err := ClientCredentials(
		context.Background(),
		WithIssuer(server.URL),
		WithClientID("client"),
		WithClientSecret("secret"),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too large")
}

func TestClientCredentialsAuthSingleFlightRenewalAndFields(t *testing.T) {
	resetDiscoveryCache()
	fixture := loadClientCredentialsFixture(t)
	var server *httptest.Server
	var calls atomic.Int32
	var formsMu sync.Mutex
	var forms []url.Values
	release := make(chan struct{})
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			_ = json.NewEncoder(w).Encode(map[string]string{
				"issuer":                 server.URL,
				"authorization_endpoint": server.URL + "/authorize",
				"token_endpoint":         server.URL + "/token",
			})
			return
		}
		if calls.Add(1) == 1 {
			<-release
		}
		require.NoError(t, r.ParseForm())
		formsMu.Lock()
		forms = append(forms, r.Form)
		formsMu.Unlock()
		_, _ = w.Write([]byte(tokenResponseJSON("token", "", 3600)))
	}))
	t.Cleanup(server.Close)

	auth, err := NewClientCredentialsAuth(
		WithIssuer(server.URL),
		WithClientID(fixture.Request.ClientID),
		WithClientSecret(fixture.Request.ClientSecret),
		WithScopes(fixture.Request.Scopes...),
		WithAudience(fixture.Request.Audience),
	)
	require.NoError(t, err)
	assert.NotContains(t, fmt.Sprintf("%#v", auth), "secret")

	results := make(chan error, 12)
	for range 12 {
		go func() {
			metadata, callErr := auth.GetRequestMetadata(context.Background())
			if callErr == nil && metadata["authorization"] != "Bearer token" {
				callErr = errors.New("unexpected authorization metadata")
			}
			results <- callErr
		}()
	}
	require.Eventually(t, func() bool { return calls.Load() == 1 }, time.Second, time.Millisecond)
	close(release)
	for range 12 {
		require.NoError(t, <-results)
	}
	assert.Equal(t, int32(1), calls.Load())
	require.Len(t, forms, 1)
	assert.Equal(t, fixture.Request.GrantType, forms[0].Get("grant_type"))
	assert.Equal(t, fixture.Request.ClientID, forms[0].Get("client_id"))
	assert.Equal(t, fixture.Request.ClientSecret, forms[0].Get("client_secret"))
	assert.Equal(t, fixture.Request.Scope, forms[0].Get("scope"))
	assert.Equal(t, fixture.Request.Audience, forms[0].Get("audience"))

	concrete := auth.(*clientCredentialsAuth)
	concrete.mu.Lock()
	concrete.token.Expiry = time.Now()
	concrete.mu.Unlock()
	_, err = auth.GetRequestMetadata(context.Background())
	require.NoError(t, err)
	assert.Equal(t, int32(2), calls.Load())
}

func TestClientCredentialsAuthLateFlightReusesCachedToken(t *testing.T) {
	auth := &clientCredentialsAuth{
		token: &oauth2.Token{
			AccessToken: "cached-token",
			Expiry:      time.Now().Add(time.Hour),
		},
	}

	accessToken, err := auth.accessTokenForExchange()
	require.NoError(t, err)
	assert.Equal(t, "cached-token", accessToken)
}

func TestClientCredentialsAuthCancellationDoesNotPoisonSharedExchange(t *testing.T) {
	resetDiscoveryCache()
	var server *httptest.Server
	started := make(chan struct{})
	release := make(chan struct{})
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			_ = json.NewEncoder(w).Encode(map[string]string{
				"issuer":                 server.URL,
				"authorization_endpoint": server.URL + "/authorize",
				"token_endpoint":         server.URL + "/token",
			})
			return
		}
		close(started)
		<-release
		_, _ = w.Write([]byte(tokenResponseJSON("token", "", 3600)))
	}))
	t.Cleanup(server.Close)
	auth, err := NewClientCredentialsAuth(
		WithIssuer(server.URL), WithClientID("client"), WithClientSecret("secret"),
	)
	require.NoError(t, err)

	canceled, cancel := context.WithCancel(context.Background())
	first := make(chan error, 1)
	go func() {
		_, callErr := auth.GetRequestMetadata(canceled)
		first <- callErr
	}()
	<-started
	second := make(chan error, 1)
	go func() {
		_, callErr := auth.GetRequestMetadata(context.Background())
		second <- callErr
	}()
	cancel()
	assert.ErrorIs(t, <-first, context.Canceled)
	close(release)
	require.NoError(t, <-second)
}

func TestClientCredentialsAuthRedactsSecretProviderError(t *testing.T) {
	auth, err := NewClientCredentialsAuth(
		WithIssuer("http://localhost:8080"),
		WithClientID("client"),
		WithClientSecretProvider(func(context.Context) (string, error) {
			return "", errors.New("supplier-sensitive-detail")
		}),
	)
	require.NoError(t, err)
	_, err = auth.GetRequestMetadata(context.Background())
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "supplier-sensitive-detail")
}

func TestClientCredentialsAuthFailsClosedOnRenewalError(t *testing.T) {
	resetDiscoveryCache()
	var server *httptest.Server
	var fail atomic.Bool
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			_ = json.NewEncoder(w).Encode(map[string]string{
				"issuer":                 server.URL,
				"authorization_endpoint": server.URL + "/authorize",
				"token_endpoint":         server.URL + "/token",
			})
			return
		}
		if fail.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error":"provider-sensitive-detail"}`))
			return
		}
		_, _ = w.Write([]byte(tokenResponseJSON("stale", "", 3600)))
	}))
	t.Cleanup(server.Close)
	auth, err := NewClientCredentialsAuth(
		WithIssuer(server.URL), WithClientID("client"), WithClientSecret("secret"),
	)
	require.NoError(t, err)
	_, err = auth.GetRequestMetadata(context.Background())
	require.NoError(t, err)
	concrete := auth.(*clientCredentialsAuth)
	concrete.mu.Lock()
	concrete.token.Expiry = time.Now()
	concrete.mu.Unlock()
	fail.Store(true)
	metadata, err := auth.GetRequestMetadata(context.Background())
	require.Error(t, err)
	assert.Nil(t, metadata)
	assert.NotContains(t, err.Error(), "stale")
	assert.NotContains(t, err.Error(), "provider-sensitive-detail")
}

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
