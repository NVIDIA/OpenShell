// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/gateway"
)

// --- T025: Device code flow tests ---

// setupDeviceMockProvider creates a mock OIDC provider for device code
// flow testing. The device authorization endpoint returns a device code
// and verification URL. The token endpoint simulates polling behavior:
// it returns "authorization_pending" for the first N polls, then returns
// a valid token response.
func setupDeviceMockProvider(t *testing.T, pendingPolls int) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	var srv *httptest.Server
	var pollCount atomic.Int32

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		doc := map[string]any{
			"issuer":                           srv.URL,
			"authorization_endpoint":           srv.URL + "/authorize",
			"token_endpoint":                   srv.URL + "/token",
			"device_authorization_endpoint":    srv.URL + "/device",
			"code_challenge_methods_supported": []string{"S256"},
		}
		_ = json.NewEncoder(w).Encode(doc)
	})

	mux.HandleFunc("/device", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]any{
			"device_code":               "test-device-code",
			"user_code":                 "ABCD-1234",
			"verification_uri":          "https://example.com/activate",
			"verification_uri_complete": "https://example.com/activate?user_code=ABCD-1234",
			"expires_in":                300,
			"interval":                  1,
		}
		_ = json.NewEncoder(w).Encode(resp)
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()

		// Only handle device code grants here.
		if r.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:device_code" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"unsupported_grant_type"}`))
			return
		}

		count := pollCount.Add(1)
		if int(count) <= pendingPolls {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"authorization_pending"}`))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(tokenResponseJSON("device-access-token", "device-refresh-token", 3600)))
	})

	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// TestDeviceLogin_Success verifies the happy path: the device code flow
// requests a device code, displays it, polls until authorized, and
// returns a valid token.
func TestDeviceLogin_Success(t *testing.T) {
	resetDiscoveryCache()

	// Provider returns "authorization_pending" for the first 2 polls,
	// then returns a token on the 3rd poll.
	provider := setupDeviceMockProvider(t, 2)

	var displayedURL, displayedCode string

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tok, err := DeviceLogin(ctx,
		WithIssuer(provider.URL),
		WithClientID("device-client"),
		WithDisplayFunc(func(verificationURL, userCode string) {
			displayedURL = verificationURL
			displayedCode = userCode
		}),
	)
	require.NoError(t, err)
	assert.Equal(t, "device-access-token", tok.AccessToken)
	assert.Equal(t, "device-refresh-token", tok.RefreshToken)

	// Verify the display callback was invoked with correct values.
	assert.Equal(t, "https://example.com/activate", displayedURL)
	assert.Equal(t, "ABCD-1234", displayedCode)
}

// TestDeviceLogin_MissingIssuer verifies that DeviceLogin returns
// ErrOIDCConfig when the issuer is not provided.
func TestDeviceLogin_MissingIssuer(t *testing.T) {
	resetDiscoveryCache()

	_, err := DeviceLogin(context.Background(),
		WithClientID("device-client"),
	)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrOIDCConfig), "expected ErrOIDCConfig, got: %v", err)
}

// TestDeviceLogin_MissingClientID verifies that DeviceLogin returns
// ErrOIDCConfig when the client ID is not provided.
func TestDeviceLogin_MissingClientID(t *testing.T) {
	resetDiscoveryCache()

	_, err := DeviceLogin(context.Background(),
		WithIssuer("https://example.com"),
	)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrOIDCConfig), "expected ErrOIDCConfig, got: %v", err)
}

// TestDeviceLogin_DiscoveryFailure verifies that DeviceLogin returns
// ErrDiscovery when the OIDC provider is unreachable.
func TestDeviceLogin_DiscoveryFailure(t *testing.T) {
	resetDiscoveryCache()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := DeviceLogin(ctx,
		WithIssuer("http://127.0.0.1:1"),
		WithClientID("device-client"),
	)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrDiscovery), "expected ErrDiscovery, got: %v", err)
}

// TestDeviceLogin_SlowDown verifies that the polling loop respects the
// "slow_down" response by increasing the polling interval.
func TestDeviceLogin_SlowDown(t *testing.T) {
	resetDiscoveryCache()

	mux := http.NewServeMux()
	var srv *httptest.Server
	var pollCount atomic.Int32

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		doc := map[string]any{
			"issuer":                        srv.URL,
			"token_endpoint":                srv.URL + "/token",
			"authorization_endpoint":        srv.URL + "/authorize",
			"device_authorization_endpoint": srv.URL + "/device",
		}
		_ = json.NewEncoder(w).Encode(doc)
	})

	mux.HandleFunc("/device", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]any{
			"device_code":      "slow-device-code",
			"user_code":        "SLOW-1234",
			"verification_uri": "https://example.com/activate",
			"expires_in":       300,
			"interval":         1,
		}
		_ = json.NewEncoder(w).Encode(resp)
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		count := pollCount.Add(1)
		w.Header().Set("Content-Type", "application/json")

		switch count {
		case 1:
			// First poll: slow_down
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"slow_down"}`))
		case 2:
			// Second poll: still pending
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"authorization_pending"}`))
		default:
			// Third poll: success
			_, _ = w.Write([]byte(tokenResponseJSON("slow-token", "", 3600)))
		}
	})

	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tok, err := DeviceLogin(ctx,
		WithIssuer(srv.URL),
		WithClientID("device-client"),
		WithDisplayFunc(func(_, _ string) {}),
	)
	require.NoError(t, err)
	assert.Equal(t, "slow-token", tok.AccessToken)
}

// TestDeviceLogin_ExpiredDeviceCode verifies that DeviceLogin returns
// ErrDeviceCode when the device code expires before authorization.
func TestDeviceLogin_ExpiredDeviceCode(t *testing.T) {
	resetDiscoveryCache()

	mux := http.NewServeMux()
	var srv *httptest.Server

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		doc := map[string]any{
			"issuer":                        srv.URL,
			"token_endpoint":                srv.URL + "/token",
			"authorization_endpoint":        srv.URL + "/authorize",
			"device_authorization_endpoint": srv.URL + "/device",
		}
		_ = json.NewEncoder(w).Encode(doc)
	})

	mux.HandleFunc("/device", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]any{
			"device_code":      "expiring-device-code",
			"user_code":        "EXPR-1234",
			"verification_uri": "https://example.com/activate",
			"expires_in":       300,
			"interval":         1,
		}
		_ = json.NewEncoder(w).Encode(resp)
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"expired_token","error_description":"device code expired"}`))
	})

	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := DeviceLogin(ctx,
		WithIssuer(srv.URL),
		WithClientID("device-client"),
		WithDisplayFunc(func(_, _ string) {}),
	)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrDeviceCode), "expected ErrDeviceCode, got: %v", err)
}

// TestDeviceLogin_CustomDisplayFunc verifies that WithDisplayFunc is
// invoked with the verification URL and user code.
func TestDeviceLogin_CustomDisplayFunc(t *testing.T) {
	resetDiscoveryCache()

	// Provider that immediately returns a token (0 pending polls).
	provider := setupDeviceMockProvider(t, 0)

	var called bool
	var capturedURL, capturedCode string

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tok, err := DeviceLogin(ctx,
		WithIssuer(provider.URL),
		WithClientID("device-client"),
		WithDisplayFunc(func(verificationURL, userCode string) {
			called = true
			capturedURL = verificationURL
			capturedCode = userCode
		}),
	)
	require.NoError(t, err)
	assert.Equal(t, "device-access-token", tok.AccessToken)
	assert.True(t, called, "display function should have been called")
	assert.Equal(t, "https://example.com/activate", capturedURL)
	assert.Equal(t, "ABCD-1234", capturedCode)
}

// TestDeviceLogin_WithGateway verifies that DeviceLogin resolves OIDC
// config from gateway metadata when WithGateway is set.
func TestDeviceLogin_WithGateway(t *testing.T) {
	resetDiscoveryCache()

	provider := setupDeviceMockProvider(t, 0)

	fakeConfig := &gateway.Config{
		Name:         "device-gw",
		Endpoint:     "gateway.example.com:443",
		Dir:          t.TempDir(),
		OIDCIssuer:   provider.URL,
		OIDCClientID: "gw-device-client",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tok, err := DeviceLogin(ctx,
		WithGateway("device-gw"),
		WithDisplayFunc(func(_, _ string) {}),
		withGatewayResolver(func(name string) (*gateway.Config, error) {
			assert.Equal(t, "device-gw", name)
			return fakeConfig, nil
		}),
	)
	require.NoError(t, err)
	assert.Equal(t, "device-access-token", tok.AccessToken)
}

// TestDeviceLogin_ContextCancellation verifies that DeviceLogin
// respects context cancellation during polling.
func TestDeviceLogin_ContextCancellation(t *testing.T) {
	resetDiscoveryCache()

	// Provider that always returns "authorization_pending" so
	// the polling loop never succeeds on its own.
	provider := setupDeviceMockProvider(t, 1000)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err := DeviceLogin(ctx,
		WithIssuer(provider.URL),
		WithClientID("device-client"),
		WithDisplayFunc(func(_, _ string) {}),
	)
	require.Error(t, err)
	// Should be ErrTimeout or context.DeadlineExceeded wrapped.
	assert.True(t,
		errors.Is(err, ErrTimeout) || errors.Is(err, context.DeadlineExceeded),
		"expected timeout error, got: %v", err,
	)
}

func TestDeviceLogin_WithTimeoutBoundsPolling(t *testing.T) {
	resetDiscoveryCache()
	provider := setupDeviceMockProvider(t, 1000)

	started := time.Now()
	_, err := DeviceLogin(context.Background(),
		WithIssuer(provider.URL),
		WithClientID("device-client"),
		WithTimeout(100*time.Millisecond),
		WithDisplayFunc(func(_, _ string) {}),
	)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTimeout)
	assert.Less(t, time.Since(started), time.Second)
}

// TestDeviceLogin_AccessDenied verifies that DeviceLogin returns
// ErrDeviceCode when the user denies authorization.
func TestDeviceLogin_AccessDenied(t *testing.T) {
	resetDiscoveryCache()

	mux := http.NewServeMux()
	var srv *httptest.Server

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		doc := map[string]any{
			"issuer":                        srv.URL,
			"token_endpoint":                srv.URL + "/token",
			"authorization_endpoint":        srv.URL + "/authorize",
			"device_authorization_endpoint": srv.URL + "/device",
		}
		_ = json.NewEncoder(w).Encode(doc)
	})

	mux.HandleFunc("/device", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]any{
			"device_code":      "denied-device-code",
			"user_code":        "DENY-1234",
			"verification_uri": "https://example.com/activate",
			"expires_in":       300,
			"interval":         1,
		}
		_ = json.NewEncoder(w).Encode(resp)
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"access_denied","error_description":"user denied"}`))
	})

	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := DeviceLogin(ctx,
		WithIssuer(srv.URL),
		WithClientID("device-client"),
		WithDisplayFunc(func(_, _ string) {}),
	)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrDeviceCode), "expected ErrDeviceCode, got: %v", err)
	assert.Contains(t, err.Error(), "access denied")
}

// TestDeviceLogin_UnknownError verifies that DeviceLogin returns
// ErrDeviceCode with the error description for unknown error codes.
func TestDeviceLogin_UnknownError(t *testing.T) {
	resetDiscoveryCache()

	mux := http.NewServeMux()
	var srv *httptest.Server

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		doc := map[string]any{
			"issuer":                        srv.URL,
			"token_endpoint":                srv.URL + "/token",
			"authorization_endpoint":        srv.URL + "/authorize",
			"device_authorization_endpoint": srv.URL + "/device",
		}
		_ = json.NewEncoder(w).Encode(doc)
	})

	mux.HandleFunc("/device", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]any{
			"device_code":      "unknown-err-code",
			"user_code":        "UNKN-1234",
			"verification_uri": "https://example.com/activate",
			"expires_in":       300,
			"interval":         1,
		}
		_ = json.NewEncoder(w).Encode(resp)
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"server_error","error_description":"internal failure"}`))
	})

	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := DeviceLogin(ctx,
		WithIssuer(srv.URL),
		WithClientID("device-client"),
		WithDisplayFunc(func(_, _ string) {}),
	)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrDeviceCode), "expected ErrDeviceCode, got: %v", err)
	assert.Contains(t, err.Error(), "server_error")
	assert.Contains(t, err.Error(), "internal failure")
}

// TestDeviceLogin_DeviceEndpointHTTPError verifies that DeviceLogin
// returns ErrDeviceCode when the device authorization endpoint returns
// a non-200 HTTP status.
func TestDeviceLogin_DeviceEndpointHTTPError(t *testing.T) {
	resetDiscoveryCache()

	mux := http.NewServeMux()
	var srv *httptest.Server

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		doc := map[string]any{
			"issuer":                        srv.URL,
			"token_endpoint":                srv.URL + "/token",
			"authorization_endpoint":        srv.URL + "/authorize",
			"device_authorization_endpoint": srv.URL + "/device",
		}
		_ = json.NewEncoder(w).Encode(doc)
	})

	mux.HandleFunc("/device", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal server error"))
	})

	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := DeviceLogin(ctx,
		WithIssuer(srv.URL),
		WithClientID("device-client"),
		WithDisplayFunc(func(_, _ string) {}),
	)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrDeviceCode), "expected ErrDeviceCode, got: %v", err)
}

// TestDeviceLogin_DeviceEndpointInvalidJSON verifies that DeviceLogin
// returns ErrDeviceCode when the device endpoint returns invalid JSON.
func TestDeviceLogin_DeviceEndpointInvalidJSON(t *testing.T) {
	resetDiscoveryCache()

	mux := http.NewServeMux()
	var srv *httptest.Server

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		doc := map[string]any{
			"issuer":                        srv.URL,
			"token_endpoint":                srv.URL + "/token",
			"authorization_endpoint":        srv.URL + "/authorize",
			"device_authorization_endpoint": srv.URL + "/device",
		}
		_ = json.NewEncoder(w).Encode(doc)
	})

	mux.HandleFunc("/device", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{not valid json`))
	})

	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := DeviceLogin(ctx,
		WithIssuer(srv.URL),
		WithClientID("device-client"),
		WithDisplayFunc(func(_, _ string) {}),
	)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrDeviceCode), "expected ErrDeviceCode, got: %v", err)
}

// TestDeviceLogin_MissingUserCode verifies that DeviceLogin returns
// ErrDeviceCode when the device endpoint returns an empty user_code.
func TestDeviceLogin_MissingUserCode(t *testing.T) {
	resetDiscoveryCache()

	mux := http.NewServeMux()
	var srv *httptest.Server

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		doc := map[string]any{
			"issuer":                        srv.URL,
			"token_endpoint":                srv.URL + "/token",
			"authorization_endpoint":        srv.URL + "/authorize",
			"device_authorization_endpoint": srv.URL + "/device",
		}
		_ = json.NewEncoder(w).Encode(doc)
	})

	mux.HandleFunc("/device", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]any{
			"device_code":      "code-but-no-user",
			"user_code":        "",
			"verification_uri": "https://example.com/activate",
			"expires_in":       300,
			"interval":         1,
		}
		_ = json.NewEncoder(w).Encode(resp)
	})

	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := DeviceLogin(ctx,
		WithIssuer(srv.URL),
		WithClientID("device-client"),
		WithDisplayFunc(func(_, _ string) {}),
	)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrDeviceCode), "expected ErrDeviceCode, got: %v", err)
}

// TestDeviceLogin_TokenEndpointInvalidJSON verifies that DeviceLogin
// returns ErrDeviceCode when the token endpoint returns invalid JSON
// during polling.
func TestDeviceLogin_TokenEndpointInvalidJSON(t *testing.T) {
	resetDiscoveryCache()

	mux := http.NewServeMux()
	var srv *httptest.Server

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		doc := map[string]any{
			"issuer":                        srv.URL,
			"token_endpoint":                srv.URL + "/token",
			"authorization_endpoint":        srv.URL + "/authorize",
			"device_authorization_endpoint": srv.URL + "/device",
		}
		_ = json.NewEncoder(w).Encode(doc)
	})

	mux.HandleFunc("/device", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]any{
			"device_code":      "json-err-code",
			"user_code":        "JSON-1234",
			"verification_uri": "https://example.com/activate",
			"expires_in":       300,
			"interval":         1,
		}
		_ = json.NewEncoder(w).Encode(resp)
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{invalid json`))
	})

	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := DeviceLogin(ctx,
		WithIssuer(srv.URL),
		WithClientID("device-client"),
		WithDisplayFunc(func(_, _ string) {}),
	)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrDeviceCode), "expected ErrDeviceCode, got: %v", err)
}

// TestDeviceLogin_NoDeviceEndpoint verifies that DeviceLogin returns
// ErrDeviceCode when the provider does not advertise a device
// authorization endpoint.
func TestDeviceLogin_NoDeviceEndpoint(t *testing.T) {
	resetDiscoveryCache()

	mux := http.NewServeMux()
	var srv *httptest.Server

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		doc := map[string]any{
			"issuer":                 srv.URL,
			"token_endpoint":         srv.URL + "/token",
			"authorization_endpoint": srv.URL + "/authorize",
			// No device_authorization_endpoint.
		}
		_ = json.NewEncoder(w).Encode(doc)
	})

	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := DeviceLogin(ctx,
		WithIssuer(srv.URL),
		WithClientID("device-client"),
		WithDisplayFunc(func(_, _ string) {}),
	)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrDeviceCode), "expected ErrDeviceCode, got: %v", err)
}
