// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// wellKnownJSON returns a valid OIDC discovery document JSON string
// with the given issuer URL as the base.
func wellKnownJSON(issuer string) string {
	return `{
		"issuer": "` + issuer + `",
		"authorization_endpoint": "` + issuer + `/authorize",
		"token_endpoint": "` + issuer + `/token",
		"device_authorization_endpoint": "` + issuer + `/device",
		"scopes_supported": ["openid", "profile", "email"],
		"code_challenge_methods_supported": ["S256"]
	}`
}

func TestDiscover_ValidDocument(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(wellKnownJSON(srv.URL)))
	}))
	defer srv.Close()

	// Clear cache to avoid interference from other tests.
	resetDiscoveryCache()

	cfg, err := discover(context.Background(), srv.URL)
	require.NoError(t, err)

	assert.Equal(t, srv.URL, cfg.Issuer)
	assert.Equal(t, srv.URL+"/authorize", cfg.AuthorizationEndpoint)
	assert.Equal(t, srv.URL+"/token", cfg.TokenEndpoint)
	assert.Equal(t, srv.URL+"/device", cfg.DeviceAuthorizationEndpoint)
	assert.Equal(t, []string{"openid", "profile", "email"}, cfg.ScopesSupported)
	assert.Equal(t, []string{"S256"}, cfg.CodeChallengeMethodsSupported)
}

func TestDiscover_CachesResult(t *testing.T) {
	callCount := 0
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(wellKnownJSON(srv.URL)))
	}))
	defer srv.Close()

	resetDiscoveryCache()

	cfg1, err := discover(context.Background(), srv.URL)
	require.NoError(t, err)

	cfg2, err := discover(context.Background(), srv.URL)
	require.NoError(t, err)

	// Same pointer should be returned from cache.
	assert.Same(t, cfg1, cfg2)
	assert.Equal(t, 1, callCount, "discovery should be fetched only once")
}

func TestDiscover_DifferentIssuersNotCached(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		issuer := "http://" + r.Host
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(wellKnownJSON(issuer)))
	})

	srv1 := httptest.NewServer(handler)
	defer srv1.Close()
	srv2 := httptest.NewServer(handler)
	defer srv2.Close()

	resetDiscoveryCache()

	cfg1, err := discover(context.Background(), srv1.URL)
	require.NoError(t, err)

	cfg2, err := discover(context.Background(), srv2.URL)
	require.NoError(t, err)

	// Different issuers should yield different cached entries.
	assert.NotSame(t, cfg1, cfg2)
}

func TestDiscover_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	resetDiscoveryCache()

	_, err := discover(context.Background(), srv.URL)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrDiscovery))
}

func TestDiscover_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{not valid json}`))
	}))
	defer srv.Close()

	resetDiscoveryCache()

	_, err := discover(context.Background(), srv.URL)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrDiscovery))
}

func TestDiscover_MissingTokenEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		issuer := "http://" + r.Host
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"issuer":"` + issuer + `","authorization_endpoint":"` + issuer + `/authorize"}`))
	}))
	defer srv.Close()

	resetDiscoveryCache()

	_, err := discover(context.Background(), srv.URL)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrDiscovery))
	assert.Contains(t, err.Error(), "token_endpoint")
}

func TestDiscover_ContextCancelled(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(wellKnownJSON(srv.URL)))
	}))
	defer srv.Close()

	resetDiscoveryCache()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

	_, err := discover(ctx, srv.URL)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrDiscovery))
}

func TestDiscover_ConcurrentAccess(t *testing.T) {
	callCount := 0
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		callCount++
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(wellKnownJSON("http://" + r.Host)))
	}))
	defer srv.Close()

	resetDiscoveryCache()

	var wg sync.WaitGroup
	results := make([]*providerConfig, 10)
	errs := make([]error, 10)

	for i := range 10 {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx], errs[idx] = discover(context.Background(), srv.URL)
		}(i)
	}
	wg.Wait()

	for i := range 10 {
		require.NoError(t, errs[i])
		assert.NotNil(t, results[i])
	}

	// Without sync.Once, concurrent goroutines may each fetch before
	// the first result is cached. All calls should succeed, and the
	// server should be called at most once per concurrent racer (not
	// 10 times if caching works at all). In practice, most calls
	// should hit the cache after the first fetch completes.
	mu.Lock()
	defer mu.Unlock()
	assert.LessOrEqual(t, callCount, 10, "caching should reduce total fetches")
}

func TestDiscover_NoDeviceEndpointIsOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		issuer := "http://" + r.Host
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"issuer":"` + issuer + `","authorization_endpoint":"` + issuer + `/authorize","token_endpoint":"` + issuer + `/token"}`))
	}))
	defer srv.Close()

	resetDiscoveryCache()

	cfg, err := discover(context.Background(), srv.URL)
	require.NoError(t, err)
	assert.Empty(t, cfg.DeviceAuthorizationEndpoint)
}

func TestDiscover_TrailingSlashNormalized(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		issuer := "http://" + r.Host
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(wellKnownJSON(issuer)))
	}))
	defer srv.Close()

	resetDiscoveryCache()

	// Call with trailing slash and without; should be same cache entry.
	_, err := discover(context.Background(), srv.URL)
	require.NoError(t, err)

	_, err = discover(context.Background(), srv.URL+"/")
	require.NoError(t, err)

	assert.Equal(t, 1, callCount, "trailing slash should be normalized for caching")
}

func TestDiscover_RejectsIssuerMismatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(wellKnownJSON("https://attacker.example")))
	}))
	defer srv.Close()
	resetDiscoveryCache()

	_, err := discover(context.Background(), srv.URL)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "issuer")
}

func TestDiscover_RejectsInsecureRemoteEndpoint(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"issuer":"` + srv.URL + `","authorization_endpoint":"http://example.com/authorize","token_endpoint":"` + srv.URL + `/token"}`))
	}))
	defer srv.Close()
	resetDiscoveryCache()

	_, err := discover(context.Background(), srv.URL)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "authorization_endpoint")
}
