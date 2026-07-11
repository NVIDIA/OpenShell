// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
)

// providerConfig holds parsed fields from an OIDC discovery document
// (.well-known/openid-configuration).
type providerConfig struct {
	Issuer                           string   `json:"issuer"`
	AuthorizationEndpoint            string   `json:"authorization_endpoint"`
	TokenEndpoint                    string   `json:"token_endpoint"`
	DeviceAuthorizationEndpoint      string   `json:"device_authorization_endpoint"`
	ScopesSupported                  []string `json:"scopes_supported"`
	CodeChallengeMethodsSupported    []string `json:"code_challenge_methods_supported"`
}

// discoveryCache stores successfully fetched provider configurations
// keyed by normalized issuer URL. Only successful results are cached;
// errors are not cached so that transient failures (network issues,
// context cancellation) do not permanently poison the cache.
var (
	discoveryCacheMu sync.Mutex
	discoveryCache   = make(map[string]*providerConfig)
)

// resetDiscoveryCache clears the in-memory discovery cache. This is
// only used by tests to avoid interference between test cases.
func resetDiscoveryCache() {
	discoveryCacheMu.Lock()
	defer discoveryCacheMu.Unlock()
	discoveryCache = make(map[string]*providerConfig)
}

// normalizeIssuer strips a trailing slash from the issuer URL so that
// "https://auth.example.com" and "https://auth.example.com/" resolve
// to the same cache key.
func normalizeIssuer(issuer string) string {
	return strings.TrimRight(issuer, "/")
}

// discover fetches and caches the OIDC discovery document for the
// given issuer URL. Only successful results are cached; failed
// fetches are retried on the next call.
func discover(ctx context.Context, issuer string) (*providerConfig, error) {
	key := normalizeIssuer(issuer)

	discoveryCacheMu.Lock()
	if cached, ok := discoveryCache[key]; ok {
		discoveryCacheMu.Unlock()
		return cached, nil
	}
	discoveryCacheMu.Unlock()

	cfg, err := fetchDiscovery(ctx, key)
	if err != nil {
		return nil, err
	}

	discoveryCacheMu.Lock()
	// Check again in case another goroutine cached it while we fetched.
	if existing, ok := discoveryCache[key]; ok {
		discoveryCacheMu.Unlock()
		return existing, nil
	}
	discoveryCache[key] = cfg
	discoveryCacheMu.Unlock()

	return cfg, nil
}

// fetchDiscovery performs the actual HTTP GET to the OIDC discovery
// endpoint and parses the response.
func fetchDiscovery(ctx context.Context, issuer string) (*providerConfig, error) {
	url := issuer + "/.well-known/openid-configuration"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDiscovery, err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDiscovery, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: discovery endpoint returned HTTP %d", ErrDiscovery, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to read discovery response: %v", ErrDiscovery, err)
	}

	var cfg providerConfig
	if err := json.Unmarshal(body, &cfg); err != nil {
		return nil, fmt.Errorf("%w: invalid discovery JSON: %v", ErrDiscovery, err)
	}

	if cfg.TokenEndpoint == "" {
		return nil, fmt.Errorf("%w: discovery document missing token_endpoint", ErrDiscovery)
	}
	if cfg.AuthorizationEndpoint == "" {
		return nil, fmt.Errorf("%w: discovery document missing authorization_endpoint", ErrDiscovery)
	}

	return &cfg, nil
}
