// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

var oidcHTTPClient = &http.Client{
	Timeout: 30 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// providerConfig holds parsed fields from an OIDC discovery document
// (.well-known/openid-configuration).
type providerConfig struct {
	Issuer                        string   `json:"issuer"`
	AuthorizationEndpoint         string   `json:"authorization_endpoint"`
	TokenEndpoint                 string   `json:"token_endpoint"`
	DeviceAuthorizationEndpoint   string   `json:"device_authorization_endpoint"`
	ScopesSupported               []string `json:"scopes_supported"`
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported"`
}

const discoveryCacheTTL = 10 * time.Minute

type discoveryCacheEntry struct {
	config    *providerConfig
	fetchedAt time.Time
}

// discoveryCache stores successfully fetched provider configurations
// keyed by normalized issuer URL. Entries expire after discoveryCacheTTL
// so that endpoint rotations are picked up without a process restart.
// Errors are not cached so that transient failures do not permanently
// poison the cache.
var (
	discoveryCacheMu sync.Mutex
	discoveryCache   = make(map[string]*discoveryCacheEntry)
)

// resetDiscoveryCache clears the in-memory discovery cache. This is
// only used by tests to avoid interference between test cases.
func resetDiscoveryCache() {
	discoveryCacheMu.Lock()
	defer discoveryCacheMu.Unlock()
	discoveryCache = make(map[string]*discoveryCacheEntry)
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
	now := time.Now()

	discoveryCacheMu.Lock()
	if entry, ok := discoveryCache[key]; ok && now.Before(entry.fetchedAt.Add(discoveryCacheTTL)) {
		discoveryCacheMu.Unlock()
		return entry.config, nil
	}
	discoveryCacheMu.Unlock()

	cfg, err := fetchDiscovery(ctx, key)
	if err != nil {
		return nil, err
	}

	discoveryCacheMu.Lock()
	if entry, ok := discoveryCache[key]; ok && now.Before(entry.fetchedAt.Add(discoveryCacheTTL)) {
		discoveryCacheMu.Unlock()
		return entry.config, nil
	}
	discoveryCache[key] = &discoveryCacheEntry{config: cfg, fetchedAt: now}
	discoveryCacheMu.Unlock()

	return cfg, nil
}

// fetchDiscovery performs the actual HTTP GET to the OIDC discovery
// endpoint and parses the response.
func fetchDiscovery(ctx context.Context, issuer string) (*providerConfig, error) {
	if err := validateSecureURL("issuer", issuer); err != nil {
		return nil, err
	}
	url := issuer + "/.well-known/openid-configuration"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDiscovery, err)
	}

	resp, err := oidcHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDiscovery, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: discovery endpoint returned HTTP %d", ErrDiscovery, resp.StatusCode)
	}

	const maxResponseBytes = 1 << 20
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: failed to read discovery response: %v", ErrDiscovery, err)
	}
	if len(body) > maxResponseBytes {
		return nil, fmt.Errorf("%w: discovery response is too large", ErrDiscovery)
	}

	var cfg providerConfig
	if err := json.Unmarshal(body, &cfg); err != nil {
		return nil, fmt.Errorf("%w: invalid discovery JSON: %v", ErrDiscovery, err)
	}
	if normalizeIssuer(cfg.Issuer) != normalizeIssuer(issuer) {
		return nil, fmt.Errorf("%w: discovery issuer does not match configured issuer", ErrDiscovery)
	}

	if cfg.TokenEndpoint == "" {
		return nil, fmt.Errorf("%w: discovery document missing token_endpoint", ErrDiscovery)
	}
	if cfg.AuthorizationEndpoint == "" {
		return nil, fmt.Errorf("%w: discovery document missing authorization_endpoint", ErrDiscovery)
	}
	for name, endpoint := range map[string]string{
		"issuer":                        cfg.Issuer,
		"authorization_endpoint":        cfg.AuthorizationEndpoint,
		"token_endpoint":                cfg.TokenEndpoint,
		"device_authorization_endpoint": cfg.DeviceAuthorizationEndpoint,
	} {
		if endpoint != "" {
			if err := validateSecureURL(name, endpoint); err != nil {
				return nil, err
			}
		}
	}

	return &cfg, nil
}

func validateSecureURL(name, raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("%w: invalid %s URL", ErrDiscovery, name)
	}
	if u.User != nil || u.Fragment != "" {
		return fmt.Errorf("%w: %s URL must not contain userinfo or a fragment", ErrDiscovery, name)
	}
	if u.Scheme == "https" {
		return nil
	}
	host := u.Hostname()
	if u.Scheme == "http" && (strings.EqualFold(host, "localhost") || isLoopbackIP(host)) {
		return nil
	}
	return fmt.Errorf("%w: %s URL must use HTTPS (HTTP is allowed only for loopback hosts)", ErrDiscovery, name)
}

func isLoopbackIP(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
