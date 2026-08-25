// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/gateway"
)

// ClientCredentials performs a non-interactive OAuth2 client credentials
// grant (RFC 6749 Section 4.4). It requires [WithIssuer], [WithClientID],
// and [WithClientSecret] (or [WithGateway] combined with [WithClientSecret]).
//
// This flow is intended for service accounts and machine-to-machine
// authentication. No user interaction occurs. The returned token
// typically contains only an access token (no refresh token).
//
// The client secret is never included in error messages (FR-014).
func ClientCredentials(ctx context.Context, opts ...LoginOption) (*oauth2.Token, error) {
	cfg, err := resolveClientCredentialsConfig(opts...)
	if err != nil {
		return nil, err
	}
	return exchangeClientCredentials(ctx, cfg, false)
}

func resolveClientCredentialsConfig(opts ...LoginOption) (*loginConfig, error) {
	cfg := &loginConfig{}
	for _, opt := range opts {
		opt(cfg)
	}
	cfg.applyDefaults()

	// Client credentials should not send interactive scopes by default.
	// Only send scopes if the caller explicitly set them via WithScopes.
	if !cfg.scopesSet {
		cfg.scopes = nil
	}

	// Resolve OIDC config from gateway if WithGateway was set.
	if cfg.gateway != "" {
		resolver := cfg.gatewayResolver
		if resolver == nil {
			resolver = gateway.LoadConfig
		}
		gwCfg, err := resolver(cfg.gateway)
		if err != nil {
			return nil, fmt.Errorf("failed to load gateway %q: %w", cfg.gateway, err)
		}
		if cfg.issuer == "" {
			cfg.issuer = gwCfg.OIDCIssuer
		}
		if cfg.clientID == "" {
			cfg.clientID = gwCfg.OIDCClientID
		}
		if !cfg.audienceSet {
			cfg.audience = gwCfg.OIDCAudience
		}
		if !cfg.scopesSet && gwCfg.OIDCScopes != "" {
			cfg.scopes = strings.Fields(gwCfg.OIDCScopes)
			cfg.scopesSet = true
		}
	}

	// Validate required configuration.
	if cfg.issuer == "" || cfg.clientID == "" {
		return nil, fmt.Errorf(
			"%w: issuer and client ID are required (use WithIssuer and WithClientID, or WithGateway)",
			ErrOIDCConfig,
		)
	}
	if cfg.clientSecret == "" && cfg.secretProvider == nil {
		return nil, fmt.Errorf(
			"%w: client secret is required (use WithClientSecret or WithClientSecretProvider)",
			ErrClientCredentials,
		)
	}
	return cfg, nil
}

func exchangeClientCredentials(ctx context.Context, cfg *loginConfig, requirePositiveExpiry bool) (*oauth2.Token, error) {
	secret := cfg.clientSecret
	if cfg.secretProvider != nil {
		value, err := cfg.secretProvider(ctx)
		if err != nil {
			return nil, fmt.Errorf("%w: client secret provider failed", ErrClientCredentials)
		}
		secret = value
	}
	if secret == "" {
		return nil, fmt.Errorf("%w: client secret must not be empty", ErrClientCredentials)
	}

	// Discover provider endpoints.
	provider, err := discover(ctx, cfg.issuer)
	if err != nil {
		return nil, err
	}

	// Build the token request with client credentials grant type.
	data := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {cfg.clientID},
		"client_secret": {secret},
	}
	if len(cfg.scopes) > 0 {
		data.Set("scope", strings.Join(cfg.scopes, " "))
	}
	if cfg.audience != "" {
		data.Set("audience", cfg.audience)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, provider.TokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create token request", ErrClientCredentials)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Use a no-redirect client for token requests that carry client_secret
	// in the POST body. A 307/308 redirect would replay the body (including
	// the secret) to the redirect target.
	noRedirectClient := *oidcHTTPClient
	noRedirectClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	resp, err := noRedirectClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: token request failed", ErrClientCredentials)
	}
	defer func() { _ = resp.Body.Close() }()

	const maxResponseBytes = 1 << 20
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: failed to read token response", ErrClientCredentials)
	}
	if len(body) > maxResponseBytes {
		return nil, fmt.Errorf("%w: token response is too large", ErrClientCredentials)
	}

	var tokResp tokenResponse
	if err := json.Unmarshal(body, &tokResp); err != nil {
		return nil, fmt.Errorf("%w: invalid token response JSON", ErrClientCredentials)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		return nil, fmt.Errorf("%w: invalid token response JSON", ErrClientCredentials)
	}

	if resp.StatusCode != http.StatusOK || tokResp.Error != "" {
		return nil, fmt.Errorf("%w: provider rejected the exchange (HTTP %d)", ErrClientCredentials, resp.StatusCode)
	}

	if tokResp.AccessToken == "" {
		return nil, fmt.Errorf("%w: token response missing access_token", ErrClientCredentials)
	}

	tok := &oauth2.Token{
		AccessToken:  tokResp.AccessToken,
		RefreshToken: tokResp.RefreshToken,
		TokenType:    tokResp.TokenType,
	}
	_, expiresInPresent := fields["expires_in"]
	if expiresInPresent && tokResp.ExpiresIn <= 0 {
		return nil, fmt.Errorf("%w: token response requires a positive expires_in", ErrClientCredentials)
	}
	if !expiresInPresent {
		if requirePositiveExpiry {
			return nil, fmt.Errorf("%w: token response requires a positive expires_in", ErrClientCredentials)
		}
		return tok, nil
	}
	tok.Expiry = time.Now().Add(time.Duration(tokResp.ExpiresIn) * time.Second)

	return tok, nil
}
