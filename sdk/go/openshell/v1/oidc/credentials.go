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
		if gwCfg.OIDCIssuer == "" || gwCfg.OIDCClientID == "" {
			return nil, fmt.Errorf(
				"%w: gateway %q has no OIDC configuration (missing oidc_issuer or oidc_client_id in metadata.json)",
				ErrOIDCConfig, cfg.gateway,
			)
		}
		cfg.issuer = gwCfg.OIDCIssuer
		cfg.clientID = gwCfg.OIDCClientID
	}

	// Validate required configuration.
	if cfg.issuer == "" || cfg.clientID == "" {
		return nil, fmt.Errorf(
			"%w: issuer and client ID are required (use WithIssuer and WithClientID, or WithGateway)",
			ErrOIDCConfig,
		)
	}
	if cfg.clientSecret == "" {
		return nil, fmt.Errorf(
			"%w: client secret is required (use WithClientSecret)",
			ErrClientCredentials,
		)
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
		"client_secret": {cfg.clientSecret},
	}
	if len(cfg.scopes) > 0 {
		data.Set("scope", strings.Join(cfg.scopes, " "))
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
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("%w: failed to read token response", ErrClientCredentials)
	}

	var tokResp tokenResponse
	if err := json.Unmarshal(body, &tokResp); err != nil {
		return nil, fmt.Errorf("%w: invalid token response JSON", ErrClientCredentials)
	}

	if resp.StatusCode != http.StatusOK || tokResp.Error != "" {
		// FR-014: Never include the client secret in error messages.
		// Only include the provider's error code and description.
		msg := "client credentials exchange failed"
		if tokResp.Error != "" {
			msg = fmt.Sprintf("provider error: %s", tokResp.Error)
			if tokResp.ErrorDesc != "" {
				msg += ": " + tokResp.ErrorDesc
			}
		}
		return nil, fmt.Errorf("%w: %s", ErrClientCredentials, msg)
	}

	if tokResp.AccessToken == "" {
		return nil, fmt.Errorf("%w: token response missing access_token", ErrClientCredentials)
	}

	tok := &oauth2.Token{
		AccessToken:  tokResp.AccessToken,
		RefreshToken: tokResp.RefreshToken,
		TokenType:    tokResp.TokenType,
	}
	if tokResp.ExpiresIn > 0 {
		tok.Expiry = time.Now().Add(time.Duration(tokResp.ExpiresIn) * time.Second)
	}

	return tok, nil
}
