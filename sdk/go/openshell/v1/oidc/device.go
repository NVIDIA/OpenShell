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

// deviceAuthResponse holds the parsed response from the device
// authorization endpoint (RFC 8628 Section 3.2).
type deviceAuthResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int64  `json:"expires_in"`
	Interval                int64  `json:"interval"`
}

// DeviceLogin performs an OAuth2 device authorization grant (RFC 8628).
//
// The flow requests a device code and user code from the provider's
// device authorization endpoint, displays them to the user (via
// [WithDisplayFunc] or stdout), and polls the token endpoint until the
// user completes authorization.
//
// Required options: [WithIssuer] and [WithClientID], or [WithGateway].
//
// The polling loop respects the provider's interval and handles the
// following token endpoint error codes:
//   - "authorization_pending": continue polling at the current interval
//   - "slow_down": increase the polling interval by 5 seconds (RFC 8628 Section 3.5)
//   - "expired_token": the device code has expired, return [ErrDeviceCode]
//   - any other error: return [ErrDeviceCode]
func DeviceLogin(ctx context.Context, opts ...LoginOption) (*oauth2.Token, error) {
	cfg := &loginConfig{}
	for _, opt := range opts {
		opt(cfg)
	}
	cfg.applyDefaults()
	if _, hasDeadline := ctx.Deadline(); !hasDeadline && cfg.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, cfg.timeout)
		defer cancel()
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

	// Discover provider endpoints.
	provider, err := discover(ctx, cfg.issuer)
	if err != nil {
		return nil, err
	}

	// Verify the provider supports device authorization.
	if provider.DeviceAuthorizationEndpoint == "" {
		return nil, fmt.Errorf(
			"%w: provider does not support device authorization (no device_authorization_endpoint in discovery)",
			ErrDeviceCode,
		)
	}

	// Request a device code from the provider.
	deviceResp, err := requestDeviceCode(ctx, provider.DeviceAuthorizationEndpoint, cfg.clientID, cfg.scopes)
	if err != nil {
		return nil, err
	}

	// Display the verification URL and user code to the user.
	if cfg.displayFunc != nil {
		cfg.displayFunc(deviceResp.VerificationURI, deviceResp.UserCode)
	} else {
		fmt.Printf("To sign in, visit: %s\n", deviceResp.VerificationURI)
		fmt.Printf("Enter code: %s\n", deviceResp.UserCode)
	}

	// Enforce device code lifetime from the provider's expires_in field.
	// If the caller's context already has a shorter deadline, that takes
	// precedence. This prevents indefinite polling against non-compliant
	// providers that never return expired_token.
	if deviceResp.ExpiresIn > 0 {
		expiry := time.Duration(deviceResp.ExpiresIn) * time.Second
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, expiry)
		defer cancel()
	}

	// Poll the token endpoint until authorization completes, expires,
	// or the context is cancelled.
	interval := deviceResp.Interval
	if interval < 1 {
		interval = 5 // default polling interval per RFC 8628
	}

	return pollDeviceToken(ctx, provider.TokenEndpoint, cfg.clientID, deviceResp.DeviceCode, interval)
}

// requestDeviceCode sends a POST to the device authorization endpoint
// and returns the parsed response containing the device code, user
// code, and verification URI.
func requestDeviceCode(ctx context.Context, endpoint, clientID string, scopes []string) (*deviceAuthResponse, error) {
	data := url.Values{
		"client_id": {clientID},
	}
	if len(scopes) > 0 {
		data.Set("scope", strings.Join(scopes, " "))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create device authorization request", ErrDeviceCode)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := oidcHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: device authorization request failed", ErrDeviceCode)
	}
	defer func() { _ = resp.Body.Close() }()

	const maxResponseBytes = 1 << 20
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("%w: failed to read device authorization response", ErrDeviceCode)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: device authorization endpoint returned HTTP %d", ErrDeviceCode, resp.StatusCode)
	}

	var deviceResp deviceAuthResponse
	if err := json.Unmarshal(body, &deviceResp); err != nil {
		return nil, fmt.Errorf("%w: invalid device authorization response JSON", ErrDeviceCode)
	}

	if deviceResp.DeviceCode == "" || deviceResp.UserCode == "" {
		return nil, fmt.Errorf("%w: device authorization response missing device_code or user_code", ErrDeviceCode)
	}

	return &deviceResp, nil
}

// pollDeviceToken polls the token endpoint at the given interval until
// the user completes authorization. It handles RFC 8628 error codes:
//   - "authorization_pending": keep polling
//   - "slow_down": increase interval by 5 seconds
//   - "expired_token": return ErrDeviceCode
func pollDeviceToken(ctx context.Context, tokenEndpoint, clientID, deviceCode string, interval int64) (*oauth2.Token, error) {
	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("%w: %v", ErrTimeout, ctx.Err())
		case <-ticker.C:
			tok, done, slowDown, err := tryDeviceTokenExchange(ctx, tokenEndpoint, clientID, deviceCode)
			if done {
				if err != nil {
					return nil, err
				}
				return tok, nil
			}
			// Adjust interval if the provider requested slow_down
			// (+5 seconds per RFC 8628 Section 3.5).
			if slowDown < 0 {
				interval += 5
				ticker.Reset(time.Duration(interval) * time.Second)
			}
		}
	}
}

// tryDeviceTokenExchange makes a single token request for the device
// code grant. Returns:
//   - (token, true, 0, nil): success
//   - (nil, true, 0, err): terminal error (expired, access_denied, etc.)
//   - (nil, false, interval, nil): continue polling (authorization_pending or slow_down)
func tryDeviceTokenExchange(ctx context.Context, tokenEndpoint, clientID, deviceCode string) (*oauth2.Token, bool, int64, error) {
	data := url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {deviceCode},
		"client_id":   {clientID},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, true, 0, fmt.Errorf("%w: failed to create token request", ErrDeviceCode)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := oidcHTTPClient.Do(req)
	if err != nil {
		// If the context was cancelled or timed out, surface that as
		// ErrTimeout so callers can distinguish "user/caller cancelled"
		// from a genuine device-code error.
		if ctx.Err() != nil {
			return nil, true, 0, fmt.Errorf("%w: %v", ErrTimeout, ctx.Err())
		}
		// Other network errors during polling are terminal.
		return nil, true, 0, fmt.Errorf("%w: token request failed", ErrDeviceCode)
	}
	defer func() { _ = resp.Body.Close() }()

	const maxTokenResponseBytes = 1 << 20
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenResponseBytes))
	if err != nil {
		return nil, true, 0, fmt.Errorf("%w: failed to read token response", ErrDeviceCode)
	}

	var tokResp tokenResponse
	if err := json.Unmarshal(body, &tokResp); err != nil {
		return nil, true, 0, fmt.Errorf("%w: invalid token response JSON", ErrDeviceCode)
	}

	// Handle error responses per RFC 8628 Section 3.5.
	if tokResp.Error != "" {
		switch tokResp.Error {
		case "authorization_pending":
			// User has not yet completed authorization. Keep polling.
			return nil, false, 0, nil
		case "slow_down":
			// Provider requests increased interval (+5 seconds per RFC 8628).
			// Return a sentinel value; the caller adds 5 to current interval.
			return nil, false, -1, nil
		case "expired_token":
			return nil, true, 0, fmt.Errorf("%w: device code expired", ErrDeviceCode)
		case "access_denied":
			return nil, true, 0, fmt.Errorf("%w: access denied by user", ErrDeviceCode)
		default:
			msg := fmt.Sprintf("device code exchange failed: %s", tokResp.Error)
			if tokResp.ErrorDesc != "" {
				msg += ": " + tokResp.ErrorDesc
			}
			return nil, true, 0, fmt.Errorf("%w: %s", ErrDeviceCode, msg)
		}
	}

	// Success: parse the token.
	if resp.StatusCode != http.StatusOK {
		return nil, true, 0, fmt.Errorf("%w: token endpoint returned HTTP %d", ErrDeviceCode, resp.StatusCode)
	}

	tok := &oauth2.Token{
		AccessToken:  tokResp.AccessToken,
		RefreshToken: tokResp.RefreshToken,
		TokenType:    tokResp.TokenType,
	}
	if tokResp.ExpiresIn > 0 {
		tok.Expiry = time.Now().Add(time.Duration(tokResp.ExpiresIn) * time.Second)
	}

	return tok, true, 0, nil
}
