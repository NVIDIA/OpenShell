// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"
	"fmt"
	"io"
	"os"
	"slices"

	"golang.org/x/oauth2"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/gateway"
)

// Login performs an interactive OIDC authorization code login.
//
// When gatewayName is non-empty, Login resolves OIDC configuration
// (issuer URL and client ID) from the gateway's metadata.json file and
// persists tokens to the gateway directory.
//
// When gatewayName is empty, the caller must provide [WithIssuer] and
// [WithClientID] options explicitly.
//
// Before starting an interactive flow, Login checks for an existing
// valid token on disk (FR-019). If a valid, non-expired token is found,
// it is returned immediately without user interaction.
//
// The flow attempts to open a browser for authorization. If the browser
// cannot be opened, or if [WithKeyboardFlow] is set, the keyboard
// fallback flow is used instead.
func Login(ctx context.Context, gatewayName string, opts ...LoginOption) (*oauth2.Token, error) {
	cfg := &loginConfig{}
	for _, opt := range opts {
		opt(cfg)
	}
	cfg.applyDefaults()

	// Apply configured timeout if the caller's context has no deadline.
	if _, hasDeadline := ctx.Deadline(); !hasDeadline && cfg.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, cfg.timeout)
		defer cancel()
	}

	// Resolve OIDC configuration from gateway or explicit options.
	tokenDir, err := resolveOIDCConfig(cfg, gatewayName)
	if err != nil {
		return nil, err
	}

	// FR-019: Check for existing valid token on disk before starting
	// an interactive flow.
	if tokenDir != "" {
		tok, readErr := readToken(tokenDir)
		if readErr == nil && tok != nil && tok.Valid() {
			return tok, nil
		}
		// If readErr is a non-NotExist error, we log and proceed.
		// Stale/expired tokens or missing files are not errors; we
		// simply proceed to the interactive flow.
	}

	// Run OIDC discovery to get provider endpoints.
	provider, err := discover(ctx, cfg.issuer)
	if err != nil {
		return nil, err
	}

	// Generate PKCE verifier and challenge if the provider supports S256.
	var codeVerifier, codeChallenge string
	if supportsS256(provider) {
		codeVerifier, err = generateCodeVerifier()
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrAuthCode, err)
		}
		codeChallenge = codeChallengeS256(codeVerifier)
	}

	// Generate cryptographic state for CSRF protection.
	state, err := generateState()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAuthCode, err)
	}

	// Determine the authorization code acquisition method.
	// The redirectURI must match exactly between the auth request and
	// the token exchange (OIDC/OAuth2 requirement).
	var code, redirectURI string
	if cfg.keyboardFlow {
		redirectURI = "urn:ietf:wg:oauth:2.0:oob"
		code, err = loginKeyboard(ctx, cfg, provider, state, codeChallenge)
	} else {
		code, redirectURI, err = loginBrowser(ctx, cfg, provider, state, codeChallenge)
	}
	if err != nil {
		return nil, err
	}

	// Exchange the authorization code for tokens.
	tok, err := exchangeCode(ctx, provider.TokenEndpoint, cfg.clientID, code, redirectURI, codeVerifier)
	if err != nil {
		return nil, err
	}

	// Persist token to disk unless in-memory mode is requested.
	if !cfg.inMemory && tokenDir != "" {
		if writeErr := writeToken(tokenDir, tok); writeErr != nil {
			return nil, writeErr
		}
	}

	return tok, nil
}

// resolveOIDCConfig resolves the OIDC issuer and client ID either from
// the gateway metadata or from explicit options. Returns the token
// directory path (empty if in-memory or no directory available).
func resolveOIDCConfig(cfg *loginConfig, gatewayName string) (string, error) {
	tokenDir := cfg.tokenDir

	if gatewayName != "" {
		// Resolve from gateway.
		resolver := cfg.gatewayResolver
		if resolver == nil {
			resolver = gateway.LoadConfig
		}
		gwCfg, err := resolver(gatewayName)
		if err != nil {
			return "", fmt.Errorf("failed to load gateway %q: %w", gatewayName, err)
		}
		if gwCfg.OIDCIssuer == "" || gwCfg.OIDCClientID == "" {
			return "", fmt.Errorf("%w: gateway %q has no OIDC configuration (missing oidc_issuer or oidc_client_id in metadata.json)", ErrOIDCConfig, gatewayName)
		}
		cfg.issuer = gwCfg.OIDCIssuer
		cfg.clientID = gwCfg.OIDCClientID
		if tokenDir == "" {
			tokenDir = gwCfg.Dir
		}
	}

	// Validate that we have the minimum required config.
	if cfg.issuer == "" || cfg.clientID == "" {
		return "", fmt.Errorf("%w: issuer and client ID are required (provide a gateway name or use WithIssuer and WithClientID)", ErrOIDCConfig)
	}

	return tokenDir, nil
}

// supportsS256 checks if the OIDC provider advertises S256 PKCE support.
func supportsS256(provider *providerConfig) bool {
	return slices.Contains(provider.CodeChallengeMethodsSupported, "S256")
}

// loginKeyboard performs the keyboard flow: builds the auth URL, shows
// it to the user, and reads the pasted authorization code.
func loginKeyboard(ctx context.Context, cfg *loginConfig, provider *providerConfig, state, challenge string) (string, error) {
	redirectURI := "urn:ietf:wg:oauth:2.0:oob"
	authURL := buildAuthURL(provider.AuthorizationEndpoint, cfg.clientID, redirectURI, state, challenge, cfg.scopes)

	input := cfg.input
	if input == nil {
		input = os.Stdin
	}
	var output io.Writer = os.Stderr
	if cfg.output != nil {
		output = cfg.output
	}

	return keyboardFlow(ctx, authURL, input, output)
}

// loginBrowser performs the browser-based flow: starts a callback server,
// opens the browser, and waits for the callback. Falls back to keyboard
// if the browser cannot be opened.
//
// Returns (code, redirectURI, error). The redirectURI must be passed to
// exchangeCode so that it exactly matches the URI used in the auth
// request. When the function falls back to keyboard flow, the returned
// redirectURI is the keyboard placeholder ("urn:ietf:wg:oauth:2.0:oob").
func loginBrowser(ctx context.Context, cfg *loginConfig, provider *providerConfig, state, challenge string) (string, string, error) {
	port := cfg.callbackPort
	if port == 0 {
		port = 8000
	}

	srv, resultCh, err := startCallbackServer(ctx, port, state)
	if err != nil {
		// Try fallback port if the primary port failed and no custom
		// port was specified.
		if cfg.callbackPort == 0 {
			port = 18000
			srv, resultCh, err = startCallbackServer(ctx, port, state)
		}
		if err != nil {
			// Cannot start callback server, fall back to keyboard.
			code, kbErr := loginKeyboard(ctx, cfg, provider, state, challenge)
			return code, "urn:ietf:wg:oauth:2.0:oob", kbErr
		}
	}
	defer func() {
		_ = srv.Close()
	}()

	redirectURI := fmt.Sprintf("http://localhost:%d/callback", port)
	authURL := buildAuthURL(provider.AuthorizationEndpoint, cfg.clientID, redirectURI, state, challenge, cfg.scopes)

	// Try to open the browser.
	if browserErr := openBrowser(authURL); browserErr != nil {
		// Browser failed, fall back to keyboard flow.
		_ = srv.Close()
		code, kbErr := loginKeyboard(ctx, cfg, provider, state, challenge)
		return code, "urn:ietf:wg:oauth:2.0:oob", kbErr
	}

	// Wait for the callback result or context cancellation.
	select {
	case <-ctx.Done():
		return "", "", fmt.Errorf("%w: %v", ErrTimeout, ctx.Err())
	case result := <-resultCh:
		if result.err != nil {
			return "", "", result.err
		}
		return result.code, redirectURI, nil
	}
}
