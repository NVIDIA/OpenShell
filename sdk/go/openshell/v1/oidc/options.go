// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"
	"io"
	"time"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/gateway"
)

// scopeOpenID is the scope that turns an OAuth2 authorization request into
// an OpenID Connect one. Interactive flows always request it.
const scopeOpenID = "openid"

// defaultScopes are the OIDC scopes requested when no custom scopes
// are specified via [WithScopes].
var defaultScopes = []string{scopeOpenID, "profile", "email"}

// defaultTimeout is the maximum duration for interactive login flows
// (browser, keyboard, device code) when no custom timeout is set.
const defaultTimeout = 2 * time.Minute

// loginConfig holds the resolved configuration for a single login
// attempt. It is built by applying [LoginOption] functions to a
// zero-value struct and then filling in defaults.
type loginConfig struct {
	issuer         string
	clientID       string
	clientSecret   string
	secretProvider func(context.Context) (string, error)
	audience       string
	audienceSet    bool
	scopes         []string
	scopesSet      bool
	callbackPort   int
	timeout        time.Duration
	timeoutSet     bool
	keyboardFlow   bool
	inMemory       bool
	displayFunc    func(verificationURL, userCode string)
	gateway        string

	// Internal fields for testing. Not exposed via public API.
	tokenDir        string                                     // override token directory
	input           io.Reader                                  // override stdin for keyboard flow
	output          io.Writer                                  // override stderr for keyboard flow
	gatewayResolver func(name string) (*gateway.Config, error) // override gateway.LoadConfig
}

// applyDefaults fills in default values for fields that were not set
// by any option function.
func (c *loginConfig) applyDefaults() {
	// Check set-ness, not the zero value, so an explicitly-set empty scope
	// list or zero timeout is honored instead of being replaced by defaults.
	if !c.scopesSet {
		// Deep copy to avoid callers mutating the package-level slice.
		c.scopes = make([]string, len(defaultScopes))
		copy(c.scopes, defaultScopes)
	}
	if !c.timeoutSet {
		c.timeout = defaultTimeout
	}
}

// requireOpenIDScope normalizes the scopes for an interactive flow so the
// request is always an OpenID Connect one. "openid" is placed first and any
// caller-supplied duplicate is dropped; the remaining scopes keep their order.
//
// Interactive flows authenticate a user, and the gateway requires a "sub"
// claim on the resulting token, so "openid" is not optional there. Callers
// remain free to request application scopes such as "sandbox:read". The
// client credentials grant has no user and is left untouched.
//
// This mirrors build_scopes in crates/openshell-cli/src/oidc_auth.rs.
func (c *loginConfig) requireOpenIDScope() {
	normalized := make([]string, 0, len(c.scopes)+1)
	normalized = append(normalized, scopeOpenID)
	for _, scope := range c.scopes {
		if scope != scopeOpenID {
			normalized = append(normalized, scope)
		}
	}
	c.scopes = normalized
}

// LoginOption configures a login attempt. Use the With* functions to
// create option values.
type LoginOption func(*loginConfig)

// WithIssuer sets the OIDC issuer URL. Required for standalone flows
// (when no gateway name is provided to [Login]).
func WithIssuer(url string) LoginOption {
	return func(c *loginConfig) {
		c.issuer = url
	}
}

// WithClientID sets the OAuth2 client ID. Required for standalone
// flows (when no gateway name is provided to [Login]).
func WithClientID(id string) LoginOption {
	return func(c *loginConfig) {
		c.clientID = id
	}
}

// WithClientSecret sets the client secret for the client credentials
// grant. Required for [ClientCredentials] and [NewClientCredentialsAuth].
func WithClientSecret(secret string) LoginOption {
	return func(c *loginConfig) {
		c.clientSecret = secret
	}
}

// WithClientSecretProvider resolves the client secret for each exchange.
// Provider errors and returned secrets are never included in SDK errors.
func WithClientSecretProvider(provider func(context.Context) (string, error)) LoginOption {
	return func(c *loginConfig) {
		c.secretProvider = provider
	}
}

// WithAudience sets the optional OAuth2 resource-server audience.
func WithAudience(audience string) LoginOption {
	return func(c *loginConfig) {
		c.audience = audience
		c.audienceSet = true
	}
}

// WithScopes overrides the default scopes (openid, profile, email).
// The provided scopes replace the defaults entirely.
//
// [Login] and [DeviceLogin] always request "openid" in addition to the
// provided scopes, so WithScopes("sandbox:read") sends "openid sandbox:read".
// [ClientCredentials] and [NewClientCredentialsAuth] send exactly what is
// provided, since that grant has no user and no ID token; calling
// WithScopes with no arguments there sends no scope parameter at all.
func WithScopes(scopes ...string) LoginOption {
	return func(c *loginConfig) {
		c.scopes = make([]string, len(scopes))
		copy(c.scopes, scopes)
		c.scopesSet = true
	}
}

// WithCallbackPort sets a fixed port for the localhost callback server.
// By default the server tries port 8000, then 18000.
func WithCallbackPort(port int) LoginOption {
	return func(c *loginConfig) {
		c.callbackPort = port
	}
}

// WithTimeout sets the maximum duration for a login flow.
// The default is 2 minutes.
//
// A non-positive duration (d <= 0) means "no deadline": the flow runs until
// it completes or the caller's context is cancelled. A caller-supplied
// context that already carries a deadline always takes precedence.
func WithTimeout(d time.Duration) LoginOption {
	return func(c *loginConfig) {
		c.timeout = d
		c.timeoutSet = true
	}
}

// WithKeyboardFlow forces the keyboard flow (manual URL copy and code
// paste) instead of attempting to open a browser.
func WithKeyboardFlow() LoginOption {
	return func(c *loginConfig) {
		c.keyboardFlow = true
	}
}

// WithInMemory skips persisting the token to disk. The returned token
// is only available in memory for the lifetime of the process.
func WithInMemory() LoginOption {
	return func(c *loginConfig) {
		c.inMemory = true
	}
}

// WithDisplayFunc sets a custom display function for the device code
// flow. The function receives the verification URL and user code that
// the user must enter to authorize the device. If not set, the default
// behavior prints to stdout.
func WithDisplayFunc(fn func(verificationURL, userCode string)) LoginOption {
	return func(c *loginConfig) {
		c.displayFunc = fn
	}
}

// WithGateway sets the gateway name for [DeviceLogin], [ClientCredentials],
// and [NewClientCredentialsAuth]. OIDC configuration is read from the
// gateway's metadata.json. Client-credentials tokens are never persisted.
func WithGateway(name string) LoginOption {
	return func(c *loginConfig) {
		c.gateway = name
	}
}

// --- Internal options for testing (unexported) ---

// withTokenDir overrides the token directory for testing.
func withTokenDir(dir string) LoginOption {
	return func(c *loginConfig) {
		c.tokenDir = dir
	}
}

// withInput overrides the input reader for keyboard flow testing.
func withInput(r io.Reader) LoginOption {
	return func(c *loginConfig) {
		c.input = r
	}
}

// withOutput overrides the output writer for keyboard flow testing.
func withOutput(w io.Writer) LoginOption {
	return func(c *loginConfig) {
		c.output = w
	}
}

// withGatewayResolver overrides the gateway.LoadConfig function for
// testing. This allows tests to inject a fake gateway resolver
// without filesystem setup.
func withGatewayResolver(fn func(name string) (*gateway.Config, error)) LoginOption {
	return func(c *loginConfig) {
		c.gatewayResolver = fn
	}
}
