// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestLoginConfig_Defaults(t *testing.T) {
	var cfg loginConfig
	cfg.applyDefaults()

	assert.Equal(t, []string{"openid", "profile", "email"}, cfg.scopes)
	assert.Equal(t, 2*time.Minute, cfg.timeout)
	assert.Empty(t, cfg.issuer)
	assert.Empty(t, cfg.clientID)
	assert.Empty(t, cfg.clientSecret)
	assert.Zero(t, cfg.callbackPort)
	assert.False(t, cfg.keyboardFlow)
	assert.False(t, cfg.inMemory)
	assert.Nil(t, cfg.displayFunc)
	assert.Empty(t, cfg.gateway)
}

func TestWithIssuer(t *testing.T) {
	var cfg loginConfig
	WithIssuer("https://auth.example.com")(&cfg)

	assert.Equal(t, "https://auth.example.com", cfg.issuer)
}

func TestWithClientID(t *testing.T) {
	var cfg loginConfig
	WithClientID("my-app")(&cfg)

	assert.Equal(t, "my-app", cfg.clientID)
}

func TestWithClientSecret(t *testing.T) {
	var cfg loginConfig
	WithClientSecret("s3cret")(&cfg)

	assert.Equal(t, "s3cret", cfg.clientSecret)
}

func TestWithScopes(t *testing.T) {
	var cfg loginConfig
	WithScopes("openid", "custom")(&cfg)
	cfg.applyDefaults()

	// Custom scopes should not be overwritten by defaults.
	assert.Equal(t, []string{"openid", "custom"}, cfg.scopes)
}

func TestWithScopes_DeepCopy(t *testing.T) {
	original := []string{"openid", "custom"}
	var cfg loginConfig
	WithScopes(original...)(&cfg)

	// Mutating the original slice should not affect the config.
	original[0] = "mutated"
	assert.Equal(t, "openid", cfg.scopes[0])
}

func TestWithCallbackPort(t *testing.T) {
	var cfg loginConfig
	WithCallbackPort(9090)(&cfg)

	assert.Equal(t, 9090, cfg.callbackPort)
}

func TestWithTimeout(t *testing.T) {
	var cfg loginConfig
	WithTimeout(5 * time.Minute)(&cfg)
	cfg.applyDefaults()

	// Custom timeout should not be overwritten by defaults.
	assert.Equal(t, 5*time.Minute, cfg.timeout)
}

func TestWithScopes_ExplicitEmptyNotOverridden(t *testing.T) {
	var cfg loginConfig
	WithScopes()(&cfg) // caller explicitly requests no scopes
	cfg.applyDefaults()

	// An explicitly-set empty scope list must be honored, not replaced by defaults.
	assert.True(t, cfg.scopesSet)
	assert.Empty(t, cfg.scopes)
}

func TestWithTimeout_ExplicitZeroNotOverridden(t *testing.T) {
	var cfg loginConfig
	WithTimeout(0)(&cfg) // caller explicitly requests no timeout
	cfg.applyDefaults()

	// An explicitly-set zero timeout must be honored, not replaced by the default.
	assert.True(t, cfg.timeoutSet)
	assert.Zero(t, cfg.timeout)
}

func TestWithTimeout_NegativeMeansNoDeadline(t *testing.T) {
	var cfg loginConfig
	WithTimeout(-1 * time.Second)(&cfg)
	cfg.applyDefaults()

	// Every flow gates on timeout > 0, so a negative duration means
	// "no deadline" exactly as zero does. It is not replaced by the default.
	assert.True(t, cfg.timeoutSet)
	assert.Negative(t, cfg.timeout)
}

// Interactive flows authenticate a user, so the request must carry the
// "openid" scope regardless of what the caller asked for. This mirrors
// build_scopes in crates/openshell-cli/src/oidc_auth.rs.
func TestRequireOpenIDScope(t *testing.T) {
	tests := []struct {
		name string
		opts []LoginOption
		want []string
	}{
		{
			name: "unset scopes keep the defaults",
			opts: nil,
			want: []string{"openid", "profile", "email"},
		},
		{
			name: "explicit empty still requests openid",
			opts: []LoginOption{WithScopes()},
			want: []string{"openid"},
		},
		{
			name: "application scopes gain openid",
			opts: []LoginOption{WithScopes("sandbox:read", "sandbox:write")},
			want: []string{"openid", "sandbox:read", "sandbox:write"},
		},
		{
			name: "existing openid is not duplicated",
			opts: []LoginOption{WithScopes("openid", "profile")},
			want: []string{"openid", "profile"},
		},
		{
			name: "openid is normalized to the front",
			opts: []LoginOption{WithScopes("profile", "openid", "email")},
			want: []string{"openid", "profile", "email"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cfg loginConfig
			for _, opt := range tt.opts {
				opt(&cfg)
			}
			cfg.applyDefaults()
			cfg.requireOpenIDScope()

			assert.Equal(t, tt.want, cfg.scopes)
		})
	}
}

func TestWithKeyboardFlow(t *testing.T) {
	var cfg loginConfig
	WithKeyboardFlow()(&cfg)

	assert.True(t, cfg.keyboardFlow)
}

func TestWithInMemory(t *testing.T) {
	var cfg loginConfig
	WithInMemory()(&cfg)

	assert.True(t, cfg.inMemory)
}

func TestWithDisplayFunc(t *testing.T) {
	called := false
	fn := func(_, _ string) { called = true }

	var cfg loginConfig
	WithDisplayFunc(fn)(&cfg)

	assert.NotNil(t, cfg.displayFunc)
	cfg.displayFunc("http://example.com", "ABCD-1234")
	assert.True(t, called)
}

func TestWithGateway(t *testing.T) {
	var cfg loginConfig
	WithGateway("prod-gw")(&cfg)

	assert.Equal(t, "prod-gw", cfg.gateway)
}

func TestMultipleOptions(t *testing.T) {
	opts := []LoginOption{
		WithIssuer("https://auth.example.com"),
		WithClientID("app-id"),
		WithScopes("openid"),
		WithTimeout(30 * time.Second),
		WithKeyboardFlow(),
	}

	var cfg loginConfig
	for _, opt := range opts {
		opt(&cfg)
	}
	cfg.applyDefaults()

	assert.Equal(t, "https://auth.example.com", cfg.issuer)
	assert.Equal(t, "app-id", cfg.clientID)
	assert.Equal(t, []string{"openid"}, cfg.scopes)
	assert.Equal(t, 30*time.Second, cfg.timeout)
	assert.True(t, cfg.keyboardFlow)
}

func TestDefaultScopes_NotMutatedByConfig(t *testing.T) {
	// Verify the package-level defaultScopes slice is not shared.
	var cfg loginConfig
	cfg.applyDefaults()
	cfg.scopes[0] = "mutated"

	assert.Equal(t, "openid", defaultScopes[0])
}

func TestLastOptionWins(t *testing.T) {
	var cfg loginConfig
	WithIssuer("first")(&cfg)
	WithIssuer("second")(&cfg)

	assert.Equal(t, "second", cfg.issuer)
}
