// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"

	v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1"
	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
)

// NewClient creates a fully wired SDK client from an on-disk gateway
// configuration. If name is empty, the active gateway (set via
// `openshell gateway use`) is used.
//
// The function resolves the gateway directory, parses metadata.json,
// loads tokens lazily, maps the auth mode to an SDK auth provider, and
// applies any ClientOptions before delegating to [v1.NewClient].
//
// NewClient is safe for concurrent use from multiple goroutines.
func NewClient(name string, opts ...ClientOption) (*v1.Client, error) {
	cfg, err := loadConfigInternal(name)
	if err != nil {
		return nil, err
	}

	// Apply caller options.
	cc := &clientConfig{}
	for _, o := range opts {
		o(cc)
	}

	// Resolve auth provider: caller override takes precedence.
	auth := cc.auth
	if auth == nil {
		auth, err = resolveAuthProvider(cfg)
		if err != nil {
			return nil, err
		}
	}

	// Build the SDK Config.
	sdkCfg := types.Config{
		Address: cfg.Endpoint,
		Auth:    auth,
	}

	// Apply TLS: caller override or auth-mode defaults.
	if cc.tls != nil {
		sdkCfg.TLS = cc.tls
	} else if cfg.AuthMode == AuthModePlaintext {
		sdkCfg.TLS = &types.TLSConfig{Insecure: true}
	}

	if cc.timeout > 0 {
		sdkCfg.Timeout = cc.timeout
	}
	if cc.retryPolicy != nil {
		sdkCfg.RetryPolicy = cc.retryPolicy
	}
	if cc.logger != nil {
		sdkCfg.Logger = cc.logger
	}

	return v1.NewClient(sdkCfg)
}

// LoadConfig reads and parses a gateway's on-disk configuration without
// creating a client connection. If name is empty, the active gateway is
// used.
//
// The returned [Config] is an immutable snapshot; changes to the on-disk
// files after this call are not reflected.
//
// LoadConfig is safe for concurrent use from multiple goroutines.
func LoadConfig(name string) (*Config, error) {
	return loadConfigInternal(name)
}

// loadConfigInternal resolves the gateway name (including active gateway
// fallback), finds the config directory, and parses metadata.json. This
// shared implementation is used by both NewClient and LoadConfig.
func loadConfigInternal(name string) (*Config, error) {
	// If name is empty, resolve the active gateway.
	if name == "" {
		activeName, err := resolveActiveGateway()
		if err != nil {
			return nil, err
		}
		name = activeName
	}

	dir, source, err := resolveGatewayDir(name)
	if err != nil {
		return nil, err
	}

	cfg, err := parseMetadata(dir)
	if err != nil {
		return nil, err
	}

	// Override name from directory (validated) rather than metadata.json.
	cfg.Name = name
	cfg.Source = source

	return cfg, nil
}

// ListGateways enumerates all available gateways from user and system
// directories. User gateways appear first. If the same name exists in
// both directories, only the user gateway is returned (user precedence).
// Returns an empty slice (not an error) when no gateways are configured.
//
// ListGateways is safe for concurrent use from multiple goroutines.
func ListGateways() ([]Info, error) {
	seen := make(map[string]bool)
	var result []Info

	activeName, _ := resolveActiveGateway()

	userBase, err := userConfigDir()
	if err == nil {
		names, listErr := listGatewayDirs(userBase)
		if listErr != nil {
			return nil, listErr
		}
		for _, name := range names {
			seen[name] = true
			result = append(result, Info{
				Name:   name,
				Active: name == activeName,
				Source: SourceUser,
			})
		}
	}

	sysNames, listErr := listGatewayDirs(systemConfigBase)
	if listErr != nil {
		return nil, listErr
	}
	for _, name := range sysNames {
		if !seen[name] {
			result = append(result, Info{
				Name:   name,
				Active: name == activeName,
				Source: SourceSystem,
			})
		}
	}

	return result, nil
}

// resolveAuthProvider maps a Config's AuthMode to an SDK AuthProvider.
// Tokens are loaded lazily where possible.
func resolveAuthProvider(cfg *Config) (types.AuthProvider, error) {
	switch cfg.AuthMode {
	case AuthModeNone:
		return v1.NoAuth(), nil

	case AuthModePlaintext:
		return v1.NoAuth(), nil

	case AuthModeCloudflareJWT:
		// Token loading is deferred to GetRequestMetadata so that
		// NewClient succeeds even when the token file is missing.
		// The error surfaces on first authentication attempt (FR-007).
		return &lazyEdgeAuth{loader: &edgeTokenLoader{dir: cfg.Dir}}, nil

	case AuthModeOIDC:
		src := newDiskTokenSource(cfg.Dir)
		return v1.RefreshableToken(src)

	case AuthModeMTLS:
		return nil, fmt.Errorf("%w: mtls is not yet supported; use WithAuth() to provide a custom auth provider", ErrUnsupportedAuthMode)

	default:
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedAuthMode, cfg.AuthMode)
	}
}
