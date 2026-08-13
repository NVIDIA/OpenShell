// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// AuthMode represents the authentication mode configured for a gateway.
type AuthMode string

// Known auth mode values matching the Rust CLI's gateway configuration.
const (
	// AuthModeNone indicates no authentication (default when auth_mode is
	// unset or explicitly "none").
	AuthModeNone AuthMode = ""

	// AuthModePlaintext indicates an insecure plaintext connection with
	// no TLS and no authentication.
	AuthModePlaintext AuthMode = "plaintext"

	// AuthModeCloudflareJWT indicates Cloudflare Access JWT authentication
	// using an edge token loaded from disk.
	AuthModeCloudflareJWT AuthMode = "cloudflare_jwt"

	// AuthModeOIDC indicates OpenID Connect authentication using a
	// refreshable token bundle loaded from disk.
	AuthModeOIDC AuthMode = "oidc"

	// AuthModeMTLS indicates mutual TLS authentication. Currently
	// unsupported; returns [ErrUnsupportedAuthMode] with guidance.
	AuthModeMTLS AuthMode = "mtls"
)

// ConfigSource identifies where a gateway configuration was found.
type ConfigSource string

const (
	// SourceUser indicates the gateway was found in the user config
	// directory ($XDG_CONFIG_HOME/openshell/gateways/).
	SourceUser ConfigSource = "user"

	// SourceSystem indicates the gateway was found in the system config
	// directory (/etc/openshell/gateways/).
	SourceSystem ConfigSource = "system"
)

// Config is a parsed representation of a gateway's on-disk metadata.json.
// It is an immutable snapshot captured at load time; subsequent changes to
// the on-disk files are not reflected.
type Config struct {
	// Name is the validated gateway name.
	Name string

	// Endpoint is the host:port address of the gateway.
	Endpoint string

	// AuthMode is the resolved authentication mode.
	AuthMode AuthMode

	// Source indicates whether the config came from the user or system
	// directory.
	Source ConfigSource

	// Dir is the absolute path to the gateway config directory.
	Dir string

	// OIDCIssuer is the OIDC provider's issuer URL read from
	// metadata.json. Empty when the gateway does not use OIDC auth.
	OIDCIssuer string

	// OIDCClientID is the OAuth2 client ID read from metadata.json.
	// Empty when the gateway does not use OIDC auth.
	OIDCClientID string
}

// Info is a lightweight summary of a gateway for listing purposes.
// It does not load tokens or validate config completeness.
type Info struct {
	// Name is the gateway name derived from the directory listing.
	Name string

	// Active indicates whether this is the currently active gateway.
	Active bool

	// Source indicates whether the gateway is from the user or system
	// directory.
	Source ConfigSource
}

// metadataJSON is the on-disk representation of metadata.json.
// Unknown fields are silently ignored for forward compatibility.
type metadataJSON struct {
	Endpoint     string `json:"gateway_endpoint"`
	AuthMode     string `json:"auth_mode"`
	Name         string `json:"name"`
	OIDCIssuer   string `json:"oidc_issuer"`
	OIDCClientID string `json:"oidc_client_id"`
}

// parseAuthMode converts a raw auth_mode string to the typed AuthMode.
// Empty string and "none" both map to AuthModeNone.
func parseAuthMode(raw string) (AuthMode, error) {
	switch raw {
	case "", "none":
		return AuthModeNone, nil
	case "plaintext":
		return AuthModePlaintext, nil
	case "cloudflare_jwt":
		return AuthModeCloudflareJWT, nil
	case "oidc":
		return AuthModeOIDC, nil
	case "mtls":
		return AuthModeMTLS, nil
	default:
		return "", fmt.Errorf("%w: %q", ErrUnsupportedAuthMode, raw)
	}
}

// parseMetadata reads and parses metadata.json from the given gateway
// directory. Unknown fields are silently ignored for forward compatibility
// with newer Rust CLI versions.
func parseMetadata(dir string) (*Config, error) {
	path := filepath.Join(dir, "metadata.json")

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrConfigParse, err)
	}

	var meta metadataJSON
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, fmt.Errorf("%w: invalid JSON in %s: %v", ErrConfigParse, path, err)
	}

	if meta.Endpoint == "" {
		return nil, fmt.Errorf("%w: missing gateway_endpoint in %s", ErrConfigParse, path)
	}

	mode, err := parseAuthMode(meta.AuthMode)
	if err != nil {
		return nil, err
	}

	return &Config{
		Name:         meta.Name,
		Endpoint:     meta.Endpoint,
		AuthMode:     mode,
		Dir:          dir,
		OIDCIssuer:   meta.OIDCIssuer,
		OIDCClientID: meta.OIDCClientID,
	}, nil
}
