// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package gateway

import "errors"

// Sentinel errors for gateway configuration failures. All wrapped errors
// returned by this package support classification via [errors.Is].
var (
	// ErrGatewayNotFound is returned when no gateway directory exists
	// in either the user or system config paths.
	ErrGatewayNotFound = errors.New("gateway: not found")

	// ErrConfigParse is returned when metadata.json is missing,
	// unreadable, or contains invalid JSON.
	ErrConfigParse = errors.New("gateway: config parse error")

	// ErrTokenLoad is returned when a token file (edge_token,
	// oidc_token.json) is missing, unreadable, or malformed.
	ErrTokenLoad = errors.New("gateway: token load error")

	// ErrUnsupportedAuthMode is returned when the auth_mode value in
	// metadata.json is not recognized (not none, plaintext,
	// cloudflare_jwt, oidc, or mtls).
	ErrUnsupportedAuthMode = errors.New("gateway: unsupported auth mode")

	// ErrInvalidGatewayName is returned when a gateway name fails
	// validation (empty, contains path separators, dots, or
	// non-ASCII-alnum-dash-underscore characters).
	ErrInvalidGatewayName = errors.New("gateway: invalid gateway name")

	// ErrNoActiveGateway is returned when no active gateway is
	// configured (active_gateway file missing or empty).
	ErrNoActiveGateway = errors.New("gateway: no active gateway")
)
