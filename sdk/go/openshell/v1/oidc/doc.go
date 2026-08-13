// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package oidc provides OIDC authentication flows for the OpenShell SDK.
//
// The package supports four authentication flows:
//
//   - Authorization Code with PKCE (interactive browser-based login)
//   - Keyboard flow (manual URL copy and code paste for headless environments)
//   - Device Code flow (RFC 8628, for input-constrained devices)
//   - Client Credentials grant (non-interactive service account authentication)
//
// # Gateway-Aware Login
//
// The primary use case is gateway-aware login, where OIDC provider
// configuration is read from a gateway's metadata.json file:
//
//	token, err := oidc.Login(ctx, "my-gateway")
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// After successful authentication, tokens are persisted to disk in the
// gateway directory as oidc_token.json, compatible with
// [gateway.NewClient] and the existing [gateway.diskTokenSource].
//
// # Standalone Login
//
// For OIDC providers not tied to an OpenShell gateway, use explicit
// configuration:
//
//	token, err := oidc.Login(ctx, "",
//	    oidc.WithIssuer("https://auth.example.com"),
//	    oidc.WithClientID("my-app"),
//	    oidc.WithInMemory(),
//	)
//
// # Device Code Flow
//
// For environments without a browser:
//
//	token, err := oidc.DeviceLogin(ctx,
//	    oidc.WithIssuer("https://auth.example.com"),
//	    oidc.WithClientID("my-app"),
//	)
//
// # Client Credentials
//
// For non-interactive service accounts:
//
//	token, err := oidc.ClientCredentials(ctx,
//	    oidc.WithIssuer("https://auth.example.com"),
//	    oidc.WithClientID("my-service"),
//	    oidc.WithClientSecret("secret"),
//	)
//
// # Error Handling
//
// The package provides typed sentinel errors for precise failure
// classification:
//
//   - [ErrDiscovery]: OIDC discovery fetch or parse failed
//   - [ErrAuthCode]: Authorization code exchange failed
//   - [ErrDeviceCode]: Device code flow failed
//   - [ErrClientCredentials]: Client credentials exchange failed
//   - [ErrTimeout]: Interactive flow timed out
//   - [ErrCallbackServer]: Localhost callback server failed to start
//   - [ErrTokenPersist]: Token disk write failed
//   - [ErrOIDCConfig]: Gateway metadata missing OIDC fields
//
// All errors support [errors.Is] for classification.
//
// # Thread Safety
//
// All exported functions are safe for concurrent use from multiple
// goroutines. OIDC discovery documents are cached in memory per issuer
// URL for the lifetime of the process.
package oidc
