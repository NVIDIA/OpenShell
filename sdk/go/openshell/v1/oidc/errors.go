// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package oidc

import "errors"

// Sentinel errors for OIDC authentication failures. All wrapped errors
// returned by this package support classification via [errors.Is].
var (
	// ErrDiscovery is returned when the OIDC discovery document
	// (.well-known/openid-configuration) cannot be fetched or parsed.
	ErrDiscovery = errors.New("oidc: discovery failed")

	// ErrAuthCode is returned when the authorization code exchange
	// fails (invalid code, expired code, provider error).
	ErrAuthCode = errors.New("oidc: auth code exchange failed")

	// ErrDeviceCode is returned when the device code flow fails
	// (request error, expired device code, provider error).
	ErrDeviceCode = errors.New("oidc: device code flow failed")

	// ErrClientCredentials is returned when the client credentials
	// grant fails (invalid credentials, provider error). The error
	// message never contains the client secret.
	ErrClientCredentials = errors.New("oidc: client credentials exchange failed")

	// ErrTimeout is returned when an interactive login flow
	// (browser, keyboard, or device code) exceeds its deadline.
	ErrTimeout = errors.New("oidc: login timed out")

	// ErrCallbackServer is returned when the localhost HTTP server
	// for the authorization code redirect cannot bind to any port.
	ErrCallbackServer = errors.New("oidc: callback server failed")

	// ErrTokenPersist is returned when the token cannot be written
	// to disk (permission error, invalid path).
	ErrTokenPersist = errors.New("oidc: token persistence failed")

	// ErrOIDCConfig is returned when gateway metadata is missing
	// the required oidc_issuer or oidc_client_id fields.
	ErrOIDCConfig = errors.New("oidc: gateway OIDC config missing")
)
