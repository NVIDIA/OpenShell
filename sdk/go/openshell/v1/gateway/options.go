// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"time"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
)

// clientConfig holds resolved options applied after gateway config
// resolution but before the v1.Client is created.
type clientConfig struct {
	logger      types.Logger
	timeout     time.Duration
	tls         *types.TLSConfig
	auth        types.AuthProvider
	retryPolicy *types.RetryPolicy
}

// ClientOption configures the behavior of [NewClient]. Options are
// applied after gateway configuration is resolved but before the
// underlying SDK client is created.
type ClientOption func(*clientConfig)

// WithLogger sets the logger on the SDK client configuration.
func WithLogger(l types.Logger) ClientOption {
	return func(c *clientConfig) {
		c.logger = l
	}
}

// WithTimeout sets the connection timeout for the SDK client.
func WithTimeout(d time.Duration) ClientOption {
	return func(c *clientConfig) {
		c.timeout = d
	}
}

// WithTLS overrides the TLS settings derived from the gateway's auth mode.
// Use this to provide custom certificates or force insecure connections.
func WithTLS(cfg *types.TLSConfig) ClientOption {
	return func(c *clientConfig) {
		c.tls = cfg
	}
}

// WithAuth overrides the auth provider that would normally be resolved
// from the gateway's auth_mode. When set, the gateway package skips
// its own auth resolution and uses the provided provider directly.
func WithAuth(provider types.AuthProvider) ClientOption {
	return func(c *clientConfig) {
		c.auth = provider
	}
}

// WithRetryPolicy sets the retry policy on the SDK client configuration.
func WithRetryPolicy(p *types.RetryPolicy) ClientOption {
	return func(c *clientConfig) {
		c.retryPolicy = p
	}
}
