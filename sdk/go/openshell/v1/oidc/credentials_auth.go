// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"
	"sync"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/sync/singleflight"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
)

const clientCredentialsLeeway = 30 * time.Second

type clientCredentialsAuth struct {
	cfg   *loginConfig
	mu    sync.Mutex
	token *oauth2.Token
	group singleflight.Group
}

// NewClientCredentialsAuth returns a renewable, memory-only client-credentials
// AuthProvider suitable for v1.Config.Auth or gateway.WithAuth. Acquisition is
// lazy, concurrent RPCs share one exchange, and expired tokens are never used
// when renewal fails.
func NewClientCredentialsAuth(opts ...LoginOption) (types.AuthProvider, error) {
	cfg, err := resolveClientCredentialsConfig(opts...)
	if err != nil {
		return nil, err
	}
	return &clientCredentialsAuth{cfg: cfg}, nil
}

func (a *clientCredentialsAuth) GetRequestMetadata(ctx context.Context, _ ...string) (map[string]string, error) {
	if accessToken, ok := a.cachedAccessToken(); ok {
		return map[string]string{"authorization": "Bearer " + accessToken}, nil
	}

	result := a.group.DoChan("exchange", func() (any, error) {
		return a.accessTokenForExchange()
	})
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case exchange := <-result:
		if exchange.Err != nil {
			return nil, exchange.Err
		}
		return map[string]string{"authorization": "Bearer " + exchange.Val.(string)}, nil
	}
}

func (a *clientCredentialsAuth) cachedAccessToken() (string, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.token != nil && time.Now().Add(clientCredentialsLeeway).Before(a.token.Expiry) {
		return a.token.AccessToken, true
	}
	return "", false
}

func (a *clientCredentialsAuth) accessTokenForExchange() (string, error) {
	// A caller can miss the initial cache check, then become the next flight
	// leader after another exchange completes and singleflight removes it.
	// Re-check here so that caller reuses the token instead of exchanging again.
	if accessToken, ok := a.cachedAccessToken(); ok {
		return accessToken, nil
	}

	exchangeCtx, cancel := context.WithTimeout(context.Background(), a.cfg.timeout)
	defer cancel()
	token, err := exchangeClientCredentials(exchangeCtx, a.cfg, true)
	if err != nil {
		return "", err
	}
	a.mu.Lock()
	a.token = token
	a.mu.Unlock()
	return token.AccessToken, nil
}

func (*clientCredentialsAuth) RequireTransportSecurity() bool { return true }

func (*clientCredentialsAuth) String() string { return "oidc.ClientCredentialsAuth" }

func (*clientCredentialsAuth) GoString() string { return "oidc.ClientCredentialsAuth{}" }
