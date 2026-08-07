// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"
	"errors"
	"sync"
	"time"

	"golang.org/x/oauth2"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
)

const defaultLeeway = 10 * time.Second

var errNilTokenSource = errors.New("openshell: TokenSource must not be nil")

// RefreshOption configures the behavior of RefreshableToken.
type RefreshOption func(*refreshConfig)

type refreshConfig struct {
	leeway time.Duration
	logger types.Logger
}

func defaultRefreshConfig() refreshConfig {
	return refreshConfig{
		leeway: defaultLeeway,
	}
}

// WithLeeway sets the duration before token expiry at which a proactive
// refresh is triggered. Default is 10 seconds.
func WithLeeway(d time.Duration) RefreshOption {
	return func(c *refreshConfig) {
		if d < 0 {
			d = 0
		}
		c.leeway = d
	}
}

// WithLogger sets the logger used for stale-token fallback warnings.
// When not set, warnings are silently dropped.
func WithLogger(l types.Logger) RefreshOption {
	return func(c *refreshConfig) {
		c.logger = l
	}
}

type refreshableAuth struct {
	source oauth2.TokenSource
	mu     sync.RWMutex
	tok    *oauth2.Token
	leeway time.Duration
	logger types.Logger
}

func (r *refreshableAuth) isTokenValid() bool {
	if r.tok == nil {
		return false
	}
	if r.tok.Expiry.IsZero() {
		return true
	}
	return time.Now().Before(r.tok.Expiry.Add(-r.leeway))
}

func (r *refreshableAuth) GetRequestMetadata(_ context.Context, _ ...string) (map[string]string, error) {
	// Fast path: RLock, return cached token if valid.
	r.mu.RLock()
	if r.isTokenValid() {
		tok := r.tok.AccessToken
		r.mu.RUnlock()
		return map[string]string{"authorization": "Bearer " + tok}, nil
	}
	r.mu.RUnlock()

	// Slow path: Lock, re-check, fetch if still stale.
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.isTokenValid() {
		return map[string]string{"authorization": "Bearer " + r.tok.AccessToken}, nil
	}

	newTok, err := r.source.Token()
	if err != nil {
		if r.tok != nil {
			if r.logger != nil {
				r.logger.Error(err, "token refresh failed, using cached token")
			}
			return map[string]string{"authorization": "Bearer " + r.tok.AccessToken}, nil
		}
		return nil, err
	}

	if newTok == nil {
		if r.tok != nil {
			if r.logger != nil {
				r.logger.Error(errors.New("token source returned nil token"), "token refresh returned nil, using cached token")
			}
			return map[string]string{"authorization": "Bearer " + r.tok.AccessToken}, nil
		}
		return nil, errors.New("openshell: token source returned nil token")
	}

	r.tok = newTok
	return map[string]string{"authorization": "Bearer " + r.tok.AccessToken}, nil
}

func (r *refreshableAuth) RequireTransportSecurity() bool {
	return true
}

// RefreshableToken returns an AuthProvider that caches tokens from src
// and refreshes them before expiry. Concurrent callers share a single
// refresh call (coalesced via RWMutex double-checked locking).
func RefreshableToken(src oauth2.TokenSource, opts ...RefreshOption) (AuthProvider, error) {
	if src == nil {
		return nil, errNilTokenSource
	}

	cfg := defaultRefreshConfig()
	for _, o := range opts {
		o(&cfg)
	}

	return &refreshableAuth{
		source: src,
		leeway: cfg.leeway,
		logger: cfg.logger,
	}, nil
}
