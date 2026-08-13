// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"
	"errors"
	"sync"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/sync/singleflight"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
)

const (
	defaultLeeway  = 10 * time.Second
	initialBackoff = 1 * time.Second
	maxBackoff     = 30 * time.Second
)

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
	source    oauth2.TokenSource
	mu        sync.Mutex
	group     singleflight.Group
	tok       *oauth2.Token
	leeway    time.Duration
	logger    types.Logger
	nextRetry time.Time
	backoff   time.Duration
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

func (r *refreshableAuth) GetRequestMetadata(ctx context.Context, _ ...string) (map[string]string, error) {
	r.mu.Lock()
	if r.isTokenValid() {
		tok := r.tok.AccessToken
		r.mu.Unlock()
		return map[string]string{"authorization": "Bearer " + tok}, nil
	}

	if !r.nextRetry.IsZero() && time.Now().Before(r.nextRetry) {
		if r.tok != nil {
			tok := r.tok.AccessToken
			r.mu.Unlock()
			return map[string]string{"authorization": "Bearer " + tok}, nil
		}
		r.mu.Unlock()
		return nil, errors.New("openshell: token refresh failed and backoff is active")
	}
	r.mu.Unlock()

	resultCh := r.group.DoChan("refresh", func() (any, error) {
		return r.source.Token()
	})
	var val any
	var err error
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case result := <-resultCh:
		val = result.Val
		err = result.Err
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if err != nil {
		if r.nextRetry.IsZero() || !time.Now().Before(r.nextRetry) {
			bo := r.backoff
			if bo == 0 {
				bo = initialBackoff
			} else {
				bo *= 2
				if bo > maxBackoff {
					bo = maxBackoff
				}
			}
			r.backoff = bo
			r.nextRetry = time.Now().Add(bo)
		}

		if r.tok != nil {
			if r.logger != nil {
				r.logger.Error(err, "token refresh failed, using cached token")
			}
			return map[string]string{"authorization": "Bearer " + r.tok.AccessToken}, nil
		}
		return nil, err
	}

	tok, ok := val.(*oauth2.Token)
	if !ok || tok == nil {
		return nil, errors.New("openshell: token source returned nil token without error")
	}
	r.tok = tok
	r.backoff = 0
	r.nextRetry = time.Time{}
	return map[string]string{"authorization": "Bearer " + r.tok.AccessToken}, nil
}

func (r *refreshableAuth) RequireTransportSecurity() bool {
	return true
}

// RefreshableToken returns an AuthProvider that caches tokens from src
// and refreshes them before expiry. Concurrent callers share a single
// in-flight refresh via singleflight. Failed refreshes trigger exponential
// backoff (1s, 2s, 4s, ..., 30s cap) to avoid amplifying token endpoint outages.
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
