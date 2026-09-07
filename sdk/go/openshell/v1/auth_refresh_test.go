// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

// mockTokenSource implements oauth2.TokenSource for testing.
type mockTokenSource struct {
	mu        sync.Mutex
	tokenFunc func() (*oauth2.Token, error)
	callCount int
}

func (m *mockTokenSource) Token() (*oauth2.Token, error) {
	m.mu.Lock()
	m.callCount++
	m.mu.Unlock()
	return m.tokenFunc()
}

func (m *mockTokenSource) calls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.callCount
}

// --- Phase 2 tests: constructor validation ---

func TestRefreshableToken_NilSource(t *testing.T) {
	_, err := RefreshableToken(nil)
	require.Error(t, err)
	assert.Equal(t, "openshell: TokenSource must not be nil", err.Error())
}

func TestRefreshableToken_ValidSource(t *testing.T) {
	src := &mockTokenSource{
		tokenFunc: func() (*oauth2.Token, error) {
			return &oauth2.Token{AccessToken: "tok", Expiry: time.Now().Add(time.Hour)}, nil
		},
	}
	provider, err := RefreshableToken(src)
	require.NoError(t, err)
	assert.NotNil(t, provider)
}

func TestGetRequestMetadata_ReturnsWhenContextCanceledDuringRefresh(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	src := &mockTokenSource{tokenFunc: func() (*oauth2.Token, error) {
		<-release
		return &oauth2.Token{AccessToken: "late-token"}, nil
	}}
	provider, err := RefreshableToken(src)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	started := time.Now()
	_, err = provider.GetRequestMetadata(ctx)

	require.ErrorIs(t, err, context.Canceled)
	assert.Less(t, time.Since(started), time.Second)
}

// --- Phase 3 / US1 tests: automatic token refresh ---

func TestGetRequestMetadata_FirstCallFetchesToken(t *testing.T) {
	src := &mockTokenSource{
		tokenFunc: func() (*oauth2.Token, error) {
			return &oauth2.Token{AccessToken: "fresh-token", Expiry: time.Now().Add(time.Hour)}, nil
		},
	}
	provider, err := RefreshableToken(src)
	require.NoError(t, err)

	md, err := provider.GetRequestMetadata(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "Bearer fresh-token", md["authorization"])
	assert.Equal(t, 1, src.calls())
}

func TestGetRequestMetadata_CachedTokenNoExtraCall(t *testing.T) {
	src := &mockTokenSource{
		tokenFunc: func() (*oauth2.Token, error) {
			return &oauth2.Token{AccessToken: "cached-token", Expiry: time.Now().Add(time.Hour)}, nil
		},
	}
	provider, err := RefreshableToken(src)
	require.NoError(t, err)

	_, err = provider.GetRequestMetadata(context.Background())
	require.NoError(t, err)

	md, err := provider.GetRequestMetadata(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "Bearer cached-token", md["authorization"])
	assert.Equal(t, 1, src.calls(), "second call should use cache, not invoke TokenSource")
}

func TestGetRequestMetadata_RefreshesExpiredToken(t *testing.T) {
	var callNum atomic.Int32
	src := &mockTokenSource{
		tokenFunc: func() (*oauth2.Token, error) {
			n := callNum.Add(1)
			if n == 1 {
				return &oauth2.Token{AccessToken: "old", Expiry: time.Now().Add(-time.Minute)}, nil
			}
			return &oauth2.Token{AccessToken: "new", Expiry: time.Now().Add(time.Hour)}, nil
		},
	}
	provider, err := RefreshableToken(src, WithLeeway(0))
	require.NoError(t, err)

	// First call gets the expired token, which is immediately stale.
	md, err := provider.GetRequestMetadata(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "Bearer old", md["authorization"])

	// Second call should trigger a refresh since the cached token is expired.
	md, err = provider.GetRequestMetadata(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "Bearer new", md["authorization"])
	assert.Equal(t, 2, src.calls())
}

func TestGetRequestMetadata_ConcurrentSingleFlight(t *testing.T) {
	var fetchCount atomic.Int32
	src := &mockTokenSource{
		tokenFunc: func() (*oauth2.Token, error) {
			fetchCount.Add(1)
			time.Sleep(100 * time.Millisecond)
			return &oauth2.Token{AccessToken: "shared-token", Expiry: time.Now().Add(time.Hour)}, nil
		},
	}
	provider, err := RefreshableToken(src)
	require.NoError(t, err)

	const goroutines = 20
	var wg sync.WaitGroup
	wg.Add(goroutines)
	ready := make(chan struct{})
	results := make([]string, goroutines)
	errs := make([]error, goroutines)

	for i := range goroutines {
		go func(idx int) {
			defer wg.Done()
			<-ready
			md, e := provider.GetRequestMetadata(context.Background())
			errs[idx] = e
			if md != nil {
				results[idx] = md["authorization"]
			}
		}(i)
	}
	close(ready)
	wg.Wait()

	for i := range goroutines {
		require.NoError(t, errs[i], "goroutine %d failed", i)
		assert.Equal(t, "Bearer shared-token", results[i], "goroutine %d got wrong token", i)
	}
	assert.Equal(t, int32(1), fetchCount.Load(), "expected exactly 1 TokenSource.Token() call, got %d", fetchCount.Load())
}

func TestRefreshableAuth_RequireTransportSecurity(t *testing.T) {
	src := &mockTokenSource{
		tokenFunc: func() (*oauth2.Token, error) {
			return &oauth2.Token{AccessToken: "t"}, nil
		},
	}
	provider, err := RefreshableToken(src)
	require.NoError(t, err)
	assert.True(t, provider.RequireTransportSecurity())
}

// --- Phase 4 / US2 tests: graceful degradation ---

func TestGetRequestMetadata_RefreshFailureReturnsStaleCachedToken(t *testing.T) {
	var callNum atomic.Int32
	src := &mockTokenSource{
		tokenFunc: func() (*oauth2.Token, error) {
			n := callNum.Add(1)
			if n == 1 {
				return &oauth2.Token{AccessToken: "stale", Expiry: time.Now().Add(-time.Minute)}, nil
			}
			return nil, fmt.Errorf("idp unavailable")
		},
	}
	provider, err := RefreshableToken(src, WithLeeway(0))
	require.NoError(t, err)

	// First call succeeds but returns already-expired token.
	_, err = provider.GetRequestMetadata(context.Background())
	require.NoError(t, err)

	// Second call: refresh fails, should return stale token.
	md, err := provider.GetRequestMetadata(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "Bearer stale", md["authorization"])
}

func TestGetRequestMetadata_RefreshFailureLogsWarning(t *testing.T) {
	var callNum atomic.Int32
	src := &mockTokenSource{
		tokenFunc: func() (*oauth2.Token, error) {
			n := callNum.Add(1)
			if n == 1 {
				return &oauth2.Token{AccessToken: "stale", Expiry: time.Now().Add(-time.Minute)}, nil
			}
			return nil, fmt.Errorf("idp unavailable")
		},
	}

	logger := &captureLogger{}
	provider, err := RefreshableToken(src, WithLeeway(0), WithLogger(logger))
	require.NoError(t, err)

	_, _ = provider.GetRequestMetadata(context.Background())
	_, _ = provider.GetRequestMetadata(context.Background())

	require.Len(t, logger.errors, 1)
	assert.Contains(t, logger.errors[0].msg, "token refresh failed")
}

func TestGetRequestMetadata_RefreshFailureNoCachedTokenReturnsError(t *testing.T) {
	src := &mockTokenSource{
		tokenFunc: func() (*oauth2.Token, error) {
			return nil, fmt.Errorf("idp unavailable")
		},
	}
	provider, err := RefreshableToken(src)
	require.NoError(t, err)

	_, err = provider.GetRequestMetadata(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "idp unavailable")
}

func TestGetRequestMetadata_RefreshFailureNoLoggerNoPanic(t *testing.T) {
	var callNum atomic.Int32
	src := &mockTokenSource{
		tokenFunc: func() (*oauth2.Token, error) {
			n := callNum.Add(1)
			if n == 1 {
				return &oauth2.Token{AccessToken: "stale", Expiry: time.Now().Add(-time.Minute)}, nil
			}
			return nil, fmt.Errorf("idp unavailable")
		},
	}
	provider, err := RefreshableToken(src, WithLeeway(0))
	require.NoError(t, err)

	_, _ = provider.GetRequestMetadata(context.Background())

	assert.NotPanics(t, func() {
		_, _ = provider.GetRequestMetadata(context.Background())
	})
}

// --- Phase 5 / US3 tests: configurable leeway ---

func TestGetRequestMetadata_DefaultLeewayTriggersRefresh(t *testing.T) {
	var callNum atomic.Int32
	src := &mockTokenSource{
		tokenFunc: func() (*oauth2.Token, error) {
			n := callNum.Add(1)
			return &oauth2.Token{
				AccessToken: fmt.Sprintf("token-%d", n),
				Expiry:      time.Now().Add(5 * time.Second), // within default 10s leeway
			}, nil
		},
	}
	provider, err := RefreshableToken(src) // default 10s leeway
	require.NoError(t, err)

	_, err = provider.GetRequestMetadata(context.Background())
	require.NoError(t, err)

	// Token expires in 5s, which is within 10s leeway, so next call should refresh.
	md, err := provider.GetRequestMetadata(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "Bearer token-2", md["authorization"])
	assert.Equal(t, 2, src.calls())
}

func TestGetRequestMetadata_CustomLeewayTriggersRefresh(t *testing.T) {
	var callNum atomic.Int32
	src := &mockTokenSource{
		tokenFunc: func() (*oauth2.Token, error) {
			n := callNum.Add(1)
			return &oauth2.Token{
				AccessToken: fmt.Sprintf("token-%d", n),
				Expiry:      time.Now().Add(25 * time.Second), // within custom 30s leeway
			}, nil
		},
	}
	provider, err := RefreshableToken(src, WithLeeway(30*time.Second))
	require.NoError(t, err)

	_, err = provider.GetRequestMetadata(context.Background())
	require.NoError(t, err)

	// Token expires in 25s, which is within 30s leeway, so next call should refresh.
	md, err := provider.GetRequestMetadata(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "Bearer token-2", md["authorization"])
	assert.Equal(t, 2, src.calls())
}

func TestGetRequestMetadata_ZeroExpiryNeverRefreshes(t *testing.T) {
	src := &mockTokenSource{
		tokenFunc: func() (*oauth2.Token, error) {
			return &oauth2.Token{AccessToken: "forever-token"}, nil // zero Expiry
		},
	}
	provider, err := RefreshableToken(src)
	require.NoError(t, err)

	_, err = provider.GetRequestMetadata(context.Background())
	require.NoError(t, err)

	// Call multiple times; should never refresh since expiry is zero.
	for range 10 {
		_, err = provider.GetRequestMetadata(context.Background())
		require.NoError(t, err)
	}
	assert.Equal(t, 1, src.calls(), "zero-expiry token should never be refreshed")
}

// --- Backoff tests ---

func TestGetRequestMetadata_BackoffSkipsRefreshDuringWindow(t *testing.T) {
	var callNum atomic.Int32
	src := &mockTokenSource{
		tokenFunc: func() (*oauth2.Token, error) {
			n := callNum.Add(1)
			if n == 1 {
				return &oauth2.Token{AccessToken: "stale", Expiry: time.Now().Add(-time.Minute)}, nil
			}
			return nil, fmt.Errorf("idp down")
		},
	}
	provider, err := RefreshableToken(src, WithLeeway(0))
	require.NoError(t, err)

	_, err = provider.GetRequestMetadata(context.Background())
	require.NoError(t, err)
	_, err = provider.GetRequestMetadata(context.Background())
	require.NoError(t, err)
	beforeCount := src.calls()
	require.Equal(t, 2, beforeCount)

	ra := provider.(*refreshableAuth)
	ra.mu.Lock()
	ra.nextRetry = time.Now().Add(time.Minute)
	ra.mu.Unlock()

	md, err := provider.GetRequestMetadata(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "Bearer stale", md["authorization"])
	assert.Equal(t, beforeCount, src.calls(), "should not call Token() during backoff window")
}

func TestGetRequestMetadata_BackoffResetsOnSuccess(t *testing.T) {
	var callNum atomic.Int32
	src := &mockTokenSource{
		tokenFunc: func() (*oauth2.Token, error) {
			n := callNum.Add(1)
			switch n {
			case 1:
				return &oauth2.Token{AccessToken: "initial", Expiry: time.Now().Add(-time.Second)}, nil
			case 2:
				return nil, fmt.Errorf("fail once")
			default:
				return &oauth2.Token{AccessToken: "recovered", Expiry: time.Now().Add(time.Hour)}, nil
			}
		},
	}
	provider, err := RefreshableToken(src, WithLeeway(0))
	require.NoError(t, err)

	_, _ = provider.GetRequestMetadata(context.Background())
	_, _ = provider.GetRequestMetadata(context.Background())

	ra := provider.(*refreshableAuth)
	ra.mu.Lock()
	ra.nextRetry = time.Time{}
	ra.mu.Unlock()

	md, err := provider.GetRequestMetadata(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "Bearer recovered", md["authorization"])

	ra.mu.Lock()
	assert.Equal(t, time.Duration(0), ra.backoff, "backoff should reset after success")
	assert.True(t, ra.nextRetry.IsZero(), "nextRetry should be zero after success")
	ra.mu.Unlock()
}

func TestGetRequestMetadata_BackoffCapsAt30s(t *testing.T) {
	src := &mockTokenSource{
		tokenFunc: func() (*oauth2.Token, error) {
			return nil, fmt.Errorf("always fail")
		},
	}
	provider, err := RefreshableToken(src, WithLeeway(0))
	require.NoError(t, err)

	ra := provider.(*refreshableAuth)

	for range 10 {
		ra.mu.Lock()
		ra.nextRetry = time.Time{}
		ra.mu.Unlock()

		_, _ = provider.GetRequestMetadata(context.Background())
	}

	ra.mu.Lock()
	assert.Equal(t, maxBackoff, ra.backoff, "backoff should cap at maxBackoff")
	ra.mu.Unlock()
}

func TestGetRequestMetadata_ConcurrentFailureBackoffNotOverIncremented(t *testing.T) {
	src := &mockTokenSource{
		tokenFunc: func() (*oauth2.Token, error) {
			time.Sleep(10 * time.Millisecond)
			return nil, fmt.Errorf("idp down")
		},
	}
	provider, err := RefreshableToken(src, WithLeeway(0))
	require.NoError(t, err)

	const goroutines = 20
	var wg sync.WaitGroup
	wg.Add(goroutines)
	ready := make(chan struct{})
	for range goroutines {
		go func() {
			defer wg.Done()
			<-ready
			_, _ = provider.GetRequestMetadata(context.Background())
		}()
	}
	close(ready)
	wg.Wait()

	ra := provider.(*refreshableAuth)
	ra.mu.Lock()
	assert.Equal(t, initialBackoff, ra.backoff,
		"a single coalesced failure should set backoff to initialBackoff, not escalate")
	ra.mu.Unlock()
	assert.Equal(t, 1, src.calls(), "singleflight should coalesce to 1 call")
}

// --- benchmarks ---

func BenchmarkGetRequestMetadata_CachedToken(b *testing.B) {
	src := &mockTokenSource{
		tokenFunc: func() (*oauth2.Token, error) {
			return &oauth2.Token{AccessToken: "bench-token", Expiry: time.Now().Add(time.Hour)}, nil
		},
	}
	provider, err := RefreshableToken(src)
	require.NoError(b, err)

	// Prime the cache.
	_, err = provider.GetRequestMetadata(context.Background())
	require.NoError(b, err)

	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		_, _ = provider.GetRequestMetadata(context.Background())
	}
}

// --- helpers ---

type logEntry struct {
	err error
	msg string
}

type captureLogger struct {
	mu     sync.Mutex
	debugs []string
	infos  []string
	errors []logEntry
}

func (l *captureLogger) Debug(msg string, _ ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.debugs = append(l.debugs, msg)
}

func (l *captureLogger) Info(msg string, _ ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.infos = append(l.infos, msg)
}

func (l *captureLogger) Error(err error, msg string, _ ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.errors = append(l.errors, logEntry{err: err, msg: msg})
}
