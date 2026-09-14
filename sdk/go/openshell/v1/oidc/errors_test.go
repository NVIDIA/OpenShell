// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSentinelErrors_AreDistinct(t *testing.T) {
	sentinels := []error{
		ErrDiscovery,
		ErrAuthCode,
		ErrDeviceCode,
		ErrClientCredentials,
		ErrTimeout,
		ErrCallbackServer,
		ErrTokenPersist,
		ErrOIDCConfig,
	}

	for i, a := range sentinels {
		for j, b := range sentinels {
			if i == j {
				continue
			}
			assert.False(t, errors.Is(a, b),
				"expected %v and %v to be distinct", a, b)
		}
	}
}

func TestSentinelErrors_MatchSelf(t *testing.T) {
	sentinels := []error{
		ErrDiscovery,
		ErrAuthCode,
		ErrDeviceCode,
		ErrClientCredentials,
		ErrTimeout,
		ErrCallbackServer,
		ErrTokenPersist,
		ErrOIDCConfig,
	}

	for _, sentinel := range sentinels {
		assert.True(t, errors.Is(sentinel, sentinel),
			"expected %v to match itself", sentinel)
	}
}

func TestSentinelErrors_WrappedMatchViIs(t *testing.T) {
	cases := []struct {
		name     string
		sentinel error
	}{
		{"ErrDiscovery", ErrDiscovery},
		{"ErrAuthCode", ErrAuthCode},
		{"ErrDeviceCode", ErrDeviceCode},
		{"ErrClientCredentials", ErrClientCredentials},
		{"ErrTimeout", ErrTimeout},
		{"ErrCallbackServer", ErrCallbackServer},
		{"ErrTokenPersist", ErrTokenPersist},
		{"ErrOIDCConfig", ErrOIDCConfig},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wrapped := fmt.Errorf("operation failed: %w", tc.sentinel)
			assert.True(t, errors.Is(wrapped, tc.sentinel),
				"wrapped error should match sentinel via errors.Is")
		})
	}
}

func TestSentinelErrors_HaveDescriptiveMessages(t *testing.T) {
	cases := []struct {
		sentinel error
		contains string
	}{
		{ErrDiscovery, "discovery"},
		{ErrAuthCode, "auth code"},
		{ErrDeviceCode, "device code"},
		{ErrClientCredentials, "client credentials"},
		{ErrTimeout, "timed out"},
		{ErrCallbackServer, "callback server"},
		{ErrTokenPersist, "token persistence"},
		{ErrOIDCConfig, "OIDC config"},
	}

	for _, tc := range cases {
		t.Run(tc.sentinel.Error(), func(t *testing.T) {
			assert.Contains(t, tc.sentinel.Error(), tc.contains)
		})
	}
}

func TestSentinelErrors_DoubleWrapped(t *testing.T) {
	inner := fmt.Errorf("http timeout: %w", ErrDiscovery)
	outer := fmt.Errorf("login failed: %w", inner)

	assert.True(t, errors.Is(outer, ErrDiscovery),
		"double-wrapped error should still match sentinel")
}
