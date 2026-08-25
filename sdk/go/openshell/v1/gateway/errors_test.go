// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

// --- T011: Error type tests ---

func TestSentinelErrors_ErrorsIs(t *testing.T) {
	sentinels := []struct {
		name string
		err  error
	}{
		{"ErrGatewayNotFound", ErrGatewayNotFound},
		{"ErrConfigParse", ErrConfigParse},
		{"ErrTokenLoad", ErrTokenLoad},
		{"ErrUnsupportedAuthMode", ErrUnsupportedAuthMode},
		{"ErrInvalidGatewayName", ErrInvalidGatewayName},
		{"ErrNoActiveGateway", ErrNoActiveGateway},
	}

	for _, tc := range sentinels {
		t.Run(tc.name+"_direct", func(t *testing.T) {
			assert.True(t, errors.Is(tc.err, tc.err),
				"errors.Is should match sentinel directly")
		})

		t.Run(tc.name+"_wrapped", func(t *testing.T) {
			wrapped := fmt.Errorf("context: %w", tc.err)
			assert.True(t, errors.Is(wrapped, tc.err),
				"errors.Is should match through fmt.Errorf wrapping")
		})

		t.Run(tc.name+"_double_wrapped", func(t *testing.T) {
			inner := fmt.Errorf("inner: %w", tc.err)
			outer := fmt.Errorf("outer: %w", inner)
			assert.True(t, errors.Is(outer, tc.err),
				"errors.Is should match through double wrapping")
		})
	}
}

func TestSentinelErrors_NotConfused(t *testing.T) {
	// Verify that different sentinel errors are not equal.
	pairs := []struct {
		a, b error
	}{
		{ErrGatewayNotFound, ErrConfigParse},
		{ErrConfigParse, ErrTokenLoad},
		{ErrTokenLoad, ErrUnsupportedAuthMode},
		{ErrUnsupportedAuthMode, ErrInvalidGatewayName},
		{ErrInvalidGatewayName, ErrNoActiveGateway},
		{ErrNoActiveGateway, ErrGatewayNotFound},
	}

	for _, tc := range pairs {
		t.Run(tc.a.Error()+"_vs_"+tc.b.Error(), func(t *testing.T) {
			assert.False(t, errors.Is(tc.a, tc.b),
				"different sentinels must not match")
		})
	}
}

func TestSentinelErrors_HaveMessages(t *testing.T) {
	sentinels := []error{
		ErrGatewayNotFound,
		ErrConfigParse,
		ErrTokenLoad,
		ErrUnsupportedAuthMode,
		ErrInvalidGatewayName,
		ErrNoActiveGateway,
	}

	for _, err := range sentinels {
		t.Run(err.Error(), func(t *testing.T) {
			msg := err.Error()
			assert.NotEmpty(t, msg)
			assert.Contains(t, msg, "gateway:")
		})
	}
}
