// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"
	"errors"
	"maps"
	"strings"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
)

// extraHeadersAuth wraps a base AuthProvider with additional static headers
// that are merged into every GetRequestMetadata call. Extra headers take
// precedence over base headers on key collision (case-insensitive).
type extraHeadersAuth struct {
	base    types.AuthProvider
	headers map[string]string // keys already lowercase, empty values filtered out
}

// WithExtraHeaders wraps base with additional per-RPC headers. Keys are
// normalized to lowercase per HTTP/2 (RFC 9113). Empty-string values are
// silently dropped. The headers map is deep-copied at construction time,
// so later mutations to the caller's map have no effect.
//
// Returns an error if base is nil or if headers is nil, empty, or contains
// only empty-string values.
func WithExtraHeaders(base AuthProvider, headers map[string]string) (AuthProvider, error) {
	if base == nil {
		return nil, errors.New("base auth provider must not be nil")
	}
	if len(headers) == 0 {
		return nil, errors.New("headers must not be nil or empty")
	}

	// Deep-copy and normalize: lowercase keys, skip empty values.
	normalized := make(map[string]string, len(headers))
	for k, v := range headers {
		if v == "" {
			continue
		}
		normalized[strings.ToLower(k)] = v
	}

	if len(normalized) == 0 {
		return nil, errors.New("headers must contain at least one non-empty value")
	}

	return &extraHeadersAuth{
		base:    base,
		headers: normalized,
	}, nil
}

// GetRequestMetadata merges base metadata with extra headers. Extra headers
// win on key collision because they are applied after the base metadata.
func (e *extraHeadersAuth) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	baseMD, err := e.base.GetRequestMetadata(ctx, uri...)
	if err != nil {
		return nil, err
	}

	// Start with base metadata (may be nil for NoAuth).
	// Normalize base keys to lowercase for case-insensitive collision.
	merged := make(map[string]string, len(baseMD)+len(e.headers))
	for k, v := range baseMD {
		merged[strings.ToLower(k)] = v
	}
	// Extra headers overwrite base on collision.
	maps.Copy(merged, e.headers)

	return merged, nil
}

// RequireTransportSecurity delegates to the base auth provider.
func (e *extraHeadersAuth) RequireTransportSecurity() bool {
	return e.base.RequireTransportSecurity()
}
