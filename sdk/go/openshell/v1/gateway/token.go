// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
)

const (
	// edgeTokenFile is the primary edge token filename.
	edgeTokenFile = "edge_token"

	// cfTokenFile is the legacy Cloudflare token filename, used as
	// fallback when edge_token does not exist.
	cfTokenFile = "cf_token"

	// oidcTokenFile is the OIDC token bundle filename.
	oidcTokenFile = "oidc_token.json"
)

// edgeTokenLoader provides lazy, thread-safe loading of the edge token
// from disk. The token is read on the first call to load() and cached
// for subsequent calls via sync.Once.
type edgeTokenLoader struct {
	dir   string
	once  sync.Once
	token string
	err   error
}

// load returns the edge token string, reading it from disk on the first
// call. It tries edge_token first, falling back to cf_token for legacy
// compatibility. The result (success or failure) is cached.
func (l *edgeTokenLoader) load() (string, error) {
	l.once.Do(func() {
		l.token, l.err = readEdgeToken(l.dir)
	})
	return l.token, l.err
}

// readEdgeToken reads the edge token from the given directory. It tries
// edge_token first, then cf_token as a legacy fallback. The file content
// is trimmed of surrounding whitespace.
func readEdgeToken(dir string) (string, error) {
	// Try primary edge_token file.
	primary := filepath.Join(dir, edgeTokenFile)
	data, err := os.ReadFile(primary)
	if err == nil {
		token := strings.TrimSpace(string(data))
		if token == "" {
			return "", fmt.Errorf("%w: edge_token file is empty", ErrTokenLoad)
		}
		return token, nil
	}
	if !os.IsNotExist(err) {
		return "", fmt.Errorf("%w: cannot read %s: %v", ErrTokenLoad, edgeTokenFile, err)
	}

	// Fallback to legacy cf_token file (only when edge_token is absent).
	legacy := filepath.Join(dir, cfTokenFile)
	data, err = os.ReadFile(legacy)
	if err != nil {
		return "", fmt.Errorf("%w: neither edge_token nor cf_token found in gateway directory", ErrTokenLoad)
	}

	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", fmt.Errorf("%w: cf_token file is empty", ErrTokenLoad)
	}

	return token, nil
}

// oidcBundle is the on-disk representation of oidc_token.json.
type oidcBundle struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	Expiry       string `json:"expiry"`
	ExpiresIn    int64  `json:"expires_in"`
}

// diskTokenSource implements oauth2.TokenSource by reading oidc_token.json
// from disk on every Token() call. This allows the source to pick up
// tokens refreshed by the Rust CLI without process restart.
type diskTokenSource struct {
	dir string
}

// newDiskTokenSource returns an oauth2.TokenSource that reads
// oidc_token.json from the given gateway directory on each Token() call.
func newDiskTokenSource(dir string) oauth2.TokenSource {
	return &diskTokenSource{dir: dir}
}

// Token reads and parses oidc_token.json, returning an oauth2.Token.
// The file is read on every call to pick up CLI-refreshed tokens.
func (d *diskTokenSource) Token() (*oauth2.Token, error) {
	path := filepath.Join(d.dir, oidcTokenFile)

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot read %s: %v", ErrTokenLoad, oidcTokenFile, err)
	}

	var bundle oidcBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return nil, fmt.Errorf("%w: invalid JSON in %s", ErrTokenLoad, oidcTokenFile)
	}

	if bundle.AccessToken == "" {
		return nil, fmt.Errorf("%w: missing access_token in %s", ErrTokenLoad, oidcTokenFile)
	}

	tok := &oauth2.Token{
		AccessToken:  bundle.AccessToken,
		RefreshToken: bundle.RefreshToken,
		TokenType:    "Bearer",
	}

	// Parse expiry: prefer explicit "expiry" field, fall back to
	// "expires_in" (seconds from now).
	if bundle.Expiry != "" {
		expiry, parseErr := time.Parse(time.RFC3339, bundle.Expiry)
		if parseErr == nil {
			tok.Expiry = expiry
		}
		// If expiry can't be parsed, leave it zero (token treated as
		// non-expiring by oauth2).
	} else if bundle.ExpiresIn > 0 {
		tok.Expiry = time.Now().Add(time.Duration(bundle.ExpiresIn) * time.Second)
	}

	return tok, nil
}

// lazyEdgeAuth implements types.AuthProvider for the cloudflare_jwt auth
// mode. Token loading is deferred to GetRequestMetadata so that
// NewClient succeeds even when the token file is missing on disk (FR-007).
// The error surfaces on the first authentication attempt.
type lazyEdgeAuth struct {
	loader *edgeTokenLoader
}

// GetRequestMetadata loads the edge token lazily and returns it as a
// Bearer authorization header. The first load is cached by the
// underlying edgeTokenLoader.
func (a *lazyEdgeAuth) GetRequestMetadata(_ context.Context, _ ...string) (map[string]string, error) {
	token, err := a.loader.load()
	if err != nil {
		return nil, err
	}
	return map[string]string{
		"authorization": "Bearer " + token,
	}, nil
}

// RequireTransportSecurity returns true because Bearer tokens must not
// be sent over plaintext connections.
func (a *lazyEdgeAuth) RequireTransportSecurity() bool {
	return true
}
