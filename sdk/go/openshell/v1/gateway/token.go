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
	"time"

	"golang.org/x/oauth2"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/internal/oidctoken"
)

const (
	// edgeTokenFile is the primary edge token filename.
	edgeTokenFile = "edge_token"

	// cfTokenFile is the legacy Cloudflare token filename, used as
	// fallback when edge_token does not exist.
	cfTokenFile = "cf_token"
)

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

// diskTokenSource implements oauth2.TokenSource by reading oidc_token.json
// from disk on every Token() call. This allows the source to pick up
// tokens refreshed by the Rust CLI without process restart.
type diskTokenSource struct {
	dir  string
	name string
}

// newDiskTokenSource returns an oauth2.TokenSource that reads
// oidc_token.json from the directory of the named gateway on each
// Token() call.
func newDiskTokenSource(dir, name string) oauth2.TokenSource {
	return &diskTokenSource{dir: dir, name: name}
}

// Token reads and parses oidc_token.json, returning an oauth2.Token.
// The file is read on every call to pick up CLI-refreshed tokens.
func (d *diskTokenSource) Token() (*oauth2.Token, error) {
	data, err := os.ReadFile(filepath.Join(d.dir, oidctoken.FileName))
	if err != nil {
		return nil, d.loadError("cannot read %s: %v", oidctoken.FileName, err)
	}

	var bundle oidctoken.Bundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return nil, d.loadError("invalid JSON in %s", oidctoken.FileName)
	}

	if bundle.AccessToken == "" {
		return nil, d.loadError("missing access_token in %s", oidctoken.FileName)
	}
	// Files from earlier Go SDK builds lack these fields and expires_at;
	// accepting them would treat their tokens as never expiring.
	if bundle.Issuer == "" || bundle.ClientID == "" {
		return nil, d.loadError("OIDC token for gateway %q is missing issuer or client_id", d.name)
	}

	tok := bundle.Token()
	if !tok.Expiry.IsZero() && !time.Now().Before(tok.Expiry) {
		return nil, d.loadError("OIDC token for gateway %q expired at %s",
			d.name, tok.Expiry.UTC().Format(time.RFC3339))
	}

	return tok, nil
}

// loadError wraps ErrTokenLoad with the CLI login command that repairs
// the token file.
func (d *diskTokenSource) loadError(format string, args ...any) error {
	return fmt.Errorf("%w: %s; run `openshell gateway login %s`",
		ErrTokenLoad, fmt.Sprintf(format, args...), d.name)
}

// lazyEdgeAuth implements types.AuthProvider for the cloudflare_jwt auth
// mode. Token loading is deferred to GetRequestMetadata so that
// NewClient succeeds even when the token file is missing on disk (FR-007).
// The error surfaces on the first authentication attempt.
type lazyEdgeAuth struct {
	dir string
}

// GetRequestMetadata reads the edge token from disk on every call and
// returns it as a Bearer authorization header. Reading each time picks up
// tokens rewritten by the CLI without a process restart.
func (a *lazyEdgeAuth) GetRequestMetadata(_ context.Context, _ ...string) (map[string]string, error) {
	token, err := readEdgeToken(a.dir)
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
