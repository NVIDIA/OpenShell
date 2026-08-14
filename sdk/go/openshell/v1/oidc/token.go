// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/oauth2"
)

// oidcTokenFile is the filename for persisted OIDC tokens. This must
// match the constant in gateway/token.go for interop.
const oidcTokenFile = "oidc_token.json"

// tokenExpiryLeeway is the grace period subtracted from the token
// expiry when checking validity. Tokens expiring within this window
// are treated as expired to avoid using a token that expires during
// an in-flight request.
const tokenExpiryLeeway = 10 * time.Second

// oidcBundle is the on-disk JSON representation of an OIDC token.
// The format is shared with the Rust CLI and the gateway package's
// diskTokenSource for interop.
type oidcBundle struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	Expiry       string `json:"expiry"`
	ExpiresIn    int64  `json:"expires_in"`
}

// writeToken persists an oauth2.Token to disk as oidc_token.json in
// the given directory. The file is written with 0600 permissions
// (owner-only) to protect credentials.
func writeToken(dir string, tok *oauth2.Token) error {
	bundle := oidcBundle{
		AccessToken:  tok.AccessToken,
		RefreshToken: tok.RefreshToken,
	}

	if !tok.Expiry.IsZero() {
		bundle.Expiry = tok.Expiry.UTC().Format(time.RFC3339)
		remaining := time.Until(tok.Expiry)
		if remaining > 0 {
			bundle.ExpiresIn = int64(remaining.Seconds())
		}
	}

	data, err := json.Marshal(bundle)
	if err != nil {
		return fmt.Errorf("%w: failed to marshal token: %v", ErrTokenPersist, err)
	}

	path := filepath.Join(dir, oidcTokenFile)
	tmp, err := os.CreateTemp(dir, ".oidc-token-*")
	if err != nil {
		return fmt.Errorf("%w: failed to create temporary token file: %v", ErrTokenPersist, err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("%w: failed to secure temporary token file: %v", ErrTokenPersist, err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("%w: failed to write %s: %v", ErrTokenPersist, path, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("%w: failed to sync %s: %v", ErrTokenPersist, path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("%w: failed to close %s: %v", ErrTokenPersist, path, err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("%w: failed to replace %s: %v", ErrTokenPersist, path, err)
	}

	return nil
}

// readToken reads an existing oidc_token.json from the given
// directory. It returns:
//   - (token, nil) if the file exists, is valid, and the token has not
//     expired (with leeway)
//   - (nil, nil) if the file does not exist, the token is expired, or
//     the access token is empty (not an error, just no reusable token)
//   - (nil, error) if the file exists but cannot be parsed
func readToken(dir string) (*oauth2.Token, error) {
	path := filepath.Join(dir, oidcTokenFile)

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("%w: cannot read %s: %v", ErrTokenPersist, path, err)
	}

	var bundle oidcBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return nil, fmt.Errorf("%w: invalid JSON in %s: %v", ErrTokenPersist, oidcTokenFile, err)
	}

	if bundle.AccessToken == "" {
		return nil, nil
	}

	tok := &oauth2.Token{
		AccessToken:  bundle.AccessToken,
		RefreshToken: bundle.RefreshToken,
		TokenType:    "Bearer",
	}

	// Parse expiry from the "expiry" field (RFC 3339). Without an
	// explicit expiry, the token is treated as non-expiring (always
	// valid); "expires_in" alone cannot reconstruct an absolute time
	// without a write timestamp.
	if bundle.Expiry != "" {
		expiry, parseErr := time.Parse(time.RFC3339, bundle.Expiry)
		if parseErr != nil {
			return nil, fmt.Errorf("%w: invalid expiry format in %s: %v", ErrTokenPersist, oidcTokenFile, parseErr)
		}
		tok.Expiry = expiry
	}

	// Check if the token has expired (with leeway).
	if !tok.Expiry.IsZero() && time.Now().After(tok.Expiry.Add(-tokenExpiryLeeway)) {
		return nil, nil // Expired; caller should re-authenticate.
	}

	return tok, nil
}
