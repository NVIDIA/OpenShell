// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package oidctoken defines the on-disk OIDC token bundle shared with the
// OpenShell CLI.
package oidctoken

import (
	"time"

	"golang.org/x/oauth2"
)

// FileName is the OIDC token bundle in a gateway directory.
const FileName = "oidc_token.json"

// Bundle is the CLI's on-disk OIDC token bundle (openshell-bootstrap OidcTokenBundle).
type Bundle struct {
	AccessToken  string  `json:"access_token"`
	RefreshToken string  `json:"refresh_token,omitempty"`
	ExpiresAt    *uint64 `json:"expires_at,omitempty"` // unix seconds
	Issuer       string  `json:"issuer"`
	ClientID     string  `json:"client_id"`
}

// FromToken converts tok into the bundle stored for issuer and clientID.
func FromToken(tok *oauth2.Token, issuer, clientID string) Bundle {
	b := Bundle{
		AccessToken:  tok.AccessToken,
		RefreshToken: tok.RefreshToken,
		Issuer:       issuer,
		ClientID:     clientID,
	}
	if !tok.Expiry.IsZero() {
		expiresAt := uint64(max(tok.Expiry.Unix(), 0))
		b.ExpiresAt = &expiresAt
	}
	return b
}

// Token converts b into a Bearer token. A nil ExpiresAt yields a zero
// Expiry, which oauth2 treats as never expiring.
func (b Bundle) Token() *oauth2.Token {
	tok := &oauth2.Token{
		AccessToken:  b.AccessToken,
		RefreshToken: b.RefreshToken,
		TokenType:    "Bearer",
	}
	if b.ExpiresAt != nil {
		tok.Expiry = time.Unix(int64(*b.ExpiresAt), 0)
	}
	return tok
}
