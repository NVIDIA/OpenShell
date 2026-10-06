// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- T012: PKCE verifier/challenge generation tests ---

func TestGenerateCodeVerifier_Length(t *testing.T) {
	verifier, err := generateCodeVerifier()
	require.NoError(t, err)

	// RFC 7636 requires 43-128 characters. Our implementation uses 32
	// random bytes -> 43 base64url characters (no padding).
	assert.GreaterOrEqual(t, len(verifier), 43)
	assert.LessOrEqual(t, len(verifier), 128)
}

func TestGenerateCodeVerifier_Base64URLSafe(t *testing.T) {
	verifier, err := generateCodeVerifier()
	require.NoError(t, err)

	// Must contain only base64url characters (A-Z, a-z, 0-9, -, _).
	// No padding (=) allowed per RFC 7636.
	for _, c := range verifier {
		valid := (c >= 'A' && c <= 'Z') ||
			(c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') ||
			c == '-' || c == '_'
		assert.True(t, valid, "invalid character in verifier: %c", c)
	}
}

func TestGenerateCodeVerifier_Unique(t *testing.T) {
	v1, err := generateCodeVerifier()
	require.NoError(t, err)

	v2, err := generateCodeVerifier()
	require.NoError(t, err)

	assert.NotEqual(t, v1, v2, "two verifiers should differ (random)")
}

func TestCodeChallengeS256(t *testing.T) {
	// RFC 7636 Appendix B test vector:
	//   verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	//   challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := codeChallengeS256(verifier)
	assert.Equal(t, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", challenge)
}

func TestCodeChallengeS256_NoPadding(t *testing.T) {
	verifier, err := generateCodeVerifier()
	require.NoError(t, err)

	challenge := codeChallengeS256(verifier)

	// S256 challenge must be base64url without padding.
	assert.NotContains(t, challenge, "=")
	assert.NotContains(t, challenge, "+")
	assert.NotContains(t, challenge, "/")
}

// --- T013: Auth code flow tests ---

func TestGenerateState_Length(t *testing.T) {
	state, err := generateState()
	require.NoError(t, err)

	// 16 random bytes -> 22 base64url chars (no padding).
	assert.GreaterOrEqual(t, len(state), 16)
}

func TestGenerateState_Unique(t *testing.T) {
	s1, err := generateState()
	require.NoError(t, err)

	s2, err := generateState()
	require.NoError(t, err)

	assert.NotEqual(t, s1, s2)
}

func TestBuildAuthURL(t *testing.T) {
	authEndpoint := "https://auth.example.com/authorize"
	clientID := "test-client"
	redirectURI := "http://localhost:8000/callback"
	state := "random-state"
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := codeChallengeS256(verifier)
	scopes := []string{"openid", "profile"}

	authURL := buildAuthURL(authEndpoint, clientID, redirectURI, state, challenge, scopes)

	parsed, err := url.Parse(authURL)
	require.NoError(t, err)

	q := parsed.Query()
	assert.Equal(t, "code", q.Get("response_type"))
	assert.Equal(t, clientID, q.Get("client_id"))
	assert.Equal(t, redirectURI, q.Get("redirect_uri"))
	assert.Equal(t, state, q.Get("state"))
	assert.Equal(t, challenge, q.Get("code_challenge"))
	assert.Equal(t, "S256", q.Get("code_challenge_method"))
	assert.Equal(t, "openid profile", q.Get("scope"))
}

func TestBuildAuthURL_NoPKCE(t *testing.T) {
	authURL := buildAuthURL(
		"https://auth.example.com/authorize",
		"test-client",
		"http://localhost:8000/callback",
		"state",
		"", // empty challenge = no PKCE
		[]string{"openid"},
	)

	parsed, err := url.Parse(authURL)
	require.NoError(t, err)

	q := parsed.Query()
	assert.Equal(t, "code", q.Get("response_type"))
	assert.Empty(t, q.Get("code_challenge"), "no PKCE when challenge is empty")
	assert.Empty(t, q.Get("code_challenge_method"))
}

func TestStartCallbackServer_ReceivesCode(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	state := "test-state-123"
	srv, resultCh, err := startCallbackServer(ctx, 0, state)
	require.NoError(t, err)
	defer func() { _ = srv.Close() }()

	// Extract the port from the server's listener address.
	addr := srv.Addr
	callbackURL := fmt.Sprintf("http://%s/callback?code=auth-code-xyz&state=%s", addr, state)

	resp, err := http.Get(callbackURL)
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	result := <-resultCh
	require.NoError(t, result.err)
	assert.Equal(t, "auth-code-xyz", result.code)
}

func TestStartCallbackServer_StateMismatch(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	state := "expected-state"
	srv, resultCh, err := startCallbackServer(ctx, 0, state)
	require.NoError(t, err)
	defer func() { _ = srv.Close() }()

	addr := srv.Addr
	callbackURL := fmt.Sprintf("http://%s/callback?code=some-code&state=wrong-state", addr)

	resp, err := http.Get(callbackURL)
	require.NoError(t, err)
	_ = resp.Body.Close()

	result := <-resultCh
	require.Error(t, result.err)
	assert.True(t, errors.Is(result.err, ErrAuthCode))
	assert.Contains(t, result.err.Error(), "state")
}

func TestStartCallbackServer_MissingCode(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	state := "test-state"
	srv, resultCh, err := startCallbackServer(ctx, 0, state)
	require.NoError(t, err)
	defer func() { _ = srv.Close() }()

	addr := srv.Addr
	callbackURL := fmt.Sprintf("http://%s/callback?state=%s", addr, state)

	resp, err := http.Get(callbackURL)
	require.NoError(t, err)
	_ = resp.Body.Close()

	result := <-resultCh
	require.Error(t, result.err)
	assert.True(t, errors.Is(result.err, ErrAuthCode))
}

func TestStartCallbackServer_ProviderError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	state := "test-state"
	srv, resultCh, err := startCallbackServer(ctx, 0, state)
	require.NoError(t, err)
	defer func() { _ = srv.Close() }()

	addr := srv.Addr
	callbackURL := fmt.Sprintf("http://%s/callback?error=access_denied&error_description=user+denied&state=%s", addr, state)

	resp, err := http.Get(callbackURL)
	require.NoError(t, err)
	_ = resp.Body.Close()

	result := <-resultCh
	require.Error(t, result.err)
	assert.True(t, errors.Is(result.err, ErrAuthCode))
	assert.Contains(t, result.err.Error(), "access_denied")
}

func TestStartCallbackServer_SpecificPort(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Port 0 tells OS to pick a free port. We just verify it works.
	srv, _, err := startCallbackServer(ctx, 0, "state")
	require.NoError(t, err)
	defer func() { _ = srv.Close() }()

	assert.NotEmpty(t, srv.Addr)
}

func TestExchangeCode_Success(t *testing.T) {
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.NoError(t, r.ParseForm())

		assert.Equal(t, "authorization_code", r.Form.Get("grant_type"))
		assert.Equal(t, "test-code", r.Form.Get("code"))
		assert.Equal(t, "test-client", r.Form.Get("client_id"))
		assert.Equal(t, "http://localhost:8000/callback", r.Form.Get("redirect_uri"))
		assert.NotEmpty(t, r.Form.Get("code_verifier"), "PKCE verifier should be sent")

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"access_token": "at-123",
			"refresh_token": "rt-456",
			"token_type": "Bearer",
			"expires_in": 3600
		}`))
	}))
	defer tokenSrv.Close()

	tok, err := exchangeCode(
		context.Background(),
		tokenSrv.URL+"/token",
		"test-client",
		"test-code",
		"http://localhost:8000/callback",
		"pkce-verifier",
	)
	require.NoError(t, err)
	assert.Equal(t, "at-123", tok.AccessToken)
	assert.Equal(t, "rt-456", tok.RefreshToken)
	assert.Equal(t, "Bearer", tok.TokenType)
	assert.False(t, tok.Expiry.IsZero())
}

func TestExchangeCode_NoPKCE(t *testing.T) {
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		assert.Empty(t, r.Form.Get("code_verifier"), "no PKCE verifier when empty")

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"access_token": "at-no-pkce",
			"token_type": "Bearer",
			"expires_in": 3600
		}`))
	}))
	defer tokenSrv.Close()

	tok, err := exchangeCode(
		context.Background(),
		tokenSrv.URL+"/token",
		"test-client",
		"test-code",
		"http://localhost:8000/callback",
		"", // empty verifier = no PKCE
	)
	require.NoError(t, err)
	assert.Equal(t, "at-no-pkce", tok.AccessToken)
}

func TestExchangeCode_ErrorResponse(t *testing.T) {
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error": "invalid_grant", "error_description": "code expired"}`))
	}))
	defer tokenSrv.Close()

	_, err := exchangeCode(
		context.Background(),
		tokenSrv.URL+"/token",
		"client",
		"bad-code",
		"http://localhost/callback",
		"verifier",
	)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrAuthCode))
}

func TestExchangeCode_SecretsNotInError(t *testing.T) {
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error": "invalid_grant"}`))
	}))
	defer tokenSrv.Close()

	_, err := exchangeCode(
		context.Background(),
		tokenSrv.URL+"/token",
		"client",
		"secret-code-value",
		"http://localhost/callback",
		"secret-verifier-value",
	)
	require.Error(t, err)
	// The error message must not contain the auth code or verifier.
	assert.NotContains(t, err.Error(), "secret-code-value")
	assert.NotContains(t, err.Error(), "secret-verifier-value")
}

func TestExchangeCode_InvalidJSON(t *testing.T) {
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`not json`))
	}))
	defer tokenSrv.Close()

	_, err := exchangeCode(
		context.Background(),
		tokenSrv.URL+"/token",
		"client",
		"code",
		"http://localhost/callback",
		"verifier",
	)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrAuthCode))
}

// tokenResponseJSON is a helper for creating token endpoint responses.
func tokenResponseJSON(accessToken, refreshToken string, expiresIn int) string {
	return fmt.Sprintf(`{
		"access_token": %q,
		"refresh_token": %q,
		"token_type": "Bearer",
		"expires_in": %d
	}`, accessToken, refreshToken, expiresIn)
}
