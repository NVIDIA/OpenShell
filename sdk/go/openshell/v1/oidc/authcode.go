// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
)

// generateCodeVerifier creates a PKCE code verifier per RFC 7636.
// It generates 32 random bytes and encodes them as base64url without
// padding, producing a 43-character string.
func generateCodeVerifier() (string, error) {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", fmt.Errorf("generate code verifier: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// codeChallengeS256 computes the S256 PKCE code challenge for the
// given verifier. It returns BASE64URL(SHA256(verifier)) without
// padding, as specified in RFC 7636 Section 4.2.
func codeChallengeS256(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// generateState creates a cryptographic state parameter for the
// authorization request. It generates 16 random bytes encoded as
// base64url without padding.
func generateState() (string, error) {
	b := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", fmt.Errorf("generate state: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// buildAuthURL constructs the authorization endpoint URL with query
// parameters for the authorization code flow. If challenge is empty,
// PKCE parameters are omitted (for providers that do not support it).
func buildAuthURL(authEndpoint, clientID, redirectURI, state, challenge string, scopes []string) string {
	u, err := url.Parse(authEndpoint)
	if err != nil || u.Scheme == "" {
		u = &url.URL{Path: authEndpoint}
	}
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("state", state)
	q.Set("scope", strings.Join(scopes, " "))

	if challenge != "" {
		q.Set("code_challenge", challenge)
		q.Set("code_challenge_method", "S256")
	}

	u.RawQuery = q.Encode()
	return u.String()
}

// callbackResult carries the authorization code (or error) from the
// callback server to the auth code flow orchestrator.
type callbackResult struct {
	code string
	err  error
}

// startCallbackServer starts a localhost HTTP server to receive the
// OIDC provider's authorization callback. It listens on the specified
// port (use 0 for OS-assigned port). The server handles a single
// callback request and sends the result on the returned channel.
//
// The caller is responsible for calling srv.Close() when done.
func startCallbackServer(ctx context.Context, port int, expectedState string) (*http.Server, <-chan callbackResult, error) {
	resultCh := make(chan callbackResult, 1)
	var sendOnce sync.Once
	send := func(r callbackResult) {
		sendOnce.Do(func() { resultCh <- r })
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()

		if errCode := q.Get("error"); errCode != "" {
			desc := q.Get("error_description")
			msg := fmt.Sprintf("provider error: %s", errCode)
			if desc != "" {
				msg += ": " + desc
			}
			http.Error(w, msg, http.StatusBadRequest)
			send(callbackResult{err: fmt.Errorf("%w: %s", ErrAuthCode, msg)})
			return
		}

		state := q.Get("state")
		if state != expectedState {
			http.Error(w, "state mismatch", http.StatusBadRequest)
			send(callbackResult{err: fmt.Errorf("%w: state mismatch", ErrAuthCode)})
			return
		}

		code := q.Get("code")
		if code == "" {
			http.Error(w, "missing authorization code", http.StatusBadRequest)
			send(callbackResult{err: fmt.Errorf("%w: missing authorization code in callback", ErrAuthCode)})
			return
		}

		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprint(w, "<html><body><h1>Login successful</h1><p>You can close this window.</p></body></html>")
		send(callbackResult{code: code})
	})

	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return nil, nil, fmt.Errorf("%w: failed to start callback server on port %d: %v", ErrCallbackServer, port, err)
	}

	srv := &http.Server{
		Addr:              listener.Addr().String(),
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}

	done := make(chan struct{})
	go func() {
		_ = srv.Serve(listener)
		close(done)
	}()

	go func() {
		select {
		case <-ctx.Done():
		case <-done:
			return
		}
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	return srv, resultCh, nil
}

// tokenResponse is the JSON structure returned by the token endpoint.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	Error        string `json:"error"`
	ErrorDesc    string `json:"error_description"`
}

// exchangeCode exchanges an authorization code for tokens at the
// token endpoint. If codeVerifier is empty, the PKCE code_verifier
// parameter is omitted from the request.
//
// Secrets (code, verifier) are never included in error messages.
func exchangeCode(ctx context.Context, tokenEndpoint, clientID, code, redirectURI, codeVerifier string) (*oauth2.Token, error) {
	data := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"client_id":    {clientID},
		"redirect_uri": {redirectURI},
	}
	if codeVerifier != "" {
		data.Set("code_verifier", codeVerifier)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create token request: %v", ErrAuthCode, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := oidcHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: token request failed: %v", ErrAuthCode, err)
	}
	defer func() { _ = resp.Body.Close() }()

	const maxResponseBytes = 1 << 20
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("%w: failed to read token response: %v", ErrAuthCode, err)
	}

	var tokResp tokenResponse
	if err := json.Unmarshal(body, &tokResp); err != nil {
		return nil, fmt.Errorf("%w: invalid token response JSON: %v", ErrAuthCode, err)
	}

	if resp.StatusCode != http.StatusOK || tokResp.Error != "" {
		msg := "token exchange failed"
		if tokResp.Error != "" {
			msg = fmt.Sprintf("token exchange failed: %s", tokResp.Error)
			if tokResp.ErrorDesc != "" {
				msg += ": " + tokResp.ErrorDesc
			}
		}
		return nil, fmt.Errorf("%w: %s", ErrAuthCode, msg)
	}

	tok := &oauth2.Token{
		AccessToken:  tokResp.AccessToken,
		RefreshToken: tokResp.RefreshToken,
		TokenType:    tokResp.TokenType,
	}
	if tokResp.ExpiresIn > 0 {
		tok.Expiry = time.Now().Add(time.Duration(tokResp.ExpiresIn) * time.Second)
	}

	return tok, nil
}
