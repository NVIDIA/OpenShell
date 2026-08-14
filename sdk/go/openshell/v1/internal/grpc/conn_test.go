// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package grpc

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func TestNewConnectionHTTPSchemeUsesPlaintext(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = lis.Close() }()

	srv := grpc.NewServer()
	go func() { _ = srv.Serve(lis) }()
	defer srv.Stop()

	conn, err := NewConnection("http://"+lis.Addr().String(), nil, nil)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
}

func TestNewConnectionHTTPSSchemeUsesTLS(t *testing.T) {
	conn, err := NewConnection("https://127.0.0.1:1", nil, nil)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
}

func TestNewConnectionNoSchemeUsesTLS(t *testing.T) {
	conn, err := NewConnection("127.0.0.1:1", nil, nil)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
}

func TestNewConnectionInsecureTLSConfig(t *testing.T) {
	conn, err := NewConnection("127.0.0.1:1", &TLSParams{Insecure: true}, nil)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
}

func TestNewConnectionHTTPWithSecureAuthRejects(t *testing.T) {
	auth := &testTokenAuth{token: "dev-token", requireSecurity: true}
	_, err := NewConnection("http://127.0.0.1:1", nil, auth)
	require.Error(t, err)
}

func TestNewConnectionHTTPWithInsecureAuth(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = lis.Close() }()

	srv := grpc.NewServer(grpc.Creds(insecure.NewCredentials()))
	go func() { _ = srv.Serve(lis) }()
	defer srv.Stop()

	auth := &testTokenAuth{token: "dev-token", requireSecurity: false}
	conn, err := NewConnection("http://"+lis.Addr().String(), nil, auth)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
}

func TestNewConnectionHTTPWithTLSParamsRejects(t *testing.T) {
	_, err := NewConnection("http://127.0.0.1:1", &TLSParams{CAFile: "/some/ca.pem"}, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "TLS parameters")
}

func TestNewConnectionHTTPWithEmptyTLSParamsAllowed(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = lis.Close() }()

	srv := grpc.NewServer()
	go func() { _ = srv.Serve(lis) }()
	defer srv.Stop()

	conn, err := NewConnection("http://"+lis.Addr().String(), &TLSParams{}, nil)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
}

type testTokenAuth struct {
	token           string
	requireSecurity bool
}

func (a *testTokenAuth) GetRequestMetadata(_ context.Context, _ ...string) (map[string]string, error) {
	return map[string]string{"authorization": "Bearer " + a.token}, nil
}

func (a *testTokenAuth) RequireTransportSecurity() bool {
	return a.requireSecurity
}
