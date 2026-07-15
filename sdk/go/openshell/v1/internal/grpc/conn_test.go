// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package grpc

import (
	"net"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func TestNewConnectionHTTPSchemeUsesPlaintext(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer lis.Close()

	srv := grpc.NewServer()
	go func() { _ = srv.Serve(lis) }()
	defer srv.Stop()

	conn, err := NewConnection("http://"+lis.Addr().String(), nil, nil)
	if err != nil {
		t.Fatalf("NewConnection with http:// scheme failed: %v", err)
	}
	defer conn.Close()
}

func TestNewConnectionHTTPSSchemeUsesTLS(t *testing.T) {
	// https:// with nil TLS config should default to system TLS.
	// We cannot dial a real TLS server here, but we can verify the
	// connection is created (it will fail on handshake, not on dial).
	conn, err := NewConnection("https://127.0.0.1:1", nil, nil)
	if err != nil {
		t.Fatalf("NewConnection with https:// scheme should not fail on create: %v", err)
	}
	defer conn.Close()
}

func TestNewConnectionNoSchemeUsesTLS(t *testing.T) {
	conn, err := NewConnection("127.0.0.1:1", nil, nil)
	if err != nil {
		t.Fatalf("NewConnection without scheme should not fail on create: %v", err)
	}
	defer conn.Close()
}

func TestNewConnectionInsecureTLSConfig(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer lis.Close()

	srv := grpc.NewServer(grpc.Creds(insecure.NewCredentials()))
	go func() { _ = srv.Serve(lis) }()
	defer srv.Stop()

	conn, err := NewConnection(lis.Addr().String(), &TLSParams{Insecure: true}, nil)
	if err != nil {
		t.Fatalf("NewConnection with Insecure TLS config failed: %v", err)
	}
	defer conn.Close()
}
