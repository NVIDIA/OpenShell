// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package grpc provides gRPC connection setup utilities.
package grpc

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// TLSParams holds TLS settings without importing the v1 package.
type TLSParams struct {
	CertFile string
	KeyFile  string
	CAFile   string
	Insecure bool
}

// NewConnection creates a gRPC client connection.
// The address may include an http:// or https:// scheme (as written by the
// upstream gateway). The scheme drives transport selection: http:// uses
// plaintext, https:// or no scheme uses TLS.
func NewConnection(address string, tlsCfg *TLSParams, auth credentials.PerRPCCredentials) (*grpc.ClientConn, error) {
	usePlaintext := false
	if strings.HasPrefix(address, "http://") {
		usePlaintext = true
		address = strings.TrimPrefix(address, "http://")
	} else {
		address = strings.TrimPrefix(address, "https://")
	}
	opts := []grpc.DialOption{}

	if usePlaintext {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else if tlsCfg != nil {
		creds, err := buildTLSCredentials(tlsCfg)
		if err != nil {
			return nil, fmt.Errorf("tls config: %w", err)
		}
		opts = append(opts, grpc.WithTransportCredentials(creds))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12})))
	}

	if auth != nil {
		if usePlaintext && auth.RequireTransportSecurity() {
			return nil, fmt.Errorf("grpc connect: auth provider requires transport security but address uses plaintext (http://)")
		}
		opts = append(opts, grpc.WithPerRPCCredentials(auth))
	}

	conn, err := grpc.NewClient(address, opts...)
	if err != nil {
		return nil, fmt.Errorf("grpc connect: %w", err)
	}
	return conn, nil
}

func buildTLSCredentials(cfg *TLSParams) (credentials.TransportCredentials, error) {
	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: cfg.Insecure, //nolint:gosec // user-requested skip for dev gateways
	}

	if cfg.CAFile != "" {
		caCert, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("invalid CA certificate")
		}
		tlsConfig.RootCAs = pool
	}

	if cfg.CertFile != "" && cfg.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("load client cert: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	} else if cfg.CertFile != "" || cfg.KeyFile != "" {
		return nil, fmt.Errorf("both CertFile and KeyFile must be provided for client certificate authentication")
	}

	return credentials.NewTLS(tlsConfig), nil
}
