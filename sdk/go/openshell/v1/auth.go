// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
)

// AuthProvider supplies per-RPC credentials. It implements the
// grpc credentials.PerRPCCredentials interface.
type AuthProvider = types.AuthProvider

type noAuth struct{}

// NoAuth returns an AuthProvider that sends no credentials.
func NoAuth() AuthProvider {
	return &noAuth{}
}

func (n *noAuth) GetRequestMetadata(_ context.Context, _ ...string) (map[string]string, error) {
	return nil, nil
}

func (n *noAuth) RequireTransportSecurity() bool {
	return false
}

type staticToken struct {
	token string
}

// StaticToken returns an AuthProvider that sends a fixed Bearer token.
func StaticToken(token string) AuthProvider {
	return &staticToken{token: token}
}

func (s *staticToken) GetRequestMetadata(_ context.Context, _ ...string) (map[string]string, error) {
	return map[string]string{
		"authorization": "Bearer " + s.token,
	}, nil
}

func (s *staticToken) RequireTransportSecurity() bool {
	return true
}
