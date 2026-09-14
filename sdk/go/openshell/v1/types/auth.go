// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package types

import "context"

// AuthProvider supplies per-RPC credentials. It implements the
// grpc credentials.PerRPCCredentials interface.
type AuthProvider interface {
	GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error)
	RequireTransportSecurity() bool
}
