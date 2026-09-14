// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"
	"io"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
)

// SSHSession represents an SSH session created for a sandbox.
type SSHSession = types.SSHSession

// tunnelConfig accumulates options for the Tunnel method.
type tunnelConfig struct {
	serviceID string
}

// TunnelOption configures an SSH tunnel opened via [SSHInterface.Tunnel].
type TunnelOption func(*tunnelConfig)

// WithTunnelServiceID sets an optional service identifier on the tunnel's
// init frame for audit and correlation purposes.
func WithTunnelServiceID(id string) TunnelOption {
	return func(c *tunnelConfig) {
		c.serviceID = id
	}
}

// SSHInterface defines operations for managing SSH sessions.
type SSHInterface interface {
	CreateSession(ctx context.Context, workspace, sandboxID string) (*SSHSession, error)
	RevokeSession(ctx context.Context, workspace, token string) (bool, error)
	Tunnel(ctx context.Context, workspace, sandboxName string, port uint32, opts ...TunnelOption) (io.ReadWriteCloser, error)
}
