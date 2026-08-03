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
	// CreateSession creates a new SSH session for the given sandbox.
	// The returned SSHSession contains connection details including the
	// sensitive Token field that must not be logged.
	//
	// Note: CreateSession accepts a raw sandbox ID, not a name.
	// For name-based access with automatic session lifecycle management,
	// prefer [SSHInterface.Tunnel] which resolves sandbox names internally
	// and revokes the session on Close.
	CreateSession(ctx context.Context, workspace, sandboxID string) (*SSHSession, error)
	// RevokeSession revokes an existing SSH session by its token.
	// Returns true if the session was actively revoked, false if it was
	// already expired or not found.
	RevokeSession(ctx context.Context, workspace, token string) (bool, error)
	// Tunnel opens a bidirectional SSH tunnel to the given port inside a
	// sandbox. It combines CreateSession and ForwardTcp(SshRelayTarget)
	// into a single call with automatic session cleanup on Close.
	//
	// The sandboxName is resolved to a sandbox ID internally. Port must
	// be in the range 1-65535.
	//
	// Errors: InvalidArgument if port is out of range or sandboxName is
	// empty; NotFound if the sandbox does not exist; Unimplemented by
	// the fake client; Unavailable if the client is closed.
	Tunnel(ctx context.Context, workspace, sandboxName string, port uint32, opts ...TunnelOption) (io.ReadWriteCloser, error)
}
