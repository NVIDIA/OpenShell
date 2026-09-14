// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"
	"io"
	"net"
)

// forwardConfig accumulates options for the Forward method.
type forwardConfig struct {
	serviceID string
}

// ForwardOption configures a TCP forward opened via [TCPInterface.Forward].
type ForwardOption func(*forwardConfig)

// WithForwardServiceID sets an optional service identifier on the forward's
// init frame for audit and correlation purposes.
func WithForwardServiceID(id string) ForwardOption {
	return func(c *forwardConfig) {
		c.serviceID = id
	}
}

// listenConfig accumulates options for the Listen method.
type listenConfig struct {
	bindAddress  string
	useSSHTunnel bool
	serviceID    string
}

// ListenOption configures a local listener opened via [TCPInterface.Listen].
type ListenOption func(*listenConfig)

// ForwardListener is the lifecycle handle for a local TCP forward. The SDK
// owns accepting and bridging local connections; callers dial Addr and call
// Close when the forwarding endpoint is no longer needed.
type ForwardListener interface {
	Addr() net.Addr
	Close() error
}

// WithBindAddress overrides the default local bind address ("127.0.0.1").
// Pass "0.0.0.0" to accept connections from any interface.
func WithBindAddress(addr string) ListenOption {
	return func(c *listenConfig) {
		c.bindAddress = addr
	}
}

// WithSSHTunnel routes each accepted connection through an SSH tunnel
// ([SSHInterface.Tunnel]) instead of the default TCP forward
// ([TCPInterface.Forward]).
func WithSSHTunnel() ListenOption {
	return func(c *listenConfig) {
		c.useSSHTunnel = true
	}
}

// WithListenServiceID sets an optional service identifier on each tunneled
// connection's init frame for audit and correlation purposes.
func WithListenServiceID(id string) ListenOption {
	return func(c *listenConfig) {
		c.serviceID = id
	}
}

// TCPInterface defines operations for TCP port forwarding to sandboxes.
// Methods accept a sandbox name and resolve it to an ID internally.
type TCPInterface interface {
	Forward(ctx context.Context, workspace, sandboxName string, port uint32, opts ...ForwardOption) (io.ReadWriteCloser, error)
	Listen(ctx context.Context, workspace, sandboxName string, remotePort uint32, localPort uint32, opts ...ListenOption) (ForwardListener, error)
}
