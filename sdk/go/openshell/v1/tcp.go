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
	// Forward opens a bidirectional TCP connection to the given port inside a
	// sandbox. The sandbox is identified by name; the SDK resolves it to an
	// ID internally. The returned io.ReadWriteCloser wraps the underlying
	// gRPC stream; closing it terminates the stream. Port must be in the
	// range 1-65535; out-of-range values are rejected client-side with an
	// InvalidArgument error before opening the gRPC stream.
	//
	// The connection respects context cancellation: if ctx is cancelled,
	// the stream is closed and pending Read/Write calls return a context error.
	Forward(ctx context.Context, workspace, sandboxName string, port uint32, opts ...ForwardOption) (io.ReadWriteCloser, error)

	// Listen binds a local TCP port and tunnels every accepted connection to
	// the given port inside a sandbox, returning a standard [net.Listener].
	// Each call to Accept on the returned listener establishes a new tunnel
	// to the sandbox port, bridging data bidirectionally.
	//
	// The sandbox is identified by name; the SDK resolves it to an ID
	// internally. remotePort must be in the range 1-65535; localPort must be
	// in the range 0-65535, where 0 lets the OS assign an ephemeral port
	// (discoverable via Addr).
	//
	// Closing the listener stops accepting new connections, tears down all
	// active tunnels, and blocks until all bridge goroutines finish.
	// Cancelling ctx triggers the same shutdown behavior.
	//
	// Errors:
	//   - InvalidArgument: sandboxName is empty, remotePort is 0 or > 65535,
	//     or localPort is > 65535
	//   - Unimplemented: returned by the fake client
	//   - Unavailable: client is closed
	Listen(ctx context.Context, workspace, sandboxName string, remotePort uint32, localPort uint32, opts ...ListenOption) (net.Listener, error)
}
