// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
)

const defaultCloseTimeout = 5 * time.Second

// tunnelConfig holds configuration set by TunnelOption functions.
type tunnelConfig struct {
	logger       types.Logger
	tlsConfig    *tls.Config
	closeTimeout time.Duration
}

// TunnelOption configures TunnelProxy behavior.
type TunnelOption func(*tunnelConfig)

// WithTunnelLogger sets the structured logger for tunnel events.
func WithTunnelLogger(l types.Logger) TunnelOption {
	return func(c *tunnelConfig) {
		c.logger = l
	}
}

// WithTunnelTLS sets TLS configuration for the WebSocket connection (wss://).
func WithTunnelTLS(cfg *tls.Config) TunnelOption {
	return func(c *tunnelConfig) {
		c.tlsConfig = cfg
	}
}

// WithCloseTimeout sets the maximum time Close waits for in-flight
// connections to drain before force-closing. Default is 5 seconds.
func WithCloseTimeout(d time.Duration) TunnelOption {
	return func(c *tunnelConfig) {
		c.closeTimeout = d
	}
}

// TunnelProxy bridges gRPC connections over a WebSocket tunnel.
// The gRPC client dials TunnelProxy.Addr() instead of the remote gateway.
// Each accepted connection spawns a goroutine that dials the gateway over
// WebSocket and copies data bidirectionally.
type TunnelProxy struct {
	listener     net.Listener
	gatewayURL   string
	edgeToken    string
	logger       types.Logger
	closeTimeout time.Duration
	httpClient   *http.Client

	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	mu        sync.Mutex
	closing   bool
	closeOnce sync.Once
	closeErr  error
}

// NewTunnelProxy creates a tunnel proxy that forwards TCP connections
// through a WebSocket connection to gatewayURL. The edgeToken authenticates
// with the edge proxy via Cloudflare Access headers on the WebSocket
// handshake.
//
// Returns error if gatewayURL is empty or invalid, or if edgeToken is empty.
func NewTunnelProxy(gatewayURL, edgeToken string, opts ...TunnelOption) (*TunnelProxy, error) {
	if gatewayURL == "" {
		return nil, errors.New("gateway URL must not be empty")
	}
	if edgeToken == "" {
		return nil, errors.New("edge token must not be empty")
	}

	// Validate the URL parses correctly.
	u, err := url.Parse(gatewayURL)
	if err != nil {
		return nil, fmt.Errorf("invalid gateway URL: %w", err)
	}
	if u.Scheme != "ws" && u.Scheme != "wss" {
		return nil, fmt.Errorf("gateway URL must use ws:// or wss:// scheme, got %q", u.Scheme)
	}
	if u.Host == "" {
		return nil, errors.New("gateway URL must include a host")
	}
	if u.Scheme == "ws" && !isLoopbackHost(u.Hostname()) {
		return nil, errors.New("gateway URL with an edge token must use wss:// (ws:// is allowed only for loopback hosts)")
	}

	cfg := tunnelConfig{
		closeTimeout: defaultCloseTimeout,
	}
	for _, o := range opts {
		o(&cfg)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	var httpClient *http.Client
	if cfg.tlsConfig != nil {
		httpClient = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: cfg.tlsConfig,
			},
		}
	}

	tp := &TunnelProxy{
		listener:     listener,
		gatewayURL:   gatewayURL,
		edgeToken:    edgeToken,
		logger:       cfg.logger,
		closeTimeout: cfg.closeTimeout,
		httpClient:   httpClient,
		ctx:          ctx,
		cancel:       cancel,
	}

	// Start the accept loop.
	tp.wg.Add(1)
	go tp.acceptLoop()

	return tp, nil
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Addr returns the local address the gRPC client should dial.
func (tp *TunnelProxy) Addr() string {
	return tp.listener.Addr().String()
}

// Close drains in-flight connections (up to the configured timeout,
// default 5s) then force-closes any remaining connections. All goroutines
// are cleaned up. Safe to call multiple times; the second and subsequent
// calls return immediately.
func (tp *TunnelProxy) Close() error {
	tp.closeOnce.Do(func() {
		tp.mu.Lock()
		tp.closing = true
		tp.mu.Unlock()

		// Stop accepting new connections.
		tp.closeErr = tp.listener.Close()

		// Wait for in-flight connections to drain, with a timeout.
		done := make(chan struct{})
		go func() {
			tp.wg.Wait()
			close(done)
		}()

		select {
		case <-done:
			// All goroutines drained cleanly.
		case <-time.After(tp.closeTimeout):
			// Timeout reached; cancel all bridge contexts to force-close.
			if tp.logger != nil {
				tp.logger.Info("tunnel close timeout reached, force-closing")
			}
			tp.cancel()
			<-done
		}
		// Always cancel to release the context tree.
		tp.cancel()
	})
	return tp.closeErr
}

// acceptLoop runs in a goroutine. It accepts local TCP connections and
// spawns a bridge goroutine for each one.
func (tp *TunnelProxy) acceptLoop() {
	defer tp.wg.Done()

	for {
		conn, err := tp.listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			if tp.logger != nil {
				tp.logger.Error(err, "tunnel accept error")
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}

		tp.mu.Lock()
		if tp.closing {
			tp.mu.Unlock()
			_ = conn.Close()
			return
		}
		tp.wg.Add(1)
		tp.mu.Unlock()

		if tp.logger != nil {
			tp.logger.Debug("tunnel connection accepted", "remote", conn.RemoteAddr().String())
		}

		go tp.bridge(conn)
	}
}

// bridge dials the gateway over WebSocket and copies data bidirectionally
// between the local TCP connection and the WebSocket connection.
func (tp *TunnelProxy) bridge(local net.Conn) {
	defer tp.wg.Done()
	defer func() { _ = local.Close() }()

	ctx, cancel := context.WithCancel(tp.ctx)
	defer cancel()

	// Build WebSocket dial options with edge auth headers.
	dialOpts := &websocket.DialOptions{
		HTTPHeader: http.Header{
			"cf-access-jwt-assertion": []string{tp.edgeToken},
			"cookie":                  []string{fmt.Sprintf("CF_Authorization=%s", tp.edgeToken)},
		},
	}
	if tp.httpClient != nil {
		dialOpts.HTTPClient = tp.httpClient
	}

	dialCtx, dialCancel := context.WithTimeout(ctx, 10*time.Second)
	defer dialCancel()

	wsConn, _, err := websocket.Dial(dialCtx, tp.gatewayURL, dialOpts)
	if err != nil {
		if tp.logger != nil {
			tp.logger.Error(err, "tunnel websocket dial failed")
		}
		return
	}
	defer func() { _ = wsConn.CloseNow() }()

	// Set a generous read limit for gRPC frames.
	wsConn.SetReadLimit(64 * 1024 * 1024) // 64 MiB

	// Convert the WebSocket connection to a net.Conn for bidirectional I/O.
	remote := websocket.NetConn(ctx, wsConn, websocket.MessageBinary)

	// Bidirectional copy.
	done := make(chan struct{}, 2)

	// Local -> Remote (WebSocket)
	go func() {
		_, _ = io.Copy(remote, local)
		done <- struct{}{}
	}()

	// Remote (WebSocket) -> Local
	go func() {
		_, _ = io.Copy(local, remote)
		done <- struct{}{}
	}()

	// Wait for one direction to finish, then tear down both.
	<-done
	cancel()
	_ = local.Close()
	<-done

	if tp.logger != nil {
		tp.logger.Debug("tunnel bridge closed")
	}
}
