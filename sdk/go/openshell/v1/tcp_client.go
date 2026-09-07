// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/internal/converter"
	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"google.golang.org/grpc"
)

type tcpClient struct {
	client    pb.OpenShellClient
	sandboxes SandboxInterface
	ssh       SSHInterface
}

func newTCPClient(conn grpc.ClientConnInterface, sandboxes SandboxInterface, ssh SSHInterface) *tcpClient {
	return &tcpClient{client: pb.NewOpenShellClient(conn), sandboxes: sandboxes, ssh: ssh}
}

func (t *tcpClient) Forward(ctx context.Context, workspace, sandboxName string, port uint32, opts ...ForwardOption) (io.ReadWriteCloser, error) {
	if sandboxName == "" {
		return nil, &StatusError{Code: ErrorInvalidArgument, Message: "sandbox name must not be empty"}
	}
	if port == 0 || port > 65535 {
		return nil, &StatusError{
			Code:    ErrorInvalidArgument,
			Message: fmt.Sprintf("port must be in range 1-65535, got %d", port),
		}
	}

	sb, err := t.sandboxes.Get(ctx, workspace, sandboxName)
	if err != nil {
		return nil, err
	}

	var cfg forwardConfig
	for _, o := range opts {
		o(&cfg)
	}

	streamCtx, cancel := context.WithCancel(ctx)
	stream, err := t.client.ForwardTcp(streamCtx)
	if err != nil {
		cancel()
		return nil, converter.FromGRPCError(err)
	}

	initFrame := &pb.TcpForwardFrame{
		Payload: &pb.TcpForwardFrame_Init{
			Init: &pb.TcpForwardInit{
				SandboxId: sb.ID,
				ServiceId: cfg.serviceID,
				Target: &pb.TcpForwardInit_Tcp{
					Tcp: &pb.TcpRelayTarget{
						Host: "127.0.0.1",
						Port: port,
					},
				},
			},
		},
	}

	if err := stream.Send(initFrame); err != nil {
		cancel()
		return nil, converter.FromGRPCError(err)
	}

	conn := &tcpForwardConn{
		stream:    stream,
		streamCtx: streamCtx,
		cancel:    cancel,
		dataCh:    make(chan []byte, 64),
		done:      make(chan struct{}),
	}
	go conn.readLoop()
	return conn, nil
}

func (t *tcpClient) Listen(ctx context.Context, workspace, sandboxName string, remotePort uint32, localPort uint32, opts ...ListenOption) (ForwardListener, error) {
	if sandboxName == "" {
		return nil, &StatusError{Code: ErrorInvalidArgument, Message: "sandbox name must not be empty"}
	}
	if remotePort == 0 || remotePort > 65535 {
		return nil, &StatusError{
			Code:    ErrorInvalidArgument,
			Message: fmt.Sprintf("port must be in range 1-65535, got %d", remotePort),
		}
	}
	if localPort > 65535 {
		return nil, &StatusError{
			Code:    ErrorInvalidArgument,
			Message: fmt.Sprintf("local port must be in range 0-65535, got %d", localPort),
		}
	}

	cfg := listenConfig{bindAddress: "127.0.0.1"}
	for _, o := range opts {
		o(&cfg)
	}

	if cfg.useSSHTunnel && t.ssh == nil {
		return nil, &StatusError{
			Code:    ErrorInvalidArgument,
			Message: "WithSSHTunnel requires an SSH client, but none is available",
		}
	}

	addr := net.JoinHostPort(cfg.bindAddress, strconv.FormatUint(uint64(localPort), 10))
	inner, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", addr, err)
	}

	listenCtx, cancel := context.WithCancel(ctx)
	tl := &tunnelListener{
		inner:       inner,
		ctx:         listenCtx,
		cancel:      cancel,
		tcp:         t,
		ssh:         t.ssh,
		workspace:   workspace,
		sandboxName: sandboxName,
		remotePort:  remotePort,
		cfg:         cfg,
	}

	// Context-watcher: if the parent context is cancelled, close the listener.
	go func() {
		<-listenCtx.Done()
		_ = tl.Close()
	}()

	// The listener is a forwarding lifecycle handle: it owns acceptance and
	// bridging. Callers only dial Addr() and close the handle when finished.
	tl.wg.Add(1)
	go tl.acceptLoop()

	return tl, nil
}

func (tl *tunnelListener) acceptLoop() {
	defer tl.wg.Done()
	for {
		if err := tl.acceptAndBridge(); err != nil {
			return
		}
	}
}

// tunnelListener implements net.Listener. It accepts local TCP connections
// and bridges each one to a sandbox port via Forward (or Tunnel in SSH mode).
type tunnelListener struct {
	inner       net.Listener
	ctx         context.Context
	cancel      context.CancelFunc
	tcp         *tcpClient
	ssh         SSHInterface
	workspace   string
	sandboxName string
	remotePort  uint32
	cfg         listenConfig
	wg          sync.WaitGroup
	mu          sync.Mutex
	closing     bool
	closeOnce   sync.Once
	closeErr    error
}

func (tl *tunnelListener) acceptAndBridge() error {
	for {
		conn, err := tl.inner.Accept()
		if err != nil {
			return err
		}

		// Establish the tunnel to the sandbox.
		var tunnel io.ReadWriteCloser
		if tl.cfg.useSSHTunnel && tl.ssh != nil {
			var tunnelOpts []TunnelOption
			if tl.cfg.serviceID != "" {
				tunnelOpts = append(tunnelOpts, WithTunnelServiceID(tl.cfg.serviceID))
			}
			tunnel, err = tl.ssh.Tunnel(tl.ctx, tl.workspace, tl.sandboxName, tl.remotePort, tunnelOpts...)
		} else {
			var fwdOpts []ForwardOption
			if tl.cfg.serviceID != "" {
				fwdOpts = append(fwdOpts, WithForwardServiceID(tl.cfg.serviceID))
			}
			tunnel, err = tl.tcp.Forward(tl.ctx, tl.workspace, tl.sandboxName, tl.remotePort, fwdOpts...)
		}

		if err != nil {
			_ = conn.Close()
			select {
			case <-tl.ctx.Done():
				return tl.ctx.Err()
			default:
				continue
			}
		}

		tl.mu.Lock()
		if tl.closing {
			tl.mu.Unlock()
			_ = conn.Close()
			_ = tunnel.Close()
			return net.ErrClosed
		}
		tl.wg.Add(1)
		tl.mu.Unlock()
		go tl.bridge(conn, tunnel)

		return nil
	}
}

// bridge copies data bidirectionally between the local connection and the
// tunnel. It runs in its own goroutine and decrements the WaitGroup on exit.
func (tl *tunnelListener) bridge(local net.Conn, tunnel io.ReadWriteCloser) {
	defer tl.wg.Done()
	defer func() { _ = local.Close() }()
	defer func() { _ = tunnel.Close() }()

	done := make(chan struct{}, 2)

	// Local → tunnel
	go func() {
		_, _ = io.Copy(tunnel, local)
		done <- struct{}{}
	}()

	// Tunnel → local
	go func() {
		_, _ = io.Copy(local, tunnel)
		done <- struct{}{}
	}()

	<-done
	_ = local.Close()
	_ = tunnel.Close()
	<-done
}

// Close stops the listener from accepting new connections, cancels all
// active tunnels, and blocks until all bridge goroutines finish.
func (tl *tunnelListener) Close() error {
	tl.closeOnce.Do(func() {
		tl.mu.Lock()
		tl.closing = true
		tl.mu.Unlock()
		tl.closeErr = tl.inner.Close()
		tl.cancel()
		tl.wg.Wait()
	})
	return tl.closeErr
}

// Addr returns the listener's network address (the bound local address).
func (tl *tunnelListener) Addr() net.Addr {
	return tl.inner.Addr()
}

// tcpForwardConn wraps a bidirectional TcpForwardFrame stream into an
// io.ReadWriteCloser. A background goroutine owns the Recv loop and routes
// data frames to dataCh. Read and Write may be called from different
// goroutines, but multiple concurrent Read callers are not supported.
type tcpForwardConn struct {
	stream    grpc.BidiStreamingClient[pb.TcpForwardFrame, pb.TcpForwardFrame]
	streamCtx context.Context
	cancel    context.CancelFunc
	sendMu    sync.Mutex
	dataCh    chan []byte
	done      chan struct{}
	errOnce   sync.Once
	err       error
	buf       []byte
}

func (c *tcpForwardConn) setErr(err error) {
	c.errOnce.Do(func() { c.err = err })
}

func (c *tcpForwardConn) readLoop() {
	defer close(c.dataCh)
	defer close(c.done)
	for {
		frame, err := c.stream.Recv()
		if err != nil {
			if err != io.EOF {
				c.setErr(converter.FromGRPCError(err))
			}
			return
		}
		data := frame.GetData()
		if data == nil {
			continue
		}
		dataCopy := make([]byte, len(data))
		copy(dataCopy, data)
		select {
		case c.dataCh <- dataCopy:
		case <-c.streamCtx.Done():
			return
		}
	}
}

func (c *tcpForwardConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(c.buf) > 0 {
		n := copy(p, c.buf)
		c.buf = c.buf[n:]
		return n, nil
	}

	data, ok := <-c.dataCh
	if !ok {
		if c.err != nil {
			return 0, c.err
		}
		return 0, io.EOF
	}
	n := copy(p, data)
	if n < len(data) {
		c.buf = append(c.buf, data[n:]...)
	}
	return n, nil
}

func (c *tcpForwardConn) Write(p []byte) (int, error) {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	err := c.stream.Send(&pb.TcpForwardFrame{
		Payload: &pb.TcpForwardFrame_Data{Data: p},
	})
	if err != nil {
		return 0, converter.FromGRPCError(err)
	}
	return len(p), nil
}

func (c *tcpForwardConn) Close() error {
	c.sendMu.Lock()
	err := c.stream.CloseSend()
	c.sendMu.Unlock()
	c.cancel()
	<-c.done
	return err
}
