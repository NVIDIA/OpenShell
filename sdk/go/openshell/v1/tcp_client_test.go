// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

// --- Mock server for TCP forwarding ---

// mockTCPServer implements the ForwardTcp bidi stream. It records the init
// frame and echoes every data frame back to the client.
type mockTCPServer struct {
	pb.UnimplementedOpenShellServer
	mu       sync.Mutex
	lastInit *pb.TcpForwardInit
	err      error // if non-nil, return this error immediately on stream open
}

func newMockTCPServer() *mockTCPServer {
	return &mockTCPServer{}
}

func (s *mockTCPServer) ForwardTcp(stream grpc.BidiStreamingServer[pb.TcpForwardFrame, pb.TcpForwardFrame]) error { //nolint:revive // proto-generated method name
	s.mu.Lock()
	earlyErr := s.err
	s.mu.Unlock()
	if earlyErr != nil {
		return earlyErr
	}

	// First frame must be init.
	frame, err := stream.Recv()
	if err != nil {
		return err
	}
	init := frame.GetInit()
	if init == nil {
		return status.Errorf(codes.InvalidArgument, "first frame must be init")
	}

	s.mu.Lock()
	s.lastInit = init
	s.mu.Unlock()

	// Echo loop: every data frame is sent back verbatim.
	for {
		frame, err = stream.Recv()
		if err != nil {
			return err
		}
		data := frame.GetData()
		if data == nil {
			continue
		}
		if err := stream.Send(&pb.TcpForwardFrame{
			Payload: &pb.TcpForwardFrame_Data{Data: data},
		}); err != nil {
			return err
		}
	}
}

// --- Test setup ---

func setupTCPTest(t *testing.T, mock *mockTCPServer) (*tcpClient, func()) {
	t.Helper()
	lis := bufconn.Listen(bufSize)
	srv := grpc.NewServer()
	pb.RegisterOpenShellServer(srv, mock)
	go func() { _ = srv.Serve(lis) }()

	conn, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithContextDialer(func(_ context.Context, _ string) (net.Conn, error) {
			return lis.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)

	return newTCPClient(conn, &stubSandboxResolver{}, nil), func() {
		_ = conn.Close()
		srv.Stop()
	}
}

// --- Tests ---

func TestTCPForward_InitFrame(t *testing.T) {
	mock := newMockTCPServer()
	client, cleanup := setupTCPTest(t, mock)
	defer cleanup()

	rwc, err := client.Forward(context.Background(), "default", "my-sandbox", 8080)
	require.NoError(t, err)
	require.NotNil(t, rwc)
	defer func() { _ = rwc.Close() }()

	// Write something to trigger the init frame to be sent (init is sent
	// on Forward, before any Write — but we need a brief moment for the
	// server to process it).
	_, err = rwc.Write([]byte("ping"))
	require.NoError(t, err)

	// Read back the echo.
	buf := make([]byte, 64)
	n, err := rwc.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, "ping", string(buf[:n]))

	// Verify the init frame the server received.
	mock.mu.Lock()
	init := mock.lastInit
	mock.mu.Unlock()

	require.NotNil(t, init)
	assert.Equal(t, "sb-my-sandbox", init.GetSandboxId())
	assert.Empty(t, init.GetServiceId(), "service_id should be empty per FR-007a")
	assert.Empty(t, init.GetAuthorizationToken())

	tcp := init.GetTcp()
	require.NotNil(t, tcp, "target should be TcpRelayTarget")
	assert.Equal(t, "127.0.0.1", tcp.GetHost())
	assert.Equal(t, uint32(8080), tcp.GetPort())
}

func TestTCPForward_ReadWrite(t *testing.T) {
	mock := newMockTCPServer()
	client, cleanup := setupTCPTest(t, mock)
	defer cleanup()

	rwc, err := client.Forward(context.Background(), "default", "test-sandbox", 3000)
	require.NoError(t, err)
	defer func() { _ = rwc.Close() }()

	// Write data and read the echo back.
	payload := []byte("hello, sandbox!")
	_, err = rwc.Write(payload)
	require.NoError(t, err)

	buf := make([]byte, 64)
	n, err := rwc.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, payload, buf[:n])

	// Second round-trip.
	_, err = rwc.Write([]byte("round2"))
	require.NoError(t, err)

	n, err = rwc.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, "round2", string(buf[:n]))
}

func TestTCPForward_Close(t *testing.T) {
	mock := newMockTCPServer()
	client, cleanup := setupTCPTest(t, mock)
	defer cleanup()

	rwc, err := client.Forward(context.Background(), "default", "my-sandbox", 5432)
	require.NoError(t, err)

	err = rwc.Close()
	require.NoError(t, err)

	// Subsequent writes should fail.
	_, err = rwc.Write([]byte("should fail"))
	assert.Error(t, err)

	// Subsequent reads should also fail.
	buf := make([]byte, 64)
	_, err = rwc.Read(buf)
	assert.Error(t, err)
}

func TestTCPForward_PartialRead(t *testing.T) {
	mock := newMockTCPServer()
	client, cleanup := setupTCPTest(t, mock)
	defer cleanup()

	rwc, err := client.Forward(context.Background(), "default", "my-sandbox", 8080)
	require.NoError(t, err)
	defer func() { _ = rwc.Close() }()

	// Write a payload larger than the read buffer.
	payload := []byte("abcdefghijklmnopqrstuvwxyz")
	_, err = rwc.Write(payload)
	require.NoError(t, err)

	// Read with a small buffer — should get partial data and buffer the rest.
	var collected []byte
	buf := make([]byte, 10)
	for len(collected) < len(payload) {
		n, readErr := rwc.Read(buf)
		require.NoError(t, readErr)
		collected = append(collected, buf[:n]...)
	}
	assert.Equal(t, payload, collected)
}

func TestTCPForward_ConcurrentReadWrite(t *testing.T) {
	mock := newMockTCPServer()
	client, cleanup := setupTCPTest(t, mock)
	defer cleanup()

	rwc, err := client.Forward(context.Background(), "default", "my-sandbox", 8080)
	require.NoError(t, err)
	defer func() { _ = rwc.Close() }()

	const iterations = 50
	var wg sync.WaitGroup
	errCh := make(chan error, 2)
	wg.Add(2)

	go func() {
		defer wg.Done()
		for range iterations {
			_, writeErr := rwc.Write([]byte("ping"))
			if writeErr != nil {
				errCh <- writeErr
				return
			}
		}
	}()

	go func() {
		defer wg.Done()
		buf := make([]byte, 64)
		for range iterations {
			_, readErr := rwc.Read(buf)
			if readErr != nil {
				errCh <- readErr
				return
			}
		}
	}()

	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("concurrent goroutine failed: %v", err)
	}
}

func TestTCPForward_PortValidation(t *testing.T) {
	mock := newMockTCPServer()
	client, cleanup := setupTCPTest(t, mock)
	defer cleanup()

	tests := []struct {
		name string
		port uint32
	}{
		{"port zero", 0},
		{"port too high", 65536},
		{"port way too high", 100000},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rwc, err := client.Forward(context.Background(), "default", "my-sandbox", tt.port)
			assert.Nil(t, rwc)
			require.Error(t, err)
			assert.True(t, IsInvalidArgument(err), "expected InvalidArgument, got: %v", err)
		})
	}

	// Valid boundary ports should not get client-side rejection.
	for _, port := range []uint32{1, 65535} {
		rwc, err := client.Forward(context.Background(), "default", "my-sandbox", port)
		require.NoError(t, err, "port %d should be valid", port)
		require.NotNil(t, rwc)
		_ = rwc.Close()
	}
}

func TestTCPForward_ContextCancellation(t *testing.T) {
	mock := newMockTCPServer()
	client, cleanup := setupTCPTest(t, mock)
	defer cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	rwc, err := client.Forward(ctx, "default", "my-sandbox", 8080)
	require.NoError(t, err)
	require.NotNil(t, rwc)

	// Cancel the context.
	cancel()

	// Reads should return an error (context cancelled propagates through the gRPC stream).
	buf := make([]byte, 64)
	_, err = rwc.Read(buf)
	assert.Error(t, err)

	// Writes should also fail after context cancellation.
	_, err = rwc.Write([]byte("should fail"))
	assert.Error(t, err)
}

func TestTCPForward_WithServiceID(t *testing.T) {
	mock := newMockTCPServer()
	client, cleanup := setupTCPTest(t, mock)
	defer cleanup()

	rwc, err := client.Forward(context.Background(), "default", "my-sandbox", 8080, WithForwardServiceID("audit-svc"))
	require.NoError(t, err)
	require.NotNil(t, rwc)
	defer func() { _ = rwc.Close() }()

	// Trigger a round-trip so the server has processed the init frame.
	_, err = rwc.Write([]byte("ping"))
	require.NoError(t, err)
	buf := make([]byte, 64)
	_, err = rwc.Read(buf)
	require.NoError(t, err)

	mock.mu.Lock()
	init := mock.lastInit
	mock.mu.Unlock()

	require.NotNil(t, init)
	assert.Equal(t, "audit-svc", init.GetServiceId())
	assert.Equal(t, "sb-my-sandbox", init.GetSandboxId())
}

func TestTCPForward_WithoutOptions_BackwardCompat(t *testing.T) {
	mock := newMockTCPServer()
	client, cleanup := setupTCPTest(t, mock)
	defer cleanup()

	rwc, err := client.Forward(context.Background(), "default", "my-sandbox", 8080)
	require.NoError(t, err)
	require.NotNil(t, rwc)
	defer func() { _ = rwc.Close() }()

	_, err = rwc.Write([]byte("ping"))
	require.NoError(t, err)
	buf := make([]byte, 64)
	_, err = rwc.Read(buf)
	require.NoError(t, err)

	mock.mu.Lock()
	init := mock.lastInit
	mock.mu.Unlock()

	require.NotNil(t, init)
	assert.Empty(t, init.GetServiceId(), "service_id should be empty when no option provided")
}

func TestTCPForward_ServerError(t *testing.T) {
	mock := newMockTCPServer()
	mock.err = status.Errorf(codes.Unavailable, "server unavailable")
	client, cleanup := setupTCPTest(t, mock)
	defer cleanup()

	rwc, err := client.Forward(context.Background(), "default", "my-sandbox", 8080)

	// The stream opens successfully (gRPC bidi streams don't fail on open),
	// but the first write or read should surface the server error.
	if err != nil {
		// When Send(initFrame) races with the server returning the error,
		// the client may get the server status or a transport-level error.
		assert.Nil(t, rwc)
		require.Error(t, err)
		return
	}

	// If stream opened, the error surfaces on Read (the server returns it
	// immediately, which closes the recv side).
	require.NotNil(t, rwc)
	defer func() { _ = rwc.Close() }()

	buf := make([]byte, 64)
	_, err = rwc.Read(buf)
	assert.Error(t, err)
}

// --- Name-to-ID resolution tests ---

func TestTCPForward_ResolvesNameToID(t *testing.T) {
	mock := newMockTCPServer()
	client, cleanup := setupTCPTest(t, mock)
	defer cleanup()

	rwc, err := client.Forward(context.Background(), "default", "my-sandbox", 8080)
	require.NoError(t, err)
	require.NotNil(t, rwc)
	defer func() { _ = rwc.Close() }()

	// Trigger a round-trip so the server has processed the init frame.
	_, err = rwc.Write([]byte("ping"))
	require.NoError(t, err)
	buf := make([]byte, 64)
	_, err = rwc.Read(buf)
	require.NoError(t, err)

	mock.mu.Lock()
	init := mock.lastInit
	mock.mu.Unlock()

	require.NotNil(t, init)
	// stubSandboxResolver returns ID "sb-<name>" — verify the proto has the resolved ID, not the name
	assert.Equal(t, "sb-my-sandbox", init.GetSandboxId(), "Forward should send resolved sandbox ID, not the name")
}

func TestTCPForward_ResolutionError(t *testing.T) {
	mock := newMockTCPServer()
	lis := bufconn.Listen(bufSize)
	srv := grpc.NewServer()
	pb.RegisterOpenShellServer(srv, mock)
	go func() { _ = srv.Serve(lis) }()

	conn, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithContextDialer(func(_ context.Context, _ string) (net.Conn, error) {
			return lis.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	defer func() {
		_ = conn.Close()
		srv.Stop()
	}()

	resolver := &stubSandboxResolver{
		getErr: &StatusError{Code: ErrorNotFound, Message: "sandbox not found"},
	}
	client := newTCPClient(conn, resolver, nil)

	rwc, err := client.Forward(context.Background(), "default", "nonexistent", 8080)
	assert.Nil(t, rwc)
	require.Error(t, err)
	assert.True(t, IsNotFound(err))
}

func TestTCPForward_EmptySandboxName(t *testing.T) {
	mock := newMockTCPServer()
	client, cleanup := setupTCPTest(t, mock)
	defer cleanup()

	rwc, err := client.Forward(context.Background(), "default", "", 8080)
	assert.Nil(t, rwc)
	require.Error(t, err)
	assert.True(t, IsInvalidArgument(err))
}

// --- Listen tests ---

func TestTCPListen_ReturnsValidListener(t *testing.T) {
	mock := newMockTCPServer()
	client, cleanup := setupTCPTest(t, mock)
	defer cleanup()

	ln, err := client.Listen(context.Background(), "default", "my-sandbox", 8080, 0)
	require.NoError(t, err)
	require.NotNil(t, ln)
	defer func() { _ = ln.Close() }()

	// Addr should return a non-nil TCP address with a non-zero port.
	addr := ln.Addr()
	require.NotNil(t, addr)
	tcpAddr, ok := addr.(*net.TCPAddr)
	require.True(t, ok, "expected *net.TCPAddr, got %T", addr)
	assert.NotZero(t, tcpAddr.Port, "OS-assigned port should be non-zero")
}

func TestTCPListen_ConcurrentConnections(t *testing.T) {
	mock := newMockTCPServer()
	client, cleanup := setupTCPTest(t, mock)
	defer cleanup()

	ln, err := client.Listen(context.Background(), "default", "my-sandbox", 8080, 0)
	require.NoError(t, err)
	require.NotNil(t, ln)
	defer func() { _ = ln.Close() }()

	const numConns = 10
	var wg sync.WaitGroup
	errCh := make(chan error, numConns)

	// Dial numConns goroutines, each independently writes and reads.
	for i := range numConns {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			conn, dialErr := net.Dial("tcp", ln.Addr().String())
			if dialErr != nil {
				errCh <- fmt.Errorf("dial %d: %w", idx, dialErr)
				return
			}
			defer func() { _ = conn.Close() }()

			payload := []byte(fmt.Sprintf("msg-%d", idx))
			_, writeErr := conn.Write(payload)
			if writeErr != nil {
				errCh <- fmt.Errorf("write %d: %w", idx, writeErr)
				return
			}

			buf := make([]byte, 256)
			n, readErr := conn.Read(buf)
			if readErr != nil {
				errCh <- fmt.Errorf("read %d: %w", idx, readErr)
				return
			}

			if string(buf[:n]) != string(payload) {
				errCh <- fmt.Errorf("conn %d: expected %q, got %q", idx, payload, buf[:n])
			}
		}(i)
	}

	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Errorf("concurrent connection error: %v", err)
	}
}

func TestTCPListen_EphemeralPort(t *testing.T) {
	mock := newMockTCPServer()
	client, cleanup := setupTCPTest(t, mock)
	defer cleanup()

	// localPort=0 → OS assigns an ephemeral port.
	ln, err := client.Listen(context.Background(), "default", "my-sandbox", 8080, 0)
	require.NoError(t, err)
	require.NotNil(t, ln)
	defer func() { _ = ln.Close() }()

	// Addr() should expose the assigned port.
	tcpAddr, ok := ln.Addr().(*net.TCPAddr)
	require.True(t, ok)
	assert.NotZero(t, tcpAddr.Port, "OS-assigned port should be non-zero")

	// Verify a connection through the ephemeral port actually works.
	conn, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	payload := []byte("ephemeral-test")
	_, err = conn.Write(payload)
	require.NoError(t, err)

	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, payload, buf[:n])
}

func TestTCPListen_EmptySandboxName(t *testing.T) {
	mock := newMockTCPServer()
	client, cleanup := setupTCPTest(t, mock)
	defer cleanup()

	ln, err := client.Listen(context.Background(), "default", "", 8080, 0)
	assert.Nil(t, ln)
	require.Error(t, err)
	assert.True(t, IsInvalidArgument(err))
}

func TestTCPListen_BidirectionalDataFlow(t *testing.T) {
	mock := newMockTCPServer()
	client, cleanup := setupTCPTest(t, mock)
	defer cleanup()

	ln, err := client.Listen(context.Background(), "default", "my-sandbox", 8080, 0)
	require.NoError(t, err)
	require.NotNil(t, ln)
	defer func() { _ = ln.Close() }()

	// Connect to the listener's local address.
	conn, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	// Write data through the local connection → tunnel → mock echo → back.
	payload := []byte("hello through the tunnel")
	_, err = conn.Write(payload)
	require.NoError(t, err)

	// Read the echoed data back.
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, payload, buf[:n])

	// Second round-trip to confirm bidirectionality.
	payload2 := []byte("round two")
	_, err = conn.Write(payload2)
	require.NoError(t, err)

	n, err = conn.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, payload2, buf[:n])
}

func TestTCPListen_InvalidRemotePort(t *testing.T) {
	mock := newMockTCPServer()
	client, cleanup := setupTCPTest(t, mock)
	defer cleanup()

	tests := []struct {
		name string
		port uint32
	}{
		{"port zero", 0},
		{"port too high", 65536},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ln, err := client.Listen(context.Background(), "default", "my-sandbox", tt.port, 0)
			assert.Nil(t, ln)
			require.Error(t, err)
			assert.True(t, IsInvalidArgument(err), "expected InvalidArgument, got: %v", err)
		})
	}
}

// --- Graceful shutdown tests ---

func TestTCPListen_CloseTerminatesConnections(t *testing.T) {
	mock := newMockTCPServer()
	client, cleanup := setupTCPTest(t, mock)
	defer cleanup()

	ln, err := client.Listen(context.Background(), "default", "my-sandbox", 8080, 0)
	require.NoError(t, err)

	const numConns = 3
	conns := make([]net.Conn, numConns)

	// Establish 3 connections.
	for i := range numConns {
		conns[i], err = net.Dial("tcp", ln.Addr().String())
		require.NoError(t, err)

		// Verify data flows before shutdown.
		_, err = conns[i].Write([]byte("pre-close"))
		require.NoError(t, err)
		buf := make([]byte, 256)
		_, err = conns[i].Read(buf)
		require.NoError(t, err)
	}

	// Close the listener. Per SC-003, this should complete within 5 seconds.
	closeDone := make(chan error, 1)
	go func() {
		closeDone <- ln.Close()
	}()

	select {
	case closeErr := <-closeDone:
		assert.NoError(t, closeErr)
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not complete within 5 seconds")
	}

	// All connections should now return errors on read.
	for i, conn := range conns {
		buf := make([]byte, 64)
		_, readErr := conn.Read(buf)
		assert.Error(t, readErr, "connection %d should be closed after listener.Close()", i)
		_ = conn.Close()
	}
}

func TestTCPListen_ContextCancellation(t *testing.T) {
	mock := newMockTCPServer()
	client, cleanup := setupTCPTest(t, mock)
	defer cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	ln, err := client.Listen(ctx, "default", "my-sandbox", 8080, 0)
	require.NoError(t, err)
	require.NotNil(t, ln)

	conn, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)

	// Verify data flows before cancellation.
	_, err = conn.Write([]byte("before-cancel"))
	require.NoError(t, err)
	buf := make([]byte, 256)
	_, err = conn.Read(buf)
	require.NoError(t, err)

	// Cancel the context — should trigger listener close.
	cancel()

	// The connection should eventually fail.
	// Give the context-watcher goroutine a moment to close the listener.
	time.Sleep(50 * time.Millisecond)

	_, err = conn.Write([]byte("after-cancel"))
	if err == nil {
		// Write may succeed if buffered, but Read should fail.
		buf = make([]byte, 64)
		_, err = conn.Read(buf)
	}
	assert.Error(t, err, "connection should fail after context cancellation")
	_ = conn.Close()
}

func TestTCPListen_CloseIsIdempotent(t *testing.T) {
	mock := newMockTCPServer()
	client, cleanup := setupTCPTest(t, mock)
	defer cleanup()

	ln, err := client.Listen(context.Background(), "default", "my-sandbox", 8080, 0)
	require.NoError(t, err)

	// Close the listener immediately.
	err = ln.Close()
	require.NoError(t, err)

	assert.NoError(t, ln.Close())
}

// --- Custom bind address tests ---

func TestTCPListen_WithBindAddress(t *testing.T) {
	mock := newMockTCPServer()
	client, cleanup := setupTCPTest(t, mock)
	defer cleanup()

	// Verify WithBindAddress is accepted and the listener binds to the
	// specified address. We use 127.0.0.1 explicitly since it is the only
	// loopback address guaranteed on all platforms (macOS does not enable
	// 127.0.0.2+ by default). The default-case assertion below confirms
	// that omitting the option also produces 127.0.0.1.
	ln, err := client.Listen(
		context.Background(), "default", "my-sandbox", 8080, 0,
		WithBindAddress("127.0.0.1"),
	)
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()

	tcpAddr, ok := ln.Addr().(*net.TCPAddr)
	require.True(t, ok, "expected *net.TCPAddr")
	assert.Equal(t, "127.0.0.1", tcpAddr.IP.String(),
		"listener should bind to the address specified by WithBindAddress")

	// Also verify that without WithBindAddress the default is 127.0.0.1.
	lnDefault, err := client.Listen(
		context.Background(), "default", "my-sandbox", 8080, 0,
	)
	require.NoError(t, err)
	defer func() { _ = lnDefault.Close() }()

	defaultAddr, ok := lnDefault.Addr().(*net.TCPAddr)
	require.True(t, ok, "expected *net.TCPAddr")
	assert.Equal(t, "127.0.0.1", defaultAddr.IP.String(),
		"default bind address should be 127.0.0.1")
}

// --- SSH tunnel transport tests ---

// mockSSHClient implements SSHInterface for testing the SSH tunnel path.
type mockSSHClient struct {
	mu          sync.Mutex
	tunnelCalls int
}

func (m *mockSSHClient) CreateSession(_ context.Context, _, _ string) (*SSHSession, error) {
	return nil, fmt.Errorf("not implemented in mock")
}

func (m *mockSSHClient) RevokeSession(_ context.Context, _, _ string) (bool, error) {
	return false, fmt.Errorf("not implemented in mock")
}

// Tunnel returns a pipe that echoes data back, and increments the call counter.
func (m *mockSSHClient) Tunnel(_ context.Context, _, _ string, _ uint32, _ ...TunnelOption) (io.ReadWriteCloser, error) {
	m.mu.Lock()
	m.tunnelCalls++
	m.mu.Unlock()

	// Create a pipe-based echo tunnel: read from one end, write back to the other.
	clientReader, serverWriter := io.Pipe()
	serverReader, clientWriter := io.Pipe()

	// Echo goroutine: copy everything from server reader to server writer.
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := serverReader.Read(buf)
			if err != nil {
				_ = serverWriter.Close()
				return
			}
			if _, wErr := serverWriter.Write(buf[:n]); wErr != nil {
				return
			}
		}
	}()

	return &pipeRWC{Reader: clientReader, Writer: clientWriter, closers: []io.Closer{clientReader, clientWriter, serverReader, serverWriter}}, nil
}

// pipeRWC wraps a Reader and Writer into an io.ReadWriteCloser.
type pipeRWC struct {
	io.Reader
	io.Writer
	closers []io.Closer
}

func (p *pipeRWC) Close() error {
	for _, c := range p.closers {
		_ = c.Close()
	}
	return nil
}

func TestTCPListen_WithSSHTunnel(t *testing.T) {
	mock := newMockTCPServer()

	// Set up the gRPC connection (needed for tcpClient even though SSH path
	// won't use Forward).
	lis := bufconn.Listen(bufSize)
	srv := grpc.NewServer()
	pb.RegisterOpenShellServer(srv, mock)
	go func() { _ = srv.Serve(lis) }()

	conn, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithContextDialer(func(_ context.Context, _ string) (net.Conn, error) {
			return lis.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	defer func() {
		_ = conn.Close()
		srv.Stop()
	}()

	sshMock := &mockSSHClient{}
	client := newTCPClient(conn, &stubSandboxResolver{}, sshMock)

	ln, err := client.Listen(
		context.Background(), "default", "my-sandbox", 8080, 0,
		WithSSHTunnel(),
		WithListenServiceID("ssh-svc"),
	)
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()

	// Connect and send data through the SSH tunnel path.
	c, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)

	payload := []byte("ssh-tunnel-test")
	_, err = c.Write(payload)
	require.NoError(t, err)

	buf := make([]byte, 256)
	n, err := c.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, string(payload), string(buf[:n]),
		"data should echo through SSH tunnel")

	// Verify that Tunnel was called (not Forward).
	sshMock.mu.Lock()
	calls := sshMock.tunnelCalls
	sshMock.mu.Unlock()
	assert.Equal(t, 1, calls, "SSH Tunnel should have been called exactly once")

	// Verify no Forward calls happened on the mock TCP server.
	mock.mu.Lock()
	initFrame := mock.lastInit
	mock.mu.Unlock()
	assert.Nil(t, initFrame, "TCP Forward should not have been called when using SSH tunnel")

	_ = c.Close()
}

func TestTCPListen_CallerSpecifiedPort(t *testing.T) {
	mock := newMockTCPServer()
	client, cleanup := setupTCPTest(t, mock)
	defer cleanup()

	const wantPort = 19876
	ln, err := client.Listen(context.Background(), "default", "my-sandbox", 8080, wantPort)
	require.NoError(t, err)
	require.NotNil(t, ln)
	defer func() { _ = ln.Close() }()

	tcpAddr, ok := ln.Addr().(*net.TCPAddr)
	require.True(t, ok)
	assert.Equal(t, wantPort, tcpAddr.Port, "listener should bind to the exact port requested")

	c, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	defer func() { _ = c.Close() }()

	_, err = c.Write([]byte("fixed-port"))
	require.NoError(t, err)

	buf := make([]byte, 64)
	n, err := c.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, "fixed-port", string(buf[:n]))
}

func TestTCPListen_ServiceIDPropagated(t *testing.T) {
	mock := newMockTCPServer()
	client, cleanup := setupTCPTest(t, mock)
	defer cleanup()

	ln, err := client.Listen(context.Background(), "default", "my-sandbox", 8080, 0,
		WithListenServiceID("test-svc-id"),
	)
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()

	c, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)

	_, err = c.Write([]byte("svc-id-test"))
	require.NoError(t, err)
	buf := make([]byte, 64)
	_, err = c.Read(buf)
	require.NoError(t, err)
	_ = c.Close()

	mock.mu.Lock()
	init := mock.lastInit
	mock.mu.Unlock()

	require.NotNil(t, init, "mock should have received the init frame")
	assert.Equal(t, "test-svc-id", init.GetServiceId(),
		"Listen should propagate service ID to the Forward init frame")
}

func TestTCPListen_WithSSHTunnel_NilSSH(t *testing.T) {
	mock := newMockTCPServer()
	lis := bufconn.Listen(bufSize)
	srv := grpc.NewServer()
	pb.RegisterOpenShellServer(srv, mock)
	go func() { _ = srv.Serve(lis) }()

	conn, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithContextDialer(func(_ context.Context, _ string) (net.Conn, error) {
			return lis.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	defer func() {
		_ = conn.Close()
		srv.Stop()
	}()

	client := newTCPClient(conn, &stubSandboxResolver{}, nil)
	_, err = client.Listen(context.Background(), "default", "my-sandbox", 8080, 0, WithSSHTunnel())
	require.Error(t, err)
	assert.True(t, IsInvalidArgument(err), "WithSSHTunnel with nil SSH client should return InvalidArgument")
}

// --- Failure injection helpers ---

// flippableResolver extends stubSandboxResolver with a mutex-guarded error
// that can be toggled at runtime (set to nil to stop failing).
type flippableResolver struct {
	mu      sync.Mutex
	failErr error
}

func (r *flippableResolver) Get(_ context.Context, _, name string) (*Sandbox, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failErr != nil {
		return nil, r.failErr
	}
	return &Sandbox{ID: "sb-" + name, Name: name}, nil
}

func (r *flippableResolver) Create(context.Context, string, string, *SandboxSpec, map[string]string, ...CreateOptions) (*Sandbox, error) {
	panic("not implemented")
}
func (r *flippableResolver) List(context.Context, string, ...ListOptions) ([]*Sandbox, error) {
	panic("not implemented")
}
func (r *flippableResolver) Delete(context.Context, string, string) error {
	panic("not implemented")
}
func (r *flippableResolver) AttachProvider(context.Context, string, string, string, uint64) (*AttachProviderResult, error) {
	panic("not implemented")
}
func (r *flippableResolver) DetachProvider(context.Context, string, string, string, uint64) (*DetachProviderResult, error) {
	panic("not implemented")
}
func (r *flippableResolver) ListProviders(context.Context, string, string) ([]*Provider, error) {
	panic("not implemented")
}
func (r *flippableResolver) WaitReady(context.Context, string, string, ...WaitOptions) (*Sandbox, error) {
	panic("not implemented")
}
func (r *flippableResolver) Watch(context.Context, string, string, ...WatchOptions) (WatchInterface[*Sandbox], error) {
	panic("not implemented")
}
func (r *flippableResolver) GetLogs(context.Context, string, string, ...LogOption) (*LogResult, error) {
	panic("not implemented")
}
func (r *flippableResolver) Stop(context.Context, string, string) (*Sandbox, error) {
	panic("not implemented")
}
func (r *flippableResolver) Start(context.Context, string, string) (*Sandbox, error) {
	panic("not implemented")
}
func (r *flippableResolver) WaitStopped(context.Context, string, string, ...WaitOptions) (*Sandbox, error) {
	panic("not implemented")
}

// --- Failure injection tests ---

func TestTCPListen_TunnelSetupRetry(t *testing.T) {
	mock := newMockTCPServer()

	lis := bufconn.Listen(bufSize)
	srv := grpc.NewServer()
	pb.RegisterOpenShellServer(srv, mock)
	go func() { _ = srv.Serve(lis) }()

	conn, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithContextDialer(func(_ context.Context, _ string) (net.Conn, error) {
			return lis.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	defer func() {
		_ = conn.Close()
		srv.Stop()
	}()

	// Use a resolver that fails initially, then succeeds.
	resolver := &flippableResolver{
		failErr: &StatusError{Code: ErrorUnavailable, Message: "sandbox unreachable"},
	}
	client := newTCPClient(conn, resolver, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	inner, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	tl := &tunnelListener{
		inner:       inner,
		ctx:         ctx,
		cancel:      cancel,
		tcp:         client,
		sandboxName: "my-sandbox",
		remotePort:  8080,
		cfg:         listenConfig{bindAddress: "127.0.0.1"},
	}

	tl.wg.Add(1)
	go tl.acceptLoop()

	// First connection triggers Forward which fails (resolver returns error).
	c1, err := net.Dial("tcp", inner.Addr().String())
	require.NoError(t, err)
	defer func() { _ = c1.Close() }()

	time.Sleep(50 * time.Millisecond)

	// Clear the error so the next Forward succeeds.
	resolver.mu.Lock()
	resolver.failErr = nil
	resolver.mu.Unlock()

	// Second connection should succeed through the retry loop.
	c2, err := net.Dial("tcp", inner.Addr().String())
	require.NoError(t, err)
	defer func() { _ = c2.Close() }()

	_, err = c2.Write([]byte("retry-ok"))
	require.NoError(t, err)
	buf := make([]byte, 32)
	n, err := c2.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, "retry-ok", string(buf[:n]))

	_ = tl.Close()
}

func TestTCPListen_TunnelFailureWithContextCancel(t *testing.T) {
	mock := newMockTCPServer()

	lis := bufconn.Listen(bufSize)
	srv := grpc.NewServer()
	pb.RegisterOpenShellServer(srv, mock)
	go func() { _ = srv.Serve(lis) }()

	conn, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithContextDialer(func(_ context.Context, _ string) (net.Conn, error) {
			return lis.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	defer func() {
		_ = conn.Close()
		srv.Stop()
	}()

	// Resolver always fails: Forward will error on every attempt.
	resolver := &flippableResolver{
		failErr: &StatusError{Code: ErrorUnavailable, Message: "permanent failure"},
	}
	client := newTCPClient(conn, resolver, nil)

	ctx, cancel := context.WithCancel(context.Background())

	ln, err := client.Listen(ctx, "default", "my-sandbox", 8080, 0)
	require.NoError(t, err)

	// Trigger a connection that will fail tunnel setup.
	c, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	_ = c.Close()

	// Give the internal accept loop time to enter tunnel setup.
	time.Sleep(50 * time.Millisecond)

	// Cancel context: the context-watcher goroutine in Listen() calls
	// Close(), which closes the inner listener and stops the accept loop.
	cancel()
	require.Eventually(t, func() bool {
		return ln.Close() == nil
	}, 5*time.Second, 10*time.Millisecond)
}
