// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"
	"fmt"
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

// --- Mock server for SSH sessions ---

type mockSSHServer struct {
	pb.UnimplementedOpenShellServer
	mu                sync.Mutex
	sessions          map[string]*pb.CreateSshSessionResponse // key: sandbox ID
	tokens            map[string]bool                         // track active tokens
	revokeCount       int                                     // total revocation attempts
	revokeHasDeadline bool
	createErr         error
	revokeErr         error
	forwardErr        error
	nextToken         string // override token for testing
	lastInit          *pb.TcpForwardInit
}

func newMockSSHServer() *mockSSHServer {
	return &mockSSHServer{
		sessions: make(map[string]*pb.CreateSshSessionResponse),
		tokens:   make(map[string]bool),
	}
}

func (s *mockSSHServer) CreateSshSession(_ context.Context, req *pb.CreateSshSessionRequest) (*pb.CreateSshSessionResponse, error) { //nolint:revive // proto-generated method name
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.createErr != nil {
		return nil, s.createErr
	}

	token := "tok-" + req.GetSandboxId()
	if s.nextToken != "" {
		token = s.nextToken
	}

	resp := &pb.CreateSshSessionResponse{
		SandboxId:          req.GetSandboxId(),
		Token:              token,
		GatewayHost:        "gw.example.com",
		GatewayPort:        2222,
		GatewayScheme:      "https",
		HostKeyFingerprint: "SHA256:abc123",
		ExpiresAtMs:        1700000000000,
	}
	s.sessions[req.GetSandboxId()] = resp
	s.tokens[token] = true
	return resp, nil
}

func (s *mockSSHServer) RevokeSshSession(ctx context.Context, req *pb.RevokeSshSessionRequest) (*pb.RevokeSshSessionResponse, error) { //nolint:revive // proto-generated method name
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revokeCount++
	_, s.revokeHasDeadline = ctx.Deadline()
	if s.revokeErr != nil {
		return nil, s.revokeErr
	}

	token := req.GetToken()
	active, exists := s.tokens[token]
	if exists && active {
		s.tokens[token] = false
		return &pb.RevokeSshSessionResponse{Revoked: true}, nil
	}
	// Already revoked or not found — not an error, just revoked=false.
	return &pb.RevokeSshSessionResponse{Revoked: false}, nil
}

func (s *mockSSHServer) ForwardTcp(stream grpc.BidiStreamingServer[pb.TcpForwardFrame, pb.TcpForwardFrame]) error { //nolint:revive // proto-generated method name
	s.mu.Lock()
	earlyErr := s.forwardErr
	s.mu.Unlock()
	if earlyErr != nil {
		return earlyErr
	}

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

// --- Mock sandbox resolver ---

type mockSandboxResolver struct {
	sandboxes map[string]*Sandbox
	err       error
}

func (m *mockSandboxResolver) Create(_ context.Context, _, _ string, _ *SandboxSpec, _ map[string]string, _ ...CreateOptions) (*Sandbox, error) {
	return nil, nil
}

func (m *mockSandboxResolver) Get(_ context.Context, _, name string) (*Sandbox, error) {
	if m.err != nil {
		return nil, m.err
	}
	sb, ok := m.sandboxes[name]
	if !ok {
		return nil, &StatusError{Code: ErrorNotFound, Message: "sandbox not found: " + name}
	}
	return sb, nil
}

func (m *mockSandboxResolver) List(_ context.Context, _ string, _ ...ListOptions) ([]*Sandbox, error) {
	return nil, nil
}
func (m *mockSandboxResolver) Delete(_ context.Context, _, _ string) error { return nil }
func (m *mockSandboxResolver) AttachProvider(_ context.Context, _, _, _ string, _ uint64) (*AttachProviderResult, error) {
	return nil, nil
}
func (m *mockSandboxResolver) DetachProvider(_ context.Context, _, _, _ string, _ uint64) (*DetachProviderResult, error) {
	return nil, nil
}
func (m *mockSandboxResolver) ListProviders(_ context.Context, _, _ string) ([]*Provider, error) {
	return nil, nil
}
func (m *mockSandboxResolver) WaitReady(_ context.Context, _, _ string, _ ...WaitOptions) (*Sandbox, error) {
	return nil, nil
}
func (m *mockSandboxResolver) Watch(_ context.Context, _, _ string, _ ...WatchOptions) (WatchInterface[*Sandbox], error) {
	return nil, nil
}
func (m *mockSandboxResolver) GetLogs(_ context.Context, _, _ string, _ ...LogOption) (*LogResult, error) {
	return nil, nil
}
func (m *mockSandboxResolver) Stop(_ context.Context, _, _ string) (*Sandbox, error) {
	return nil, nil
}
func (m *mockSandboxResolver) Start(_ context.Context, _, _ string) (*Sandbox, error) {
	return nil, nil
}
func (m *mockSandboxResolver) WaitStopped(_ context.Context, _, _ string, _ ...WaitOptions) (*Sandbox, error) {
	return nil, nil
}

// --- Test setup ---

func setupSSHTest(t *testing.T, mock *mockSSHServer) (*sshClient, func()) {
	t.Helper()
	return setupSSHTestWithSandboxes(t, mock, nil)
}

func setupSSHTestWithSandboxes(t *testing.T, mock *mockSSHServer, sandboxes SandboxInterface) (*sshClient, func()) {
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

	return newSSHClient(conn, sandboxes), func() {
		_ = conn.Close()
		srv.Stop()
	}
}

// --- Tests ---

func TestSSHCreateSession(t *testing.T) {
	mock := newMockSSHServer()
	client, cleanup := setupSSHTest(t, mock)
	defer cleanup()

	session, err := client.CreateSession(context.Background(), "default", "my-sandbox")

	require.NoError(t, err)
	require.NotNil(t, session)
	assert.Equal(t, "my-sandbox", session.SandboxID)
	assert.Equal(t, "tok-my-sandbox", session.Token)
	assert.Equal(t, "gw.example.com", session.GatewayHost)
	assert.Equal(t, uint32(2222), session.GatewayPort)
	assert.Equal(t, "https", session.GatewayScheme)
	assert.Equal(t, "SHA256:abc123", session.HostKeyFingerprint)
	assert.Equal(t, int64(1700000000000), session.ExpiresAtMs)
}

func TestSSHCreateSession_Error(t *testing.T) {
	mock := newMockSSHServer()
	mock.createErr = status.Errorf(codes.NotFound, "sandbox not found")
	client, cleanup := setupSSHTest(t, mock)
	defer cleanup()

	session, err := client.CreateSession(context.Background(), "default", "missing")

	assert.Nil(t, session)
	require.Error(t, err)
	assert.True(t, IsNotFound(err))
}

func TestSSHRevokeSession(t *testing.T) {
	mock := newMockSSHServer()
	client, cleanup := setupSSHTest(t, mock)
	defer cleanup()

	// Create a session first.
	session, err := client.CreateSession(context.Background(), "default", "my-sandbox")
	require.NoError(t, err)

	// Revoke it — should return true.
	revoked, err := client.RevokeSession(context.Background(), "default", session.Token)

	require.NoError(t, err)
	assert.True(t, revoked)
}

func TestSSHRevokeSession_AlreadyRevoked(t *testing.T) {
	mock := newMockSSHServer()
	client, cleanup := setupSSHTest(t, mock)
	defer cleanup()

	// Create and revoke.
	session, err := client.CreateSession(context.Background(), "default", "my-sandbox")
	require.NoError(t, err)
	_, err = client.RevokeSession(context.Background(), "default", session.Token)
	require.NoError(t, err)

	// Revoke again — should return false (already revoked).
	revoked, err := client.RevokeSession(context.Background(), "default", session.Token)

	require.NoError(t, err)
	assert.False(t, revoked)
}

func TestSSHRevokeSession_Error(t *testing.T) {
	mock := newMockSSHServer()
	mock.revokeErr = status.Errorf(codes.Internal, "internal error")
	client, cleanup := setupSSHTest(t, mock)
	defer cleanup()

	revoked, err := client.RevokeSession(context.Background(), "default", "some-token")

	assert.False(t, revoked)
	require.Error(t, err)
	var se *StatusError
	require.ErrorAs(t, err, &se)
	assert.Equal(t, ErrorInternal, se.Code)
}

// --- Tunnel tests (T012) ---

func defaultSandboxResolver() *mockSandboxResolver {
	return &mockSandboxResolver{
		sandboxes: map[string]*Sandbox{
			"my-sandbox": {ID: "sb-123", Name: "my-sandbox"},
		},
	}
}

func TestSSHTunnel_Success(t *testing.T) {
	mock := newMockSSHServer()
	resolver := defaultSandboxResolver()
	client, cleanup := setupSSHTestWithSandboxes(t, mock, resolver)
	defer cleanup()

	rwc, err := client.Tunnel(context.Background(), "default", "my-sandbox", 22)
	require.NoError(t, err)
	require.NotNil(t, rwc)
	defer func() { _ = rwc.Close() }()

	// Round-trip to verify the stream works.
	_, err = rwc.Write([]byte("hello"))
	require.NoError(t, err)

	buf := make([]byte, 64)
	n, err := rwc.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, "hello", string(buf[:n]))

	// Verify init frame sent to server.
	mock.mu.Lock()
	init := mock.lastInit
	mock.mu.Unlock()

	require.NotNil(t, init)
	assert.Equal(t, "sb-123", init.GetSandboxId())
	assert.NotEmpty(t, init.GetAuthorizationToken())
	assert.NotNil(t, init.GetSsh(), "target should be SshRelayTarget")
}

func TestSSHTunnel_WithServiceID(t *testing.T) {
	mock := newMockSSHServer()
	resolver := defaultSandboxResolver()
	client, cleanup := setupSSHTestWithSandboxes(t, mock, resolver)
	defer cleanup()

	rwc, err := client.Tunnel(context.Background(), "default", "my-sandbox", 22, WithTunnelServiceID("audit-svc"))
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
	assert.Equal(t, "audit-svc", init.GetServiceId())
}

func TestSSHTunnel_InvalidPort(t *testing.T) {
	mock := newMockSSHServer()
	resolver := defaultSandboxResolver()
	client, cleanup := setupSSHTestWithSandboxes(t, mock, resolver)
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
			rwc, err := client.Tunnel(context.Background(), "default", "my-sandbox", tt.port)
			assert.Nil(t, rwc)
			require.Error(t, err)
			assert.True(t, IsInvalidArgument(err))
		})
	}
}

func TestSSHTunnel_EmptySandboxName(t *testing.T) {
	mock := newMockSSHServer()
	resolver := defaultSandboxResolver()
	client, cleanup := setupSSHTestWithSandboxes(t, mock, resolver)
	defer cleanup()

	rwc, err := client.Tunnel(context.Background(), "default", "", 22)
	assert.Nil(t, rwc)
	require.Error(t, err)
	assert.True(t, IsInvalidArgument(err))
}

func TestSSHTunnel_SandboxNotFound(t *testing.T) {
	mock := newMockSSHServer()
	resolver := defaultSandboxResolver()
	client, cleanup := setupSSHTestWithSandboxes(t, mock, resolver)
	defer cleanup()

	rwc, err := client.Tunnel(context.Background(), "default", "nonexistent", 22)
	assert.Nil(t, rwc)
	require.Error(t, err)
	assert.True(t, IsNotFound(err))
}

func TestSSHTunnel_SessionRevokedOnForwardFailure(t *testing.T) {
	mock := newMockSSHServer()
	mock.forwardErr = status.Errorf(codes.Internal, "forward failed")
	resolver := defaultSandboxResolver()
	client, cleanup := setupSSHTestWithSandboxes(t, mock, resolver)
	defer cleanup()

	rwc, err := client.Tunnel(context.Background(), "default", "my-sandbox", 22)

	if err != nil {
		assert.Nil(t, rwc)
	} else {
		require.NotNil(t, rwc)
		buf := make([]byte, 64)
		_, err = rwc.Read(buf)
		assert.Error(t, err)
		_ = rwc.Close()
	}

	// Session should have been revoked since the forward failed.
	mock.mu.Lock()
	tokenRevoked := false
	for _, active := range mock.tokens {
		if !active {
			tokenRevoked = true
			break
		}
	}
	mock.mu.Unlock()
	assert.True(t, tokenRevoked, "session token should be revoked after forward failure")
}

func TestSSHTunnel_SessionRevokedOnClose(t *testing.T) {
	mock := newMockSSHServer()
	resolver := defaultSandboxResolver()
	client, cleanup := setupSSHTestWithSandboxes(t, mock, resolver)
	defer cleanup()

	rwc, err := client.Tunnel(context.Background(), "default", "my-sandbox", 22)
	require.NoError(t, err)

	// Close the tunnel, which should revoke the session.
	err = rwc.Close()
	require.NoError(t, err)

	mock.mu.Lock()
	tokenRevoked := false
	for _, active := range mock.tokens {
		if !active {
			tokenRevoked = true
			break
		}
	}
	mock.mu.Unlock()
	assert.True(t, tokenRevoked, "session token should be revoked after tunnel close")
	assert.True(t, mock.revokeHasDeadline, "cleanup revocation must have a deadline")
}

func TestSSHTunnel_DoubleClose(t *testing.T) {
	mock := newMockSSHServer()
	resolver := defaultSandboxResolver()
	client, cleanup := setupSSHTestWithSandboxes(t, mock, resolver)
	defer cleanup()

	rwc, err := client.Tunnel(context.Background(), "default", "my-sandbox", 22)
	require.NoError(t, err)

	err = rwc.Close()
	require.NoError(t, err)

	// Second close should not panic or return a different error.
	err = rwc.Close()
	assert.NoError(t, err)
}

func TestSSHTunnel_ContextCancellation(t *testing.T) {
	mock := newMockSSHServer()
	resolver := defaultSandboxResolver()
	client, cleanup := setupSSHTestWithSandboxes(t, mock, resolver)
	defer cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	rwc, err := client.Tunnel(ctx, "default", "my-sandbox", 22)
	require.NoError(t, err)
	require.NotNil(t, rwc)

	cancel()

	buf := make([]byte, 64)
	_, err = rwc.Read(buf)
	assert.Error(t, err)

	_, err = rwc.Write([]byte("should fail"))
	assert.Error(t, err)

	_ = rwc.Close()
}

func TestSSHTunnel_TokenNotExposed(t *testing.T) {
	mock := newMockSSHServer()
	mock.nextToken = "secret-tunnel-token-xyz"
	resolver := defaultSandboxResolver()
	client, cleanup := setupSSHTestWithSandboxes(t, mock, resolver)
	defer cleanup()

	rwc, err := client.Tunnel(context.Background(), "default", "my-sandbox", 22)
	require.NoError(t, err)
	require.NotNil(t, rwc)
	defer func() { _ = rwc.Close() }()

	repr := fmt.Sprintf("%v", rwc)
	assert.NotContains(t, repr, "secret-tunnel-token-xyz",
		"token must not leak through the returned value's string representation")
}

func TestSSHTunnel_ContextCancelRevokesSession(t *testing.T) {
	mock := newMockSSHServer()
	resolver := defaultSandboxResolver()
	client, cleanup := setupSSHTestWithSandboxes(t, mock, resolver)
	defer cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	rwc, err := client.Tunnel(ctx, "default", "my-sandbox", 22)
	require.NoError(t, err)
	require.NotNil(t, rwc)

	cancel()

	require.Eventually(t, func() bool {
		mock.mu.Lock()
		defer mock.mu.Unlock()
		for _, active := range mock.tokens {
			if !active {
				return true
			}
		}
		return false
	}, 5*time.Second, 10*time.Millisecond, "session token should be revoked after context cancel")
}

func TestSSHTunnel_ContextCancelThenClose(t *testing.T) {
	mock := newMockSSHServer()
	resolver := defaultSandboxResolver()
	client, cleanup := setupSSHTestWithSandboxes(t, mock, resolver)
	defer cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	rwc, err := client.Tunnel(ctx, "default", "my-sandbox", 22)
	require.NoError(t, err)
	require.NotNil(t, rwc)

	cancel()

	// Wait for the cleanup goroutine to complete its revocation.
	require.Eventually(t, func() bool {
		mock.mu.Lock()
		defer mock.mu.Unlock()
		for _, active := range mock.tokens {
			if !active {
				return true
			}
		}
		return false
	}, 5*time.Second, 10*time.Millisecond)

	// Explicit Close() after the cleanup goroutine already ran.
	err = rwc.Close()
	assert.NoError(t, err)

	mock.mu.Lock()
	count := mock.revokeCount
	mock.mu.Unlock()
	assert.Equal(t, 1, count, "exactly one revocation should occur (closeOnce idempotency)")
}

func TestSSHTunnel_CloseBeforeContextCancel(t *testing.T) {
	mock := newMockSSHServer()
	resolver := defaultSandboxResolver()
	client, cleanup := setupSSHTestWithSandboxes(t, mock, resolver)
	defer cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	rwc, err := client.Tunnel(ctx, "default", "my-sandbox", 22)
	require.NoError(t, err)
	require.NotNil(t, rwc)

	// Explicit Close() first (revokes the session).
	err = rwc.Close()
	require.NoError(t, err)

	// Cancel context after Close() already completed.
	cancel()

	// Verify the cleanup goroutine does not trigger a second revocation.
	require.Never(t, func() bool {
		mock.mu.Lock()
		defer mock.mu.Unlock()
		return mock.revokeCount > 1
	}, 200*time.Millisecond, 10*time.Millisecond, "cleanup goroutine should not revoke again")

	mock.mu.Lock()
	count := mock.revokeCount
	tokenRevoked := false
	for _, active := range mock.tokens {
		if !active {
			tokenRevoked = true
			break
		}
	}
	mock.mu.Unlock()

	assert.True(t, tokenRevoked, "session should be revoked")
	assert.Equal(t, 1, count, "exactly one revocation should occur")
}
