// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"

	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

type mockFileServer struct {
	pb.UnimplementedOpenShellServer
	createResp     *pb.CreateSshSessionResponse
	createErr      error
	revokeResp     *pb.RevokeSshSessionResponse
	revokeErr      error
	lastCreateReq  *pb.CreateSshSessionRequest
	lastRevokeReq  *pb.RevokeSshSessionRequest
	createCallCount int
	revokeCallCount int
}

func newMockFileServer() *mockFileServer {
	return &mockFileServer{}
}

func (s *mockFileServer) CreateSshSession(_ context.Context, req *pb.CreateSshSessionRequest) (*pb.CreateSshSessionResponse, error) { //nolint:revive // method name matches proto interface
	s.lastCreateReq = req
	s.createCallCount++
	if s.createErr != nil {
		return nil, s.createErr
	}
	return s.createResp, nil
}

func (s *mockFileServer) RevokeSshSession(_ context.Context, req *pb.RevokeSshSessionRequest) (*pb.RevokeSshSessionResponse, error) { //nolint:revive // method name matches proto interface
	s.lastRevokeReq = req
	s.revokeCallCount++
	if s.revokeErr != nil {
		return nil, s.revokeErr
	}
	return s.revokeResp, nil
}

func setupFileTest(t *testing.T, mock *mockFileServer) (*fileClient, func()) {
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

	return newFileClient(conn, &stubSandboxResolver{}), func() {
		_ = conn.Close()
		srv.Stop()
	}
}

// --- T051: Upload and Download tests ---

func TestFileUpload(t *testing.T) {
	mock := newMockFileServer()
	mock.createResp = &pb.CreateSshSessionResponse{
		SandboxId:   "sb-test-sandbox",
		Token:       "session-token-123",
		GatewayHost: "gateway.example.com",
		GatewayPort: 2222,
	}
	mock.revokeResp = &pb.RevokeSshSessionResponse{Revoked: true}
	client, cleanup := setupFileTest(t, mock)
	defer cleanup()

	tmpDir := t.TempDir()
	localPath := filepath.Join(tmpDir, "upload.txt")
	require.NoError(t, os.WriteFile(localPath, []byte("file content"), 0644))

	err := client.Upload(context.Background(), "test-sandbox", localPath, "/remote/upload.txt")

	// Upload will fail because there's no real SSH server, but it should
	// at least call CreateSshSession with the resolved sandbox ID
	// and attempt the transfer. The error is from the SSH connection, not the RPC.
	assert.Equal(t, "sb-test-sandbox", mock.lastCreateReq.GetSandboxId())
	assert.Equal(t, 1, mock.createCallCount)

	// We accept an error here since there's no real SSH server to connect to.
	// Integration tests will verify end-to-end transfer.
	_ = err
}

func TestFileUpload_CreateSessionError(t *testing.T) {
	mock := newMockFileServer()
	mock.createErr = status.Error(codes.NotFound, "sandbox not found")
	client, cleanup := setupFileTest(t, mock)
	defer cleanup()

	tmpDir := t.TempDir()
	localPath := filepath.Join(tmpDir, "upload.txt")
	require.NoError(t, os.WriteFile(localPath, []byte("content"), 0644))

	err := client.Upload(context.Background(), "test-sandbox", localPath, "/remote/file.txt")

	require.Error(t, err)
	assert.True(t, IsNotFound(err))
}

func TestFileDownload(t *testing.T) {
	mock := newMockFileServer()
	mock.createResp = &pb.CreateSshSessionResponse{
		SandboxId:   "sb-test-sandbox",
		Token:       "session-token-456",
		GatewayHost: "gateway.example.com",
		GatewayPort: 2222,
	}
	mock.revokeResp = &pb.RevokeSshSessionResponse{Revoked: true}
	client, cleanup := setupFileTest(t, mock)
	defer cleanup()

	tmpDir := t.TempDir()
	localPath := filepath.Join(tmpDir, "download.txt")

	err := client.Download(context.Background(), "test-sandbox", "/remote/file.txt", localPath)

	// Download will fail at SSH connection (no real server), but should
	// call CreateSshSession with the resolved sandbox ID.
	assert.Equal(t, "sb-test-sandbox", mock.lastCreateReq.GetSandboxId())
	assert.Equal(t, 1, mock.createCallCount)

	_ = err
}

func TestFileDownload_CreateSessionError(t *testing.T) {
	mock := newMockFileServer()
	mock.createErr = status.Error(codes.PermissionDenied, "access denied")
	client, cleanup := setupFileTest(t, mock)
	defer cleanup()

	tmpDir := t.TempDir()
	localPath := filepath.Join(tmpDir, "download.txt")

	err := client.Download(context.Background(), "test-sandbox", "/remote/file.txt", localPath)

	require.Error(t, err)
	assert.True(t, IsPermissionDenied(err))
}

// --- T052: Upload error cases ---

func TestFileUpload_NonExistentLocalFile(t *testing.T) {
	mock := newMockFileServer()
	client, cleanup := setupFileTest(t, mock)
	defer cleanup()

	err := client.Upload(context.Background(), "test-sandbox", "/nonexistent/file.txt", "/remote/file.txt")

	require.Error(t, err)
	// Should fail before contacting gateway
	assert.Equal(t, 0, mock.createCallCount)
}

func TestFileUpload_LocalPathIsDirectory(t *testing.T) {
	mock := newMockFileServer()
	client, cleanup := setupFileTest(t, mock)
	defer cleanup()

	tmpDir := t.TempDir()

	err := client.Upload(context.Background(), "test-sandbox", tmpDir, "/remote/file.txt")

	require.Error(t, err)
	// Should fail before contacting gateway
	assert.Equal(t, 0, mock.createCallCount)
}

func TestFileUpload_EmptySandboxName(t *testing.T) {
	mock := newMockFileServer()
	client, cleanup := setupFileTest(t, mock)
	defer cleanup()

	tmpDir := t.TempDir()
	localPath := filepath.Join(tmpDir, "file.txt")
	require.NoError(t, os.WriteFile(localPath, []byte("content"), 0644))

	err := client.Upload(context.Background(), "", localPath, "/remote/file.txt")

	require.Error(t, err)
	assert.Equal(t, 0, mock.createCallCount)
}

func TestFileDownload_EmptyRemotePath(t *testing.T) {
	mock := newMockFileServer()
	client, cleanup := setupFileTest(t, mock)
	defer cleanup()

	tmpDir := t.TempDir()
	localPath := filepath.Join(tmpDir, "download.txt")

	err := client.Download(context.Background(), "test-sandbox", "", localPath)

	require.Error(t, err)
	assert.Equal(t, 0, mock.createCallCount)
}

// --- Name-to-ID resolution tests ---

func TestFileUpload_ResolvesNameToID(t *testing.T) {
	mock := newMockFileServer()
	mock.createResp = &pb.CreateSshSessionResponse{
		SandboxId:   "sb-my-sandbox",
		Token:       "token",
		GatewayHost: "gw.example.com",
		GatewayPort: 2222,
	}
	mock.revokeResp = &pb.RevokeSshSessionResponse{Revoked: true}
	client, cleanup := setupFileTest(t, mock)
	defer cleanup()

	tmpDir := t.TempDir()
	localPath := filepath.Join(tmpDir, "upload.txt")
	require.NoError(t, os.WriteFile(localPath, []byte("content"), 0644))

	_ = client.Upload(context.Background(), "my-sandbox", localPath, "/remote/file.txt")

	// Verify the proto request contains the resolved ID, not the name
	assert.Equal(t, "sb-my-sandbox", mock.lastCreateReq.GetSandboxId())
}

func TestFileUpload_ResolutionError(t *testing.T) {
	mock := newMockFileServer()
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
	client := newFileClient(conn, resolver)

	tmpDir := t.TempDir()
	localPath := filepath.Join(tmpDir, "upload.txt")
	require.NoError(t, os.WriteFile(localPath, []byte("content"), 0644))

	err = client.Upload(context.Background(), "nonexistent", localPath, "/remote/file.txt")
	require.Error(t, err)
	assert.True(t, IsNotFound(err))
	assert.Equal(t, 0, mock.createCallCount)
}

func TestFileDownload_ResolvesNameToID(t *testing.T) {
	mock := newMockFileServer()
	client, cleanup := setupFileTest(t, mock)
	defer cleanup()

	localPath := filepath.Join(t.TempDir(), "downloaded.txt")
	_ = client.Download(context.Background(), "my-sandbox", "/remote/file.txt", localPath)

	assert.Equal(t, "sb-my-sandbox", mock.lastCreateReq.GetSandboxId())
}

func TestFileDownload_ResolutionError(t *testing.T) {
	mock := newMockFileServer()
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
	client := newFileClient(conn, resolver)

	localPath := filepath.Join(t.TempDir(), "downloaded.txt")
	err = client.Download(context.Background(), "nonexistent", "/remote/file.txt", localPath)
	require.Error(t, err)
	assert.True(t, IsNotFound(err))
	assert.Equal(t, 0, mock.createCallCount)
}
