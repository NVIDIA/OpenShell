// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"
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

// stubSandboxResolver implements SandboxInterface for testing name-to-ID resolution.
// Get returns a Sandbox with ID = "sb-" + name. All other methods panic.
type stubSandboxResolver struct {
	getErr error // if non-nil, Get returns this error
}

func (r *stubSandboxResolver) Get(_ context.Context, _, name string) (*Sandbox, error) {
	if r.getErr != nil {
		return nil, r.getErr
	}
	return &Sandbox{ID: "sb-" + name, Name: name}, nil
}

func (r *stubSandboxResolver) Create(context.Context, string, string, *SandboxSpec, map[string]string, ...CreateOptions) (*Sandbox, error) {
	panic("not implemented")
}
func (r *stubSandboxResolver) List(context.Context, string, ...ListOptions) ([]*Sandbox, error) {
	panic("not implemented")
}
func (r *stubSandboxResolver) Delete(context.Context, string, string) error {
	panic("not implemented")
}
func (r *stubSandboxResolver) AttachProvider(context.Context, string, string, string, uint64) (*AttachProviderResult, error) {
	panic("not implemented")
}
func (r *stubSandboxResolver) DetachProvider(context.Context, string, string, string, uint64) (*DetachProviderResult, error) {
	panic("not implemented")
}
func (r *stubSandboxResolver) ListProviders(context.Context, string, string) ([]*Provider, error) {
	panic("not implemented")
}
func (r *stubSandboxResolver) WaitReady(context.Context, string, string, ...WaitOptions) (*Sandbox, error) {
	panic("not implemented")
}
func (r *stubSandboxResolver) Watch(context.Context, string, string, ...WatchOptions) (WatchInterface[*Sandbox], error) {
	panic("not implemented")
}
func (r *stubSandboxResolver) GetLogs(context.Context, string, string, ...LogOption) (*LogResult, error) {
	panic("not implemented")
}
func (r *stubSandboxResolver) Stop(context.Context, string, string) (*Sandbox, error) {
	panic("not implemented")
}
func (r *stubSandboxResolver) Start(context.Context, string, string) (*Sandbox, error) {
	panic("not implemented")
}
func (r *stubSandboxResolver) WaitStopped(context.Context, string, string, ...WaitOptions) (*Sandbox, error) {
	panic("not implemented")
}

type mockExecServer struct {
	pb.UnimplementedOpenShellServer
	mu              sync.Mutex
	execEvents      []*pb.ExecSandboxEvent
	execErr         error
	lastExecRequest *pb.ExecSandboxRequest

	interactiveEvents    []*pb.ExecSandboxEvent
	interactiveErr       error
	interactiveWaitInput bool
	interactiveBlock     bool
	receivedInputs       []*pb.ExecSandboxInput
}

func newMockExecServer() *mockExecServer {
	return &mockExecServer{}
}

func (s *mockExecServer) ExecSandbox(req *pb.ExecSandboxRequest, stream grpc.ServerStreamingServer[pb.ExecSandboxEvent]) error {
	s.mu.Lock()
	s.lastExecRequest = req
	events := make([]*pb.ExecSandboxEvent, len(s.execEvents))
	copy(events, s.execEvents)
	execErr := s.execErr
	s.mu.Unlock()

	if execErr != nil {
		return execErr
	}

	for _, ev := range events {
		if err := stream.Send(ev); err != nil {
			return err
		}
	}
	return nil
}

func (s *mockExecServer) ExecSandboxInteractive(stream grpc.BidiStreamingServer[pb.ExecSandboxInput, pb.ExecSandboxEvent]) error {
	s.mu.Lock()
	interactiveErr := s.interactiveErr
	interactiveBlock := s.interactiveBlock
	events := make([]*pb.ExecSandboxEvent, len(s.interactiveEvents))
	copy(events, s.interactiveEvents)
	s.mu.Unlock()

	if interactiveErr != nil {
		return interactiveErr
	}

	// Read the start message
	startMsg, err := stream.Recv()
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.receivedInputs = append(s.receivedInputs, startMsg)
	s.mu.Unlock()
	if interactiveBlock {
		<-stream.Context().Done()
		return stream.Context().Err()
	}

	s.mu.Lock()
	waitInput := s.interactiveWaitInput
	s.mu.Unlock()

	if waitInput {
		msg, recvErr := stream.Recv()
		if recvErr != nil {
			return recvErr
		}
		s.mu.Lock()
		s.receivedInputs = append(s.receivedInputs, msg)
		s.mu.Unlock()
	}

	// Read subsequent messages until client closes, collecting them
	go func() {
		for {
			msg, recvErr := stream.Recv()
			if recvErr != nil {
				return
			}
			s.mu.Lock()
			s.receivedInputs = append(s.receivedInputs, msg)
			s.mu.Unlock()
		}
	}()

	// Send canned events
	for _, ev := range events {
		if err := stream.Send(ev); err != nil {
			return err
		}
	}
	return nil
}

func setupExecTest(t *testing.T, mock *mockExecServer) (*execClient, func()) {
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

	return newExecClient(conn, &stubSandboxResolver{}), func() {
		_ = conn.Close()
		srv.Stop()
	}
}

// --- T043: Run and Stream tests ---

func TestExecRun(t *testing.T) {
	mock := newMockExecServer()
	mock.execEvents = []*pb.ExecSandboxEvent{
		{Payload: &pb.ExecSandboxEvent_Stdout{Stdout: &pb.ExecSandboxStdout{Data: []byte("hello ")}}},
		{Payload: &pb.ExecSandboxEvent_Stdout{Stdout: &pb.ExecSandboxStdout{Data: []byte("world\n")}}},
		{Payload: &pb.ExecSandboxEvent_Stderr{Stderr: &pb.ExecSandboxStderr{Data: []byte("warn\n")}}},
		{Payload: &pb.ExecSandboxEvent_Exit{Exit: &pb.ExecSandboxExit{ExitCode: 0}}},
	}
	client, cleanup := setupExecTest(t, mock)
	defer cleanup()

	result, err := client.Run(context.Background(), "default", "test-sandbox", []string{"echo", "hello", "world"})

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, 0, result.ExitCode)
	assert.Equal(t, []byte("hello world\n"), result.Stdout)
	assert.Equal(t, []byte("warn\n"), result.Stderr)
}

func TestExecRun_WithOptions(t *testing.T) {
	mock := newMockExecServer()
	mock.execEvents = []*pb.ExecSandboxEvent{
		{Payload: &pb.ExecSandboxEvent_Exit{Exit: &pb.ExecSandboxExit{ExitCode: 0}}},
	}
	client, cleanup := setupExecTest(t, mock)
	defer cleanup()

	opts := ExecOptions{
		Env:     map[string]string{"FOO": "bar"},
		WorkDir: "/tmp",
	}
	result, err := client.Run(context.Background(), "default", "test-sandbox", []string{"ls"}, opts)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, 0, result.ExitCode)

	mock.mu.Lock()
	defer mock.mu.Unlock()
	assert.Equal(t, "sb-test-sandbox", mock.lastExecRequest.GetSandboxId())
	assert.Equal(t, []string{"ls"}, mock.lastExecRequest.GetCommand())
	assert.Equal(t, "/tmp", mock.lastExecRequest.GetWorkdir())
	assert.Equal(t, map[string]string{"FOO": "bar"}, mock.lastExecRequest.GetEnvironment())
}

func TestExecRun_NonZeroExit(t *testing.T) {
	mock := newMockExecServer()
	mock.execEvents = []*pb.ExecSandboxEvent{
		{Payload: &pb.ExecSandboxEvent_Stderr{Stderr: &pb.ExecSandboxStderr{Data: []byte("fail\n")}}},
		{Payload: &pb.ExecSandboxEvent_Exit{Exit: &pb.ExecSandboxExit{ExitCode: 1}}},
	}
	client, cleanup := setupExecTest(t, mock)
	defer cleanup()

	result, err := client.Run(context.Background(), "default", "test-sandbox", []string{"false"})

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, 1, result.ExitCode)
	assert.Empty(t, result.Stdout)
	assert.Equal(t, []byte("fail\n"), result.Stderr)
}

func TestExecRun_ServerError(t *testing.T) {
	mock := newMockExecServer()
	mock.execErr = status.Error(codes.NotFound, "sandbox not found")
	client, cleanup := setupExecTest(t, mock)
	defer cleanup()

	_, err := client.Run(context.Background(), "default", "missing-sandbox", []string{"ls"})

	require.Error(t, err)
	assert.True(t, IsNotFound(err))
}

func TestExecStream(t *testing.T) {
	mock := newMockExecServer()
	mock.execEvents = []*pb.ExecSandboxEvent{
		{Payload: &pb.ExecSandboxEvent_Stdout{Stdout: &pb.ExecSandboxStdout{Data: []byte("line1\n")}}},
		{Payload: &pb.ExecSandboxEvent_Stderr{Stderr: &pb.ExecSandboxStderr{Data: []byte("err1\n")}}},
		{Payload: &pb.ExecSandboxEvent_Stdout{Stdout: &pb.ExecSandboxStdout{Data: []byte("line2\n")}}},
		{Payload: &pb.ExecSandboxEvent_Exit{Exit: &pb.ExecSandboxExit{ExitCode: 42}}},
	}
	client, cleanup := setupExecTest(t, mock)
	defer cleanup()

	stream, err := client.Stream(context.Background(), "default", "test-sandbox", []string{"cat"})
	require.NoError(t, err)
	require.NotNil(t, stream)
	defer func() { _ = stream.Close() }()

	chunk1, err := stream.Next()
	require.NoError(t, err)
	assert.Equal(t, StreamStdout, chunk1.Stream)
	assert.Equal(t, []byte("line1\n"), chunk1.Data)

	chunk2, err := stream.Next()
	require.NoError(t, err)
	assert.Equal(t, StreamStderr, chunk2.Stream)
	assert.Equal(t, []byte("err1\n"), chunk2.Data)

	chunk3, err := stream.Next()
	require.NoError(t, err)
	assert.Equal(t, StreamStdout, chunk3.Stream)
	assert.Equal(t, []byte("line2\n"), chunk3.Data)

	// Next call after exit should return io.EOF
	_, err = stream.Next()
	assert.ErrorIs(t, err, io.EOF)

	exitCode, err := stream.ExitCode()
	require.NoError(t, err)
	assert.Equal(t, 42, exitCode)
}

func TestExecStream_ServerError(t *testing.T) {
	mock := newMockExecServer()
	mock.execErr = status.Error(codes.Internal, "internal error")
	client, cleanup := setupExecTest(t, mock)
	defer cleanup()

	stream, err := client.Stream(context.Background(), "default", "test-sandbox", []string{"ls"})
	if err != nil {
		var se *StatusError
		require.ErrorAs(t, err, &se)
		assert.Equal(t, ErrorInternal, se.Code)
		return
	}
	_, err = stream.Next()
	require.Error(t, err)
}

func TestExecStream_EmptyOutput(t *testing.T) {
	mock := newMockExecServer()
	mock.execEvents = []*pb.ExecSandboxEvent{
		{Payload: &pb.ExecSandboxEvent_Exit{Exit: &pb.ExecSandboxExit{ExitCode: 0}}},
	}
	client, cleanup := setupExecTest(t, mock)
	defer cleanup()

	stream, err := client.Stream(context.Background(), "default", "test-sandbox", []string{"true"})
	require.NoError(t, err)
	defer func() { _ = stream.Close() }()

	_, err = stream.Next()
	assert.ErrorIs(t, err, io.EOF)

	exitCode, err := stream.ExitCode()
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)
}

// --- T044: Interactive session tests ---

func TestExecInteractive(t *testing.T) {
	mock := newMockExecServer()
	mock.interactiveEvents = []*pb.ExecSandboxEvent{
		{Payload: &pb.ExecSandboxEvent_Stdout{Stdout: &pb.ExecSandboxStdout{Data: []byte("$ ")}}},
		{Payload: &pb.ExecSandboxEvent_Stdout{Stdout: &pb.ExecSandboxStdout{Data: []byte("output\n")}}},
		{Payload: &pb.ExecSandboxEvent_Exit{Exit: &pb.ExecSandboxExit{ExitCode: 0}}},
	}
	client, cleanup := setupExecTest(t, mock)
	defer cleanup()

	session, err := client.Interactive(context.Background(), "default", "test-sandbox", []string{"/bin/bash"}, 80, 24)
	require.NoError(t, err)
	require.NotNil(t, session)
	defer func() { _ = session.Close() }()

	// Read output
	buf := make([]byte, 1024)
	n, err := session.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, "$ ", string(buf[:n]))

	// Verify start message was received
	mock.mu.Lock()
	require.GreaterOrEqual(t, len(mock.receivedInputs), 1)
	startInput := mock.receivedInputs[0]
	mock.mu.Unlock()

	startReq := startInput.GetStart()
	require.NotNil(t, startReq)
	assert.Equal(t, "sb-test-sandbox", startReq.GetSandboxId())
	assert.Equal(t, []string{"/bin/bash"}, startReq.GetCommand())
	assert.True(t, startReq.GetTty())
	assert.Equal(t, uint32(80), startReq.GetCols())
	assert.Equal(t, uint32(24), startReq.GetRows())
}

func TestExecInteractive_CloseCancelsReceiveStream(t *testing.T) {
	mock := newMockExecServer()
	mock.interactiveBlock = true
	client, cleanup := setupExecTest(t, mock)
	defer cleanup()

	session, err := client.Interactive(context.Background(), "default", "test-sandbox", []string{"/bin/sh"}, 80, 24)
	require.NoError(t, err)

	closed := make(chan error, 1)
	go func() { closed <- session.Close() }()

	select {
	case err := <-closed:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("InteractiveSession.Close did not cancel the receive stream")
	}
}

func TestExecInteractive_Write(t *testing.T) {
	mock := newMockExecServer()
	mock.interactiveWaitInput = true
	mock.interactiveEvents = []*pb.ExecSandboxEvent{
		{Payload: &pb.ExecSandboxEvent_Stdout{Stdout: &pb.ExecSandboxStdout{Data: []byte("$ ")}}},
		{Payload: &pb.ExecSandboxEvent_Exit{Exit: &pb.ExecSandboxExit{ExitCode: 0}}},
	}
	client, cleanup := setupExecTest(t, mock)
	defer cleanup()

	session, err := client.Interactive(context.Background(), "default", "test-sandbox", []string{"/bin/sh"}, 80, 24)
	require.NoError(t, err)
	defer func() { _ = session.Close() }()

	n, err := session.Write([]byte("ls\n"))
	require.NoError(t, err)
	assert.Equal(t, 3, n)
}

func TestExecInteractive_Resize(t *testing.T) {
	mock := newMockExecServer()
	mock.interactiveWaitInput = true
	mock.interactiveEvents = []*pb.ExecSandboxEvent{
		{Payload: &pb.ExecSandboxEvent_Stdout{Stdout: &pb.ExecSandboxStdout{Data: []byte("$ ")}}},
		{Payload: &pb.ExecSandboxEvent_Exit{Exit: &pb.ExecSandboxExit{ExitCode: 0}}},
	}
	client, cleanup := setupExecTest(t, mock)
	defer cleanup()

	session, err := client.Interactive(context.Background(), "default", "test-sandbox", []string{"/bin/sh"}, 80, 24)
	require.NoError(t, err)
	defer func() { _ = session.Close() }()

	err = session.Resize(120, 40)
	require.NoError(t, err)
}

func TestExecInteractive_ServerError(t *testing.T) {
	mock := newMockExecServer()
	mock.interactiveErr = status.Error(codes.PermissionDenied, "not allowed")
	client, cleanup := setupExecTest(t, mock)
	defer cleanup()

	session, err := client.Interactive(context.Background(), "default", "test-sandbox", []string{"/bin/sh"}, 80, 24)
	if err != nil {
		assert.True(t, IsPermissionDenied(err), "expected permission denied, got: %v", err)
		return
	}
	buf := make([]byte, 1024)
	_, err = session.Read(buf)
	require.Error(t, err)
}

func TestExecInteractive_ExitCode(t *testing.T) {
	mock := newMockExecServer()
	mock.interactiveEvents = []*pb.ExecSandboxEvent{
		{Payload: &pb.ExecSandboxEvent_Stdout{Stdout: &pb.ExecSandboxStdout{Data: []byte("done\n")}}},
		{Payload: &pb.ExecSandboxEvent_Exit{Exit: &pb.ExecSandboxExit{ExitCode: 130}}},
	}
	client, cleanup := setupExecTest(t, mock)
	defer cleanup()

	session, err := client.Interactive(context.Background(), "default", "test-sandbox", []string{"/bin/sh"}, 80, 24)
	require.NoError(t, err)

	// Drain output
	buf := make([]byte, 1024)
	for {
		_, readErr := session.Read(buf)
		if readErr != nil {
			break
		}
	}

	exitCode, err := session.ExitCode()
	require.NoError(t, err)
	assert.Equal(t, 130, exitCode)

	_ = session.Close()
}

func TestExecInteractive_ConcurrentReadAndExitCode(t *testing.T) {
	mock := newMockExecServer()
	mock.interactiveEvents = []*pb.ExecSandboxEvent{
		{Payload: &pb.ExecSandboxEvent_Stdout{Stdout: &pb.ExecSandboxStdout{Data: []byte("line1\n")}}},
		{Payload: &pb.ExecSandboxEvent_Stdout{Stdout: &pb.ExecSandboxStdout{Data: []byte("line2\n")}}},
		{Payload: &pb.ExecSandboxEvent_Stdout{Stdout: &pb.ExecSandboxStdout{Data: []byte("line3\n")}}},
		{Payload: &pb.ExecSandboxEvent_Exit{Exit: &pb.ExecSandboxExit{ExitCode: 0}}},
	}

	client, cleanup := setupExecTest(t, mock)
	defer cleanup()

	session, err := client.Interactive(context.Background(), "default", "test-sandbox", []string{"sh"}, 80, 24)
	require.NoError(t, err)

	var wg sync.WaitGroup
	var readData []byte
	var readErr error

	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 1024)
		for {
			n, err := session.Read(buf)
			if err != nil {
				readErr = err
				return
			}
			readData = append(readData, buf[:n]...)
		}
	}()

	exitCode, exitErr := session.ExitCode()
	wg.Wait()

	require.NoError(t, exitErr)
	assert.Equal(t, 0, exitCode)
	assert.Equal(t, io.EOF, readErr)
	assert.Contains(t, string(readData), "line1\n")
}

// --- Name-to-ID resolution tests ---

func TestExecRun_ResolvesNameToID(t *testing.T) {
	mock := newMockExecServer()
	mock.execEvents = []*pb.ExecSandboxEvent{
		{Payload: &pb.ExecSandboxEvent_Exit{Exit: &pb.ExecSandboxExit{ExitCode: 0}}},
	}
	client, cleanup := setupExecTest(t, mock)
	defer cleanup()

	_, err := client.Run(context.Background(), "default", "my-sandbox", []string{"echo", "hi"})
	require.NoError(t, err)

	mock.mu.Lock()
	defer mock.mu.Unlock()
	// Verify the proto request contains the resolved ID, not the name
	assert.Equal(t, "sb-my-sandbox", mock.lastExecRequest.GetSandboxId())
}

func TestExecRun_ResolutionError(t *testing.T) {
	resolver := &stubSandboxResolver{
		getErr: &StatusError{Code: ErrorNotFound, Message: "sandbox not found"},
	}
	client := newExecClient(stubConn(t), resolver)

	_, err := client.Run(context.Background(), "default", "nonexistent", []string{"ls"})
	require.Error(t, err)
	assert.True(t, IsNotFound(err))
}

func TestExecStream_ResolvesNameToID(t *testing.T) {
	mock := newMockExecServer()
	mock.execEvents = []*pb.ExecSandboxEvent{
		{Payload: &pb.ExecSandboxEvent_Exit{Exit: &pb.ExecSandboxExit{ExitCode: 0}}},
	}
	client, cleanup := setupExecTest(t, mock)
	defer cleanup()

	stream, err := client.Stream(context.Background(), "default", "my-sandbox", []string{"echo"})
	require.NoError(t, err)

	_, _ = stream.ExitCode()
	_ = stream.Close()

	mock.mu.Lock()
	defer mock.mu.Unlock()
	assert.Equal(t, "sb-my-sandbox", mock.lastExecRequest.GetSandboxId())
}

func TestExecStream_ResolutionError(t *testing.T) {
	resolver := &stubSandboxResolver{
		getErr: &StatusError{Code: ErrorNotFound, Message: "sandbox not found"},
	}
	client := newExecClient(stubConn(t), resolver)

	_, err := client.Stream(context.Background(), "default", "nonexistent", []string{"ls"})
	require.Error(t, err)
	assert.True(t, IsNotFound(err))
}

func TestExecInteractive_ResolvesNameToID(t *testing.T) {
	mock := newMockExecServer()
	mock.interactiveEvents = []*pb.ExecSandboxEvent{
		{Payload: &pb.ExecSandboxEvent_Exit{Exit: &pb.ExecSandboxExit{ExitCode: 0}}},
	}
	client, cleanup := setupExecTest(t, mock)
	defer cleanup()

	session, err := client.Interactive(context.Background(), "default", "my-sandbox", []string{"/bin/sh"}, 80, 24)
	require.NoError(t, err)

	_, _ = session.ExitCode()
	_ = session.Close()

	mock.mu.Lock()
	defer mock.mu.Unlock()
	require.NotEmpty(t, mock.receivedInputs)
	startReq := mock.receivedInputs[0].GetStart()
	require.NotNil(t, startReq)
	assert.Equal(t, "sb-my-sandbox", startReq.GetSandboxId())
}

func TestExecInteractive_ResolutionError(t *testing.T) {
	resolver := &stubSandboxResolver{
		getErr: &StatusError{Code: ErrorNotFound, Message: "sandbox not found"},
	}
	client := newExecClient(stubConn(t), resolver)

	_, err := client.Interactive(context.Background(), "default", "nonexistent", []string{"/bin/sh"}, 80, 24)
	require.Error(t, err)
	assert.True(t, IsNotFound(err))
}

func TestExecRun_EmptySandboxName(t *testing.T) {
	client := newExecClient(stubConn(t), &stubSandboxResolver{})
	_, err := client.Run(context.Background(), "default", "", []string{"ls"})
	require.Error(t, err)
	assert.True(t, IsInvalidArgument(err))
}

func TestExecStream_EmptySandboxName(t *testing.T) {
	client := newExecClient(stubConn(t), &stubSandboxResolver{})
	_, err := client.Stream(context.Background(), "default", "", []string{"ls"})
	require.Error(t, err)
	assert.True(t, IsInvalidArgument(err))
}

func TestExecInteractive_EmptySandboxName(t *testing.T) {
	client := newExecClient(stubConn(t), &stubSandboxResolver{})
	_, err := client.Interactive(context.Background(), "default", "", []string{"/bin/sh"}, 80, 24)
	require.Error(t, err)
	assert.True(t, IsInvalidArgument(err))
}

// stubConn creates a minimal gRPC connection for resolution-error tests
// where the RPC is never reached.
func stubConn(t *testing.T) *grpc.ClientConn {
	t.Helper()
	lis := bufconn.Listen(bufSize)
	srv := grpc.NewServer()
	pb.RegisterOpenShellServer(srv, newMockExecServer())
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(func() { srv.Stop() })

	conn, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithContextDialer(func(_ context.Context, _ string) (net.Conn, error) {
			return lis.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}
