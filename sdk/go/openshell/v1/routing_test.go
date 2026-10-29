// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"

	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

// routingServer reports owner from GetSandbox and records the replica header
// of every streaming call ("" when unrouted). Routed calls fail with routedErr.
type routingServer struct {
	pb.UnimplementedOpenShellServer
	owner     string
	routedErr error

	mu       sync.Mutex
	wantedBy []string
	routes   []string
}

func (s *routingServer) GetSandbox(ctx context.Context, _ *pb.GetSandboxRequest) (*pb.SandboxResponse, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	s.mu.Lock()
	s.wantedBy = append(s.wantedBy, firstValue(md, ownerRequestHeader))
	s.mu.Unlock()
	if s.owner != "" {
		_ = grpc.SetHeader(ctx, metadata.Pairs(ownerReplicaHeader, s.owner))
	}
	return &pb.SandboxResponse{Sandbox: &pb.Sandbox{}}, nil
}

// route records the call and returns the error a routed call should fail with.
func (s *routingServer) route(ctx context.Context) error {
	md, _ := metadata.FromIncomingContext(ctx)
	replica := firstValue(md, routeReplicaHeader)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.routes = append(s.routes, replica)
	if replica != "" {
		return s.routedErr
	}
	return nil
}

func (s *routingServer) ExecSandbox(_ *pb.ExecSandboxRequest, stream grpc.ServerStreamingServer[pb.ExecSandboxEvent]) error {
	if err := s.route(stream.Context()); err != nil {
		return err
	}
	return stream.Send(exitEvent())
}

func (s *routingServer) ExecSandboxInteractive(stream grpc.BidiStreamingServer[pb.ExecSandboxInput, pb.ExecSandboxEvent]) error {
	if _, err := stream.Recv(); err != nil {
		return err
	}
	if err := s.route(stream.Context()); err != nil {
		return err
	}
	return stream.Send(exitEvent())
}

func (s *routingServer) ForwardTcp(stream grpc.BidiStreamingServer[pb.TcpForwardFrame, pb.TcpForwardFrame]) error { //nolint:revive // proto-generated method name
	if _, err := stream.Recv(); err != nil {
		return err
	}
	if err := s.route(stream.Context()); err != nil {
		return err
	}
	return stream.Send(&pb.TcpForwardFrame{Payload: &pb.TcpForwardFrame_Data{Data: []byte("pong")}})
}

func exitEvent() *pb.ExecSandboxEvent {
	return &pb.ExecSandboxEvent{Payload: &pb.ExecSandboxEvent_Exit{Exit: &pb.ExecSandboxExit{}}}
}

func firstValue(md metadata.MD, key string) string {
	if v := md.Get(key); len(v) > 0 {
		return v[0]
	}
	return ""
}

func routingClients(t *testing.T, srv *routingServer) (*execClient, *tcpClient) {
	t.Helper()
	lis := bufconn.Listen(bufSize)
	gs := grpc.NewServer()
	pb.RegisterOpenShellServer(gs, srv)
	go func() { _ = gs.Serve(lis) }()
	conn, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = conn.Close()
		gs.Stop()
	})
	sandboxes := newSandboxClient(conn)
	return newExecClient(conn, sandboxes), newTCPClient(conn, sandboxes, nil)
}

func TestExecRoutesToOwner(t *testing.T) {
	srv := &routingServer{owner: "openshell-1"}
	exec, _ := routingClients(t, srv)

	_, err := exec.Run(context.Background(), "default", "box", []string{"true"})
	require.NoError(t, err)

	assert.Equal(t, []string{"1"}, srv.wantedBy)
	assert.Equal(t, []string{"openshell-1"}, srv.routes)
}

func TestExecWithoutOwnerIsUnrouted(t *testing.T) {
	srv := &routingServer{}
	exec, _ := routingClients(t, srv)

	_, err := exec.Run(context.Background(), "default", "box", []string{"true"})
	require.NoError(t, err)

	assert.Equal(t, []string{""}, srv.routes)
}

func TestRoutedCallsRetryOnceWithoutHintWhenOwnerHasNoEndpoints(t *testing.T) {
	srv := &routingServer{owner: "openshell-1", routedErr: status.Error(codes.Unavailable, "")}
	exec, tcp := routingClients(t, srv)
	ctx := context.Background()

	_, err := exec.Run(ctx, "default", "box", []string{"true"})
	require.NoError(t, err)

	stream, err := exec.Stream(ctx, "default", "box", []string{"true"})
	require.NoError(t, err)
	code, err := stream.ExitCode()
	require.NoError(t, err)
	assert.Zero(t, code)

	session, err := exec.Interactive(ctx, "default", "box", []string{"sh"}, 80, 24)
	require.NoError(t, err)
	_, err = session.ExitCode()
	require.NoError(t, err)

	conn, err := tcp.Forward(ctx, "default", "box", 8080)
	require.NoError(t, err)
	buf := make([]byte, 4)
	_, err = io.ReadFull(conn, buf)
	require.NoError(t, err)
	assert.Equal(t, "pong", string(buf))
	_ = conn.Close()

	// Each call is attempted routed, then once unrouted.
	assert.Equal(t, []string{
		"openshell-1", "", "openshell-1", "", "openshell-1", "", "openshell-1", "",
	}, srv.routes)
}

func TestRoutedCallDoesNotRetryOnGatewayError(t *testing.T) {
	srv := &routingServer{owner: "openshell-1", routedErr: status.Error(codes.Unavailable, "supervisor not connected")}
	exec, tcp := routingClients(t, srv)
	ctx := context.Background()

	_, err := exec.Run(ctx, "default", "box", []string{"true"})
	require.Error(t, err)
	_, err = tcp.Forward(ctx, "default", "box", 8080)
	require.Error(t, err)

	assert.Equal(t, []string{"openshell-1", "openshell-1"}, srv.routes)
}

func TestRetryUnrouted(t *testing.T) {
	assert.True(t, retryUnrouted(status.Error(codes.Unavailable, "")))
	assert.True(t, retryUnrouted(status.Error(codes.Unavailable, "no healthy upstream")))
	assert.True(t, retryUnrouted(status.Error(codes.Unavailable, "upstream connect error: connection failure")))
	assert.False(t, retryUnrouted(status.Error(codes.Unavailable, "supervisor not connected")))
	assert.False(t, retryUnrouted(status.Error(codes.NotFound, "")))
	assert.False(t, retryUnrouted(io.EOF))
	assert.False(t, retryUnrouted(nil))
}
