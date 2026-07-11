// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"
	"net"
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

const bufSize = 1024 * 1024

type mockHealthServer struct {
	pb.UnimplementedOpenShellServer
	status  pb.ServiceStatus
	version string
	err     error
}

func (s *mockHealthServer) Health(_ context.Context, _ *pb.HealthRequest) (*pb.HealthResponse, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &pb.HealthResponse{
		Status:  s.status,
		Version: s.version,
	}, nil
}

func newMockHealthServer(s pb.ServiceStatus, version string, err error) (*grpc.ClientConn, func()) {
	lis := bufconn.Listen(bufSize)
	srv := grpc.NewServer()
	pb.RegisterOpenShellServer(srv, &mockHealthServer{status: s, version: version, err: err})

	go func() { _ = srv.Serve(lis) }()

	conn, err2 := grpc.NewClient("passthrough:///bufconn",
		grpc.WithContextDialer(func(_ context.Context, _ string) (net.Conn, error) {
			return lis.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)

	if err2 != nil {
		srv.Stop()
		panic("grpc.NewClient failed: " + err2.Error())
	}

	return conn, func() {
		_ = conn.Close()
		srv.Stop()
	}
}

func TestHealthCheck_Success(t *testing.T) {
	conn, cleanup := newMockHealthServer(pb.ServiceStatus_SERVICE_STATUS_HEALTHY, "1.2.3", nil)
	defer cleanup()

	h := newHealthClient(conn)
	result, err := h.Check(context.Background())

	require.NoError(t, err)
	assert.True(t, result.Healthy)
	assert.Equal(t, "1.2.3", result.Version)
}

func TestHealthCheck_Degraded(t *testing.T) {
	conn, cleanup := newMockHealthServer(pb.ServiceStatus_SERVICE_STATUS_DEGRADED, "2.0.0", nil)
	defer cleanup()

	h := newHealthClient(conn)
	result, err := h.Check(context.Background())

	require.NoError(t, err)
	assert.False(t, result.Healthy)
	assert.Equal(t, "2.0.0", result.Version)
}

func TestHealthCheck_Unhealthy(t *testing.T) {
	conn, cleanup := newMockHealthServer(pb.ServiceStatus_SERVICE_STATUS_UNHEALTHY, "3.0.0", nil)
	defer cleanup()

	h := newHealthClient(conn)
	result, err := h.Check(context.Background())

	require.NoError(t, err)
	assert.False(t, result.Healthy)
	assert.Equal(t, "3.0.0", result.Version)
}

func TestHealthCheck_Unavailable(t *testing.T) {
	conn, cleanup := newMockHealthServer(0, "", status.Error(codes.Unavailable, "service down"))
	defer cleanup()

	h := newHealthClient(conn)
	_, err := h.Check(context.Background())

	require.Error(t, err)
	assert.True(t, IsUnavailable(err))
}
