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
	status          pb.ServiceStatus
	version         string
	err             error
	gatewayInfoResp *pb.GetGatewayInfoResponse
	currentUserResp *pb.GetCurrentUserResponse
	gatewayInfoErr  error
	currentUserErr  error
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

func (s *mockHealthServer) GetGatewayInfo(_ context.Context, _ *pb.GetGatewayInfoRequest) (*pb.GetGatewayInfoResponse, error) {
	if s.gatewayInfoErr != nil {
		return nil, s.gatewayInfoErr
	}
	return s.gatewayInfoResp, nil
}

func (s *mockHealthServer) GetCurrentUser(_ context.Context, _ *pb.GetCurrentUserRequest) (*pb.GetCurrentUserResponse, error) {
	if s.currentUserErr != nil {
		return nil, s.currentUserErr
	}
	return s.currentUserResp, nil
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

func newMockGatewayInfoServer(resp *pb.GetGatewayInfoResponse, err error) (*grpc.ClientConn, func()) {
	mock := &mockHealthServer{
		gatewayInfoResp: resp,
		gatewayInfoErr:  err,
		status:          pb.ServiceStatus_SERVICE_STATUS_HEALTHY,
		version:         "1.0.0",
	}
	lis := bufconn.Listen(bufSize)
	srv := grpc.NewServer()
	pb.RegisterOpenShellServer(srv, mock)

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

func TestGetGatewayInfo_Success(t *testing.T) {
	resp := &pb.GetGatewayInfoResponse{
		Status:         pb.ServiceStatus_SERVICE_STATUS_HEALTHY,
		GatewayVersion: "1.5.0",
		ComputeDrivers: []*pb.ComputeDriverInfo{
			{
				Name: "k8s",
				Capabilities: &pb.ComputeDriverCapabilities{
					DriverName:    "kubernetes",
					DriverVersion: "2.1.0",
				},
			},
		},
	}
	conn, cleanup := newMockGatewayInfoServer(resp, nil)
	defer cleanup()

	h := newHealthClient(conn)
	info, err := h.GetGatewayInfo(context.Background())

	require.NoError(t, err)
	require.NotNil(t, info)
	assert.Equal(t, ServiceStatusHealthy, info.Status)
	assert.Equal(t, "1.5.0", info.Version)
	require.Len(t, info.ComputeDrivers, 1)
	assert.Equal(t, "k8s", info.ComputeDrivers[0].Name)
	assert.Equal(t, "kubernetes", info.ComputeDrivers[0].DriverName)
	assert.Equal(t, "2.1.0", info.ComputeDrivers[0].DriverVersion)
}

func TestGetGatewayInfo_Error(t *testing.T) {
	conn, cleanup := newMockGatewayInfoServer(nil, status.Error(codes.PermissionDenied, "not admin"))
	defer cleanup()

	h := newHealthClient(conn)
	_, err := h.GetGatewayInfo(context.Background())

	require.Error(t, err)
	assert.True(t, IsPermissionDenied(err))
}

func newMockCurrentUserServer(resp *pb.GetCurrentUserResponse, err error) (*grpc.ClientConn, func()) {
	mock := &mockHealthServer{
		currentUserResp: resp,
		currentUserErr:  err,
		status:          pb.ServiceStatus_SERVICE_STATUS_HEALTHY,
		version:         "1.0.0",
	}
	lis := bufconn.Listen(bufSize)
	srv := grpc.NewServer()
	pb.RegisterOpenShellServer(srv, mock)

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

func TestGetCurrentUser_Success(t *testing.T) {
	resp := &pb.GetCurrentUserResponse{
		Subject:          "user-123",
		DisplayName:      "Test User",
		Roles:            []string{"admin"},
		Scopes:           []string{"read", "write"},
		IdentityProvider: "oidc-provider",
	}
	conn, cleanup := newMockCurrentUserServer(resp, nil)
	defer cleanup()

	h := newHealthClient(conn)
	user, err := h.GetCurrentUser(context.Background())

	require.NoError(t, err)
	require.NotNil(t, user)
	assert.Equal(t, "user-123", user.Subject)
	assert.Equal(t, "Test User", user.DisplayName)
	assert.Equal(t, []string{"admin"}, user.Roles)
	assert.Equal(t, []string{"read", "write"}, user.Scopes)
	assert.Equal(t, "oidc-provider", user.IdentityProvider)
}

func TestGetCurrentUser_Unauthenticated(t *testing.T) {
	conn, cleanup := newMockCurrentUserServer(nil, status.Error(codes.Unauthenticated, "invalid token"))
	defer cleanup()

	h := newHealthClient(conn)
	_, err := h.GetCurrentUser(context.Background())

	require.Error(t, err)
	assert.True(t, IsUnauthenticated(err))
}
