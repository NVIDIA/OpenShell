// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"
	"net"
	"testing"

	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/inferencev1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

type mockInferenceServer struct {
	pb.UnimplementedInferenceServer

	setResp    *pb.SetInferenceRouteResponse
	getResp    *pb.GetInferenceRouteResponse
	deleteResp *pb.DeleteInferenceRouteResponse
	err        error

	lastSetReq    *pb.SetInferenceRouteRequest
	lastGetReq    *pb.GetInferenceRouteRequest
	lastDeleteReq *pb.DeleteInferenceRouteRequest
}

func (s *mockInferenceServer) SetInferenceRoute(_ context.Context, req *pb.SetInferenceRouteRequest) (*pb.SetInferenceRouteResponse, error) {
	s.lastSetReq = req
	if s.err != nil {
		return nil, s.err
	}
	return s.setResp, nil
}

func (s *mockInferenceServer) GetInferenceRoute(_ context.Context, req *pb.GetInferenceRouteRequest) (*pb.GetInferenceRouteResponse, error) {
	s.lastGetReq = req
	if s.err != nil {
		return nil, s.err
	}
	return s.getResp, nil
}

func (s *mockInferenceServer) DeleteInferenceRoute(_ context.Context, req *pb.DeleteInferenceRouteRequest) (*pb.DeleteInferenceRouteResponse, error) {
	s.lastDeleteReq = req
	if s.err != nil {
		return nil, s.err
	}
	return s.deleteResp, nil
}

func newMockInferenceServer(mock *mockInferenceServer) (*grpc.ClientConn, func()) {
	lis := bufconn.Listen(bufSize)
	srv := grpc.NewServer()
	pb.RegisterInferenceServer(srv, mock)

	go func() { _ = srv.Serve(lis) }()

	conn, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithContextDialer(func(_ context.Context, _ string) (net.Conn, error) {
			return lis.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		srv.Stop()
		panic("grpc.NewClient failed: " + err.Error())
	}

	return conn, func() {
		_ = conn.Close()
		srv.Stop()
	}
}

// --- SetRoute tests ---

func TestSetRoute_Success(t *testing.T) {
	mock := &mockInferenceServer{
		setResp: &pb.SetInferenceRouteResponse{
			ProviderName:        "openai",
			ModelId:             "gpt-4",
			Version:             1,
			RouteName:           "my-route",
			ValidationPerformed: true,
			ValidatedEndpoints: []*pb.ValidatedEndpoint{
				{Url: "https://api.openai.com/v1", Protocol: "openai"},
			},
			TimeoutSecs: 120,
			Workspace:   "team-alpha",
		},
	}
	conn, cleanup := newMockInferenceServer(mock)
	defer cleanup()

	ic := newInferenceClient(conn)
	route, err := ic.SetRoute(context.Background(), "team-alpha", &InferenceRouteConfig{
		ProviderName: "openai",
		ModelID:      "gpt-4",
		RouteName:    "my-route",
		NoVerify:     false,
		TimeoutSecs:  120,
	})

	require.NoError(t, err)
	require.NotNil(t, route)
	assert.Equal(t, "openai", route.ProviderName)
	assert.Equal(t, "gpt-4", route.ModelID)
	assert.Equal(t, uint64(1), route.Version)
	assert.Equal(t, "my-route", route.RouteName)
	assert.True(t, route.ValidationPerformed)
	require.Len(t, route.ValidatedEndpoints, 1)
	assert.Equal(t, "https://api.openai.com/v1", route.ValidatedEndpoints[0].URL)
	assert.Equal(t, "openai", route.ValidatedEndpoints[0].Protocol)
	assert.Equal(t, uint64(120), route.TimeoutSecs)
	assert.Equal(t, "team-alpha", route.Workspace)

	// Verify the proto request was correctly constructed.
	assert.Equal(t, "openai", mock.lastSetReq.GetProviderName())
	assert.Equal(t, "gpt-4", mock.lastSetReq.GetModelId())
	assert.Equal(t, "my-route", mock.lastSetReq.GetRouteName())
	assert.Equal(t, "team-alpha", mock.lastSetReq.GetWorkspace())
	assert.Equal(t, uint64(120), mock.lastSetReq.GetTimeoutSecs())
}

func TestSetRoute_EmptyWorkspace(t *testing.T) {
	mock := &mockInferenceServer{}
	conn, cleanup := newMockInferenceServer(mock)
	defer cleanup()

	ic := newInferenceClient(conn)
	_, err := ic.SetRoute(context.Background(), "", &InferenceRouteConfig{
		ProviderName: "openai",
		ModelID:      "gpt-4",
	})

	require.Error(t, err)
	assert.True(t, IsInvalidArgument(err))
}

func TestSetRoute_NilConfig(t *testing.T) {
	mock := &mockInferenceServer{}
	conn, cleanup := newMockInferenceServer(mock)
	defer cleanup()

	ic := newInferenceClient(conn)
	_, err := ic.SetRoute(context.Background(), "ws", nil)

	require.Error(t, err)
	assert.True(t, IsInvalidArgument(err))
}

func TestSetRoute_EmptyProviderName(t *testing.T) {
	mock := &mockInferenceServer{}
	conn, cleanup := newMockInferenceServer(mock)
	defer cleanup()

	ic := newInferenceClient(conn)
	_, err := ic.SetRoute(context.Background(), "ws", &InferenceRouteConfig{
		ProviderName: "",
		ModelID:      "gpt-4",
	})

	require.Error(t, err)
	assert.True(t, IsInvalidArgument(err))
}

func TestSetRoute_EmptyModelID(t *testing.T) {
	mock := &mockInferenceServer{}
	conn, cleanup := newMockInferenceServer(mock)
	defer cleanup()

	ic := newInferenceClient(conn)
	_, err := ic.SetRoute(context.Background(), "ws", &InferenceRouteConfig{
		ProviderName: "openai",
		ModelID:      "",
	})

	require.Error(t, err)
	assert.True(t, IsInvalidArgument(err))
}

func TestSetRoute_EmptyRouteName(t *testing.T) {
	mock := &mockInferenceServer{
		setResp: &pb.SetInferenceRouteResponse{
			ProviderName: "openai",
			ModelId:      "gpt-4",
			Version:      1,
			RouteName:    "",
			Workspace:    "ws",
		},
	}
	conn, cleanup := newMockInferenceServer(mock)
	defer cleanup()

	ic := newInferenceClient(conn)
	route, err := ic.SetRoute(context.Background(), "ws", &InferenceRouteConfig{
		ProviderName: "openai",
		ModelID:      "gpt-4",
		RouteName:    "",
	})

	require.NoError(t, err)
	require.NotNil(t, route)
	assert.Empty(t, route.RouteName)
}

func TestSetRoute_PermissionDenied(t *testing.T) {
	mock := &mockInferenceServer{
		err: status.Error(codes.PermissionDenied, "workspace admin required"),
	}
	conn, cleanup := newMockInferenceServer(mock)
	defer cleanup()

	ic := newInferenceClient(conn)
	_, err := ic.SetRoute(context.Background(), "ws", &InferenceRouteConfig{
		ProviderName: "openai",
		ModelID:      "gpt-4",
	})

	require.Error(t, err)
	assert.True(t, IsPermissionDenied(err))
}

func TestSetRoute_NoVerify(t *testing.T) {
	mock := &mockInferenceServer{
		setResp: &pb.SetInferenceRouteResponse{
			ProviderName: "openai",
			ModelId:      "gpt-4",
			Version:      1,
			Workspace:    "ws",
		},
	}
	conn, cleanup := newMockInferenceServer(mock)
	defer cleanup()

	ic := newInferenceClient(conn)
	_, err := ic.SetRoute(context.Background(), "ws", &InferenceRouteConfig{
		ProviderName: "openai",
		ModelID:      "gpt-4",
		NoVerify:     true,
	})

	require.NoError(t, err)
	assert.True(t, mock.lastSetReq.GetNoVerify())
}

// --- GetRoute tests ---

func TestGetRoute_Success(t *testing.T) {
	mock := &mockInferenceServer{
		getResp: &pb.GetInferenceRouteResponse{
			ProviderName: "vertex",
			ModelId:      "gemini-pro",
			Version:      3,
			RouteName:    "default",
			TimeoutSecs:  60,
			Workspace:    "prod",
		},
	}
	conn, cleanup := newMockInferenceServer(mock)
	defer cleanup()

	ic := newInferenceClient(conn)
	route, err := ic.GetRoute(context.Background(), "prod", "default")

	require.NoError(t, err)
	require.NotNil(t, route)
	assert.Equal(t, "vertex", route.ProviderName)
	assert.Equal(t, "gemini-pro", route.ModelID)
	assert.Equal(t, uint64(3), route.Version)
	assert.Equal(t, "default", route.RouteName)
	assert.Equal(t, uint64(60), route.TimeoutSecs)
	assert.Equal(t, "prod", route.Workspace)
	assert.False(t, route.ValidationPerformed)
	assert.Nil(t, route.ValidatedEndpoints)

	assert.Equal(t, "prod", mock.lastGetReq.GetWorkspace())
	assert.Equal(t, "default", mock.lastGetReq.GetRouteName())
}

func TestGetRoute_EmptyWorkspace(t *testing.T) {
	mock := &mockInferenceServer{}
	conn, cleanup := newMockInferenceServer(mock)
	defer cleanup()

	ic := newInferenceClient(conn)
	_, err := ic.GetRoute(context.Background(), "", "my-route")

	require.Error(t, err)
	assert.True(t, IsInvalidArgument(err))
}

func TestGetRoute_NotFound(t *testing.T) {
	mock := &mockInferenceServer{
		err: status.Error(codes.NotFound, "route not found"),
	}
	conn, cleanup := newMockInferenceServer(mock)
	defer cleanup()

	ic := newInferenceClient(conn)
	_, err := ic.GetRoute(context.Background(), "ws", "missing-route")

	require.Error(t, err)
	assert.True(t, IsNotFound(err))
}

func TestGetRoute_EmptyRouteName(t *testing.T) {
	mock := &mockInferenceServer{
		getResp: &pb.GetInferenceRouteResponse{
			ProviderName: "openai",
			ModelId:      "gpt-4",
			Version:      1,
			RouteName:    "",
			Workspace:    "ws",
		},
	}
	conn, cleanup := newMockInferenceServer(mock)
	defer cleanup()

	ic := newInferenceClient(conn)
	route, err := ic.GetRoute(context.Background(), "ws", "")

	require.NoError(t, err)
	require.NotNil(t, route)
	assert.Empty(t, route.RouteName)
	assert.Empty(t, mock.lastGetReq.GetRouteName())
}

// --- DeleteRoute tests ---

func TestDeleteRoute_Success(t *testing.T) {
	mock := &mockInferenceServer{
		deleteResp: &pb.DeleteInferenceRouteResponse{Deleted: true},
	}
	conn, cleanup := newMockInferenceServer(mock)
	defer cleanup()

	ic := newInferenceClient(conn)
	err := ic.DeleteRoute(context.Background(), "ws", "my-route")

	require.NoError(t, err)
	assert.Equal(t, "ws", mock.lastDeleteReq.GetWorkspace())
	assert.Equal(t, "my-route", mock.lastDeleteReq.GetRouteName())
}

func TestDeleteRoute_EmptyWorkspace(t *testing.T) {
	mock := &mockInferenceServer{}
	conn, cleanup := newMockInferenceServer(mock)
	defer cleanup()

	ic := newInferenceClient(conn)
	err := ic.DeleteRoute(context.Background(), "", "my-route")

	require.Error(t, err)
	assert.True(t, IsInvalidArgument(err))
}

func TestDeleteRoute_Idempotent(t *testing.T) {
	// Deleting a non-existent route should succeed (gateway returns OK).
	mock := &mockInferenceServer{
		deleteResp: &pb.DeleteInferenceRouteResponse{Deleted: false},
	}
	conn, cleanup := newMockInferenceServer(mock)
	defer cleanup()

	ic := newInferenceClient(conn)
	err := ic.DeleteRoute(context.Background(), "ws", "nonexistent")

	require.NoError(t, err)
}

func TestDeleteRoute_PermissionDenied(t *testing.T) {
	mock := &mockInferenceServer{
		err: status.Error(codes.PermissionDenied, "workspace admin required"),
	}
	conn, cleanup := newMockInferenceServer(mock)
	defer cleanup()

	ic := newInferenceClient(conn)
	err := ic.DeleteRoute(context.Background(), "ws", "my-route")

	require.Error(t, err)
	assert.True(t, IsPermissionDenied(err))
}

func TestDeleteRoute_EmptyRouteName(t *testing.T) {
	mock := &mockInferenceServer{
		deleteResp: &pb.DeleteInferenceRouteResponse{Deleted: true},
	}
	conn, cleanup := newMockInferenceServer(mock)
	defer cleanup()

	ic := newInferenceClient(conn)
	err := ic.DeleteRoute(context.Background(), "ws", "")

	require.NoError(t, err)
	assert.Empty(t, mock.lastDeleteReq.GetRouteName())
}
