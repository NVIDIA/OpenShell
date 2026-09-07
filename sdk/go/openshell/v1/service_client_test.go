// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"
	"net"
	"sync"
	"testing"

	dm "github.com/NVIDIA/OpenShell/sdk/go/proto/datamodelv1"
	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

// --- Mock server for service endpoints ---

type mockServiceServer struct {
	pb.UnimplementedOpenShellServer
	mu        sync.Mutex
	endpoints map[string]*pb.ServiceEndpointResponse // key: "sandbox/service"
	exposeErr error
	getErr    error
	listErr   error
	deleteErr error
}

func newMockServiceServer() *mockServiceServer {
	return &mockServiceServer{
		endpoints: make(map[string]*pb.ServiceEndpointResponse),
	}
}

func serviceKey(sandbox, service string) string {
	return sandbox + "/" + service
}

func (s *mockServiceServer) ExposeService(_ context.Context, req *pb.ExposeServiceRequest) (*pb.ServiceEndpointResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.exposeErr != nil {
		return nil, s.exposeErr
	}

	resp := &pb.ServiceEndpointResponse{
		Endpoint: &pb.ServiceEndpoint{
			Metadata: &dm.ObjectMeta{
				Id: "ep-" + req.GetService(),
			},
			SandboxName: req.GetSandbox(),
			ServiceName: req.GetService(),
			TargetPort:  req.GetTargetPort(),
			Domain:      req.GetDomain(),
		},
	}
	if req.GetDomain() {
		resp.Url = "https://" + req.GetService() + ".example.com"
	}

	s.endpoints[serviceKey(req.GetSandbox(), req.GetService())] = resp
	return resp, nil
}

func (s *mockServiceServer) GetService(_ context.Context, req *pb.GetServiceRequest) (*pb.ServiceEndpointResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.getErr != nil {
		return nil, s.getErr
	}

	ep, ok := s.endpoints[serviceKey(req.GetSandbox(), req.GetService())]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "service %q not found in sandbox %q", req.GetService(), req.GetSandbox())
	}
	return ep, nil
}

func (s *mockServiceServer) ListServices(_ context.Context, req *pb.ListServicesRequest) (*pb.ListServicesResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listErr != nil {
		return nil, s.listErr
	}

	var services []*pb.ServiceEndpointResponse
	for key, ep := range s.endpoints {
		prefix := req.GetSandbox() + "/"
		if req.GetSandbox() == "" || (len(key) >= len(prefix) && key[:len(prefix)] == prefix) {
			services = append(services, ep)
		}
	}
	return &pb.ListServicesResponse{Services: services}, nil
}

func (s *mockServiceServer) DeleteService(_ context.Context, req *pb.DeleteServiceRequest) (*pb.DeleteServiceResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.deleteErr != nil {
		return nil, s.deleteErr
	}

	key := serviceKey(req.GetSandbox(), req.GetService())
	_, ok := s.endpoints[key]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "service %q not found in sandbox %q", req.GetService(), req.GetSandbox())
	}
	delete(s.endpoints, key)
	return &pb.DeleteServiceResponse{Deleted: true}, nil
}

// --- Test setup ---

func setupServiceTest(t *testing.T, mock *mockServiceServer) (*serviceClient, func()) {
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

	return newServiceClient(conn), func() {
		_ = conn.Close()
		srv.Stop()
	}
}

// --- Tests ---

func TestServiceExpose(t *testing.T) {
	mock := newMockServiceServer()
	client, cleanup := setupServiceTest(t, mock)
	defer cleanup()

	ep, err := client.Expose(context.Background(), "default", "web-app", "api", 8080, true)

	require.NoError(t, err)
	require.NotNil(t, ep)
	assert.Equal(t, "ep-api", ep.ID)
	assert.Equal(t, "web-app", ep.SandboxName)
	assert.Equal(t, "api", ep.ServiceName)
	assert.Equal(t, uint32(8080), ep.TargetPort)
	assert.True(t, ep.Domain)
	assert.Equal(t, "https://api.example.com", ep.URL)
}

func TestServiceExpose_NoDomain(t *testing.T) {
	mock := newMockServiceServer()
	client, cleanup := setupServiceTest(t, mock)
	defer cleanup()

	ep, err := client.Expose(context.Background(), "default", "web-app", "api", 8080, false)

	require.NoError(t, err)
	require.NotNil(t, ep)
	assert.False(t, ep.Domain)
	assert.Empty(t, ep.URL)
}

func TestServiceExpose_Error(t *testing.T) {
	mock := newMockServiceServer()
	mock.exposeErr = status.Errorf(codes.NotFound, "sandbox not found")
	client, cleanup := setupServiceTest(t, mock)
	defer cleanup()

	ep, err := client.Expose(context.Background(), "default", "missing", "api", 8080, true)

	assert.Nil(t, ep)
	require.Error(t, err)
	assert.True(t, IsNotFound(err))
}

func TestServiceGet(t *testing.T) {
	mock := newMockServiceServer()
	client, cleanup := setupServiceTest(t, mock)
	defer cleanup()

	// First expose, then get
	_, err := client.Expose(context.Background(), "default", "web-app", "api", 8080, true)
	require.NoError(t, err)

	ep, err := client.Get(context.Background(), "default", "web-app", "api")

	require.NoError(t, err)
	require.NotNil(t, ep)
	assert.Equal(t, "api", ep.ServiceName)
	assert.Equal(t, "web-app", ep.SandboxName)
}

func TestServiceGet_NotFound(t *testing.T) {
	mock := newMockServiceServer()
	client, cleanup := setupServiceTest(t, mock)
	defer cleanup()

	ep, err := client.Get(context.Background(), "default", "web-app", "nonexistent")

	assert.Nil(t, ep)
	require.Error(t, err)
	assert.True(t, IsNotFound(err))
}

func TestServiceGet_Error(t *testing.T) {
	mock := newMockServiceServer()
	mock.getErr = status.Errorf(codes.Internal, "internal error")
	client, cleanup := setupServiceTest(t, mock)
	defer cleanup()

	ep, err := client.Get(context.Background(), "default", "web-app", "api")

	assert.Nil(t, ep)
	require.Error(t, err)
}

func TestServiceList(t *testing.T) {
	mock := newMockServiceServer()
	client, cleanup := setupServiceTest(t, mock)
	defer cleanup()

	// Expose two services
	_, err := client.Expose(context.Background(), "default", "web-app", "api", 8080, true)
	require.NoError(t, err)
	_, err = client.Expose(context.Background(), "default", "web-app", "web", 3000, false)
	require.NoError(t, err)

	endpoints, err := client.List(context.Background(), "default", "web-app")

	require.NoError(t, err)
	assert.Len(t, endpoints, 2)
}

func TestServiceList_Empty(t *testing.T) {
	mock := newMockServiceServer()
	client, cleanup := setupServiceTest(t, mock)
	defer cleanup()

	endpoints, err := client.List(context.Background(), "default", "web-app")

	require.NoError(t, err)
	assert.Empty(t, endpoints)
}

func TestServiceList_WithOptions(t *testing.T) {
	mock := newMockServiceServer()
	client, cleanup := setupServiceTest(t, mock)
	defer cleanup()

	_, err := client.Expose(context.Background(), "default", "web-app", "api", 8080, true)
	require.NoError(t, err)

	endpoints, err := client.List(context.Background(), "default", "web-app", ListOptions{Limit: 10, Offset: 0})

	require.NoError(t, err)
	assert.Len(t, endpoints, 1)
}

func TestServiceList_Error(t *testing.T) {
	mock := newMockServiceServer()
	mock.listErr = status.Errorf(codes.Unavailable, "unavailable")
	client, cleanup := setupServiceTest(t, mock)
	defer cleanup()

	endpoints, err := client.List(context.Background(), "default", "web-app")

	assert.Nil(t, endpoints)
	require.Error(t, err)
	assert.True(t, IsUnavailable(err))
}

func TestServiceDelete(t *testing.T) {
	mock := newMockServiceServer()
	client, cleanup := setupServiceTest(t, mock)
	defer cleanup()

	// Expose then delete
	_, err := client.Expose(context.Background(), "default", "web-app", "api", 8080, true)
	require.NoError(t, err)

	err = client.Delete(context.Background(), "default", "web-app", "api")

	require.NoError(t, err)

	// Verify subsequent Get returns NotFound
	ep, err := client.Get(context.Background(), "default", "web-app", "api")
	assert.Nil(t, ep)
	require.Error(t, err)
	assert.True(t, IsNotFound(err))
}

func TestServiceDelete_NotFound(t *testing.T) {
	mock := newMockServiceServer()
	client, cleanup := setupServiceTest(t, mock)
	defer cleanup()

	err := client.Delete(context.Background(), "default", "web-app", "nonexistent")

	require.Error(t, err)
	assert.True(t, IsNotFound(err))
}

func TestServiceDelete_Error(t *testing.T) {
	mock := newMockServiceServer()
	mock.deleteErr = status.Errorf(codes.Internal, "internal error")
	client, cleanup := setupServiceTest(t, mock)
	defer cleanup()

	err := client.Delete(context.Background(), "default", "web-app", "api")

	require.Error(t, err)
}
