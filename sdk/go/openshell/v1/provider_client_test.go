// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"
	"net"
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

type mockProviderServer struct {
	pb.UnimplementedOpenShellServer
	providers map[string]*dm.Provider
	createErr error
	getErr    error
	listErr   error
	updateErr error
	deleteErr error
}

func newMockProviderServer() *mockProviderServer {
	return &mockProviderServer{
		providers: make(map[string]*dm.Provider),
	}
}

func (s *mockProviderServer) CreateProvider(_ context.Context, req *pb.CreateProviderRequest) (*pb.ProviderResponse, error) {
	if s.createErr != nil {
		return nil, s.createErr
	}
	p := req.GetProvider()
	if p.GetMetadata() != nil {
		s.providers[p.GetMetadata().GetName()] = p
	}
	return &pb.ProviderResponse{Provider: p}, nil
}

func (s *mockProviderServer) GetProvider(_ context.Context, req *pb.GetProviderRequest) (*pb.ProviderResponse, error) {
	if s.getErr != nil {
		return nil, s.getErr
	}
	p, ok := s.providers[req.GetName()]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "provider %q not found", req.GetName())
	}
	return &pb.ProviderResponse{Provider: p}, nil
}

func (s *mockProviderServer) ListProviders(_ context.Context, _ *pb.ListProvidersRequest) (*pb.ListProvidersResponse, error) {
	if s.listErr != nil {
		return nil, s.listErr
	}
	var list []*dm.Provider
	for _, p := range s.providers {
		list = append(list, p)
	}
	return &pb.ListProvidersResponse{Providers: list}, nil
}

func (s *mockProviderServer) UpdateProvider(_ context.Context, req *pb.UpdateProviderRequest) (*pb.ProviderResponse, error) {
	if s.updateErr != nil {
		return nil, s.updateErr
	}
	p := req.GetProvider()
	if p.GetMetadata() != nil {
		name := p.GetMetadata().GetName()
		if _, ok := s.providers[name]; !ok {
			return nil, status.Errorf(codes.NotFound, "provider %q not found", name)
		}
		s.providers[name] = p
	}
	return &pb.ProviderResponse{Provider: p}, nil
}

func (s *mockProviderServer) DeleteProvider(_ context.Context, req *pb.DeleteProviderRequest) (*pb.DeleteProviderResponse, error) {
	if s.deleteErr != nil {
		return nil, s.deleteErr
	}
	delete(s.providers, req.GetName())
	return &pb.DeleteProviderResponse{}, nil
}

func setupProviderTest(t *testing.T, mock *mockProviderServer) (*providerClient, func()) {
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

	return newProviderClient(conn), func() {
		_ = conn.Close()
		srv.Stop()
	}
}

func TestProviderCreate(t *testing.T) {
	mock := newMockProviderServer()
	client, cleanup := setupProviderTest(t, mock)
	defer cleanup()

	p := &Provider{
		Name: "my-claude",
		Type: "claude",
		Spec: ProviderSpec{
			Credentials: map[string]string{"API_KEY": "secret"},
			Config:      map[string]string{"region": "us-east-1"},
		},
	}

	result, err := client.Create(context.Background(), "default", p)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "my-claude", result.Name)
	assert.Equal(t, "claude", result.Type)
	assert.Nil(t, result.Spec.Credentials, "credentials are write-only and should not be returned")
}

func TestProviderCreate_AlreadyExists(t *testing.T) {
	mock := newMockProviderServer()
	mock.createErr = status.Error(codes.AlreadyExists, "provider already exists")
	client, cleanup := setupProviderTest(t, mock)
	defer cleanup()

	_, err := client.Create(context.Background(), "default", &Provider{Name: "dup"})

	require.Error(t, err)
	assert.True(t, IsAlreadyExists(err))
}

func TestProviderGet(t *testing.T) {
	mock := newMockProviderServer()
	mock.providers["existing"] = &dm.Provider{
		Metadata: &dm.ObjectMeta{Id: "p1", Name: "existing"},
		Type:     "gitlab",
	}
	client, cleanup := setupProviderTest(t, mock)
	defer cleanup()

	result, err := client.Get(context.Background(), "default", "existing")

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "existing", result.Name)
	assert.Equal(t, "gitlab", result.Type)
}

func TestProviderGet_NotFound(t *testing.T) {
	mock := newMockProviderServer()
	client, cleanup := setupProviderTest(t, mock)
	defer cleanup()

	_, err := client.Get(context.Background(), "default", "nonexistent")

	require.Error(t, err)
	assert.True(t, IsNotFound(err))
}

func TestProviderList(t *testing.T) {
	mock := newMockProviderServer()
	mock.providers["p1"] = &dm.Provider{
		Metadata: &dm.ObjectMeta{Name: "p1"},
		Type:     "claude",
	}
	mock.providers["p2"] = &dm.Provider{
		Metadata: &dm.ObjectMeta{Name: "p2"},
		Type:     "gitlab",
	}
	client, cleanup := setupProviderTest(t, mock)
	defer cleanup()

	result, err := client.List(context.Background(), "default")

	require.NoError(t, err)
	assert.Len(t, result, 2)
}

func TestProviderList_Empty(t *testing.T) {
	mock := newMockProviderServer()
	client, cleanup := setupProviderTest(t, mock)
	defer cleanup()

	result, err := client.List(context.Background(), "default")

	require.NoError(t, err)
	assert.Empty(t, result)
}

func TestProviderUpdate(t *testing.T) {
	mock := newMockProviderServer()
	mock.providers["updatable"] = &dm.Provider{
		Metadata: &dm.ObjectMeta{Name: "updatable"},
		Type:     "claude",
	}
	client, cleanup := setupProviderTest(t, mock)
	defer cleanup()

	p := &Provider{
		Name: "updatable",
		Type: "claude",
		Spec: ProviderSpec{
			Credentials: map[string]string{"API_KEY": "new-secret"},
		},
	}

	result, err := client.Update(context.Background(), "default", p)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "updatable", result.Name)
}

func TestProviderUpdate_NotFound(t *testing.T) {
	mock := newMockProviderServer()
	client, cleanup := setupProviderTest(t, mock)
	defer cleanup()

	_, err := client.Update(context.Background(), "default", &Provider{Name: "missing"})

	require.Error(t, err)
	assert.True(t, IsNotFound(err))
}

func TestProviderDelete(t *testing.T) {
	mock := newMockProviderServer()
	mock.providers["deleteme"] = &dm.Provider{
		Metadata: &dm.ObjectMeta{Name: "deleteme"},
	}
	client, cleanup := setupProviderTest(t, mock)
	defer cleanup()

	err := client.Delete(context.Background(), "default", "deleteme")

	require.NoError(t, err)
	assert.Empty(t, mock.providers["deleteme"])
}

func TestProviderDelete_NotFound(t *testing.T) {
	mock := newMockProviderServer()
	mock.deleteErr = status.Error(codes.NotFound, "not found")
	client, cleanup := setupProviderTest(t, mock)
	defer cleanup()

	err := client.Delete(context.Background(), "default", "nonexistent")

	require.Error(t, err)
	assert.True(t, IsNotFound(err))
}

func TestProviderEnsure_Creates(t *testing.T) {
	mock := newMockProviderServer()
	client, cleanup := setupProviderTest(t, mock)
	defer cleanup()

	p := &Provider{
		Name: "new-provider",
		Type: "claude",
		Spec: ProviderSpec{
			Credentials: map[string]string{"KEY": "val"},
		},
	}

	result, err := client.Ensure(context.Background(), "default", p)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "new-provider", result.Name)
}

func TestProviderEnsure_Updates(t *testing.T) {
	mock := newMockProviderServer()
	mock.providers["existing"] = &dm.Provider{
		Metadata: &dm.ObjectMeta{Name: "existing"},
		Type:     "claude",
		Config:   map[string]string{"old": "config"},
	}
	client, cleanup := setupProviderTest(t, mock)
	defer cleanup()

	p := &Provider{
		Name: "existing",
		Type: "claude",
		Spec: ProviderSpec{
			Config: map[string]string{"new": "config"},
		},
	}

	result, err := client.Ensure(context.Background(), "default", p)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "existing", result.Name)
}
