// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	dm "github.com/NVIDIA/OpenShell/sdk/go/proto/datamodelv1"
	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
)

type mockTemplateServer struct {
	pb.UnimplementedOpenShellServer
	mu        sync.Mutex
	templates map[string]*pb.SandboxTemplate

	lastCreate *pb.CreateSandboxTemplateRequest
	lastGet    *pb.GetSandboxTemplateRequest
	lastList   *pb.ListSandboxTemplatesRequest
	lastDelete *pb.DeleteSandboxTemplateRequest
}

func newMockTemplateServer() *mockTemplateServer {
	return &mockTemplateServer{templates: make(map[string]*pb.SandboxTemplate)}
}

func (s *mockTemplateServer) CreateSandboxTemplate(_ context.Context, req *pb.CreateSandboxTemplateRequest) (*pb.SandboxTemplateResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastCreate = proto.Clone(req).(*pb.CreateSandboxTemplateRequest)
	template := proto.Clone(req.GetTemplate()).(*pb.SandboxTemplate)
	if template.Metadata == nil {
		template.Metadata = &dm.ObjectMeta{}
	}
	template.Metadata.Workspace = req.GetWorkspace()
	template.Metadata.ResourceVersion = 1
	s.templates[template.GetMetadata().GetName()] = template
	return &pb.SandboxTemplateResponse{Template: template}, nil
}

func (s *mockTemplateServer) GetSandboxTemplate(_ context.Context, req *pb.GetSandboxTemplateRequest) (*pb.SandboxTemplateResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastGet = proto.Clone(req).(*pb.GetSandboxTemplateRequest)
	return &pb.SandboxTemplateResponse{Template: s.templates[req.GetName()]}, nil
}

func (s *mockTemplateServer) ListSandboxTemplates(_ context.Context, req *pb.ListSandboxTemplatesRequest) (*pb.ListSandboxTemplatesResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastList = proto.Clone(req).(*pb.ListSandboxTemplatesRequest)
	templates := make([]*pb.SandboxTemplate, 0, len(s.templates))
	for _, template := range s.templates {
		templates = append(templates, proto.Clone(template).(*pb.SandboxTemplate))
	}
	return &pb.ListSandboxTemplatesResponse{Templates: templates}, nil
}

func (s *mockTemplateServer) DeleteSandboxTemplate(_ context.Context, req *pb.DeleteSandboxTemplateRequest) (*pb.DeleteSandboxTemplateResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastDelete = proto.Clone(req).(*pb.DeleteSandboxTemplateRequest)
	_, existed := s.templates[req.GetName()]
	delete(s.templates, req.GetName())
	return &pb.DeleteSandboxTemplateResponse{Deleted: existed}, nil
}

func setupTemplateTest(t *testing.T, srv *mockTemplateServer) (*sandboxTemplateClient, func()) {
	t.Helper()
	lis := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	pb.RegisterOpenShellServer(server, srv)
	go func() {
		_ = server.Serve(lis)
	}()

	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return lis.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)

	return newSandboxTemplateClient(conn), func() {
		require.NoError(t, conn.Close())
		server.Stop()
		require.NoError(t, lis.Close())
	}
}

func TestSandboxTemplateCRUD(t *testing.T) {
	mock := newMockTemplateServer()
	client, cleanup := setupTemplateTest(t, mock)
	defer cleanup()

	template := &SandboxTemplate{
		Name:   "gpu-kata",
		Labels: map[string]string{"team": "platform"},
		Spec: SandboxTemplateSpec{
			Workload: &SandboxWorkloadConfig{Image: "python:3.12"},
			DriverConfig: map[string]any{
				"kubernetes": map[string]any{"runtime_class_name": "kata"},
			},
			DesiredServiceLevel: &SandboxServiceLevel{
				Startup: &SandboxStartup{ReadyWithin: 30 * time.Second, MaxBurst: 4},
			},
		},
	}

	created, err := client.Create(context.Background(), "default", template)
	require.NoError(t, err)
	require.NotNil(t, created)
	assert.Equal(t, "gpu-kata", created.Name)
	mock.mu.Lock()
	createReq := mock.lastCreate
	mock.mu.Unlock()
	require.NotNil(t, createReq)
	assert.Equal(t, "default", createReq.GetWorkspace())
	assert.Equal(t, "python:3.12", createReq.GetTemplate().GetSpec().GetWorkload().GetImage())
	assert.Equal(t, "kata", createReq.GetTemplate().GetSpec().GetDriverConfig().GetFields()["kubernetes"].GetStructValue().GetFields()["runtime_class_name"].GetStringValue())
	assert.Equal(t, durationpb.New(30*time.Second).AsDuration(), createReq.GetTemplate().GetSpec().GetDesiredServiceLevel().GetStartup().GetReadyWithin().AsDuration())
	assert.Equal(t, uint32(4), createReq.GetTemplate().GetSpec().GetDesiredServiceLevel().GetStartup().GetMaxBurst())

	got, err := client.Get(context.Background(), "default", "gpu-kata")
	require.NoError(t, err)
	assert.Equal(t, "gpu-kata", got.Name)

	listed, err := client.List(context.Background(), "default", ListOptions{Limit: 50, Offset: 10})
	require.NoError(t, err)
	assert.Len(t, listed, 1)
	mock.mu.Lock()
	listReq := mock.lastList
	mock.mu.Unlock()
	require.NotNil(t, listReq)
	assert.Equal(t, "default", listReq.GetWorkspace())
	assert.False(t, listReq.GetAllWorkspaces())
	assert.Equal(t, uint32(50), listReq.GetLimit())
	assert.Equal(t, uint32(10), listReq.GetOffset())

	err = client.Delete(context.Background(), "default", "gpu-kata")
	require.NoError(t, err)
	mock.mu.Lock()
	deleteReq := mock.lastDelete
	mock.mu.Unlock()
	require.NotNil(t, deleteReq)
	assert.Equal(t, "gpu-kata", deleteReq.GetName())
	assert.Equal(t, "default", deleteReq.GetWorkspace())
}

func TestSandboxTemplateListAllWorkspacesClearsWorkspace(t *testing.T) {
	mock := newMockTemplateServer()
	client, cleanup := setupTemplateTest(t, mock)
	defer cleanup()

	_, err := client.List(context.Background(), "default", ListOptions{AllWorkspaces: true})
	require.NoError(t, err)

	mock.mu.Lock()
	req := mock.lastList
	mock.mu.Unlock()
	require.NotNil(t, req)
	assert.True(t, req.GetAllWorkspaces())
	assert.Empty(t, req.GetWorkspace())
}

func TestSandboxTemplateListRejectsNegativePagination(t *testing.T) {
	client, cleanup := setupTemplateTest(t, newMockTemplateServer())
	defer cleanup()

	_, err := client.List(context.Background(), "default", ListOptions{Limit: -1})
	require.Error(t, err)
	assert.True(t, IsInvalidArgument(err))

	_, err = client.List(context.Background(), "default", ListOptions{Offset: -1})
	require.Error(t, err)
	assert.True(t, IsInvalidArgument(err))
}

func TestSandboxTemplateCreateRejectsNil(t *testing.T) {
	client, cleanup := setupTemplateTest(t, newMockTemplateServer())
	defer cleanup()

	_, err := client.Create(context.Background(), "default", nil)
	require.Error(t, err)
	assert.True(t, IsInvalidArgument(err))
}
