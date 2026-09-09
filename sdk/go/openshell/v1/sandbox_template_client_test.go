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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
)

type mockSandboxTemplateServer struct {
	pb.UnimplementedOpenShellServer
	mu sync.Mutex

	templates map[string]*pb.SandboxWorkloadTemplate

	createRequest *pb.CreateSandboxTemplateRequest
	getRequest    *pb.GetSandboxTemplateRequest
	listRequest   *pb.ListSandboxTemplatesRequest
	deleteRequest *pb.DeleteSandboxTemplateRequest

	createErr error
	getErr    error
	listErr   error
	deleteErr error
}

func newMockSandboxTemplateServer() *mockSandboxTemplateServer {
	return &mockSandboxTemplateServer{
		templates: make(map[string]*pb.SandboxWorkloadTemplate),
	}
}

func (s *mockSandboxTemplateServer) CreateSandboxTemplate(_ context.Context, req *pb.CreateSandboxTemplateRequest) (*pb.SandboxTemplateResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.createRequest = proto.Clone(req).(*pb.CreateSandboxTemplateRequest)
	if s.createErr != nil {
		return nil, s.createErr
	}
	template := proto.Clone(req.GetTemplate()).(*pb.SandboxWorkloadTemplate)
	if template.Metadata == nil {
		template.Metadata = &dm.ObjectMeta{}
	}
	template.Metadata.Workspace = req.GetWorkspace()
	template.Metadata.ResourceVersion = 1
	s.templates[template.Metadata.GetName()] = template
	return &pb.SandboxTemplateResponse{Template: proto.Clone(template).(*pb.SandboxWorkloadTemplate)}, nil
}

func (s *mockSandboxTemplateServer) GetSandboxTemplate(_ context.Context, req *pb.GetSandboxTemplateRequest) (*pb.SandboxTemplateResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.getRequest = proto.Clone(req).(*pb.GetSandboxTemplateRequest)
	if s.getErr != nil {
		return nil, s.getErr
	}
	template, ok := s.templates[req.GetName()]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "template %q not found", req.GetName())
	}
	return &pb.SandboxTemplateResponse{Template: proto.Clone(template).(*pb.SandboxWorkloadTemplate)}, nil
}

func (s *mockSandboxTemplateServer) ListSandboxTemplates(_ context.Context, req *pb.ListSandboxTemplatesRequest) (*pb.ListSandboxTemplatesResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.listRequest = proto.Clone(req).(*pb.ListSandboxTemplatesRequest)
	if s.listErr != nil {
		return nil, s.listErr
	}
	templates := make([]*pb.SandboxWorkloadTemplate, 0, len(s.templates))
	for _, template := range s.templates {
		templates = append(templates, proto.Clone(template).(*pb.SandboxWorkloadTemplate))
	}
	return &pb.ListSandboxTemplatesResponse{Templates: templates}, nil
}

func (s *mockSandboxTemplateServer) DeleteSandboxTemplate(_ context.Context, req *pb.DeleteSandboxTemplateRequest) (*pb.DeleteSandboxTemplateResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deleteRequest = proto.Clone(req).(*pb.DeleteSandboxTemplateRequest)
	if s.deleteErr != nil {
		return nil, s.deleteErr
	}
	delete(s.templates, req.GetName())
	return &pb.DeleteSandboxTemplateResponse{Deleted: true}, nil
}

func setupSandboxTemplateTest(t *testing.T, mock *mockSandboxTemplateServer) (*sandboxTemplateClient, func()) {
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

	return newSandboxTemplateClient(conn), func() {
		_ = conn.Close()
		srv.Stop()
	}
}

func TestSandboxTemplateCreate(t *testing.T) {
	mock := newMockSandboxTemplateServer()
	client, cleanup := setupSandboxTemplateTest(t, mock)
	defer cleanup()
	gpuCount := uint32(1)

	template, err := client.Create(context.Background(), "default", &SandboxWorkloadTemplate{
		Name: "gpu-kata",
		Labels: map[string]string{
			"team": "platform",
		},
		Spec: SandboxWorkloadTemplateSpec{
			Workload: &SandboxWorkloadConfig{
				Image:       "nvcr.io/nvidia/openshell:latest",
				Environment: map[string]string{"NVIDIA_VISIBLE_DEVICES": "all"},
				Resources: &SandboxResources{
					CPU:    "2",
					Memory: "8Gi",
					GPU:    &SandboxGPURequirements{Count: &gpuCount},
				},
			},
			DriverConfig: map[string]any{
				"kubernetes": map[string]any{"runtimeClassName": "kata"},
			},
			DesiredServiceLevel: &SandboxServiceLevel{
				Startup: &SandboxStartup{
					ReadyWithin: 45 * time.Second,
					MaxBurst:    2,
				},
			},
		},
	})

	require.NoError(t, err)
	require.NotNil(t, template)
	assert.Equal(t, "gpu-kata", template.Name)
	assert.Equal(t, "default", template.Workspace)
	assert.Equal(t, uint64(1), template.ResourceVersion)
	mock.mu.Lock()
	defer mock.mu.Unlock()
	require.NotNil(t, mock.createRequest)
	assert.Equal(t, "default", mock.createRequest.Workspace)
	assert.Equal(t, "gpu-kata", mock.createRequest.Template.Metadata.Name)
	assert.Equal(t, "2", mock.createRequest.Template.Spec.Workload.Resources.Cpu)
	assert.Equal(t, "8Gi", mock.createRequest.Template.Spec.Workload.Resources.Memory)
	require.NotNil(t, mock.createRequest.Template.Spec.Workload.Resources.Gpu)
	require.NotNil(t, mock.createRequest.Template.Spec.Workload.Resources.Gpu.Count)
	assert.Equal(t, uint32(1), *mock.createRequest.Template.Spec.Workload.Resources.Gpu.Count)
	assert.Equal(t, durationpb.New(45*time.Second), mock.createRequest.Template.Spec.DesiredServiceLevel.Startup.ReadyWithin)
}

func TestSandboxTemplateCreate_RejectsNilTemplate(t *testing.T) {
	mock := newMockSandboxTemplateServer()
	client, cleanup := setupSandboxTemplateTest(t, mock)
	defer cleanup()

	_, err := client.Create(context.Background(), "default", nil)

	require.Error(t, err)
	assert.True(t, IsInvalidArgument(err))
}

func TestSandboxTemplateCreate_RejectsUnrepresentableDriverConfigBeforeRPC(t *testing.T) {
	mock := newMockSandboxTemplateServer()
	client, cleanup := setupSandboxTemplateTest(t, mock)
	defer cleanup()

	_, err := client.Create(context.Background(), "default", &SandboxWorkloadTemplate{
		Name: "bad",
		Spec: SandboxWorkloadTemplateSpec{
			DriverConfig: map[string]any{"invalid": make(chan int)},
		},
	})

	require.Error(t, err)
	assert.True(t, IsInvalidArgument(err))
	mock.mu.Lock()
	defer mock.mu.Unlock()
	assert.Nil(t, mock.createRequest)
}

func TestSandboxTemplateGetListDelete(t *testing.T) {
	mock := newMockSandboxTemplateServer()
	mock.templates["gpu-kata"] = &pb.SandboxWorkloadTemplate{
		Metadata: &dm.ObjectMeta{Name: "gpu-kata", Workspace: "default"},
		Spec: &pb.SandboxWorkloadTemplateSpec{
			Workload: &pb.SandboxWorkloadConfig{Image: "img:v1"},
		},
	}
	client, cleanup := setupSandboxTemplateTest(t, mock)
	defer cleanup()

	got, err := client.Get(context.Background(), "default", "gpu-kata")
	require.NoError(t, err)
	assert.Equal(t, "gpu-kata", got.Name)
	assert.Equal(t, "img:v1", got.Spec.Workload.Image)

	list, err := client.List(context.Background(), "default", ListOptions{
		Limit:         10,
		Offset:        2,
		LabelSelector: "team=runtime",
		AllWorkspaces: true,
	})
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, "gpu-kata", list[0].Name)

	deleted, err := client.Delete(context.Background(), "default", "gpu-kata")
	require.NoError(t, err)
	assert.True(t, deleted)

	mock.mu.Lock()
	defer mock.mu.Unlock()
	require.NotNil(t, mock.getRequest)
	assert.Equal(t, "default", mock.getRequest.Workspace)
	assert.Equal(t, "gpu-kata", mock.getRequest.Name)
	require.NotNil(t, mock.listRequest)
	assert.Empty(t, mock.listRequest.Workspace)
	assert.Equal(t, uint32(10), mock.listRequest.Limit)
	assert.Equal(t, uint32(2), mock.listRequest.Offset)
	assert.Equal(t, "team=runtime", mock.listRequest.LabelSelector)
	assert.True(t, mock.listRequest.AllWorkspaces)
	require.NotNil(t, mock.deleteRequest)
	assert.Equal(t, "default", mock.deleteRequest.Workspace)
	assert.Equal(t, "gpu-kata", mock.deleteRequest.Name)
}

func TestSandboxTemplateList_RejectsNegativePagination(t *testing.T) {
	mock := newMockSandboxTemplateServer()
	client, cleanup := setupSandboxTemplateTest(t, mock)
	defer cleanup()

	_, err := client.List(context.Background(), "default", ListOptions{Limit: -1})
	require.Error(t, err)
	assert.True(t, IsInvalidArgument(err))

	_, err = client.List(context.Background(), "default", ListOptions{Offset: -1})
	require.Error(t, err)
	assert.True(t, IsInvalidArgument(err))
}
