// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package compatibility_test

import (
	"context"
	"net"
	"testing"

	dm "github.com/NVIDIA/OpenShell/sdk/go/proto/datamodelv1"
	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func TestSandboxStatusRetainsBaselinePublicShape(t *testing.T) {
	// Freeze the pre-image-update fields and tags: private operation state must
	// not enlarge the public Rust struct or leak into generated SDK messages.
	fields := []string{
		"agent_pod", "agent_fd", "sandbox_fd", "conditions", "phase",
		"current_policy_version", "main_process_instance_id", "exit_code",
		"endpoint_statuses", "configuration_admission", "configuration_activated",
		"provisioning", "restart_count", "next_restart_time",
		"main_process_started_time", "last_token_grant_failure",
	}
	descriptor := (&pb.SandboxStatus{}).ProtoReflect().Descriptor()
	require.Equal(t, len(fields), descriptor.Fields().Len())
	for i, name := range fields {
		field := descriptor.Fields().ByName(protoreflect.Name(name))
		require.NotNil(t, field, name)
		require.Equal(t, protoreflect.FieldNumber(i+2), field.Number(), name)
	}
	require.Nil(t, pb.File_openshell_proto.Messages().ByName("SandboxImageUpdate"))
	legacy := pb.File_openshell_proto.Services().ByName("OpenShell")
	require.Nil(t, legacy.Methods().ByName("UpdateSandbox"))
	updates := pb.File_openshell_proto.Services().ByName("SandboxUpdates")
	require.NotNil(t, updates)
	require.Equal(t, 1, updates.Methods().Len())
	method := updates.Methods().Get(0)
	require.Equal(t, protoreflect.FullName("openshell.v1.UpdateSandboxRequest"), method.Input().FullName())
	require.Equal(t, protoreflect.FullName("openshell.v1.SandboxResponse"), method.Output().FullName())
	require.Equal(t, "/openshell.v1.SandboxUpdates/UpdateSandbox", pb.SandboxUpdates_UpdateSandbox_FullMethodName)
}

type legacyHealthServer struct {
	pb.UnimplementedOpenShellServer
}

func (legacyHealthServer) Health(context.Context, *pb.HealthRequest) (*pb.HealthResponse, error) {
	return &pb.HealthResponse{Version: "legacy-compatible"}, nil
}

type imageUpdateServer struct {
	pb.UnimplementedSandboxUpdatesServer
	request *pb.UpdateSandboxRequest
}

func (s *imageUpdateServer) UpdateSandbox(_ context.Context, request *pb.UpdateSandboxRequest) (*pb.SandboxResponse, error) {
	s.request = proto.Clone(request).(*pb.UpdateSandboxRequest)
	return &pb.SandboxResponse{Sandbox: &pb.Sandbox{
		Metadata: &dm.ObjectMeta{Id: "stable-id", Name: request.Name, Workspace: request.WorkspaceScope.GetWorkspace()},
		Spec:     &pb.SandboxSpec{Template: &pb.SandboxTemplate{Image: request.Image}},
	}}, nil
}

func TestSeparateSandboxUpdatesTransportCoexistsWithLegacyOpenShell(t *testing.T) {
	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer(grpc.UnaryInterceptor(func(ctx context.Context, request any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if info.FullMethod == pb.SandboxUpdates_UpdateSandbox_FullMethodName {
			md, _ := metadata.FromIncomingContext(ctx)
			if len(md.Get("authorization")) == 0 {
				return nil, status.Error(codes.Unauthenticated, "bearer required")
			}
		}
		return handler(ctx, request)
	}))
	updatesServer := &imageUpdateServer{}
	pb.RegisterOpenShellServer(server, legacyHealthServer{})
	pb.RegisterSandboxUpdatesServer(server, updatesServer)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	t.Cleanup(func() { _ = listener.Close() })
	conn, err := grpc.NewClient("passthrough:///sandbox-updates", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
		return listener.Dial()
	}))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	legacy := pb.NewOpenShellClient(conn)
	health, err := legacy.Health(context.Background(), &pb.HealthRequest{})
	require.NoError(t, err)
	require.Equal(t, "legacy-compatible", health.Version)
	updates := pb.NewSandboxUpdatesClient(conn)
	request := &pb.UpdateSandboxRequest{
		WorkspaceScope:          &dm.WorkspaceSelector{Selection: &dm.WorkspaceSelector_Workspace{Workspace: "team"}},
		Name:                    "sandbox",
		Image:                   "example/workload:new",
		ExpectedResourceVersion: 42,
		RequestId:               "550e8400-e29b-41d4-a716-446655440000",
	}
	_, err = updates.UpdateSandbox(context.Background(), request)
	require.Equal(t, codes.Unauthenticated, status.Code(err))
	require.Nil(t, updatesServer.request)
	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("authorization", "Bearer test-token"))
	response, err := updates.UpdateSandbox(ctx, request)
	require.NoError(t, err)
	require.True(t, proto.Equal(request, updatesServer.request))
	require.Equal(t, "stable-id", response.Sandbox.Metadata.Id)
	require.Equal(t, "team", response.Sandbox.Metadata.Workspace)
	require.Equal(t, request.Image, response.Sandbox.Spec.Template.Image)
	// The old service has no accidental update endpoint.
	err = conn.Invoke(ctx, "/openshell.v1.OpenShell/UpdateSandbox", request, &pb.SandboxResponse{})
	require.Equal(t, codes.Unimplemented, status.Code(err))
}
