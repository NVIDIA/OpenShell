// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"
	"net"
	"testing"

	dm "github.com/NVIDIA/OpenShell/sdk/go/proto/datamodelv1"
	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	sbv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/sandboxv1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

type frozenPolicyServer struct {
	pb.UnimplementedFrozenSandboxPoliciesServer
	createRequest *pb.CreateFrozenSandboxRequest
	getRequest    *pb.GetFrozenSandboxPolicyRequest
	updateRequest *pb.UpdateFrozenGlobalConfigRequest
	ack           *pb.FrozenSandboxPolicyState
	state         *pb.FrozenSandboxPolicyState
}

func (s *frozenPolicyServer) CreateSandbox(_ context.Context, request *pb.CreateFrozenSandboxRequest) (*pb.FrozenSandboxResponse, error) {
	s.createRequest = request
	return &pb.FrozenSandboxResponse{
		Sandbox:      &pb.Sandbox{Metadata: &dm.ObjectMeta{Id: "created-id", Name: request.Name, Workspace: request.GetWorkspaceScope().GetWorkspace()}},
		FrozenPolicy: s.ack,
		ServiceUrls:  map[string]string{"web": "https://web.example"},
	}, nil
}

func (s *frozenPolicyServer) GetPolicy(_ context.Context, request *pb.GetFrozenSandboxPolicyRequest) (*pb.FrozenSandboxPolicyState, error) {
	s.getRequest = request
	return s.state, nil
}

func (s *frozenPolicyServer) UpdateGlobalConfig(_ context.Context, request *pb.UpdateFrozenGlobalConfigRequest) (*pb.UpdateFrozenGlobalConfigResponse, error) {
	s.updateRequest = request
	return &pb.UpdateFrozenGlobalConfigResponse{Update: &pb.UpdateConfigResponse{Version: 7}, FrozenSandboxes: []string{"staging/frozen"}}, nil
}

func frozenTestClient(t *testing.T, frozen *frozenPolicyServer) (*Client, *mockSandboxServer) {
	t.Helper()
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer()
	legacy := newMockSandboxServer()
	pb.RegisterOpenShellServer(server, legacy)
	if frozen != nil {
		pb.RegisterFrozenSandboxPoliciesServer(server, frozen)
	}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	conn, err := grpc.NewClient("passthrough:///frozen-test", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return &Client{conn: conn}, legacy
}

func TestFrozenPoliciesCreateUsesOptionalService(t *testing.T) {
	for _, template := range []bool{false, true} {
		for _, ack := range []*pb.FrozenSandboxPolicyState{nil, {}, {Requested: true}} {
			t.Run(nameForFrozenCase(template, ack), func(t *testing.T) {
				server := &frozenPolicyServer{ack: ack}
				client, legacy := frozenTestClient(t, server)
				spec := &SandboxSpec{Policy: &SandboxPolicy{Version: 1}, Providers: []string{"github"}}
				var sandbox *Sandbox
				var err error
				if template {
					sandbox, err = client.FrozenPolicies().CreateFromTemplate(context.Background(), "staging", "frozen", "agent", spec)
				} else {
					sandbox, err = client.FrozenPolicies().Create(context.Background(), "staging", "frozen", spec)
				}
				if ack.GetRequested() {
					require.NoError(t, err)
					assert.Equal(t, "https://web.example", sandbox.ServiceURLs["web"])
				} else {
					require.ErrorContains(t, err, "did not acknowledge frozen creation")
					assert.ErrorContains(t, err, "created-id")
					assert.Nil(t, sandbox)
				}
				require.NotNil(t, server.createRequest)
				assert.Equal(t, "staging", server.createRequest.GetWorkspaceScope().GetWorkspace())
				assert.Equal(t, uint32(1), server.createRequest.GetSpec().GetPolicy().GetVersion())
				assert.Equal(t, []string{"github"}, server.createRequest.GetSpec().GetProviders())
				if template {
					assert.Equal(t, "agent", server.createRequest.WorkloadTemplate)
				}
				assert.Nil(t, legacy.createRequest)
			})
		}
	}
}

func nameForFrozenCase(template bool, ack *pb.FrozenSandboxPolicyState) string {
	name := "direct"
	if template {
		name = "template"
	}
	if ack == nil {
		return name + "/missing"
	}
	if ack.Requested {
		return name + "/accepted"
	}
	return name + "/declined"
}

func TestFrozenPoliciesOlderGatewayDoesNotCreate(t *testing.T) {
	client, legacy := frozenTestClient(t, nil)
	_, err := client.FrozenPolicies().Create(context.Background(), "default", "frozen", &SandboxSpec{})
	require.Error(t, err)
	assert.True(t, IsUnimplemented(err))
	assert.Nil(t, legacy.createRequest)
}

func TestFrozenPoliciesReadsPendingAndCapturedPolicyAndGlobalExceptions(t *testing.T) {
	server := &frozenPolicyServer{state: &pb.FrozenSandboxPolicyState{Requested: true}}
	client, _ := frozenTestClient(t, server)
	state, err := client.FrozenPolicies().Get(context.Background(), "staging", "frozen")
	require.NoError(t, err)
	assert.True(t, state.Requested)
	assert.Nil(t, state.Policy)
	server.state.Policy = &pb.FrozenSandboxPolicy{Policy: &sbv1.SandboxPolicy{Version: 1}, Version: 3, PolicyHash: "accepted-hash", PolicySource: sbv1.PolicySource_POLICY_SOURCE_GLOBAL, GlobalPolicyVersion: 7}
	state, err = client.FrozenPolicies().Get(context.Background(), "staging", "frozen")
	require.NoError(t, err)
	require.NotNil(t, state.Policy)
	assert.Equal(t, "accepted-hash", state.Policy.PolicyHash)
	assert.Equal(t, PolicySourceGlobal, state.Policy.PolicySource)
	assert.Equal(t, "staging", server.getRequest.GetWorkspaceScope().GetWorkspace())
	update := &ConfigUpdate{Policy: &SandboxPolicy{Version: 1}}
	result, err := client.FrozenPolicies().UpdateGlobalConfig(context.Background(), update)
	require.NoError(t, err)
	assert.Equal(t, []string{"staging/frozen"}, result.FrozenSandboxes)
	assert.Equal(t, uint32(7), result.Update.Version)
	assert.True(t, server.updateRequest.Global)
	assert.False(t, update.Global, "the caller's mutation is not modified")
}

func TestFrozenPoliciesUpdateGlobalConfigRejectsSandboxSelector(t *testing.T) {
	server := &frozenPolicyServer{}
	client, _ := frozenTestClient(t, server)
	update := &ConfigUpdate{Name: "production", Policy: &SandboxPolicy{Version: 1}}
	result, err := client.FrozenPolicies().UpdateGlobalConfig(context.Background(), update)
	require.ErrorContains(t, err, "must not specify a sandbox name")
	assert.True(t, IsInvalidArgument(err))
	assert.Nil(t, result)
	assert.Nil(t, server.updateRequest, "invalid sandbox selectors must not reach the global mutation RPC")
	assert.Equal(t, "production", update.Name)
	assert.False(t, update.Global)
}
