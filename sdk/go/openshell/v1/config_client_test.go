// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"
	"net"
	"sync"
	"testing"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	sbv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/sandboxv1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

// --- Mock server for Config RPCs ---

type mockConfigServer struct {
	pb.UnimplementedOpenShellServer
	mu sync.Mutex

	// Canned responses.
	sandboxResp *sbv1.GetSandboxConfigResponse
	gatewayResp *sbv1.GetGatewayConfigResponse
	updateResp  *pb.UpdateConfigResponse

	// Recorded requests.
	lastSandboxReq *sbv1.GetSandboxConfigRequest
	lastGatewayReq *sbv1.GetGatewayConfigRequest
	lastUpdateReq  *pb.UpdateConfigRequest

	// Inject errors.
	sandboxErr error
	gatewayErr error
	updateErr  error
}

func newMockConfigServer() *mockConfigServer {
	return &mockConfigServer{}
}

func (s *mockConfigServer) GetSandboxConfig(_ context.Context, req *sbv1.GetSandboxConfigRequest) (*sbv1.GetSandboxConfigResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastSandboxReq = req
	if s.sandboxErr != nil {
		return nil, s.sandboxErr
	}
	return s.sandboxResp, nil
}

func (s *mockConfigServer) GetGatewayConfig(_ context.Context, req *sbv1.GetGatewayConfigRequest) (*sbv1.GetGatewayConfigResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastGatewayReq = req
	if s.gatewayErr != nil {
		return nil, s.gatewayErr
	}
	return s.gatewayResp, nil
}

func (s *mockConfigServer) UpdateConfig(_ context.Context, req *pb.UpdateConfigRequest) (*pb.UpdateConfigResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastUpdateReq = req
	if s.updateErr != nil {
		return nil, s.updateErr
	}
	return s.updateResp, nil
}

// --- Test setup ---

func setupConfigTest(t *testing.T, mock *mockConfigServer) (*configClient, func()) {
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

	return newConfigClient(conn, &stubSandboxResolver{}), func() {
		_ = conn.Close()
		srv.Stop()
	}
}

// --- GetSandbox tests ---

func TestConfigGetSandbox(t *testing.T) {
	mock := newMockConfigServer()
	mock.sandboxResp = &sbv1.GetSandboxConfigResponse{
		Policy: &sbv1.SandboxPolicy{
			Version: 4,
			Filesystem: &sbv1.FilesystemPolicy{
				ReadOnly: []string{"/etc"},
			},
		},
		Version:             3,
		PolicyHash:          "sha256:deadbeef",
		ConfigRevision:      42,
		PolicySource:        sbv1.PolicySource_POLICY_SOURCE_SANDBOX,
		GlobalPolicyVersion: 1,
		ProviderEnvRevision: 7,
		Settings: map[string]*sbv1.EffectiveSetting{
			"max_tokens": {
				Value: &sbv1.SettingValue{
					Value: &sbv1.SettingValue_IntValue{IntValue: 4096},
				},
				Scope: sbv1.SettingScope_SETTING_SCOPE_SANDBOX,
			},
			"debug": {
				Value: &sbv1.SettingValue{
					Value: &sbv1.SettingValue_BoolValue{BoolValue: true},
				},
				Scope: sbv1.SettingScope_SETTING_SCOPE_GLOBAL,
			},
		},
	}

	client, cleanup := setupConfigTest(t, mock)
	defer cleanup()

	sc, err := client.GetSandbox(context.Background(), "default", "my-sandbox")

	require.NoError(t, err)
	require.NotNil(t, sc)

	// Verify request was forwarded with resolved ID (stubSandboxResolver returns "sb-<name>").
	mock.mu.Lock()
	assert.Equal(t, "sb-my-sandbox", mock.lastSandboxReq.GetSandboxId())
	mock.mu.Unlock()

	// Scalar fields.
	assert.Equal(t, uint32(3), sc.PolicyVersion)
	assert.Equal(t, "sha256:deadbeef", sc.PolicyHash)
	assert.Equal(t, uint64(42), sc.ConfigRevision)
	assert.Equal(t, PolicySource("sandbox"), sc.PolicySource)
	assert.Equal(t, uint32(1), sc.GlobalPolicyVersion)
	assert.Equal(t, uint64(7), sc.ProviderEnvRevision)

	// Typed SandboxPolicy.
	require.NotNil(t, sc.Policy)
	assert.Equal(t, uint32(4), sc.Policy.Version)
	require.NotNil(t, sc.Policy.Filesystem)
	assert.Equal(t, []string{"/etc"}, sc.Policy.Filesystem.ReadOnly)

	// Settings map.
	require.Len(t, sc.Settings, 2)

	maxTok := sc.Settings["max_tokens"]
	assert.Equal(t, SettingValueType("int"), maxTok.Value.Type)
	assert.Equal(t, int64(4096), maxTok.Value.IntVal)
	assert.Equal(t, SettingScope("sandbox"), maxTok.Scope)

	debug := sc.Settings["debug"]
	assert.Equal(t, SettingValueType("bool"), debug.Value.Type)
	assert.True(t, debug.Value.BoolVal)
	assert.Equal(t, SettingScope("global"), debug.Scope)
}

func TestConfigGetSandbox_DeepCopy(t *testing.T) {
	mock := newMockConfigServer()
	mock.sandboxResp = &sbv1.GetSandboxConfigResponse{
		Version: 1,
		Settings: map[string]*sbv1.EffectiveSetting{
			"key": {
				Value: &sbv1.SettingValue{
					Value: &sbv1.SettingValue_BytesValue{BytesValue: []byte("original")},
				},
				Scope: sbv1.SettingScope_SETTING_SCOPE_SANDBOX,
			},
		},
	}

	client, cleanup := setupConfigTest(t, mock)
	defer cleanup()

	sc, err := client.GetSandbox(context.Background(), "default", "sb1")
	require.NoError(t, err)

	// Mutate the returned setting — should not affect future calls.
	sc.Settings["key"] = EffectiveSetting{}

	sc2, err := client.GetSandbox(context.Background(), "default", "sb1")
	require.NoError(t, err)

	// The server still returns the original value — verifies we're not
	// sharing references between calls.
	require.Contains(t, sc2.Settings, "key")
	assert.Equal(t, []byte("original"), sc2.Settings["key"].Value.BytesVal)
}

func TestConfigGetSandbox_Error(t *testing.T) {
	mock := newMockConfigServer()
	mock.sandboxErr = status.Errorf(codes.Unavailable, "server unavailable")

	client, cleanup := setupConfigTest(t, mock)
	defer cleanup()

	sc, err := client.GetSandbox(context.Background(), "default", "my-sandbox")

	assert.Nil(t, sc)
	require.Error(t, err)
	assert.True(t, IsUnavailable(err))
}

// --- Name-to-ID resolution tests ---

func TestConfigGetSandbox_ResolvesNameToID(t *testing.T) {
	mock := newMockConfigServer()
	mock.sandboxResp = &sbv1.GetSandboxConfigResponse{Version: 1}

	client, cleanup := setupConfigTest(t, mock)
	defer cleanup()

	sc, err := client.GetSandbox(context.Background(), "default", "my-sandbox")
	require.NoError(t, err)
	require.NotNil(t, sc)

	// stubSandboxResolver returns ID "sb-<name>" — verify the proto has the resolved ID, not the name.
	mock.mu.Lock()
	assert.Equal(t, "sb-my-sandbox", mock.lastSandboxReq.GetSandboxId(), "GetSandbox should send resolved sandbox ID, not the name")
	mock.mu.Unlock()
}

func TestConfigGetSandbox_ResolutionError(t *testing.T) {
	mock := newMockConfigServer()
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
	defer func() {
		_ = conn.Close()
		srv.Stop()
	}()

	resolver := &stubSandboxResolver{
		getErr: &StatusError{Code: ErrorNotFound, Message: "sandbox not found"},
	}
	client := newConfigClient(conn, resolver)

	sc, err := client.GetSandbox(context.Background(), "default", "nonexistent")
	assert.Nil(t, sc)
	require.Error(t, err)
	assert.True(t, IsNotFound(err))
}

// --- GetGateway tests ---

func TestConfigGetGateway(t *testing.T) {
	mock := newMockConfigServer()
	mock.gatewayResp = &sbv1.GetGatewayConfigResponse{
		SettingsRevision: 99,
		Settings: map[string]*sbv1.SettingValue{
			"rate_limit": {
				Value: &sbv1.SettingValue_IntValue{IntValue: 1000},
			},
			"motd": {
				Value: &sbv1.SettingValue_StringValue{StringValue: "welcome"},
			},
		},
	}

	client, cleanup := setupConfigTest(t, mock)
	defer cleanup()

	gc, err := client.GetGateway(context.Background())

	require.NoError(t, err)
	require.NotNil(t, gc)

	assert.Equal(t, uint64(99), gc.SettingsRevision)
	require.Len(t, gc.Settings, 2)

	rl := gc.Settings["rate_limit"]
	assert.Equal(t, SettingValueType("int"), rl.Type)
	assert.Equal(t, int64(1000), rl.IntVal)

	motd := gc.Settings["motd"]
	assert.Equal(t, SettingValueType("string"), motd.Type)
	assert.Equal(t, "welcome", motd.StringVal)
}

func TestConfigGetGateway_Error(t *testing.T) {
	mock := newMockConfigServer()
	mock.gatewayErr = status.Errorf(codes.Internal, "internal error")

	client, cleanup := setupConfigTest(t, mock)
	defer cleanup()

	gc, err := client.GetGateway(context.Background())

	assert.Nil(t, gc)
	require.Error(t, err)
	var se *StatusError
	require.ErrorAs(t, err, &se)
	assert.Equal(t, ErrorInternal, se.Code)
}

// --- Update tests ---

func TestConfigUpdate_SandboxScope(t *testing.T) {
	mock := newMockConfigServer()
	mock.updateResp = &pb.UpdateConfigResponse{
		Version:          5,
		PolicyHash:       "sha256:cafe",
		SettingsRevision: 10,
		Deleted:          false,
	}

	client, cleanup := setupConfigTest(t, mock)
	defer cleanup()

	update := &ConfigUpdate{
		Name:       "my-sandbox",
		SettingKey: "max_tokens",
		SettingValue: &SettingValue{
			Type:   SettingValueInt,
			IntVal: 8192,
		},
		ExpectedResourceVersion: 4,
	}

	result, err := client.Update(context.Background(), "default", update)

	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, uint32(5), result.Version)
	assert.Equal(t, "sha256:cafe", result.PolicyHash)
	assert.Equal(t, uint64(10), result.SettingsRevision)
	assert.False(t, result.Deleted)

	// Verify request was correctly converted.
	mock.mu.Lock()
	req := mock.lastUpdateReq
	mock.mu.Unlock()

	require.NotNil(t, req)
	assert.Equal(t, "my-sandbox", req.GetName())
	assert.Equal(t, "max_tokens", req.GetSettingKey())
	assert.False(t, req.GetGlobal())
	assert.Equal(t, uint64(4), req.GetExpectedResourceVersion())
	assert.Equal(t, int64(8192), req.GetSettingValue().GetIntValue())
}

func TestConfigUpdate_GlobalScope(t *testing.T) {
	mock := newMockConfigServer()
	mock.updateResp = &pb.UpdateConfigResponse{
		SettingsRevision: 20,
	}

	client, cleanup := setupConfigTest(t, mock)
	defer cleanup()

	update := &ConfigUpdate{
		Global:     true,
		SettingKey: "global_flag",
		SettingValue: &SettingValue{
			Type:    SettingValueBool,
			BoolVal: true,
		},
	}

	result, err := client.Update(context.Background(), "default", update)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, uint64(20), result.SettingsRevision)

	mock.mu.Lock()
	req := mock.lastUpdateReq
	mock.mu.Unlock()

	assert.True(t, req.GetGlobal())
	assert.Empty(t, req.GetName())
}

func TestConfigUpdate_DeleteSetting(t *testing.T) {
	mock := newMockConfigServer()
	mock.updateResp = &pb.UpdateConfigResponse{
		SettingsRevision: 15,
		Deleted:          true,
	}

	client, cleanup := setupConfigTest(t, mock)
	defer cleanup()

	update := &ConfigUpdate{
		Name:          "my-sandbox",
		SettingKey:    "deprecated_key",
		DeleteSetting: true,
	}

	result, err := client.Update(context.Background(), "default", update)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Deleted)
	assert.Equal(t, uint64(15), result.SettingsRevision)

	mock.mu.Lock()
	req := mock.lastUpdateReq
	mock.mu.Unlock()

	assert.True(t, req.GetDeleteSetting())
}

func TestConfigUpdate_WithPolicy(t *testing.T) {
	mock := newMockConfigServer()
	mock.updateResp = &pb.UpdateConfigResponse{
		Version:    2,
		PolicyHash: "sha256:newpolicy",
	}

	client, cleanup := setupConfigTest(t, mock)
	defer cleanup()

	update := &ConfigUpdate{
		Name: "my-sandbox",
		Policy: &types.SandboxPolicy{
			Version: 5,
			Filesystem: &types.FilesystemPolicy{
				ReadOnly: []string{"/usr"},
			},
		},
	}

	result, err := client.Update(context.Background(), "default", update)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, uint32(2), result.Version)

	// Verify the typed policy was converted and sent as proto.
	mock.mu.Lock()
	req := mock.lastUpdateReq
	mock.mu.Unlock()

	require.NotNil(t, req.GetPolicy())
	assert.Equal(t, uint32(5), req.GetPolicy().GetVersion())
	require.NotNil(t, req.GetPolicy().GetFilesystem())
	assert.Equal(t, []string{"/usr"}, req.GetPolicy().GetFilesystem().GetReadOnly())
}

func TestConfigUpdate_RejectsUnrepresentableMiddlewareConfigBeforeRPC(t *testing.T) {
	mock := newMockConfigServer()
	client, cleanup := setupConfigTest(t, mock)
	defer cleanup()

	_, err := client.Update(context.Background(), "default", &ConfigUpdate{Policy: &SandboxPolicy{
		NetworkMiddlewares: map[string]types.NetworkMiddlewareConfig{
			"audit": {Config: map[string]any{"invalid": make(chan int)}},
		},
	}})
	require.Error(t, err)
	assert.True(t, IsInvalidArgument(err))
	mock.mu.Lock()
	defer mock.mu.Unlock()
	assert.Nil(t, mock.lastUpdateReq)
}

func TestConfigUpdate_Error(t *testing.T) {
	mock := newMockConfigServer()
	mock.updateErr = status.Errorf(codes.FailedPrecondition, "version mismatch")

	client, cleanup := setupConfigTest(t, mock)
	defer cleanup()

	update := &ConfigUpdate{
		Name:                    "my-sandbox",
		SettingKey:              "key",
		ExpectedResourceVersion: 99,
	}

	result, err := client.Update(context.Background(), "default", update)

	assert.Nil(t, result)
	require.Error(t, err)
	var se *StatusError
	require.ErrorAs(t, err, &se)
	assert.Equal(t, ErrorConflict, se.Code)
}

func TestConfigUpdate_NilUpdate(t *testing.T) {
	mock := newMockConfigServer()
	client, cleanup := setupConfigTest(t, mock)
	defer cleanup()

	result, err := client.Update(context.Background(), "default", nil)

	assert.Nil(t, result)
	require.Error(t, err)
	assert.True(t, IsInvalidArgument(err))
}

func TestConfigUpdate_MergeOperationsAccepted(t *testing.T) {
	mock := newMockConfigServer()
	mock.updateResp = &pb.UpdateConfigResponse{
		Version:    3,
		PolicyHash: "abc123",
	}
	client, cleanup := setupConfigTest(t, mock)
	defer cleanup()

	update := &ConfigUpdate{
		Name:            "my-sandbox",
		MergeOperations: []types.PolicyMergeOperation{{RemoveRule: &types.RemoveNetworkRule{RuleName: "test"}}},
	}

	result, err := client.Update(context.Background(), "default", update)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, uint32(3), result.Version)
	assert.Equal(t, "abc123", result.PolicyHash)

	// Verify the merge operations were serialized in the proto request
	mock.mu.Lock()
	req := mock.lastUpdateReq
	mock.mu.Unlock()
	require.NotNil(t, req)
	assert.NotEmpty(t, req.GetMergeOperations(), "MergeOperations should be serialized to proto")
}

func TestConfigUpdate_ErrorConflict(t *testing.T) {
	mock := newMockConfigServer()
	mock.updateErr = status.Error(codes.Aborted, "resource version conflict")
	client, cleanup := setupConfigTest(t, mock)
	defer cleanup()

	update := &ConfigUpdate{
		Name:                    "my-sandbox",
		ExpectedResourceVersion: 5,
	}

	result, err := client.Update(context.Background(), "default", update)

	assert.Nil(t, result)
	require.Error(t, err)
	assert.True(t, IsConflict(err))
}

func TestConfigGetSandbox_EmptySandboxName(t *testing.T) {
	mock := newMockConfigServer()
	client, cleanup := setupConfigTest(t, mock)
	defer cleanup()

	cfg, err := client.GetSandbox(context.Background(), "default", "")
	assert.Nil(t, cfg)
	require.Error(t, err)
	assert.True(t, IsInvalidArgument(err))
}
