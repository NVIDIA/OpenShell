// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

// --- Mock server for credential refresh ---

type mockRefreshServer struct {
	pb.UnimplementedOpenShellServer
	mu           sync.Mutex
	statuses     map[string]*pb.ProviderCredentialRefreshStatus // key: "provider/credentialKey"
	getStatusErr error
	configureErr error
	rotateErr    error
	deleteErr    error
}

func newMockRefreshServer() *mockRefreshServer {
	return &mockRefreshServer{
		statuses: make(map[string]*pb.ProviderCredentialRefreshStatus),
	}
}

func refreshKey(provider, credentialKey string) string {
	return provider + "/" + credentialKey
}

func (s *mockRefreshServer) GetProviderRefreshStatus(_ context.Context, req *pb.GetProviderRefreshStatusRequest) (*pb.GetProviderRefreshStatusResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.getStatusErr != nil {
		return nil, s.getStatusErr
	}

	var creds []*pb.ProviderCredentialRefreshStatus
	if req.GetCredentialKey() != "" {
		// Return specific credential
		st, ok := s.statuses[refreshKey(req.GetProvider(), req.GetCredentialKey())]
		if ok {
			creds = append(creds, st)
		}
	} else {
		// Return all credentials for provider
		for key, st := range s.statuses {
			if len(key) > len(req.GetProvider()) && key[:len(req.GetProvider())+1] == req.GetProvider()+"/" {
				creds = append(creds, st)
			}
		}
	}
	return &pb.GetProviderRefreshStatusResponse{Credentials: creds}, nil
}

func (s *mockRefreshServer) ConfigureProviderRefresh(_ context.Context, req *pb.ConfigureProviderRefreshRequest) (*pb.ConfigureProviderRefreshResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.configureErr != nil {
		return nil, s.configureErr
	}

	st := &pb.ProviderCredentialRefreshStatus{
		ProviderName:  req.GetProvider(),
		ProviderId:    "prov-id-" + req.GetProvider(),
		CredentialKey: req.GetCredentialKey(),
		Strategy:      req.GetStrategy(),
		Status:        "active",
		ExpiresAtMs:   req.GetExpiresAtMs(),
	}
	s.statuses[refreshKey(req.GetProvider(), req.GetCredentialKey())] = st
	return &pb.ConfigureProviderRefreshResponse{Status: st}, nil
}

func (s *mockRefreshServer) RotateProviderCredential(_ context.Context, req *pb.RotateProviderCredentialRequest) (*pb.RotateProviderCredentialResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rotateErr != nil {
		return nil, s.rotateErr
	}

	key := refreshKey(req.GetProvider(), req.GetCredentialKey())
	st, ok := s.statuses[key]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "refresh config %q not found", key)
	}
	st.Status = "rotated"
	st.LastRefreshAtMs = time.Now().UnixMilli()
	return &pb.RotateProviderCredentialResponse{Status: st}, nil
}

func (s *mockRefreshServer) DeleteProviderRefresh(_ context.Context, req *pb.DeleteProviderRefreshRequest) (*pb.DeleteProviderRefreshResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.deleteErr != nil {
		return nil, s.deleteErr
	}

	key := refreshKey(req.GetProvider(), req.GetCredentialKey())
	_, ok := s.statuses[key]
	if !ok {
		return &pb.DeleteProviderRefreshResponse{Deleted: false}, nil
	}
	delete(s.statuses, key)
	return &pb.DeleteProviderRefreshResponse{Deleted: true}, nil
}

// --- Test setup ---

func setupRefreshTest(t *testing.T, mock *mockRefreshServer) (*refreshClient, func()) {
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

	return newRefreshClient(conn), func() {
		_ = conn.Close()
		srv.Stop()
	}
}

// --- GetStatus tests ---

func TestRefreshGetStatus(t *testing.T) {
	mock := newMockRefreshServer()
	client, cleanup := setupRefreshTest(t, mock)
	defer cleanup()

	// Configure a credential first
	cfg := &RefreshConfig{
		Provider:      "openai",
		CredentialKey: "api-key",
		Strategy:      RefreshStrategyOAuth2RefreshToken,
		Material:      map[string]string{"refresh_token": "tok-123"},
	}
	_, err := client.Configure(context.Background(), "default", cfg)
	require.NoError(t, err)

	// Get status for specific credential
	statuses, err := client.GetStatus(context.Background(), "default", "openai", "api-key")

	require.NoError(t, err)
	require.Len(t, statuses, 1)
	assert.Equal(t, "openai", statuses[0].ProviderName)
	assert.Equal(t, "api-key", statuses[0].CredentialKey)
	assert.Equal(t, RefreshStrategyOAuth2RefreshToken, statuses[0].Strategy)
	assert.Equal(t, "active", statuses[0].Status)
}

func TestRefreshGetStatus_AllCredentials(t *testing.T) {
	mock := newMockRefreshServer()
	client, cleanup := setupRefreshTest(t, mock)
	defer cleanup()

	// Configure two credentials
	_, err := client.Configure(context.Background(), "default", &RefreshConfig{
		Provider:      "openai",
		CredentialKey: "key-1",
		Strategy:      RefreshStrategyStatic,
	})
	require.NoError(t, err)
	_, err = client.Configure(context.Background(), "default", &RefreshConfig{
		Provider:      "openai",
		CredentialKey: "key-2",
		Strategy:      RefreshStrategyExternal,
	})
	require.NoError(t, err)

	// Get all statuses (empty credentialKey)
	statuses, err := client.GetStatus(context.Background(), "default", "openai", "")

	require.NoError(t, err)
	assert.Len(t, statuses, 2)
}

func TestRefreshGetStatus_Empty(t *testing.T) {
	mock := newMockRefreshServer()
	client, cleanup := setupRefreshTest(t, mock)
	defer cleanup()

	statuses, err := client.GetStatus(context.Background(), "default", "openai", "nonexistent")

	require.NoError(t, err)
	assert.Empty(t, statuses)
}

func TestRefreshGetStatus_Error(t *testing.T) {
	mock := newMockRefreshServer()
	mock.getStatusErr = status.Errorf(codes.Internal, "internal error")
	client, cleanup := setupRefreshTest(t, mock)
	defer cleanup()

	statuses, err := client.GetStatus(context.Background(), "default", "openai", "key")

	assert.Nil(t, statuses)
	require.Error(t, err)
}

// --- Configure tests ---

func TestRefreshConfigure(t *testing.T) {
	mock := newMockRefreshServer()
	client, cleanup := setupRefreshTest(t, mock)
	defer cleanup()

	expires := time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC)
	cfg := &RefreshConfig{
		Provider:           "openai",
		CredentialKey:      "api-key",
		Strategy:           RefreshStrategyOAuth2ClientCredentials,
		Material:           map[string]string{"client_id": "id-1", "client_secret": "sec-1"},
		SecretMaterialKeys: []string{"client_secret"},
		ExpiresAt:          &expires,
	}

	result, err := client.Configure(context.Background(), "default", cfg)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "openai", result.ProviderName)
	assert.Equal(t, "prov-id-openai", result.ProviderID)
	assert.Equal(t, "api-key", result.CredentialKey)
	assert.Equal(t, RefreshStrategyOAuth2ClientCredentials, result.Strategy)
	assert.Equal(t, "active", result.Status)
}

func TestRefreshConfigure_MinimalConfig(t *testing.T) {
	mock := newMockRefreshServer()
	client, cleanup := setupRefreshTest(t, mock)
	defer cleanup()

	cfg := &RefreshConfig{
		Provider:      "anthropic",
		CredentialKey: "key",
		Strategy:      RefreshStrategyStatic,
	}

	result, err := client.Configure(context.Background(), "default", cfg)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "anthropic", result.ProviderName)
	assert.Equal(t, RefreshStrategyStatic, result.Strategy)
}

func TestRefreshConfigure_Error(t *testing.T) {
	mock := newMockRefreshServer()
	mock.configureErr = status.Errorf(codes.InvalidArgument, "invalid config")
	client, cleanup := setupRefreshTest(t, mock)
	defer cleanup()

	cfg := &RefreshConfig{
		Provider:      "openai",
		CredentialKey: "key",
		Strategy:      RefreshStrategyStatic,
	}

	result, err := client.Configure(context.Background(), "default", cfg)

	assert.Nil(t, result)
	require.Error(t, err)
	assert.True(t, IsInvalidArgument(err))
}

// --- Rotate tests ---

func TestRefreshRotate(t *testing.T) {
	mock := newMockRefreshServer()
	client, cleanup := setupRefreshTest(t, mock)
	defer cleanup()

	// Configure first
	_, err := client.Configure(context.Background(), "default", &RefreshConfig{
		Provider:      "openai",
		CredentialKey: "api-key",
		Strategy:      RefreshStrategyOAuth2RefreshToken,
	})
	require.NoError(t, err)

	// Rotate
	result, err := client.Rotate(context.Background(), "default", "openai", "api-key")

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "rotated", result.Status)
	assert.False(t, result.LastRefreshAt.IsZero())
}

func TestRefreshRotate_NotFound(t *testing.T) {
	mock := newMockRefreshServer()
	client, cleanup := setupRefreshTest(t, mock)
	defer cleanup()

	result, err := client.Rotate(context.Background(), "default", "openai", "nonexistent")

	assert.Nil(t, result)
	require.Error(t, err)
	assert.True(t, IsNotFound(err))
}

func TestRefreshRotate_Error(t *testing.T) {
	mock := newMockRefreshServer()
	mock.rotateErr = status.Errorf(codes.Unavailable, "unavailable")
	client, cleanup := setupRefreshTest(t, mock)
	defer cleanup()

	result, err := client.Rotate(context.Background(), "default", "openai", "key")

	assert.Nil(t, result)
	require.Error(t, err)
	assert.True(t, IsUnavailable(err))
}

// --- Delete tests ---

func TestRefreshDelete(t *testing.T) {
	mock := newMockRefreshServer()
	client, cleanup := setupRefreshTest(t, mock)
	defer cleanup()

	// Configure first
	_, err := client.Configure(context.Background(), "default", &RefreshConfig{
		Provider:      "openai",
		CredentialKey: "api-key",
		Strategy:      RefreshStrategyStatic,
	})
	require.NoError(t, err)

	// Delete
	deleted, err := client.Delete(context.Background(), "default", "openai", "api-key")

	require.NoError(t, err)
	assert.True(t, deleted)

	// Verify it's gone
	statuses, err := client.GetStatus(context.Background(), "default", "openai", "api-key")
	require.NoError(t, err)
	assert.Empty(t, statuses)
}

func TestRefreshDelete_NotConfigured(t *testing.T) {
	mock := newMockRefreshServer()
	client, cleanup := setupRefreshTest(t, mock)
	defer cleanup()

	deleted, err := client.Delete(context.Background(), "default", "openai", "nonexistent")

	require.NoError(t, err)
	assert.False(t, deleted)
}

func TestRefreshDelete_Error(t *testing.T) {
	mock := newMockRefreshServer()
	mock.deleteErr = status.Errorf(codes.Internal, "internal error")
	client, cleanup := setupRefreshTest(t, mock)
	defer cleanup()

	deleted, err := client.Delete(context.Background(), "default", "openai", "key")

	assert.False(t, deleted)
	require.Error(t, err)
}

// --- Integration test: full lifecycle ---

func TestRefreshLifecycle(t *testing.T) {
	mock := newMockRefreshServer()
	client, cleanup := setupRefreshTest(t, mock)
	defer cleanup()

	ctx := context.Background()

	// 1. Configure
	cfg := &RefreshConfig{
		Provider:      "openai",
		CredentialKey: "api-key",
		Strategy:      RefreshStrategyOAuth2RefreshToken,
		Material:      map[string]string{"refresh_token": "tok-123"},
	}
	st, err := client.Configure(ctx, "default", cfg)
	require.NoError(t, err)
	assert.Equal(t, "active", st.Status)

	// 2. GetStatus
	statuses, err := client.GetStatus(ctx, "default", "openai", "api-key")
	require.NoError(t, err)
	require.Len(t, statuses, 1)

	// 3. Rotate
	rotated, err := client.Rotate(ctx, "default", "openai", "api-key")
	require.NoError(t, err)
	assert.Equal(t, "rotated", rotated.Status)

	// 4. Delete
	deleted, err := client.Delete(ctx, "default", "openai", "api-key")
	require.NoError(t, err)
	assert.True(t, deleted)

	// 5. Verify removed
	statuses, err = client.GetStatus(ctx, "default", "openai", "api-key")
	require.NoError(t, err)
	assert.Empty(t, statuses)
}
