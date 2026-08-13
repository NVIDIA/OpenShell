// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"
	"net"
	"sync"
	"testing"

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

// --- Mock server for provider profiles ---

type mockProfileServer struct {
	pb.UnimplementedOpenShellServer
	mu       sync.Mutex
	profiles map[string]*pb.ProviderProfile // key: profile ID

	listErr   error
	getErr    error
	importErr error
	updateErr error
	lintErr   error
	deleteErr error

	lastListReq *pb.ListProviderProfilesRequest
}

func newMockProfileServer() *mockProfileServer {
	return &mockProfileServer{
		profiles: make(map[string]*pb.ProviderProfile),
	}
}

func (s *mockProfileServer) ListProviderProfiles(_ context.Context, req *pb.ListProviderProfilesRequest) (*pb.ListProviderProfilesResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastListReq = req
	if s.listErr != nil {
		return nil, s.listErr
	}

	var profiles []*pb.ProviderProfile
	for _, p := range s.profiles {
		profiles = append(profiles, p)
	}
	return &pb.ListProviderProfilesResponse{Profiles: profiles}, nil
}

func (s *mockProfileServer) GetProviderProfile(_ context.Context, req *pb.GetProviderProfileRequest) (*pb.ProviderProfileResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.getErr != nil {
		return nil, s.getErr
	}

	p, ok := s.profiles[req.GetId()]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "profile %q not found", req.GetId())
	}
	return &pb.ProviderProfileResponse{Profile: p}, nil
}

func (s *mockProfileServer) ImportProviderProfiles(_ context.Context, req *pb.ImportProviderProfilesRequest) (*pb.ImportProviderProfilesResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.importErr != nil {
		return nil, s.importErr
	}

	var imported []*pb.ProviderProfile
	for _, item := range req.GetProfiles() {
		p := item.GetProfile()
		if p != nil {
			s.profiles[p.GetId()] = p
			imported = append(imported, p)
		}
	}
	return &pb.ImportProviderProfilesResponse{
		Profiles: imported,
		Imported: len(imported) > 0,
	}, nil
}

func (s *mockProfileServer) UpdateProviderProfiles(_ context.Context, req *pb.UpdateProviderProfilesRequest) (*pb.UpdateProviderProfilesResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.updateErr != nil {
		return nil, s.updateErr
	}

	id := req.GetId()
	existing, ok := s.profiles[id]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "profile %q not found", id)
	}

	if req.GetExpectedResourceVersion() != existing.GetResourceVersion() {
		return nil, status.Errorf(codes.FailedPrecondition, "resource version mismatch")
	}

	p := req.GetProfile().GetProfile()
	if p != nil {
		p.ResourceVersion = existing.GetResourceVersion() + 1
		s.profiles[id] = p
	}

	return &pb.UpdateProviderProfilesResponse{
		Profile: p,
		Updated: true,
	}, nil
}

func (s *mockProfileServer) LintProviderProfiles(_ context.Context, req *pb.LintProviderProfilesRequest) (*pb.LintProviderProfilesResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lintErr != nil {
		return nil, s.lintErr
	}

	// Simple lint: valid if all profiles have an ID
	var diagnostics []*pb.ProviderProfileDiagnostic
	valid := true
	for _, item := range req.GetProfiles() {
		p := item.GetProfile()
		if p != nil && p.GetId() == "" {
			valid = false
			diagnostics = append(diagnostics, &pb.ProviderProfileDiagnostic{
				Source:   item.GetSource(),
				Field:    "id",
				Message:  "profile ID is required",
				Severity: "error",
			})
		}
	}
	return &pb.LintProviderProfilesResponse{
		Diagnostics: diagnostics,
		Valid:       valid,
	}, nil
}

func (s *mockProfileServer) DeleteProviderProfile(_ context.Context, req *pb.DeleteProviderProfileRequest) (*pb.DeleteProviderProfileResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.deleteErr != nil {
		return nil, s.deleteErr
	}

	_, ok := s.profiles[req.GetId()]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "profile %q not found", req.GetId())
	}
	delete(s.profiles, req.GetId())
	return &pb.DeleteProviderProfileResponse{Deleted: true}, nil
}

// --- Test setup ---

func setupProfileTest(t *testing.T, mock *mockProfileServer) (*profileClient, func()) {
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

	return newProfileClient(conn), func() {
		_ = conn.Close()
		srv.Stop()
	}
}

// seedProfile adds a profile to the mock server store for testing.
func seedProfile(mock *mockProfileServer, id, displayName string, category pb.ProviderProfileCategory) {
	mock.mu.Lock()
	defer mock.mu.Unlock()
	mock.profiles[id] = &pb.ProviderProfile{
		Id:              id,
		DisplayName:     displayName,
		Description:     "Test profile " + id,
		Category:        category,
		ResourceVersion: 1,
		Credentials: []*pb.ProviderProfileCredential{
			{Name: "api-key", Description: "API Key", Required: true, Refresh: &pb.ProviderCredentialRefresh{}},
		},
		Endpoints: []*sbv1.NetworkEndpoint{
			{Host: "localhost", Port: 8080, Protocol: "http"},
		},
		Binaries: []*sbv1.NetworkBinary{
			{Path: "/usr/bin/provider"},
		},
	}
}

// --- List tests ---

func TestProfileList(t *testing.T) {
	mock := newMockProfileServer()
	seedProfile(mock, "p1", "Profile One", pb.ProviderProfileCategory_PROVIDER_PROFILE_CATEGORY_INFERENCE)
	seedProfile(mock, "p2", "Profile Two", pb.ProviderProfileCategory_PROVIDER_PROFILE_CATEGORY_AGENT)
	client, cleanup := setupProfileTest(t, mock)
	defer cleanup()

	profiles, err := client.List(context.Background(), "default")

	require.NoError(t, err)
	assert.Len(t, profiles, 2)
}

func TestProfileList_Empty(t *testing.T) {
	mock := newMockProfileServer()
	client, cleanup := setupProfileTest(t, mock)
	defer cleanup()

	profiles, err := client.List(context.Background(), "default")

	require.NoError(t, err)
	assert.Empty(t, profiles)
}

func TestProfileList_WithOptions(t *testing.T) {
	mock := newMockProfileServer()
	seedProfile(mock, "p1", "Profile One", pb.ProviderProfileCategory_PROVIDER_PROFILE_CATEGORY_INFERENCE)
	client, cleanup := setupProfileTest(t, mock)
	defer cleanup()

	profiles, err := client.List(context.Background(), "default", ListOptions{Limit: 10, Offset: 5})

	require.NoError(t, err)
	assert.Len(t, profiles, 1)
	require.NotNil(t, mock.lastListReq)
	assert.Equal(t, uint32(10), mock.lastListReq.GetLimit())
	assert.Equal(t, uint32(5), mock.lastListReq.GetOffset())
}

func TestProfileList_Error(t *testing.T) {
	mock := newMockProfileServer()
	mock.listErr = status.Errorf(codes.Unavailable, "unavailable")
	client, cleanup := setupProfileTest(t, mock)
	defer cleanup()

	profiles, err := client.List(context.Background(), "default")

	assert.Nil(t, profiles)
	require.Error(t, err)
	assert.True(t, IsUnavailable(err))
}

// --- Get tests ---

func TestProfileGet(t *testing.T) {
	mock := newMockProfileServer()
	seedProfile(mock, "p1", "Profile One", pb.ProviderProfileCategory_PROVIDER_PROFILE_CATEGORY_INFERENCE)
	client, cleanup := setupProfileTest(t, mock)
	defer cleanup()

	profile, err := client.Get(context.Background(), "default", "p1")

	require.NoError(t, err)
	require.NotNil(t, profile)
	assert.Equal(t, "p1", profile.ID)
	assert.Equal(t, "Profile One", profile.DisplayName)
	assert.Equal(t, ProfileCategoryInference, profile.Category)
	assert.Equal(t, uint64(1), profile.ResourceVersion)
	// Verify credential deep copy
	require.Len(t, profile.Credentials, 1)
	assert.Equal(t, "api-key", profile.Credentials[0].Name)
	assert.True(t, profile.Credentials[0].Required)
	assert.True(t, profile.Credentials[0].Secret) // derived from Refresh != nil
	// Verify endpoint deep copy
	require.Len(t, profile.Endpoints, 1)
	assert.Equal(t, "localhost", profile.Endpoints[0].Host)
	assert.Equal(t, uint32(8080), profile.Endpoints[0].Port)
	// Verify binary deep copy
	require.Len(t, profile.Binaries, 1)
	assert.Equal(t, "/usr/bin/provider", profile.Binaries[0].Path)
}

func TestProfileGet_NotFound(t *testing.T) {
	mock := newMockProfileServer()
	client, cleanup := setupProfileTest(t, mock)
	defer cleanup()

	profile, err := client.Get(context.Background(), "default", "nonexistent")

	assert.Nil(t, profile)
	require.Error(t, err)
	assert.True(t, IsNotFound(err))
}

func TestProfileGet_Error(t *testing.T) {
	mock := newMockProfileServer()
	mock.getErr = status.Errorf(codes.Internal, "internal error")
	client, cleanup := setupProfileTest(t, mock)
	defer cleanup()

	profile, err := client.Get(context.Background(), "default", "p1")

	assert.Nil(t, profile)
	require.Error(t, err)
}

// --- Import tests ---

func TestProfileImport(t *testing.T) {
	mock := newMockProfileServer()
	client, cleanup := setupProfileTest(t, mock)
	defer cleanup()

	items := []ProfileImportItem{
		{
			Profile: ProviderProfile{
				ID:          "p1",
				DisplayName: "New Profile",
				Category:    ProfileCategoryInference,
			},
			Source: "test.yaml",
		},
	}

	result, err := client.Import(context.Background(), "default", items)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Imported)
	assert.Len(t, result.Profiles, 1)
	assert.Equal(t, "p1", result.Profiles[0].ID)
}

func TestProfileImport_MultipleItems(t *testing.T) {
	mock := newMockProfileServer()
	client, cleanup := setupProfileTest(t, mock)
	defer cleanup()

	items := []ProfileImportItem{
		{
			Profile: ProviderProfile{ID: "p1", DisplayName: "Profile 1"},
			Source:  "a.yaml",
		},
		{
			Profile: ProviderProfile{ID: "p2", DisplayName: "Profile 2"},
			Source:  "b.yaml",
		},
	}

	result, err := client.Import(context.Background(), "default", items)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Imported)
	assert.Len(t, result.Profiles, 2)
}

func TestProfileImport_Error(t *testing.T) {
	mock := newMockProfileServer()
	mock.importErr = status.Errorf(codes.InvalidArgument, "bad request")
	client, cleanup := setupProfileTest(t, mock)
	defer cleanup()

	items := []ProfileImportItem{
		{Profile: ProviderProfile{ID: "p1"}, Source: "test.yaml"},
	}

	result, err := client.Import(context.Background(), "default", items)

	assert.Nil(t, result)
	require.Error(t, err)
	assert.True(t, IsInvalidArgument(err))
}

// --- Update tests ---

func TestProfileUpdate(t *testing.T) {
	mock := newMockProfileServer()
	seedProfile(mock, "p1", "Original", pb.ProviderProfileCategory_PROVIDER_PROFILE_CATEGORY_INFERENCE)
	client, cleanup := setupProfileTest(t, mock)
	defer cleanup()

	item := ProfileImportItem{
		Profile: ProviderProfile{
			ID:          "p1",
			DisplayName: "Updated",
			Category:    ProfileCategoryAgent,
		},
		Source: "update.yaml",
	}

	result, err := client.Update(context.Background(), "default", "p1", 1, item)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Updated)
	require.NotNil(t, result.Profile)
	assert.Equal(t, uint64(2), result.Profile.ResourceVersion) // bumped by mock
}

func TestProfileUpdate_NotFound(t *testing.T) {
	mock := newMockProfileServer()
	client, cleanup := setupProfileTest(t, mock)
	defer cleanup()

	item := ProfileImportItem{
		Profile: ProviderProfile{ID: "missing"},
		Source:  "test.yaml",
	}

	result, err := client.Update(context.Background(), "default", "missing", 1, item)

	assert.Nil(t, result)
	require.Error(t, err)
	assert.True(t, IsNotFound(err))
}

func TestProfileUpdate_VersionMismatch(t *testing.T) {
	mock := newMockProfileServer()
	seedProfile(mock, "p1", "Original", pb.ProviderProfileCategory_PROVIDER_PROFILE_CATEGORY_INFERENCE)
	client, cleanup := setupProfileTest(t, mock)
	defer cleanup()

	item := ProfileImportItem{
		Profile: ProviderProfile{ID: "p1"},
		Source:  "test.yaml",
	}

	// Use wrong version (99 instead of 1)
	result, err := client.Update(context.Background(), "default", "p1", 99, item)

	assert.Nil(t, result)
	require.Error(t, err)
}

func TestProfileUpdate_Error(t *testing.T) {
	mock := newMockProfileServer()
	mock.updateErr = status.Errorf(codes.Internal, "internal error")
	client, cleanup := setupProfileTest(t, mock)
	defer cleanup()

	item := ProfileImportItem{
		Profile: ProviderProfile{ID: "p1"},
		Source:  "test.yaml",
	}

	result, err := client.Update(context.Background(), "default", "p1", 1, item)

	assert.Nil(t, result)
	require.Error(t, err)
}

// --- Lint tests ---

func TestProfileLint_Valid(t *testing.T) {
	mock := newMockProfileServer()
	client, cleanup := setupProfileTest(t, mock)
	defer cleanup()

	items := []ProfileImportItem{
		{
			Profile: ProviderProfile{ID: "p1", DisplayName: "Good Profile"},
			Source:  "test.yaml",
		},
	}

	result, err := client.Lint(context.Background(), "default", items)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Valid)
	assert.Empty(t, result.Diagnostics)
}

func TestProfileLint_Invalid(t *testing.T) {
	mock := newMockProfileServer()
	client, cleanup := setupProfileTest(t, mock)
	defer cleanup()

	items := []ProfileImportItem{
		{
			Profile: ProviderProfile{ID: "", DisplayName: "Bad Profile"}, // empty ID triggers lint error
			Source:  "bad.yaml",
		},
	}

	result, err := client.Lint(context.Background(), "default", items)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Valid)
	require.Len(t, result.Diagnostics, 1)
	assert.Equal(t, "id", result.Diagnostics[0].Field)
	assert.Equal(t, "error", result.Diagnostics[0].Severity)
}

func TestProfileLint_Error(t *testing.T) {
	mock := newMockProfileServer()
	mock.lintErr = status.Errorf(codes.Unavailable, "unavailable")
	client, cleanup := setupProfileTest(t, mock)
	defer cleanup()

	items := []ProfileImportItem{
		{Profile: ProviderProfile{ID: "p1"}, Source: "test.yaml"},
	}

	result, err := client.Lint(context.Background(), "default", items)

	assert.Nil(t, result)
	require.Error(t, err)
	assert.True(t, IsUnavailable(err))
}

// --- Delete tests ---

func TestProfileDelete(t *testing.T) {
	mock := newMockProfileServer()
	seedProfile(mock, "p1", "Profile One", pb.ProviderProfileCategory_PROVIDER_PROFILE_CATEGORY_INFERENCE)
	client, cleanup := setupProfileTest(t, mock)
	defer cleanup()

	deleted, err := client.Delete(context.Background(), "default", "p1")

	require.NoError(t, err)
	assert.True(t, deleted)

	// Verify subsequent Get returns NotFound
	profile, err := client.Get(context.Background(), "default", "p1")
	assert.Nil(t, profile)
	require.Error(t, err)
	assert.True(t, IsNotFound(err))
}

func TestProfileDelete_NotFound(t *testing.T) {
	mock := newMockProfileServer()
	client, cleanup := setupProfileTest(t, mock)
	defer cleanup()

	deleted, err := client.Delete(context.Background(), "default", "nonexistent")

	assert.False(t, deleted)
	require.Error(t, err)
	assert.True(t, IsNotFound(err))
}

func TestProfileDelete_Error(t *testing.T) {
	mock := newMockProfileServer()
	mock.deleteErr = status.Errorf(codes.Internal, "internal error")
	client, cleanup := setupProfileTest(t, mock)
	defer cleanup()

	deleted, err := client.Delete(context.Background(), "default", "p1")

	assert.False(t, deleted)
	require.Error(t, err)
}
