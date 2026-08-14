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

// --- Mock server for Policy RPCs ---

type mockPolicyServer struct {
	pb.UnimplementedOpenShellServer
	mu sync.Mutex

	// Canned responses.
	getDraftResp   *pb.GetDraftPolicyResponse
	approveResp    *pb.ApproveDraftChunkResponse
	rejectResp     *pb.RejectDraftChunkResponse
	approveAllResp *pb.ApproveAllDraftChunksResponse
	clearResp      *pb.ClearDraftChunksResponse
	historyResp    *pb.GetDraftHistoryResponse
	statusResp     *pb.GetSandboxPolicyStatusResponse
	listResp       *pb.ListSandboxPoliciesResponse
	editResp       *pb.EditDraftChunkResponse
	undoResp       *pb.UndoDraftChunkResponse

	// Recorded requests.
	lastGetDraftReq   *pb.GetDraftPolicyRequest
	lastApproveReq    *pb.ApproveDraftChunkRequest
	lastRejectReq     *pb.RejectDraftChunkRequest
	lastApproveAllReq *pb.ApproveAllDraftChunksRequest
	lastClearReq      *pb.ClearDraftChunksRequest
	lastHistoryReq    *pb.GetDraftHistoryRequest
	lastStatusReq     *pb.GetSandboxPolicyStatusRequest
	lastListReq       *pb.ListSandboxPoliciesRequest
	lastEditReq       *pb.EditDraftChunkRequest
	lastUndoReq       *pb.UndoDraftChunkRequest

	// Inject errors.
	getDraftErr   error
	approveErr    error
	rejectErr     error
	approveAllErr error
	clearErr      error
	historyErr    error
	statusErr     error
	listErr       error
	editErr       error
	undoErr       error
}

func newMockPolicyServer() *mockPolicyServer {
	return &mockPolicyServer{}
}

func (s *mockPolicyServer) GetDraftPolicy(_ context.Context, req *pb.GetDraftPolicyRequest) (*pb.GetDraftPolicyResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastGetDraftReq = req
	if s.getDraftErr != nil {
		return nil, s.getDraftErr
	}
	return s.getDraftResp, nil
}

func (s *mockPolicyServer) ApproveDraftChunk(_ context.Context, req *pb.ApproveDraftChunkRequest) (*pb.ApproveDraftChunkResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastApproveReq = req
	if s.approveErr != nil {
		return nil, s.approveErr
	}
	return s.approveResp, nil
}

func (s *mockPolicyServer) RejectDraftChunk(_ context.Context, req *pb.RejectDraftChunkRequest) (*pb.RejectDraftChunkResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastRejectReq = req
	if s.rejectErr != nil {
		return nil, s.rejectErr
	}
	return s.rejectResp, nil
}

func (s *mockPolicyServer) ApproveAllDraftChunks(_ context.Context, req *pb.ApproveAllDraftChunksRequest) (*pb.ApproveAllDraftChunksResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastApproveAllReq = req
	if s.approveAllErr != nil {
		return nil, s.approveAllErr
	}
	return s.approveAllResp, nil
}

func (s *mockPolicyServer) ClearDraftChunks(_ context.Context, req *pb.ClearDraftChunksRequest) (*pb.ClearDraftChunksResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastClearReq = req
	if s.clearErr != nil {
		return nil, s.clearErr
	}
	return s.clearResp, nil
}

func (s *mockPolicyServer) GetDraftHistory(_ context.Context, req *pb.GetDraftHistoryRequest) (*pb.GetDraftHistoryResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastHistoryReq = req
	if s.historyErr != nil {
		return nil, s.historyErr
	}
	return s.historyResp, nil
}

func (s *mockPolicyServer) GetSandboxPolicyStatus(_ context.Context, req *pb.GetSandboxPolicyStatusRequest) (*pb.GetSandboxPolicyStatusResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastStatusReq = req
	if s.statusErr != nil {
		return nil, s.statusErr
	}
	return s.statusResp, nil
}

func (s *mockPolicyServer) ListSandboxPolicies(_ context.Context, req *pb.ListSandboxPoliciesRequest) (*pb.ListSandboxPoliciesResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastListReq = req
	if s.listErr != nil {
		return nil, s.listErr
	}
	return s.listResp, nil
}

func (s *mockPolicyServer) EditDraftChunk(_ context.Context, req *pb.EditDraftChunkRequest) (*pb.EditDraftChunkResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastEditReq = req
	if s.editErr != nil {
		return nil, s.editErr
	}
	return s.editResp, nil
}

func (s *mockPolicyServer) UndoDraftChunk(_ context.Context, req *pb.UndoDraftChunkRequest) (*pb.UndoDraftChunkResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastUndoReq = req
	if s.undoErr != nil {
		return nil, s.undoErr
	}
	return s.undoResp, nil
}

// --- Test setup ---

func setupPolicyTest(t *testing.T, mock *mockPolicyServer) (*policyClient, func()) {
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

	return newPolicyClient(conn), func() {
		_ = conn.Close()
		srv.Stop()
	}
}

// ===========================================================================
// Phase 2 (T020): GetDraft, ApproveDraftChunk, RejectDraftChunk
// ===========================================================================

func TestPolicyGetDraft(t *testing.T) {
	mock := newMockPolicyServer()
	mock.getDraftResp = &pb.GetDraftPolicyResponse{
		Chunks: []*pb.PolicyChunk{
			{
				Id:               "chunk-1",
				Status:           "pending",
				RuleName:         "allow-dns",
				Rationale:        "DNS access needed",
				Confidence:       0.95,
				DenialSummaryIds: []string{"ds-1", "ds-2"},
				CreatedAtMs:      1700000000000,
				Stage:            "initial",
				HitCount:         3,
				Binary:           "/usr/bin/curl",
				ProposedRule: &sbv1.NetworkPolicyRule{
					Name: "allow-dns-rule",
				},
			},
			{
				Id:       "chunk-2",
				Status:   "approved",
				RuleName: "allow-https",
			},
		},
		RollingSummary:   "Two rules proposed",
		DraftVersion:     5,
		LastAnalyzedAtMs: 1700000001000,
	}

	client, cleanup := setupPolicyTest(t, mock)
	defer cleanup()

	draft, err := client.GetDraft(context.Background(), "default", "my-sandbox")

	require.NoError(t, err)
	require.NotNil(t, draft)

	// Verify request was forwarded.
	mock.mu.Lock()
	assert.Equal(t, "my-sandbox", mock.lastGetDraftReq.GetName())
	assert.Empty(t, mock.lastGetDraftReq.GetStatusFilter())
	mock.mu.Unlock()

	// Verify response mapping.
	assert.Equal(t, "Two rules proposed", draft.RollingSummary)
	assert.Equal(t, uint64(5), draft.DraftVersion)
	assert.False(t, draft.LastAnalyzedAt.IsZero())

	require.Len(t, draft.Chunks, 2)

	c1 := draft.Chunks[0]
	assert.Equal(t, "chunk-1", c1.ID)
	assert.Equal(t, "pending", c1.Status)
	assert.Equal(t, "allow-dns", c1.RuleName)
	assert.Equal(t, "DNS access needed", c1.Rationale)
	assert.InDelta(t, float32(0.95), c1.Confidence, 0.001)
	assert.Equal(t, []string{"ds-1", "ds-2"}, c1.DenialSummaryIDs)
	assert.Equal(t, "initial", c1.Stage)
	assert.Equal(t, int32(3), c1.HitCount)
	assert.Equal(t, "/usr/bin/curl", c1.Binary)
	require.NotNil(t, c1.ProposedRule)
	assert.Equal(t, "allow-dns-rule", c1.ProposedRule.Name)

	c2 := draft.Chunks[1]
	assert.Equal(t, "chunk-2", c2.ID)
	assert.Equal(t, "approved", c2.Status)
}

func TestPolicyGetDraft_WithStatusFilter(t *testing.T) {
	mock := newMockPolicyServer()
	mock.getDraftResp = &pb.GetDraftPolicyResponse{
		Chunks: []*pb.PolicyChunk{
			{Id: "chunk-1", Status: "pending"},
		},
		DraftVersion: 3,
	}

	client, cleanup := setupPolicyTest(t, mock)
	defer cleanup()

	draft, err := client.GetDraft(context.Background(), "default", "sb1", types.WithStatusFilter("pending"))

	require.NoError(t, err)
	require.NotNil(t, draft)

	// Verify status filter was forwarded.
	mock.mu.Lock()
	assert.Equal(t, "pending", mock.lastGetDraftReq.GetStatusFilter())
	mock.mu.Unlock()

	require.Len(t, draft.Chunks, 1)
	assert.Equal(t, "pending", draft.Chunks[0].Status)
}

func TestPolicyGetDraft_Error(t *testing.T) {
	mock := newMockPolicyServer()
	mock.getDraftErr = status.Errorf(codes.NotFound, "sandbox not found")

	client, cleanup := setupPolicyTest(t, mock)
	defer cleanup()

	draft, err := client.GetDraft(context.Background(), "default", "missing")

	assert.Nil(t, draft)
	require.Error(t, err)
	assert.True(t, IsNotFound(err))
}

func TestPolicyApproveDraftChunk(t *testing.T) {
	mock := newMockPolicyServer()
	mock.approveResp = &pb.ApproveDraftChunkResponse{
		PolicyVersion: 7,
		PolicyHash:    "sha256:abc123",
	}

	client, cleanup := setupPolicyTest(t, mock)
	defer cleanup()

	result, err := client.ApproveDraftChunk(context.Background(), "default", "my-sandbox", "chunk-1")

	require.NoError(t, err)
	require.NotNil(t, result)

	// Verify request was forwarded.
	mock.mu.Lock()
	assert.Equal(t, "my-sandbox", mock.lastApproveReq.GetName())
	assert.Equal(t, "chunk-1", mock.lastApproveReq.GetChunkId())
	mock.mu.Unlock()

	// Verify response mapping.
	assert.Equal(t, uint32(7), result.PolicyVersion)
	assert.Equal(t, "sha256:abc123", result.PolicyHash)
}

func TestPolicyApproveDraftChunk_Error(t *testing.T) {
	mock := newMockPolicyServer()
	mock.approveErr = status.Errorf(codes.NotFound, "chunk not found")

	client, cleanup := setupPolicyTest(t, mock)
	defer cleanup()

	result, err := client.ApproveDraftChunk(context.Background(), "default", "sb1", "bad-chunk")

	assert.Nil(t, result)
	require.Error(t, err)
	assert.True(t, IsNotFound(err))
}

func TestPolicyRejectDraftChunk(t *testing.T) {
	mock := newMockPolicyServer()
	mock.rejectResp = &pb.RejectDraftChunkResponse{}

	client, cleanup := setupPolicyTest(t, mock)
	defer cleanup()

	err := client.RejectDraftChunk(context.Background(), "default", "my-sandbox", "chunk-2", "too broad")

	require.NoError(t, err)

	// Verify request was forwarded.
	mock.mu.Lock()
	assert.Equal(t, "my-sandbox", mock.lastRejectReq.GetName())
	assert.Equal(t, "chunk-2", mock.lastRejectReq.GetChunkId())
	assert.Equal(t, "too broad", mock.lastRejectReq.GetReason())
	mock.mu.Unlock()
}

func TestPolicyRejectDraftChunk_Error(t *testing.T) {
	mock := newMockPolicyServer()
	mock.rejectErr = status.Errorf(codes.InvalidArgument, "invalid chunk")

	client, cleanup := setupPolicyTest(t, mock)
	defer cleanup()

	err := client.RejectDraftChunk(context.Background(), "default", "sb1", "bad", "reason")

	require.Error(t, err)
	assert.True(t, IsInvalidArgument(err))
}

// ===========================================================================
// Phase 3 (T022): ApproveAllDraftChunks, ClearDraftChunks, GetDraftHistory
// ===========================================================================

func TestPolicyApproveAllDraftChunks(t *testing.T) {
	mock := newMockPolicyServer()
	mock.approveAllResp = &pb.ApproveAllDraftChunksResponse{
		PolicyVersion:  8,
		PolicyHash:     "sha256:bulk",
		ChunksApproved: 5,
		ChunksSkipped:  2,
	}

	client, cleanup := setupPolicyTest(t, mock)
	defer cleanup()

	result, err := client.ApproveAllDraftChunks(context.Background(), "default", "my-sandbox")

	require.NoError(t, err)
	require.NotNil(t, result)

	// Verify default: security-flagged NOT included.
	mock.mu.Lock()
	assert.Equal(t, "my-sandbox", mock.lastApproveAllReq.GetName())
	assert.False(t, mock.lastApproveAllReq.GetIncludeSecurityFlagged())
	mock.mu.Unlock()

	assert.Equal(t, uint32(8), result.PolicyVersion)
	assert.Equal(t, "sha256:bulk", result.PolicyHash)
	assert.Equal(t, uint32(5), result.ChunksApproved)
	assert.Equal(t, uint32(2), result.ChunksSkipped)
}

func TestPolicyApproveAllDraftChunks_WithSecurityFlagged(t *testing.T) {
	mock := newMockPolicyServer()
	mock.approveAllResp = &pb.ApproveAllDraftChunksResponse{
		PolicyVersion:  9,
		PolicyHash:     "sha256:all",
		ChunksApproved: 7,
		ChunksSkipped:  0,
	}

	client, cleanup := setupPolicyTest(t, mock)
	defer cleanup()

	result, err := client.ApproveAllDraftChunks(context.Background(), "default", "sb1", types.WithIncludeSecurityFlagged())

	require.NoError(t, err)
	require.NotNil(t, result)

	// Verify security-flagged flag was sent.
	mock.mu.Lock()
	assert.True(t, mock.lastApproveAllReq.GetIncludeSecurityFlagged())
	mock.mu.Unlock()

	assert.Equal(t, uint32(7), result.ChunksApproved)
	assert.Equal(t, uint32(0), result.ChunksSkipped)
}

func TestPolicyApproveAllDraftChunks_Error(t *testing.T) {
	mock := newMockPolicyServer()
	mock.approveAllErr = status.Errorf(codes.NotFound, "sandbox not found")

	client, cleanup := setupPolicyTest(t, mock)
	defer cleanup()

	result, err := client.ApproveAllDraftChunks(context.Background(), "default", "missing")

	assert.Nil(t, result)
	require.Error(t, err)
	assert.True(t, IsNotFound(err))
}

func TestPolicyClearDraftChunks(t *testing.T) {
	mock := newMockPolicyServer()
	mock.clearResp = &pb.ClearDraftChunksResponse{
		ChunksCleared: 4,
	}

	client, cleanup := setupPolicyTest(t, mock)
	defer cleanup()

	result, err := client.ClearDraftChunks(context.Background(), "default", "my-sandbox")

	require.NoError(t, err)
	require.NotNil(t, result)

	// Verify request was forwarded.
	mock.mu.Lock()
	assert.Equal(t, "my-sandbox", mock.lastClearReq.GetName())
	mock.mu.Unlock()

	assert.Equal(t, uint32(4), result.ChunksCleared)
}

func TestPolicyClearDraftChunks_Error(t *testing.T) {
	mock := newMockPolicyServer()
	mock.clearErr = status.Errorf(codes.Internal, "internal error")

	client, cleanup := setupPolicyTest(t, mock)
	defer cleanup()

	result, err := client.ClearDraftChunks(context.Background(), "default", "sb1")

	assert.Nil(t, result)
	require.Error(t, err)
	var se *StatusError
	require.ErrorAs(t, err, &se)
	assert.Equal(t, ErrorInternal, se.Code)
}

func TestPolicyGetDraftHistory(t *testing.T) {
	mock := newMockPolicyServer()
	mock.historyResp = &pb.GetDraftHistoryResponse{
		Entries: []*pb.DraftHistoryEntry{
			{
				TimestampMs: 1700000000000,
				EventType:   "approved",
				Description: "Chunk chunk-1 approved",
				ChunkId:     "chunk-1",
			},
			{
				TimestampMs: 1700000001000,
				EventType:   "rejected",
				Description: "Chunk chunk-2 rejected: too broad",
				ChunkId:     "chunk-2",
			},
		},
	}

	client, cleanup := setupPolicyTest(t, mock)
	defer cleanup()

	entries, err := client.GetDraftHistory(context.Background(), "default", "my-sandbox")

	require.NoError(t, err)
	require.Len(t, entries, 2)

	// Verify request was forwarded.
	mock.mu.Lock()
	assert.Equal(t, "my-sandbox", mock.lastHistoryReq.GetName())
	mock.mu.Unlock()

	assert.Equal(t, "approved", entries[0].EventType)
	assert.Equal(t, "Chunk chunk-1 approved", entries[0].Description)
	assert.Equal(t, "chunk-1", entries[0].ChunkID)
	assert.False(t, entries[0].Timestamp.IsZero())

	assert.Equal(t, "rejected", entries[1].EventType)
	assert.Equal(t, "chunk-2", entries[1].ChunkID)
}

func TestPolicyGetDraftHistory_Empty(t *testing.T) {
	mock := newMockPolicyServer()
	mock.historyResp = &pb.GetDraftHistoryResponse{}

	client, cleanup := setupPolicyTest(t, mock)
	defer cleanup()

	entries, err := client.GetDraftHistory(context.Background(), "default", "sb1")

	require.NoError(t, err)
	assert.Nil(t, entries)
}

func TestPolicyGetDraftHistory_Error(t *testing.T) {
	mock := newMockPolicyServer()
	mock.historyErr = status.Errorf(codes.NotFound, "sandbox not found")

	client, cleanup := setupPolicyTest(t, mock)
	defer cleanup()

	entries, err := client.GetDraftHistory(context.Background(), "default", "missing")

	assert.Nil(t, entries)
	require.Error(t, err)
	assert.True(t, IsNotFound(err))
}

// ===========================================================================
// Phase 4 (T024): GetStatus, List, EditDraftChunk, UndoDraftChunk
// ===========================================================================

func TestPolicyGetStatus(t *testing.T) {
	mock := newMockPolicyServer()
	mock.statusResp = &pb.GetSandboxPolicyStatusResponse{
		Revision: &pb.SandboxPolicyRevision{
			Version:     3,
			PolicyHash:  "sha256:rev3",
			Status:      pb.PolicyStatus_POLICY_STATUS_LOADED,
			CreatedAtMs: 1700000000000,
			LoadedAtMs:  1700000001000,
		},
		ActiveVersion: 3,
	}

	client, cleanup := setupPolicyTest(t, mock)
	defer cleanup()

	result, err := client.GetStatus(context.Background(), "default", "my-sandbox")

	require.NoError(t, err)
	require.NotNil(t, result)

	// Verify request was forwarded (no version = latest).
	mock.mu.Lock()
	assert.Equal(t, "my-sandbox", mock.lastStatusReq.GetName())
	assert.Equal(t, uint32(0), mock.lastStatusReq.GetVersion())
	mock.mu.Unlock()

	assert.Equal(t, uint32(3), result.ActiveVersion)
	assert.Equal(t, uint32(3), result.Revision.Version)
	assert.Equal(t, "sha256:rev3", result.Revision.PolicyHash)
	assert.Equal(t, PolicyLoadStatusLoaded, result.Revision.Status)
	assert.False(t, result.Revision.CreatedAt.IsZero())
	assert.False(t, result.Revision.LoadedAt.IsZero())
}

func TestPolicyGetStatus_WithVersion(t *testing.T) {
	mock := newMockPolicyServer()
	mock.statusResp = &pb.GetSandboxPolicyStatusResponse{
		Revision: &pb.SandboxPolicyRevision{
			Version:    2,
			PolicyHash: "sha256:rev2",
			Status:     pb.PolicyStatus_POLICY_STATUS_SUPERSEDED,
		},
		ActiveVersion: 3,
	}

	client, cleanup := setupPolicyTest(t, mock)
	defer cleanup()

	result, err := client.GetStatus(context.Background(), "default", "sb1", types.WithVersion(2))

	require.NoError(t, err)
	require.NotNil(t, result)

	// Verify version was forwarded.
	mock.mu.Lock()
	assert.Equal(t, uint32(2), mock.lastStatusReq.GetVersion())
	mock.mu.Unlock()

	assert.Equal(t, uint32(2), result.Revision.Version)
	assert.Equal(t, PolicyLoadStatusSuperseded, result.Revision.Status)
	assert.Equal(t, uint32(3), result.ActiveVersion)
}

func TestPolicyGetStatus_WithGlobal(t *testing.T) {
	mock := newMockPolicyServer()
	mock.statusResp = &pb.GetSandboxPolicyStatusResponse{
		Revision: &pb.SandboxPolicyRevision{
			Version:    1,
			PolicyHash: "sha256:global-rev1",
			Status:     pb.PolicyStatus_POLICY_STATUS_LOADED,
		},
		ActiveVersion: 1,
	}

	client, cleanup := setupPolicyTest(t, mock)
	defer cleanup()

	// GetStatus with global flag and empty name/workspace.
	result, err := client.GetStatus(context.Background(), "", "", types.WithStatusGlobal(true))

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, uint32(1), result.Revision.Version)
	assert.Equal(t, "sha256:global-rev1", result.Revision.PolicyHash)

	// Verify global flag was forwarded in the proto request.
	mock.mu.Lock()
	assert.True(t, mock.lastStatusReq.GetGlobal())
	assert.Empty(t, mock.lastStatusReq.GetName())
	assert.Empty(t, mock.lastStatusReq.GetWorkspace())
	mock.mu.Unlock()
}

func TestPolicyGetStatus_WithGlobalIgnoresNonEmptyName(t *testing.T) {
	mock := newMockPolicyServer()
	mock.statusResp = &pb.GetSandboxPolicyStatusResponse{
		Revision: &pb.SandboxPolicyRevision{
			Version:    1,
			PolicyHash: "sha256:global-rev1",
			Status:     pb.PolicyStatus_POLICY_STATUS_LOADED,
		},
		ActiveVersion: 1,
	}

	client, cleanup := setupPolicyTest(t, mock)
	defer cleanup()

	result, err := client.GetStatus(context.Background(), "some-workspace", "some-sandbox", types.WithStatusGlobal(true))

	require.NoError(t, err)
	require.NotNil(t, result)

	mock.mu.Lock()
	assert.True(t, mock.lastStatusReq.GetGlobal())
	assert.Equal(t, "some-sandbox", mock.lastStatusReq.GetName())
	assert.Equal(t, "some-workspace", mock.lastStatusReq.GetWorkspace())
	mock.mu.Unlock()
}

func TestPolicyGetStatus_WithGlobalAndVersion(t *testing.T) {
	mock := newMockPolicyServer()
	mock.statusResp = &pb.GetSandboxPolicyStatusResponse{
		Revision: &pb.SandboxPolicyRevision{
			Version:    3,
			PolicyHash: "sha256:global-rev3",
			Status:     pb.PolicyStatus_POLICY_STATUS_SUPERSEDED,
		},
		ActiveVersion: 5,
	}

	client, cleanup := setupPolicyTest(t, mock)
	defer cleanup()

	// Global flag composes with WithVersion.
	result, err := client.GetStatus(context.Background(), "", "",
		types.WithStatusGlobal(true),
		types.WithVersion(3),
	)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, uint32(3), result.Revision.Version)
	assert.Equal(t, uint32(5), result.ActiveVersion)

	mock.mu.Lock()
	assert.True(t, mock.lastStatusReq.GetGlobal())
	assert.Equal(t, uint32(3), mock.lastStatusReq.GetVersion())
	mock.mu.Unlock()
}

func TestPolicyGetStatus_WithoutGlobal_PreservesExistingBehavior(t *testing.T) {
	mock := newMockPolicyServer()
	mock.statusResp = &pb.GetSandboxPolicyStatusResponse{
		Revision: &pb.SandboxPolicyRevision{
			Version: 1,
			Status:  pb.PolicyStatus_POLICY_STATUS_LOADED,
		},
		ActiveVersion: 1,
	}

	client, cleanup := setupPolicyTest(t, mock)
	defer cleanup()

	_, err := client.GetStatus(context.Background(), "default", "my-sandbox")

	require.NoError(t, err)

	// Verify global flag is false by default.
	mock.mu.Lock()
	assert.False(t, mock.lastStatusReq.GetGlobal())
	assert.Equal(t, "default", mock.lastStatusReq.GetWorkspace())
	assert.Equal(t, "my-sandbox", mock.lastStatusReq.GetName())
	mock.mu.Unlock()
}

func TestPolicyGetStatus_Error(t *testing.T) {
	mock := newMockPolicyServer()
	mock.statusErr = status.Errorf(codes.NotFound, "sandbox not found")

	client, cleanup := setupPolicyTest(t, mock)
	defer cleanup()

	result, err := client.GetStatus(context.Background(), "default", "missing")

	assert.Nil(t, result)
	require.Error(t, err)
	assert.True(t, IsNotFound(err))
}

func TestPolicyList(t *testing.T) {
	mock := newMockPolicyServer()
	mock.listResp = &pb.ListSandboxPoliciesResponse{
		Revisions: []*pb.SandboxPolicyRevision{
			{
				Version:     1,
				PolicyHash:  "sha256:v1",
				Status:      pb.PolicyStatus_POLICY_STATUS_SUPERSEDED,
				CreatedAtMs: 1700000000000,
			},
			{
				Version:     2,
				PolicyHash:  "sha256:v2",
				Status:      pb.PolicyStatus_POLICY_STATUS_LOADED,
				CreatedAtMs: 1700000001000,
				LoadedAtMs:  1700000002000,
			},
		},
	}

	client, cleanup := setupPolicyTest(t, mock)
	defer cleanup()

	revisions, err := client.List(context.Background(), "default")

	require.NoError(t, err)
	require.Len(t, revisions, 2)

	// Verify request was forwarded (no pagination options).
	mock.mu.Lock()
	assert.Equal(t, "default", mock.lastListReq.GetWorkspace())
	assert.Equal(t, uint32(0), mock.lastListReq.GetLimit())
	assert.Equal(t, uint32(0), mock.lastListReq.GetOffset())
	mock.mu.Unlock()

	assert.Equal(t, uint32(1), revisions[0].Version)
	assert.Equal(t, "sha256:v1", revisions[0].PolicyHash)
	assert.Equal(t, PolicyLoadStatusSuperseded, revisions[0].Status)

	assert.Equal(t, uint32(2), revisions[1].Version)
	assert.Equal(t, "sha256:v2", revisions[1].PolicyHash)
	assert.Equal(t, PolicyLoadStatusLoaded, revisions[1].Status)
}

func TestPolicyList_WithPagination(t *testing.T) {
	mock := newMockPolicyServer()
	mock.listResp = &pb.ListSandboxPoliciesResponse{
		Revisions: []*pb.SandboxPolicyRevision{
			{Version: 3, PolicyHash: "sha256:v3"},
		},
	}

	client, cleanup := setupPolicyTest(t, mock)
	defer cleanup()

	revisions, err := client.List(context.Background(), "default",
		types.WithLimit(10),
		types.WithOffset(20),
	)

	require.NoError(t, err)
	require.Len(t, revisions, 1)

	// Verify pagination options were forwarded.
	mock.mu.Lock()
	assert.Equal(t, uint32(10), mock.lastListReq.GetLimit())
	assert.Equal(t, uint32(20), mock.lastListReq.GetOffset())
	mock.mu.Unlock()
}

func TestPolicyList_Empty(t *testing.T) {
	mock := newMockPolicyServer()
	mock.listResp = &pb.ListSandboxPoliciesResponse{}

	client, cleanup := setupPolicyTest(t, mock)
	defer cleanup()

	revisions, err := client.List(context.Background(), "default")

	require.NoError(t, err)
	assert.Nil(t, revisions)
}

func TestPolicyList_WithGlobal(t *testing.T) {
	mock := newMockPolicyServer()
	mock.listResp = &pb.ListSandboxPoliciesResponse{
		Revisions: []*pb.SandboxPolicyRevision{
			{Version: 1, PolicyHash: "sha256:global-v1"},
		},
	}

	client, cleanup := setupPolicyTest(t, mock)
	defer cleanup()

	// List with global flag and empty workspace.
	revisions, err := client.List(context.Background(), "", types.WithListGlobal(true))

	require.NoError(t, err)
	require.Len(t, revisions, 1)
	assert.Equal(t, uint32(1), revisions[0].Version)
	assert.Equal(t, "sha256:global-v1", revisions[0].PolicyHash)

	// Verify global flag was forwarded in the proto request.
	mock.mu.Lock()
	assert.True(t, mock.lastListReq.GetGlobal())
	assert.Empty(t, mock.lastListReq.GetWorkspace())
	mock.mu.Unlock()
}

func TestPolicyList_WithGlobalIgnoresWorkspace(t *testing.T) {
	mock := newMockPolicyServer()
	mock.listResp = &pb.ListSandboxPoliciesResponse{
		Revisions: []*pb.SandboxPolicyRevision{
			{Version: 1, PolicyHash: "sha256:global-v1"},
		},
	}

	client, cleanup := setupPolicyTest(t, mock)
	defer cleanup()

	revisions, err := client.List(context.Background(), "some-workspace", types.WithListGlobal(true))

	require.NoError(t, err)
	require.Len(t, revisions, 1)

	mock.mu.Lock()
	assert.True(t, mock.lastListReq.GetGlobal())
	assert.Equal(t, "some-workspace", mock.lastListReq.GetWorkspace())
	mock.mu.Unlock()
}

func TestPolicyList_WithGlobalAndPagination(t *testing.T) {
	mock := newMockPolicyServer()
	mock.listResp = &pb.ListSandboxPoliciesResponse{
		Revisions: []*pb.SandboxPolicyRevision{
			{Version: 5, PolicyHash: "sha256:global-v5"},
		},
	}

	client, cleanup := setupPolicyTest(t, mock)
	defer cleanup()

	// Global flag composes with pagination options.
	revisions, err := client.List(context.Background(), "",
		types.WithListGlobal(true),
		types.WithLimit(10),
		types.WithOffset(20),
	)

	require.NoError(t, err)
	require.Len(t, revisions, 1)

	mock.mu.Lock()
	assert.True(t, mock.lastListReq.GetGlobal())
	assert.Equal(t, uint32(10), mock.lastListReq.GetLimit())
	assert.Equal(t, uint32(20), mock.lastListReq.GetOffset())
	mock.mu.Unlock()
}

func TestPolicyList_WithoutGlobal_PreservesExistingBehavior(t *testing.T) {
	mock := newMockPolicyServer()
	mock.listResp = &pb.ListSandboxPoliciesResponse{
		Revisions: []*pb.SandboxPolicyRevision{
			{Version: 1, PolicyHash: "sha256:v1"},
		},
	}

	client, cleanup := setupPolicyTest(t, mock)
	defer cleanup()

	revisions, err := client.List(context.Background(), "default")

	require.NoError(t, err)
	require.Len(t, revisions, 1)

	// Verify global flag is false by default.
	mock.mu.Lock()
	assert.False(t, mock.lastListReq.GetGlobal())
	assert.Equal(t, "default", mock.lastListReq.GetWorkspace())
	mock.mu.Unlock()
}

func TestPolicyList_Error(t *testing.T) {
	mock := newMockPolicyServer()
	mock.listErr = status.Errorf(codes.NotFound, "sandbox not found")

	client, cleanup := setupPolicyTest(t, mock)
	defer cleanup()

	revisions, err := client.List(context.Background(), "default")

	assert.Nil(t, revisions)
	require.Error(t, err)
	assert.True(t, IsNotFound(err))
}

func TestPolicyEditDraftChunk(t *testing.T) {
	mock := newMockPolicyServer()
	mock.editResp = &pb.EditDraftChunkResponse{}

	client, cleanup := setupPolicyTest(t, mock)
	defer cleanup()

	rule := &NetworkPolicyRule{
		Name: "allow-https",
		Endpoints: []PolicyNetworkEndpoint{
			{Host: "example.com", Port: 443, Protocol: "tcp"},
		},
	}

	err := client.EditDraftChunk(context.Background(), "default", "my-sandbox", "chunk-1", rule)

	require.NoError(t, err)

	// Verify request was forwarded.
	mock.mu.Lock()
	assert.Equal(t, "my-sandbox", mock.lastEditReq.GetName())
	assert.Equal(t, "chunk-1", mock.lastEditReq.GetChunkId())
	require.NotNil(t, mock.lastEditReq.GetProposedRule())
	assert.Equal(t, "allow-https", mock.lastEditReq.GetProposedRule().GetName())
	require.Len(t, mock.lastEditReq.GetProposedRule().GetEndpoints(), 1)
	assert.Equal(t, "example.com", mock.lastEditReq.GetProposedRule().GetEndpoints()[0].GetHost())
	mock.mu.Unlock()
}

func TestPolicyEditDraftChunk_Error(t *testing.T) {
	mock := newMockPolicyServer()
	mock.editErr = status.Errorf(codes.InvalidArgument, "invalid rule")

	client, cleanup := setupPolicyTest(t, mock)
	defer cleanup()

	err := client.EditDraftChunk(context.Background(), "default", "sb1", "chunk-1", &NetworkPolicyRule{})

	require.Error(t, err)
	assert.True(t, IsInvalidArgument(err))
}

func TestPolicyUndoDraftChunk(t *testing.T) {
	mock := newMockPolicyServer()
	mock.undoResp = &pb.UndoDraftChunkResponse{
		PolicyVersion: 10,
		PolicyHash:    "sha256:undo",
	}

	client, cleanup := setupPolicyTest(t, mock)
	defer cleanup()

	result, err := client.UndoDraftChunk(context.Background(), "default", "my-sandbox", "chunk-3")

	require.NoError(t, err)
	require.NotNil(t, result)

	// Verify request was forwarded.
	mock.mu.Lock()
	assert.Equal(t, "my-sandbox", mock.lastUndoReq.GetName())
	assert.Equal(t, "chunk-3", mock.lastUndoReq.GetChunkId())
	mock.mu.Unlock()

	assert.Equal(t, uint32(10), result.PolicyVersion)
	assert.Equal(t, "sha256:undo", result.PolicyHash)
}

func TestPolicyUndoDraftChunk_Error(t *testing.T) {
	mock := newMockPolicyServer()
	mock.undoErr = status.Errorf(codes.NotFound, "chunk not found")

	client, cleanup := setupPolicyTest(t, mock)
	defer cleanup()

	result, err := client.UndoDraftChunk(context.Background(), "default", "sb1", "bad-chunk")

	assert.Nil(t, result)
	require.Error(t, err)
	assert.True(t, IsNotFound(err))
}
