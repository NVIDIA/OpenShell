// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package converter

import (
	"testing"

	v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	sbv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/sandboxv1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
)

// --- PolicyLoadStatus ---

func TestPolicyLoadStatusFromProto(t *testing.T) {
	tests := []struct {
		proto pb.PolicyStatus
		want  v1.PolicyLoadStatus
	}{
		{pb.PolicyStatus_POLICY_STATUS_UNSPECIFIED, v1.PolicyLoadStatusUnspecified},
		{pb.PolicyStatus_POLICY_STATUS_PENDING, v1.PolicyLoadStatusPending},
		{pb.PolicyStatus_POLICY_STATUS_LOADED, v1.PolicyLoadStatusLoaded},
		{pb.PolicyStatus_POLICY_STATUS_FAILED, v1.PolicyLoadStatusFailed},
		{pb.PolicyStatus_POLICY_STATUS_SUPERSEDED, v1.PolicyLoadStatusSuperseded},
	}
	for _, tt := range tests {
		t.Run(tt.proto.String(), func(t *testing.T) {
			assert.Equal(t, tt.want, PolicyLoadStatusFromProto(tt.proto))
		})
	}
}

func TestPolicyLoadStatusToProto(t *testing.T) {
	tests := []struct {
		sdk  v1.PolicyLoadStatus
		want pb.PolicyStatus
	}{
		{v1.PolicyLoadStatusUnspecified, pb.PolicyStatus_POLICY_STATUS_UNSPECIFIED},
		{v1.PolicyLoadStatusPending, pb.PolicyStatus_POLICY_STATUS_PENDING},
		{v1.PolicyLoadStatusLoaded, pb.PolicyStatus_POLICY_STATUS_LOADED},
		{v1.PolicyLoadStatusFailed, pb.PolicyStatus_POLICY_STATUS_FAILED},
		{v1.PolicyLoadStatusSuperseded, pb.PolicyStatus_POLICY_STATUS_SUPERSEDED},
	}
	for _, tt := range tests {
		t.Run(tt.sdk.String(), func(t *testing.T) {
			assert.Equal(t, tt.want, PolicyLoadStatusToProto(tt.sdk))
		})
	}
}

func TestPolicyLoadStatusRoundTrip(t *testing.T) {
	for _, s := range []v1.PolicyLoadStatus{
		v1.PolicyLoadStatusUnspecified,
		v1.PolicyLoadStatusPending,
		v1.PolicyLoadStatusLoaded,
		v1.PolicyLoadStatusFailed,
		v1.PolicyLoadStatusSuperseded,
	} {
		assert.Equal(t, s, PolicyLoadStatusFromProto(PolicyLoadStatusToProto(s)))
	}
}

// --- PolicyChunk ---

func TestPolicyChunkFromProto(t *testing.T) {
	proto := &pb.PolicyChunk{
		Id:                "chunk-1",
		Status:            "pending",
		RuleName:          "web-api",
		Rationale:         "Observed DNS resolution",
		SecurityNotes:     "No concerns",
		Confidence:        0.95,
		DenialSummaryIds:  []string{"d1", "d2"},
		CreatedAtMs:       1700000000000,
		DecidedAtMs:       1700000001000,
		Stage:             "initial",
		SupersedesChunkId: "chunk-0",
		HitCount:          5,
		FirstSeenMs:       1699999999000,
		LastSeenMs:        1700000000500,
		Binary:            "/usr/bin/curl",
		ValidationResult:  "valid",
		RejectionReason:   "",
		ProposedRule: &sbv1.NetworkPolicyRule{
			Name: "web-api",
			Endpoints: []*sbv1.NetworkEndpoint{
				{Host: "api.example.com", Port: 443, Protocol: "rest"},
			},
		},
	}

	chunk := PolicyChunkFromProto(proto)

	require.NotNil(t, chunk)
	assert.Equal(t, "chunk-1", chunk.ID)
	assert.Equal(t, "pending", chunk.Status)
	assert.Equal(t, "web-api", chunk.RuleName)
	assert.Equal(t, "Observed DNS resolution", chunk.Rationale)
	assert.Equal(t, "No concerns", chunk.SecurityNotes)
	assert.InDelta(t, float32(0.95), chunk.Confidence, 0.001)
	assert.Equal(t, []string{"d1", "d2"}, chunk.DenialSummaryIDs)
	assert.False(t, chunk.CreatedAt.IsZero())
	assert.False(t, chunk.DecidedAt.IsZero())
	assert.Equal(t, "initial", chunk.Stage)
	assert.Equal(t, "chunk-0", chunk.SupersedesChunkID)
	assert.Equal(t, int32(5), chunk.HitCount)
	assert.False(t, chunk.FirstSeen.IsZero())
	assert.False(t, chunk.LastSeen.IsZero())
	assert.Equal(t, "/usr/bin/curl", chunk.Binary)
	assert.Equal(t, "valid", chunk.ValidationResult)
	assert.Empty(t, chunk.RejectionReason)

	require.NotNil(t, chunk.ProposedRule)
	assert.Equal(t, "web-api", chunk.ProposedRule.Name)
	require.Len(t, chunk.ProposedRule.Endpoints, 1)
	assert.Equal(t, "api.example.com", chunk.ProposedRule.Endpoints[0].Host)
}

func TestPolicyChunkFromProto_Nil(t *testing.T) {
	assert.Nil(t, PolicyChunkFromProto(nil))
}

func TestPolicyChunkDeepCopy(t *testing.T) {
	proto := &pb.PolicyChunk{
		Id:               "c1",
		DenialSummaryIds: []string{"d1"},
	}

	chunk := PolicyChunkFromProto(proto)
	proto.DenialSummaryIds[0] = "changed"

	assert.Equal(t, "d1", chunk.DenialSummaryIDs[0])
}

// --- DraftPolicy ---

func TestDraftPolicyFromProto(t *testing.T) {
	proto := &pb.GetDraftPolicyResponse{
		Chunks: []*pb.PolicyChunk{
			{Id: "c1", Status: "pending", RuleName: "rule1"},
			{Id: "c2", Status: "approved", RuleName: "rule2"},
		},
		RollingSummary:   "Analysis summary",
		DraftVersion:     42,
		LastAnalyzedAtMs: 1700000000000,
	}

	draft := DraftPolicyFromProto(proto)

	require.NotNil(t, draft)
	assert.Len(t, draft.Chunks, 2)
	assert.Equal(t, "c1", draft.Chunks[0].ID)
	assert.Equal(t, "c2", draft.Chunks[1].ID)
	assert.Equal(t, "Analysis summary", draft.RollingSummary)
	assert.Equal(t, uint64(42), draft.DraftVersion)
	assert.False(t, draft.LastAnalyzedAt.IsZero())
}

func TestDraftPolicyFromProto_Nil(t *testing.T) {
	assert.Nil(t, DraftPolicyFromProto(nil))
}

func TestDraftPolicyFromProto_EmptyChunks(t *testing.T) {
	proto := &pb.GetDraftPolicyResponse{
		RollingSummary: "empty",
		DraftVersion:   1,
	}

	draft := DraftPolicyFromProto(proto)
	require.NotNil(t, draft)
	assert.Empty(t, draft.Chunks)
}

// --- SandboxPolicy ---

func TestSandboxPolicyFromProtoNil(t *testing.T) {
	assert.Nil(t, SandboxPolicyFromProto(nil))
}

func TestSandboxPolicyToProtoNil(t *testing.T) {
	assert.Nil(t, SandboxPolicyToProto(nil))
}

func TestSandboxPolicyRoundTrip(t *testing.T) {
	original := &v1.SandboxPolicy{
		Version: 5,
		Filesystem: &v1.FilesystemPolicy{
			IncludeWorkdir: true,
			ReadOnly:       []string{"/etc", "/usr/share"},
			ReadWrite:      []string{"/tmp", "/workspace"},
		},
		Landlock: &v1.LandlockPolicy{
			Compatibility: "best_effort",
		},
		Process: &v1.ProcessPolicy{
			RunAsUser:  "sandbox-user",
			RunAsGroup: "sandbox-group",
		},
		NetworkPolicies: map[string]v1.NetworkPolicyRule{
			"web-api": {
				Name: "web-api",
				Endpoints: []v1.PolicyNetworkEndpoint{
					{Host: "api.example.com", Port: 443, Protocol: "rest"},
				},
			},
			"db": {
				Name: "db",
				Endpoints: []v1.PolicyNetworkEndpoint{
					{Host: "db.internal", Port: 5432, Protocol: "tcp"},
				},
			},
		},
	}

	proto := SandboxPolicyToProto(original)
	require.NotNil(t, proto)

	roundTrip := SandboxPolicyFromProto(proto)
	require.NotNil(t, roundTrip)

	assert.Equal(t, original.Version, roundTrip.Version)

	// Filesystem
	require.NotNil(t, roundTrip.Filesystem)
	assert.Equal(t, original.Filesystem.IncludeWorkdir, roundTrip.Filesystem.IncludeWorkdir)
	assert.Equal(t, original.Filesystem.ReadOnly, roundTrip.Filesystem.ReadOnly)
	assert.Equal(t, original.Filesystem.ReadWrite, roundTrip.Filesystem.ReadWrite)

	// Landlock
	require.NotNil(t, roundTrip.Landlock)
	assert.Equal(t, original.Landlock.Compatibility, roundTrip.Landlock.Compatibility)

	// Process
	require.NotNil(t, roundTrip.Process)
	assert.Equal(t, original.Process.RunAsUser, roundTrip.Process.RunAsUser)
	assert.Equal(t, original.Process.RunAsGroup, roundTrip.Process.RunAsGroup)

	// NetworkPolicies
	require.Len(t, roundTrip.NetworkPolicies, 2)
	webAPI, ok := roundTrip.NetworkPolicies["web-api"]
	require.True(t, ok)
	assert.Equal(t, "web-api", webAPI.Name)
	require.Len(t, webAPI.Endpoints, 1)
	assert.Equal(t, "api.example.com", webAPI.Endpoints[0].Host)

	db, ok := roundTrip.NetworkPolicies["db"]
	require.True(t, ok)
	assert.Equal(t, "db", db.Name)
}

func TestSandboxPolicyDeepCopy(t *testing.T) {
	// Build a proto, convert to SDK, mutate proto, verify SDK is isolated.
	proto := &sbv1.SandboxPolicy{
		Version: 1,
		Filesystem: &sbv1.FilesystemPolicy{
			IncludeWorkdir: true,
			ReadOnly:       []string{"/original"},
			ReadWrite:      []string{"/tmp"},
		},
		NetworkPolicies: map[string]*sbv1.NetworkPolicyRule{
			"rule1": {
				Name: "rule1",
				Endpoints: []*sbv1.NetworkEndpoint{
					{Host: "original.host", Port: 80},
				},
			},
		},
	}

	sdk := SandboxPolicyFromProto(proto)
	require.NotNil(t, sdk)

	// Mutate proto source after conversion.
	proto.Version = 99
	proto.Filesystem.ReadOnly[0] = "mutated"
	proto.Filesystem.ReadWrite[0] = "mutated"
	proto.NetworkPolicies["rule1"].Name = "mutated"
	proto.NetworkPolicies["rule1"].Endpoints[0].Host = "mutated.host"

	// SDK values must be unaffected.
	assert.Equal(t, uint32(1), sdk.Version)
	assert.Equal(t, "/original", sdk.Filesystem.ReadOnly[0])
	assert.Equal(t, "/tmp", sdk.Filesystem.ReadWrite[0])
	assert.Equal(t, "rule1", sdk.NetworkPolicies["rule1"].Name)
	assert.Equal(t, "original.host", sdk.NetworkPolicies["rule1"].Endpoints[0].Host)

	// Also test ToProto deep-copy isolation.
	protoOut := SandboxPolicyToProto(sdk)
	require.NotNil(t, protoOut)

	// Mutate SDK after ToProto conversion.
	sdk.Filesystem.ReadOnly[0] = "sdk-mutated"

	// Proto output must be unaffected.
	assert.Equal(t, "/original", protoOut.Filesystem.ReadOnly[0])
}

func TestSandboxPolicyPartialSubPolicies(t *testing.T) {
	t.Run("only filesystem", func(t *testing.T) {
		original := &v1.SandboxPolicy{
			Version: 1,
			Filesystem: &v1.FilesystemPolicy{
				ReadOnly: []string{"/etc"},
			},
		}
		roundTrip := SandboxPolicyFromProto(SandboxPolicyToProto(original))
		require.NotNil(t, roundTrip)
		require.NotNil(t, roundTrip.Filesystem)
		assert.Nil(t, roundTrip.Landlock)
		assert.Nil(t, roundTrip.Process)
		assert.Nil(t, roundTrip.NetworkPolicies)
	})

	t.Run("only landlock", func(t *testing.T) {
		original := &v1.SandboxPolicy{
			Version: 2,
			Landlock: &v1.LandlockPolicy{
				Compatibility: "hard_requirement",
			},
		}
		roundTrip := SandboxPolicyFromProto(SandboxPolicyToProto(original))
		require.NotNil(t, roundTrip)
		assert.Nil(t, roundTrip.Filesystem)
		require.NotNil(t, roundTrip.Landlock)
		assert.Equal(t, "hard_requirement", roundTrip.Landlock.Compatibility)
		assert.Nil(t, roundTrip.Process)
		assert.Nil(t, roundTrip.NetworkPolicies)
	})

	t.Run("only process", func(t *testing.T) {
		original := &v1.SandboxPolicy{
			Process: &v1.ProcessPolicy{
				RunAsUser: "nobody",
			},
		}
		roundTrip := SandboxPolicyFromProto(SandboxPolicyToProto(original))
		require.NotNil(t, roundTrip)
		assert.Nil(t, roundTrip.Filesystem)
		assert.Nil(t, roundTrip.Landlock)
		require.NotNil(t, roundTrip.Process)
		assert.Equal(t, "nobody", roundTrip.Process.RunAsUser)
	})

	t.Run("only network policies", func(t *testing.T) {
		original := &v1.SandboxPolicy{
			NetworkPolicies: map[string]v1.NetworkPolicyRule{
				"r1": {Name: "r1"},
			},
		}
		roundTrip := SandboxPolicyFromProto(SandboxPolicyToProto(original))
		require.NotNil(t, roundTrip)
		assert.Nil(t, roundTrip.Filesystem)
		assert.Nil(t, roundTrip.Landlock)
		assert.Nil(t, roundTrip.Process)
		require.Len(t, roundTrip.NetworkPolicies, 1)
	})

	t.Run("empty network policies map preserved", func(t *testing.T) {
		proto := &sbv1.SandboxPolicy{
			NetworkPolicies: map[string]*sbv1.NetworkPolicyRule{},
		}
		// Proto empty map is non-nil, so converter creates an empty SDK map.
		sdk := SandboxPolicyFromProto(proto)
		require.NotNil(t, sdk)
		require.NotNil(t, sdk.NetworkPolicies)
		assert.Empty(t, sdk.NetworkPolicies)
	})
}

func TestFilesystemPolicyRoundTrip(t *testing.T) {
	original := &v1.FilesystemPolicy{
		IncludeWorkdir: true,
		ReadOnly:       []string{"/etc", "/usr/lib"},
		ReadWrite:      []string{"/tmp", "/var/run"},
	}

	proto := filesystemPolicyToProto(original)
	require.NotNil(t, proto)

	roundTrip := filesystemPolicyFromProto(proto)
	require.NotNil(t, roundTrip)

	assert.Equal(t, original.IncludeWorkdir, roundTrip.IncludeWorkdir)
	assert.Equal(t, original.ReadOnly, roundTrip.ReadOnly)
	assert.Equal(t, original.ReadWrite, roundTrip.ReadWrite)
}

func TestFilesystemPolicyNil(t *testing.T) {
	assert.Nil(t, filesystemPolicyFromProto(nil))
	assert.Nil(t, filesystemPolicyToProto(nil))
}

func TestLandlockPolicyRoundTrip(t *testing.T) {
	original := &v1.LandlockPolicy{
		Compatibility: "best_effort",
	}

	proto := landlockPolicyToProto(original)
	require.NotNil(t, proto)

	roundTrip := landlockPolicyFromProto(proto)
	require.NotNil(t, roundTrip)

	assert.Equal(t, original.Compatibility, roundTrip.Compatibility)
}

func TestLandlockPolicyNil(t *testing.T) {
	assert.Nil(t, landlockPolicyFromProto(nil))
	assert.Nil(t, landlockPolicyToProto(nil))
}

func TestProcessPolicyRoundTrip(t *testing.T) {
	original := &v1.ProcessPolicy{
		RunAsUser:  "app-user",
		RunAsGroup: "app-group",
	}

	proto := processPolicyToProto(original)
	require.NotNil(t, proto)

	roundTrip := processPolicyFromProto(proto)
	require.NotNil(t, roundTrip)

	assert.Equal(t, original.RunAsUser, roundTrip.RunAsUser)
	assert.Equal(t, original.RunAsGroup, roundTrip.RunAsGroup)
}

func TestProcessPolicyNil(t *testing.T) {
	assert.Nil(t, processPolicyFromProto(nil))
	assert.Nil(t, processPolicyToProto(nil))
}

// --- SandboxPolicyRevision ---

func TestSandboxPolicyRevisionFromProto(t *testing.T) {
	proto := &pb.SandboxPolicyRevision{
		Version:     3,
		PolicyHash:  "sha256:abc123",
		Status:      pb.PolicyStatus_POLICY_STATUS_LOADED,
		LoadError:   "",
		CreatedAtMs: 1700000000000,
		LoadedAtMs:  1700000001000,
		Provenance:  map[string]string{"source": "api", "user": "admin"},
	}

	rev := SandboxPolicyRevisionFromProto(proto)

	require.NotNil(t, rev)
	assert.Equal(t, uint32(3), rev.Version)
	assert.Equal(t, "sha256:abc123", rev.PolicyHash)
	assert.Equal(t, v1.PolicyLoadStatusLoaded, rev.Status)
	assert.Empty(t, rev.LoadError)
	assert.False(t, rev.CreatedAt.IsZero())
	assert.False(t, rev.LoadedAt.IsZero())
	assert.Equal(t, map[string]string{"source": "api", "user": "admin"}, rev.Provenance)

	proto.Provenance["source"] = "MUTATED"
	assert.Equal(t, "api", rev.Provenance["source"], "provenance must be deep copied")
}

func TestSandboxPolicyRevisionFromProto_Nil(t *testing.T) {
	assert.Nil(t, SandboxPolicyRevisionFromProto(nil))
}

func TestSandboxPolicyRevisionFromProto_WithPolicy(t *testing.T) {
	proto := &pb.SandboxPolicyRevision{
		Version:    1,
		PolicyHash: "sha256:def",
		Status:     pb.PolicyStatus_POLICY_STATUS_LOADED,
		Policy: &sbv1.SandboxPolicy{
			Version: 2,
			Filesystem: &sbv1.FilesystemPolicy{
				ReadOnly: []string{"/etc"},
			},
		},
	}

	rev := SandboxPolicyRevisionFromProto(proto)
	require.NotNil(t, rev)
	require.NotNil(t, rev.Policy, "typed SandboxPolicy should be populated when proto policy is set")
	assert.Equal(t, uint32(2), rev.Policy.Version)
	require.NotNil(t, rev.Policy.Filesystem)
	assert.Equal(t, []string{"/etc"}, rev.Policy.Filesystem.ReadOnly)
}

// --- PolicyStatusResult ---

func TestPolicyStatusResultFromProto(t *testing.T) {
	proto := &pb.GetSandboxPolicyStatusResponse{
		Revision: &pb.SandboxPolicyRevision{
			Version:    5,
			PolicyHash: "sha256:xyz",
			Status:     pb.PolicyStatus_POLICY_STATUS_PENDING,
		},
		ActiveVersion: 4,
	}

	result := PolicyStatusResultFromProto(proto)

	require.NotNil(t, result)
	assert.Equal(t, uint32(5), result.Revision.Version)
	assert.Equal(t, "sha256:xyz", result.Revision.PolicyHash)
	assert.Equal(t, v1.PolicyLoadStatusPending, result.Revision.Status)
	assert.Equal(t, uint32(4), result.ActiveVersion)
}

func TestPolicyStatusResultFromProto_Nil(t *testing.T) {
	assert.Nil(t, PolicyStatusResultFromProto(nil))
}

// --- ApproveResult ---

func TestApproveResultFromProto(t *testing.T) {
	proto := &pb.ApproveDraftChunkResponse{
		PolicyVersion: 7,
		PolicyHash:    "sha256:merged",
	}

	result := ApproveResultFromProto(proto)

	require.NotNil(t, result)
	assert.Equal(t, uint32(7), result.PolicyVersion)
	assert.Equal(t, "sha256:merged", result.PolicyHash)
}

func TestApproveResultFromProto_Nil(t *testing.T) {
	assert.Nil(t, ApproveResultFromProto(nil))
}

// --- ApproveAllResult ---

func TestApproveAllResultFromProto(t *testing.T) {
	proto := &pb.ApproveAllDraftChunksResponse{
		PolicyVersion:  8,
		PolicyHash:     "sha256:all",
		ChunksApproved: 10,
		ChunksSkipped:  2,
	}

	result := ApproveAllResultFromProto(proto)

	require.NotNil(t, result)
	assert.Equal(t, uint32(8), result.PolicyVersion)
	assert.Equal(t, "sha256:all", result.PolicyHash)
	assert.Equal(t, uint32(10), result.ChunksApproved)
	assert.Equal(t, uint32(2), result.ChunksSkipped)
}

func TestApproveAllResultFromProto_Nil(t *testing.T) {
	assert.Nil(t, ApproveAllResultFromProto(nil))
}

// --- UndoResult ---

func TestUndoResultFromProto(t *testing.T) {
	proto := &pb.UndoDraftChunkResponse{
		PolicyVersion: 6,
		PolicyHash:    "sha256:reverted",
	}

	result := UndoResultFromProto(proto)

	require.NotNil(t, result)
	assert.Equal(t, uint32(6), result.PolicyVersion)
	assert.Equal(t, "sha256:reverted", result.PolicyHash)
}

func TestUndoResultFromProto_Nil(t *testing.T) {
	assert.Nil(t, UndoResultFromProto(nil))
}

// --- ClearResult ---

func TestClearResultFromProto(t *testing.T) {
	proto := &pb.ClearDraftChunksResponse{
		ChunksCleared: 15,
	}

	result := ClearResultFromProto(proto)

	require.NotNil(t, result)
	assert.Equal(t, uint32(15), result.ChunksCleared)
}

func TestClearResultFromProto_Nil(t *testing.T) {
	assert.Nil(t, ClearResultFromProto(nil))
}

// --- DraftHistoryEntry ---

func TestDraftHistoryEntryFromProto(t *testing.T) {
	proto := &pb.DraftHistoryEntry{
		TimestampMs: 1700000000000,
		EventType:   "approved",
		Description: "Chunk c1 approved",
		ChunkId:     "c1",
	}

	entry := DraftHistoryEntryFromProto(proto)

	require.NotNil(t, entry)
	assert.False(t, entry.Timestamp.IsZero())
	assert.Equal(t, "approved", entry.EventType)
	assert.Equal(t, "Chunk c1 approved", entry.Description)
	assert.Equal(t, "c1", entry.ChunkID)
}

func TestDraftHistoryEntryFromProto_Nil(t *testing.T) {
	assert.Nil(t, DraftHistoryEntryFromProto(nil))
}

// --- NetworkMiddleware ---

func TestSandboxPolicyFromProto_WithMiddleware(t *testing.T) {
	proto := &sbv1.SandboxPolicy{
		Version: 3,
		NetworkMiddlewares: map[string]*sbv1.NetworkMiddlewareConfig{
			"sigv4-rewriter": {
				Name:       "sigv4-rewriter",
				Middleware: "aws-sigv4",
				OnError:    "fail_closed",
				Order:      10,
				Config: func() *structpb.Struct {
					s, _ := structpb.NewStruct(map[string]any{
						"region":  "us-east-1",
						"service": "bedrock",
					})
					return s
				}(),
				Endpoints: &sbv1.MiddlewareEndpointSelector{
					Include: []string{"*.bedrock.amazonaws.com"},
					Exclude: []string{"sts.amazonaws.com"},
				},
			},
		},
	}

	policy := SandboxPolicyFromProto(proto)

	require.NotNil(t, policy)
	require.Contains(t, policy.NetworkMiddlewares, "sigv4-rewriter")
	mw := policy.NetworkMiddlewares["sigv4-rewriter"]
	assert.Equal(t, "sigv4-rewriter", mw.Name)
	assert.Equal(t, "aws-sigv4", mw.Middleware)
	assert.Equal(t, "fail_closed", mw.OnError)
	assert.Equal(t, int32(10), mw.Order)
	require.NotNil(t, mw.Config)
	assert.Equal(t, "us-east-1", mw.Config["region"])
	assert.Equal(t, "bedrock", mw.Config["service"])
	require.NotNil(t, mw.Endpoints)
	assert.Equal(t, []string{"*.bedrock.amazonaws.com"}, mw.Endpoints.Include)
	assert.Equal(t, []string{"sts.amazonaws.com"}, mw.Endpoints.Exclude)
}

func TestSandboxPolicyMiddlewareRoundTrip(t *testing.T) {
	original := &v1.SandboxPolicy{
		Version: 5,
		NetworkMiddlewares: map[string]v1.NetworkMiddlewareConfig{
			"rate-limiter": {
				Name:       "rate-limiter",
				Middleware: "envoy-ratelimit",
				OnError:    "fail_open",
				Order:      20,
				Config: map[string]any{
					"requests_per_second": float64(100),
				},
				Endpoints: &v1.MiddlewareEndpointSelector{
					Include: []string{"api.*"},
				},
			},
		},
	}

	proto := SandboxPolicyToProto(original)
	require.NotNil(t, proto)

	roundTrip := SandboxPolicyFromProto(proto)
	require.NotNil(t, roundTrip)

	require.Contains(t, roundTrip.NetworkMiddlewares, "rate-limiter")
	mw := roundTrip.NetworkMiddlewares["rate-limiter"]
	assert.Equal(t, original.NetworkMiddlewares["rate-limiter"].Name, mw.Name)
	assert.Equal(t, original.NetworkMiddlewares["rate-limiter"].Middleware, mw.Middleware)
	assert.Equal(t, original.NetworkMiddlewares["rate-limiter"].OnError, mw.OnError)
	assert.Equal(t, original.NetworkMiddlewares["rate-limiter"].Order, mw.Order)
	assert.Equal(t, original.NetworkMiddlewares["rate-limiter"].Config["requests_per_second"], mw.Config["requests_per_second"])
	assert.Equal(t, original.NetworkMiddlewares["rate-limiter"].Endpoints.Include, mw.Endpoints.Include)
}

func TestSandboxPolicyMiddlewareDeepCopy(t *testing.T) {
	proto := &sbv1.SandboxPolicy{
		NetworkMiddlewares: map[string]*sbv1.NetworkMiddlewareConfig{
			"test": {
				Endpoints: &sbv1.MiddlewareEndpointSelector{
					Include: []string{"original.com"},
				},
			},
		},
	}

	policy := SandboxPolicyFromProto(proto)
	proto.NetworkMiddlewares["test"].Endpoints.Include[0] = "mutated.com"

	assert.Equal(t, "original.com", policy.NetworkMiddlewares["test"].Endpoints.Include[0])
}
