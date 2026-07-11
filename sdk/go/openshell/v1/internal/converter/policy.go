// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package converter

import (
	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	sbv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/sandboxv1"
)

// --- PolicyLoadStatus enum mapping ---

// PolicyLoadStatusFromProto converts a proto PolicyStatus to an SDK PolicyLoadStatus.
func PolicyLoadStatusFromProto(s pb.PolicyStatus) types.PolicyLoadStatus {
	switch s {
	case pb.PolicyStatus_POLICY_STATUS_PENDING:
		return types.PolicyLoadStatusPending
	case pb.PolicyStatus_POLICY_STATUS_LOADED:
		return types.PolicyLoadStatusLoaded
	case pb.PolicyStatus_POLICY_STATUS_FAILED:
		return types.PolicyLoadStatusFailed
	case pb.PolicyStatus_POLICY_STATUS_SUPERSEDED:
		return types.PolicyLoadStatusSuperseded
	default:
		return types.PolicyLoadStatusUnspecified
	}
}

// PolicyLoadStatusToProto converts an SDK PolicyLoadStatus to a proto PolicyStatus.
func PolicyLoadStatusToProto(s types.PolicyLoadStatus) pb.PolicyStatus {
	switch s {
	case types.PolicyLoadStatusPending:
		return pb.PolicyStatus_POLICY_STATUS_PENDING
	case types.PolicyLoadStatusLoaded:
		return pb.PolicyStatus_POLICY_STATUS_LOADED
	case types.PolicyLoadStatusFailed:
		return pb.PolicyStatus_POLICY_STATUS_FAILED
	case types.PolicyLoadStatusSuperseded:
		return pb.PolicyStatus_POLICY_STATUS_SUPERSEDED
	default:
		return pb.PolicyStatus_POLICY_STATUS_UNSPECIFIED
	}
}

// --- PolicyChunk ---

// PolicyChunkFromProto converts a proto PolicyChunk to an SDK PolicyChunk.
func PolicyChunkFromProto(c *pb.PolicyChunk) *types.PolicyChunk {
	if c == nil {
		return nil
	}
	return &types.PolicyChunk{
		ID:                c.GetId(),
		Status:            c.GetStatus(),
		RuleName:          c.GetRuleName(),
		ProposedRule:      NetworkPolicyRuleFromProto(c.GetProposedRule()),
		Rationale:         c.GetRationale(),
		SecurityNotes:     c.GetSecurityNotes(),
		Confidence:        c.GetConfidence(),
		DenialSummaryIDs:  CopyStringSlice(c.GetDenialSummaryIds()),
		CreatedAt:         TimeFromMillis(c.GetCreatedAtMs()),
		DecidedAt:         TimeFromMillis(c.GetDecidedAtMs()),
		Stage:             c.GetStage(),
		SupersedesChunkID: c.GetSupersedesChunkId(),
		HitCount:          c.GetHitCount(),
		FirstSeen:         TimeFromMillis(c.GetFirstSeenMs()),
		LastSeen:          TimeFromMillis(c.GetLastSeenMs()),
		Binary:            c.GetBinary(),
		ValidationResult:  c.GetValidationResult(),
		RejectionReason:   c.GetRejectionReason(),
	}
}

// --- DraftPolicy ---

// DraftPolicyFromProto converts a proto GetDraftPolicyResponse to an SDK DraftPolicy.
func DraftPolicyFromProto(r *pb.GetDraftPolicyResponse) *types.DraftPolicy {
	if r == nil {
		return nil
	}
	result := &types.DraftPolicy{
		RollingSummary: r.GetRollingSummary(),
		DraftVersion:   r.GetDraftVersion(),
		LastAnalyzedAt: TimeFromMillis(r.GetLastAnalyzedAtMs()),
	}
	if chunks := r.GetChunks(); len(chunks) > 0 {
		result.Chunks = make([]types.PolicyChunk, 0, len(chunks))
		for _, c := range chunks {
			if converted := PolicyChunkFromProto(c); converted != nil {
				result.Chunks = append(result.Chunks, *converted)
			}
		}
	}
	return result
}

// --- SandboxPolicy ---

// SandboxPolicyFromProto converts a proto SandboxPolicy to an SDK SandboxPolicy.
// Returns nil for nil input. All slice and map fields are deep-copied.
func SandboxPolicyFromProto(p *sbv1.SandboxPolicy) *types.SandboxPolicy {
	if p == nil {
		return nil
	}
	result := &types.SandboxPolicy{
		Version:    p.GetVersion(),
		Filesystem: filesystemPolicyFromProto(p.GetFilesystem()),
		Landlock:   landlockPolicyFromProto(p.GetLandlock()),
		Process:    processPolicyFromProto(p.GetProcess()),
	}
	if np := p.GetNetworkPolicies(); np != nil {
		result.NetworkPolicies = make(map[string]types.NetworkPolicyRule, len(np))
		for k, v := range np {
			if converted := NetworkPolicyRuleFromProto(v); converted != nil {
				result.NetworkPolicies[k] = *converted
			}
		}
	}
	return result
}

// SandboxPolicyToProto converts an SDK SandboxPolicy to a proto SandboxPolicy.
// Returns nil for nil input. All slice and map fields are deep-copied.
func SandboxPolicyToProto(p *types.SandboxPolicy) *sbv1.SandboxPolicy {
	if p == nil {
		return nil
	}
	result := &sbv1.SandboxPolicy{
		Version:    p.Version,
		Filesystem: filesystemPolicyToProto(p.Filesystem),
		Landlock:   landlockPolicyToProto(p.Landlock),
		Process:    processPolicyToProto(p.Process),
	}
	if p.NetworkPolicies != nil {
		result.NetworkPolicies = make(map[string]*sbv1.NetworkPolicyRule, len(p.NetworkPolicies))
		for k, v := range p.NetworkPolicies {
			result.NetworkPolicies[k] = NetworkPolicyRuleToProto(&v)
		}
	}
	return result
}

func filesystemPolicyFromProto(f *sbv1.FilesystemPolicy) *types.FilesystemPolicy {
	if f == nil {
		return nil
	}
	return &types.FilesystemPolicy{
		IncludeWorkdir: f.GetIncludeWorkdir(),
		ReadOnly:       CopyStringSlice(f.GetReadOnly()),
		ReadWrite:      CopyStringSlice(f.GetReadWrite()),
	}
}

func filesystemPolicyToProto(f *types.FilesystemPolicy) *sbv1.FilesystemPolicy {
	if f == nil {
		return nil
	}
	return &sbv1.FilesystemPolicy{
		IncludeWorkdir: f.IncludeWorkdir,
		ReadOnly:       CopyStringSlice(f.ReadOnly),
		ReadWrite:      CopyStringSlice(f.ReadWrite),
	}
}

func landlockPolicyFromProto(l *sbv1.LandlockPolicy) *types.LandlockPolicy {
	if l == nil {
		return nil
	}
	return &types.LandlockPolicy{
		Compatibility: l.GetCompatibility(),
	}
}

func landlockPolicyToProto(l *types.LandlockPolicy) *sbv1.LandlockPolicy {
	if l == nil {
		return nil
	}
	return &sbv1.LandlockPolicy{
		Compatibility: l.Compatibility,
	}
}

func processPolicyFromProto(p *sbv1.ProcessPolicy) *types.ProcessPolicy {
	if p == nil {
		return nil
	}
	return &types.ProcessPolicy{
		RunAsUser:  p.GetRunAsUser(),
		RunAsGroup: p.GetRunAsGroup(),
	}
}

func processPolicyToProto(p *types.ProcessPolicy) *sbv1.ProcessPolicy {
	if p == nil {
		return nil
	}
	return &sbv1.ProcessPolicy{
		RunAsUser:  p.RunAsUser,
		RunAsGroup: p.RunAsGroup,
	}
}

// --- SandboxPolicyRevision ---

// SandboxPolicyRevisionFromProto converts a proto SandboxPolicyRevision to an SDK SandboxPolicyRevision.
func SandboxPolicyRevisionFromProto(r *pb.SandboxPolicyRevision) *types.SandboxPolicyRevision {
	if r == nil {
		return nil
	}
	return &types.SandboxPolicyRevision{
		Version:    r.GetVersion(),
		PolicyHash: r.GetPolicyHash(),
		Status:     PolicyLoadStatusFromProto(r.GetStatus()),
		LoadError:  r.GetLoadError(),
		CreatedAt:  TimeFromMillis(r.GetCreatedAtMs()),
		LoadedAt:   TimeFromMillis(r.GetLoadedAtMs()),
		Policy:     SandboxPolicyFromProto(r.GetPolicy()),
	}
}

// --- PolicyStatusResult ---

// PolicyStatusResultFromProto converts a proto GetSandboxPolicyStatusResponse to an SDK PolicyStatusResult.
func PolicyStatusResultFromProto(r *pb.GetSandboxPolicyStatusResponse) *types.PolicyStatusResult {
	if r == nil {
		return nil
	}
	result := &types.PolicyStatusResult{
		ActiveVersion: r.GetActiveVersion(),
	}
	if rev := SandboxPolicyRevisionFromProto(r.GetRevision()); rev != nil {
		result.Revision = *rev
	}
	return result
}

// --- ApproveResult ---

// ApproveResultFromProto converts a proto ApproveDraftChunkResponse to an SDK ApproveResult.
func ApproveResultFromProto(r *pb.ApproveDraftChunkResponse) *types.ApproveResult {
	if r == nil {
		return nil
	}
	return &types.ApproveResult{
		PolicyVersion: r.GetPolicyVersion(),
		PolicyHash:    r.GetPolicyHash(),
	}
}

// --- ApproveAllResult ---

// ApproveAllResultFromProto converts a proto ApproveAllDraftChunksResponse to an SDK ApproveAllResult.
func ApproveAllResultFromProto(r *pb.ApproveAllDraftChunksResponse) *types.ApproveAllResult {
	if r == nil {
		return nil
	}
	return &types.ApproveAllResult{
		PolicyVersion:  r.GetPolicyVersion(),
		PolicyHash:     r.GetPolicyHash(),
		ChunksApproved: r.GetChunksApproved(),
		ChunksSkipped:  r.GetChunksSkipped(),
	}
}

// --- UndoResult ---

// UndoResultFromProto converts a proto UndoDraftChunkResponse to an SDK UndoResult.
func UndoResultFromProto(r *pb.UndoDraftChunkResponse) *types.UndoResult {
	if r == nil {
		return nil
	}
	return &types.UndoResult{
		PolicyVersion: r.GetPolicyVersion(),
		PolicyHash:    r.GetPolicyHash(),
	}
}

// --- ClearResult ---

// ClearResultFromProto converts a proto ClearDraftChunksResponse to an SDK ClearResult.
func ClearResultFromProto(r *pb.ClearDraftChunksResponse) *types.ClearResult {
	if r == nil {
		return nil
	}
	return &types.ClearResult{
		ChunksCleared: r.GetChunksCleared(),
	}
}

// --- DraftHistoryEntry ---

// DraftHistoryEntryFromProto converts a proto DraftHistoryEntry to an SDK DraftHistoryEntry.
func DraftHistoryEntryFromProto(e *pb.DraftHistoryEntry) *types.DraftHistoryEntry {
	if e == nil {
		return nil
	}
	return &types.DraftHistoryEntry{
		Timestamp:   TimeFromMillis(e.GetTimestampMs()),
		EventType:   e.GetEventType(),
		Description: e.GetDescription(),
		ChunkID:     e.GetChunkId(),
	}
}
