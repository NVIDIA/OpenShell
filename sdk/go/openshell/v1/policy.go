// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
)

// SandboxPolicy is the top-level security policy configuration for a sandbox.
type SandboxPolicy = types.SandboxPolicy

// FilesystemPolicy controls which directories the sandbox can access.
type FilesystemPolicy = types.FilesystemPolicy

// LandlockPolicy configures the Linux Landlock LSM.
type LandlockPolicy = types.LandlockPolicy

// ProcessPolicy controls the user and group identity for sandboxed processes.
type ProcessPolicy = types.ProcessPolicy

// PolicyChunk represents a single proposed policy change in the draft inbox.
type PolicyChunk = types.PolicyChunk

// DraftChunkApproval binds a bulk approval to an evaluated proposal.
type DraftChunkApproval = types.DraftChunkApproval

// DraftPolicy contains the full draft policy state returned by GetDraft.
type DraftPolicy = types.DraftPolicy

// PolicyStatusResult contains the status of a sandbox's policy.
type PolicyStatusResult = types.PolicyStatusResult

// SandboxPolicyRevision represents a versioned policy revision for a sandbox.
type SandboxPolicyRevision = types.SandboxPolicyRevision

// PolicyLoadStatus represents the load state of a policy revision.
type PolicyLoadStatus = types.PolicyLoadStatus

// PolicyLoadStatus constants re-exported from types package.
const (
	PolicyLoadStatusUnspecified = types.PolicyLoadStatusUnspecified
	PolicyLoadStatusPending     = types.PolicyLoadStatusPending
	PolicyLoadStatusLoaded      = types.PolicyLoadStatusLoaded
	PolicyLoadStatusFailed      = types.PolicyLoadStatusFailed
	PolicyLoadStatusSuperseded  = types.PolicyLoadStatusSuperseded
)

// ApproveResult contains the result of approving a single draft chunk.
type ApproveResult = types.ApproveResult

// ApproveAllResult contains the result of approving all draft chunks.
type ApproveAllResult = types.ApproveAllResult

// UndoResult contains the result of undoing a draft chunk approval.
type UndoResult = types.UndoResult

// ClearResult contains the result of clearing all draft chunks.
type ClearResult = types.ClearResult

// DraftHistoryEntry represents a single event in the draft policy history.
type DraftHistoryEntry = types.DraftHistoryEntry

// GetDraftOption configures a GetDraft call.
type GetDraftOption = types.GetDraftOption

// WithStatusFilter filters draft chunks by approval status.
var WithStatusFilter = types.WithStatusFilter

// ApproveAllOption configures an ApproveAllDraftChunks call.
type ApproveAllOption = types.ApproveAllOption

// WithIncludeSecurityFlagged includes security-flagged chunks in bulk approval.
var WithIncludeSecurityFlagged = types.WithIncludeSecurityFlagged

// WithDraftApprovals supplies token-bound chunks for bulk approval.
var WithDraftApprovals = types.WithDraftApprovals

// GetStatusOption configures a GetStatus call.
type GetStatusOption = types.GetStatusOption

// WithVersion queries a specific policy version instead of the latest.
var WithVersion = types.WithVersion

// ListPolicyOption configures a List call.
type ListPolicyOption = types.ListPolicyOption

// WithLimit sets the maximum number of revisions to return.
var WithLimit = types.WithLimit

// WithOffset sets the pagination offset.
var WithOffset = types.WithOffset

// WithListGlobal enables global policy mode on List. When true, the query
// retrieves gateway-global policy revisions instead of sandbox-scoped ones.
var WithListGlobal = types.WithListGlobal

// WithStatusGlobal enables global policy mode on GetStatus. When true, the
// query retrieves gateway-global policy status instead of sandbox-scoped status.
var WithStatusGlobal = types.WithStatusGlobal

// PolicyInterface defines operations for managing sandbox policy drafts,
// approvals, and revision history.
type PolicyInterface interface {
	GetDraft(ctx context.Context, workspace, sandboxName string, opts ...GetDraftOption) (*DraftPolicy, error)
	ApproveDraftChunk(ctx context.Context, workspace, sandboxName, chunkID, reviewToken string) (*ApproveResult, error)
	RejectDraftChunk(ctx context.Context, workspace, sandboxName, chunkID, reason string) error
	ApproveAllDraftChunks(ctx context.Context, workspace, sandboxName string, opts ...ApproveAllOption) (*ApproveAllResult, error)
	ClearDraftChunks(ctx context.Context, workspace, sandboxName string) (*ClearResult, error)
	GetDraftHistory(ctx context.Context, workspace, sandboxName string) ([]DraftHistoryEntry, error)
	GetStatus(ctx context.Context, workspace, sandboxName string, opts ...GetStatusOption) (*PolicyStatusResult, error)
	List(ctx context.Context, workspace string, opts ...ListPolicyOption) ([]SandboxPolicyRevision, error)
	EditDraftChunk(ctx context.Context, workspace, sandboxName, chunkID string, proposedRule *NetworkPolicyRule) error
	UndoDraftChunk(ctx context.Context, workspace, sandboxName, chunkID string) (*UndoResult, error)
}
