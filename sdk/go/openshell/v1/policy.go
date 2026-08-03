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

// PolicyInterface defines operations for managing sandbox policy drafts,
// approvals, and revision history.
type PolicyInterface interface {
	// GetDraft retrieves the current draft policy for a sandbox, including
	// all pending, approved, and rejected chunks. Use WithStatusFilter to
	// return only chunks matching a specific status.
	//
	// Errors: NotFound if the sandbox does not exist; InvalidArgument if the
	// sandbox name is empty; Unimplemented by the fake client.
	GetDraft(ctx context.Context, workspace, sandboxName string, opts ...GetDraftOption) (*DraftPolicy, error)

	// ApproveDraftChunk approves a single pending draft chunk, merging
	// its proposed rule into the active policy.
	//
	// Errors: NotFound if the sandbox or chunk does not exist;
	// InvalidArgument if the sandbox name or chunk ID is empty;
	// Conflict if the chunk has already been approved or rejected;
	// Unimplemented by the fake client.
	ApproveDraftChunk(ctx context.Context, workspace, sandboxName, chunkID string) (*ApproveResult, error)

	// RejectDraftChunk rejects a single pending draft chunk with an
	// optional reason that is fed to future LLM analysis context.
	//
	// Errors: NotFound if the sandbox or chunk does not exist;
	// InvalidArgument if the sandbox name or chunk ID is empty;
	// Conflict if the chunk has already been approved or rejected;
	// Unimplemented by the fake client.
	RejectDraftChunk(ctx context.Context, workspace, sandboxName, chunkID, reason string) error

	// ApproveAllDraftChunks approves all pending draft chunks at once.
	// By default, security-flagged chunks are skipped. Use
	// WithIncludeSecurityFlagged to include them.
	//
	// Errors: NotFound if the sandbox does not exist; InvalidArgument if
	// the sandbox name is empty; Unimplemented by the fake client.
	ApproveAllDraftChunks(ctx context.Context, workspace, sandboxName string, opts ...ApproveAllOption) (*ApproveAllResult, error)

	// ClearDraftChunks removes all pending draft chunks for a sandbox.
	//
	// Errors: NotFound if the sandbox does not exist; InvalidArgument if
	// the sandbox name is empty; Unimplemented by the fake client.
	ClearDraftChunks(ctx context.Context, workspace, sandboxName string) (*ClearResult, error)

	// GetDraftHistory returns the chronological decision history for a
	// sandbox's draft policy (approvals, rejections, edits, undos, clears).
	//
	// Errors: NotFound if the sandbox does not exist; InvalidArgument if
	// the sandbox name is empty; Unimplemented by the fake client.
	GetDraftHistory(ctx context.Context, workspace, sandboxName string) ([]DraftHistoryEntry, error)

	// GetStatus retrieves the policy status for a sandbox, including the
	// queried revision and the active version. Use WithVersion to query a
	// specific version instead of the latest.
	//
	// Errors: NotFound if the sandbox or requested version does not exist;
	// InvalidArgument if the sandbox name is empty;
	// Unimplemented by the fake client.
	GetStatus(ctx context.Context, workspace, sandboxName string, opts ...GetStatusOption) (*PolicyStatusResult, error)

	// List returns policy revisions for a sandbox, ordered by version.
	// Use WithLimit and WithOffset for pagination.
	//
	// Errors: NotFound if the sandbox does not exist; InvalidArgument if
	// the sandbox name is empty; Unimplemented by the fake client.
	List(ctx context.Context, workspace string, opts ...ListPolicyOption) ([]SandboxPolicyRevision, error)

	// EditDraftChunk replaces the proposed rule of a pending draft chunk
	// with the given network policy rule.
	//
	// Errors: NotFound if the sandbox or chunk does not exist;
	// InvalidArgument if the sandbox name, chunk ID, or proposed rule is
	// empty/nil; Conflict if the chunk is not in a pending state;
	// Unimplemented by the fake client.
	EditDraftChunk(ctx context.Context, workspace, sandboxName, chunkID string, proposedRule *NetworkPolicyRule) error

	// UndoDraftChunk reverses a previously approved chunk, removing its
	// merged rule from the active policy.
	//
	// Errors: NotFound if the sandbox or chunk does not exist;
	// InvalidArgument if the sandbox name or chunk ID is empty;
	// Conflict if the chunk has not been approved;
	// Unimplemented by the fake client.
	UndoDraftChunk(ctx context.Context, workspace, sandboxName, chunkID string) (*UndoResult, error)
}
