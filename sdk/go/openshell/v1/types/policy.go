// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package types

import "time"

// PolicyLoadStatus represents the load state of a policy revision.
type PolicyLoadStatus int

const (
	// PolicyLoadStatusUnspecified is the default zero value.
	PolicyLoadStatusUnspecified PolicyLoadStatus = iota
	// PolicyLoadStatusPending means the policy is queued for loading.
	PolicyLoadStatusPending
	// PolicyLoadStatusLoaded means the policy was successfully loaded.
	PolicyLoadStatusLoaded
	// PolicyLoadStatusFailed means the policy failed to load.
	PolicyLoadStatusFailed
	// PolicyLoadStatusSuperseded means a newer revision replaced this one.
	PolicyLoadStatusSuperseded
)

// String returns the human-readable name of the load status.
func (s PolicyLoadStatus) String() string {
	switch s {
	case PolicyLoadStatusUnspecified:
		return "Unspecified"
	case PolicyLoadStatusPending:
		return "Pending"
	case PolicyLoadStatusLoaded:
		return "Loaded"
	case PolicyLoadStatusFailed:
		return "Failed"
	case PolicyLoadStatusSuperseded:
		return "Superseded"
	default:
		return "Unknown"
	}
}

// PolicyChunk represents a single proposed policy change in the draft inbox.
type PolicyChunk struct {
	// ID is the unique chunk identifier.
	ID string
	// Status is the approval status: "pending", "approved", "rejected".
	Status string
	// RuleName is the proposed network_policies map key.
	RuleName string
	// ProposedRule is the proposed network policy rule.
	ProposedRule *NetworkPolicyRule

	// Rationale is a human-readable explanation of why this rule is proposed.
	Rationale string
	// SecurityNotes contains security concerns flagged by analysis (empty if none).
	SecurityNotes string
	// Confidence is the analysis confidence score (0.0-1.0).
	Confidence float32
	// DenialSummaryIDs lists the IDs of denial summaries that led to this chunk.
	DenialSummaryIDs []string
	// CreatedAt is when the chunk was created.
	CreatedAt time.Time
	// DecidedAt is when the user approved/rejected (zero if undecided).
	DecidedAt time.Time
	// Stage is the recommendation stage: "initial" or "refined".
	Stage string
	// SupersedesChunkID is the initial chunk ID this refined chunk replaces.
	SupersedesChunkID string
	// HitCount is how many times this endpoint was seen across denial flush cycles.
	HitCount int32
	// FirstSeen is the first time this endpoint was proposed.
	FirstSeen time.Time
	// LastSeen is the most recent time this endpoint was re-proposed.
	LastSeen time.Time
	// Binary is the binary path that triggered the denial.
	Binary string
	// ValidationResult is the prover output from gateway-side static checks.
	ValidationResult string
	// RejectionReason is the operator-supplied text accompanying a rejection.
	RejectionReason string
	// ApplicationError is the complete-candidate preflight/application failure.
	ApplicationError string
	// ReviewToken binds an approval to the exact evaluated candidate.
	ReviewToken                  string
	CurrentEffectivePolicyHash   string
	CandidateEffectivePolicyHash string
	CurrentEffectivePolicy       *SandboxPolicy
	CandidateEffectivePolicy     *SandboxPolicy
}

// DraftChunkApproval binds one bulk approval decision to a reviewed chunk.
type DraftChunkApproval struct {
	ChunkID     string
	ReviewToken string
}

// DraftPolicy contains the full draft policy state returned by GetDraft.
type DraftPolicy struct {
	// Chunks contains the draft policy chunks.
	Chunks []PolicyChunk
	// RollingSummary is an LLM-generated summary of all analysis.
	RollingSummary string
	// DraftVersion is the current draft version number.
	DraftVersion uint64
	// LastAnalyzedAt is when the last analysis completed.
	LastAnalyzedAt time.Time
}

// SandboxPolicy is the top-level security policy configuration for a sandbox.
// It contains filesystem access rules, Landlock LSM configuration, process
// identity rules, and named network access policies.
type SandboxPolicy struct {
	// Version is the policy version number. The server may override this on write.
	Version uint32
	// Filesystem controls which directories the sandbox can access.
	// Nil means no filesystem policy is specified.
	Filesystem *FilesystemPolicy
	// Landlock configures the Linux Landlock LSM.
	// Nil means no landlock policy is specified.
	Landlock *LandlockPolicy
	// Process controls the user and group identity for sandboxed processes.
	// Nil means no process policy is specified.
	Process *ProcessPolicy
	// NetworkPolicies contains named network access rules.
	// Nil means no network policies are specified; an empty map is distinct from nil.
	NetworkPolicies map[string]NetworkPolicyRule
	// NetworkMiddlewares contains named middleware pipeline configurations for
	// network egress. Nil means no middleware is specified; an empty map is distinct from nil.
	NetworkMiddlewares map[string]NetworkMiddlewareConfig
}

// NetworkMiddlewareConfig configures a supervisor middleware pipeline for
// network egress. Middleware configs are referenced by name in the policy.
type NetworkMiddlewareConfig struct {
	Name       string
	Middleware string
	Config     map[string]any
	OnError    string
	Endpoints  *MiddlewareEndpointSelector
	Order      int32
}

// MiddlewareEndpointSelector controls which admitted destinations use a
// middleware config, using host glob patterns.
type MiddlewareEndpointSelector struct {
	Include []string
	Exclude []string
}

// FilesystemPolicy controls which directories the sandbox can access
// in read-only or read-write mode.
type FilesystemPolicy struct {
	// IncludeWorkdir auto-includes the working directory as read-write.
	IncludeWorkdir bool
	// ReadOnly is the list of read-only directory paths.
	// Nil means no read-only directories; an empty slice is distinct from nil.
	ReadOnly []string
	// ReadWrite is the list of read-write directory paths.
	// Nil means no read-write directories; an empty slice is distinct from nil.
	ReadWrite []string
}

// LandlockPolicy configures the Linux Landlock LSM for filesystem restriction enforcement.
type LandlockPolicy struct {
	// Compatibility is the compatibility mode (e.g., "best_effort", "hard_requirement").
	Compatibility string
}

// ProcessPolicy controls the user and group identity under which sandboxed processes execute.
type ProcessPolicy struct {
	// RunAsUser is the user name for sandboxed processes.
	RunAsUser string
	// RunAsGroup is the group name for sandboxed processes.
	RunAsGroup string
}

// SandboxPolicyRevision represents a versioned policy revision for a sandbox.
type SandboxPolicyRevision struct {
	// Version is the policy version (monotonically increasing per sandbox).
	Version uint32
	// PolicyHash is the SHA-256 hash of the serialized policy payload.
	PolicyHash string
	// Status is the load status of this revision.
	Status PolicyLoadStatus
	// LoadError is the error message if status is Failed.
	LoadError string
	// CreatedAt is when this revision was created.
	CreatedAt time.Time
	// LoadedAt is when this revision was loaded by the sandbox.
	LoadedAt time.Time
	// Policy is the typed security policy for this revision. Nil when not requested or absent.
	Policy *SandboxPolicy
	// Provenance is immutable metadata supplied with this policy revision.
	Provenance map[string]string
}

// PolicyStatusResult contains the status of a sandbox's policy.
type PolicyStatusResult struct {
	// Revision is the queried policy revision.
	Revision SandboxPolicyRevision
	// ActiveVersion is the currently active (loaded) policy version.
	ActiveVersion uint32
}

// ApproveResult contains the result of approving a single draft chunk.
type ApproveResult struct {
	// PolicyVersion is the new policy version after merge.
	PolicyVersion uint32
	// PolicyHash is the SHA-256 hash of the new policy.
	PolicyHash string
}

// ApproveAllResult contains the result of approving all draft chunks.
type ApproveAllResult struct {
	// PolicyVersion is the new policy version after merge.
	PolicyVersion uint32
	// PolicyHash is the SHA-256 hash of the new policy.
	PolicyHash string
	// ChunksApproved is the number of chunks approved.
	ChunksApproved uint32
	// ChunksSkipped is the number of chunks skipped (security-flagged).
	ChunksSkipped uint32
}

// UndoResult contains the result of undoing a draft chunk approval.
type UndoResult struct {
	// PolicyVersion is the new policy version after removal.
	PolicyVersion uint32
	// PolicyHash is the SHA-256 hash of the updated policy.
	PolicyHash string
}

// ClearResult contains the result of clearing all draft chunks.
type ClearResult struct {
	// ChunksCleared is the number of chunks cleared.
	ChunksCleared uint32
}

// DraftHistoryEntry represents a single event in the draft policy history.
type DraftHistoryEntry struct {
	// Timestamp is when the event occurred.
	Timestamp time.Time
	// EventType is the event type (e.g., "approved", "rejected", "cleared").
	EventType string
	// Description is a human-readable description.
	Description string
	// ChunkID is the associated chunk ID (if applicable).
	ChunkID string
}

// getDraftConfig holds configuration for GetDraft calls.
type getDraftConfig struct {
	statusFilter string
}

// GetDraftOption configures a GetDraft call.
type GetDraftOption func(*getDraftConfig)

// WithStatusFilter filters draft chunks by approval status.
func WithStatusFilter(status string) GetDraftOption {
	return func(c *getDraftConfig) {
		c.statusFilter = status
	}
}

// ApplyGetDraftOptions applies options and returns the config.
func ApplyGetDraftOptions(opts []GetDraftOption) getDraftConfig { //nolint:revive // unexported return is intentional; consumed only by v1 package
	var cfg getDraftConfig
	for _, opt := range opts {
		opt(&cfg)
	}
	return cfg
}

// StatusFilter returns the configured status filter.
func (c *getDraftConfig) StatusFilter() string {
	return c.statusFilter
}

// approveAllConfig holds configuration for ApproveAllDraftChunks calls.
type approveAllConfig struct {
	includeSecurityFlagged bool
	approvals              []DraftChunkApproval
}

// WithDraftApprovals supplies the exact reviewed chunk tokens for bulk approval.
func WithDraftApprovals(approvals ...DraftChunkApproval) ApproveAllOption {
	return func(c *approveAllConfig) {
		c.approvals = append([]DraftChunkApproval(nil), approvals...)
	}
}

// ApproveAllOption configures an ApproveAllDraftChunks call.
type ApproveAllOption func(*approveAllConfig)

// WithIncludeSecurityFlagged includes security-flagged chunks in bulk approval.
func WithIncludeSecurityFlagged() ApproveAllOption {
	return func(c *approveAllConfig) {
		c.includeSecurityFlagged = true
	}
}

// ApplyApproveAllOptions applies options and returns the config.
func ApplyApproveAllOptions(opts []ApproveAllOption) approveAllConfig { //nolint:revive // unexported return is intentional; consumed only by v1 package
	var cfg approveAllConfig
	for _, opt := range opts {
		opt(&cfg)
	}
	return cfg
}

// IncludeSecurityFlagged returns whether security-flagged chunks are included.
func (c *approveAllConfig) IncludeSecurityFlagged() bool {
	return c.includeSecurityFlagged
}

// Approvals returns a copy of the configured token-bound approvals.
func (c *approveAllConfig) Approvals() []DraftChunkApproval {
	return append([]DraftChunkApproval(nil), c.approvals...)
}

// getStatusConfig holds configuration for GetStatus calls.
type getStatusConfig struct {
	version uint32
	global  bool
}

// GetStatusOption configures a GetStatus call.
type GetStatusOption func(*getStatusConfig)

// WithVersion queries a specific policy version instead of the latest.
func WithVersion(version uint32) GetStatusOption {
	return func(c *getStatusConfig) {
		c.version = version
	}
}

// WithStatusGlobal enables global policy mode on GetStatus. When true,
// the query retrieves gateway-global policy status instead of sandbox-scoped
// status, and the sandbox name and workspace parameters are ignored.
func WithStatusGlobal(global bool) GetStatusOption {
	return func(c *getStatusConfig) {
		c.global = global
	}
}

// ApplyGetStatusOptions applies options and returns the config.
func ApplyGetStatusOptions(opts []GetStatusOption) getStatusConfig { //nolint:revive // unexported return is intentional; consumed only by v1 package
	var cfg getStatusConfig
	for _, opt := range opts {
		opt(&cfg)
	}
	return cfg
}

// Version returns the configured version (0 means latest).
func (c *getStatusConfig) Version() uint32 {
	return c.version
}

// Global returns whether global policy mode is enabled.
func (c *getStatusConfig) Global() bool {
	return c.global
}

// listPolicyConfig holds configuration for List calls.
type listPolicyConfig struct {
	limit  uint32
	offset uint32
	global bool
}

// ListPolicyOption configures a List call.
type ListPolicyOption func(*listPolicyConfig)

// WithLimit sets the maximum number of revisions to return.
func WithLimit(limit uint32) ListPolicyOption {
	return func(c *listPolicyConfig) {
		c.limit = limit
	}
}

// WithOffset sets the pagination offset.
func WithOffset(offset uint32) ListPolicyOption {
	return func(c *listPolicyConfig) {
		c.offset = offset
	}
}

// WithListGlobal enables global policy mode on List. When true, the query
// retrieves gateway-global policy revisions instead of sandbox-scoped ones,
// and the workspace parameter is ignored.
func WithListGlobal(global bool) ListPolicyOption {
	return func(c *listPolicyConfig) {
		c.global = global
	}
}

// ApplyListPolicyOptions applies options and returns the config.
func ApplyListPolicyOptions(opts []ListPolicyOption) listPolicyConfig { //nolint:revive // unexported return is intentional; consumed only by v1 package
	var cfg listPolicyConfig
	for _, opt := range opts {
		opt(&cfg)
	}
	return cfg
}

// Limit returns the configured limit (0 means server default).
func (c *listPolicyConfig) Limit() uint32 {
	return c.limit
}

// Offset returns the configured offset.
func (c *listPolicyConfig) Offset() uint32 {
	return c.offset
}

// Global returns whether global policy mode is enabled.
func (c *listPolicyConfig) Global() bool {
	return c.global
}
