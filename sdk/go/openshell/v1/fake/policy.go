// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package fake

import (
	"context"
	"maps"
	"slices"
	"strings"
	"sync"

	v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1"
	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
)

func copySandboxPolicyRevision(r types.SandboxPolicyRevision) types.SandboxPolicyRevision {
	if r.Policy != nil {
		cp := *r.Policy
		if r.Policy.NetworkPolicies != nil {
			cp.NetworkPolicies = make(map[string]types.NetworkPolicyRule, len(r.Policy.NetworkPolicies))
			maps.Copy(cp.NetworkPolicies, r.Policy.NetworkPolicies)
		}
		r.Policy = &cp
	}
	return r
}

// fakePolicyClient implements v1.PolicyInterface. List and GetStatus support
// in-memory global and sandbox-scoped revisions. Other methods return
// Unimplemented because policy management requires a real gateway.
type fakePolicyClient struct {
	mu         sync.RWMutex
	closedFunc func() bool

	// globalRevisions stores gateway-global policy revisions.
	globalRevisions []types.SandboxPolicyRevision
	// sandboxRevisions stores sandbox-scoped revisions keyed by "workspace/name".
	sandboxRevisions map[string][]types.SandboxPolicyRevision
}

// newFakePolicyClient creates a new fakePolicyClient.
func newFakePolicyClient(closedFunc func() bool) *fakePolicyClient {
	return &fakePolicyClient{
		closedFunc:       closedFunc,
		sandboxRevisions: make(map[string][]types.SandboxPolicyRevision),
	}
}

// AddGlobalRevision adds a global policy revision for test seeding.
func (c *fakePolicyClient) AddGlobalRevision(rev types.SandboxPolicyRevision) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.globalRevisions = append(c.globalRevisions, copySandboxPolicyRevision(rev))
}

// AddRevision adds a sandbox-scoped policy revision for test seeding.
func (c *fakePolicyClient) AddRevision(workspace, name string, rev types.SandboxPolicyRevision) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := workspace + "/" + name
	c.sandboxRevisions[key] = append(c.sandboxRevisions[key], copySandboxPolicyRevision(rev))
}

// GetDraft returns Unimplemented.
func (c *fakePolicyClient) GetDraft(_ context.Context, _, _ string, _ ...v1.GetDraftOption) (*types.DraftPolicy, error) {
	if c.closedFunc() {
		return nil, &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}
	return nil, &types.StatusError{Code: types.ErrorUnimplemented, Message: "GetDraft is not supported by the fake client"}
}

// ApproveDraftChunk returns Unimplemented.
func (c *fakePolicyClient) ApproveDraftChunk(_ context.Context, _, _, _ string) (*types.ApproveResult, error) {
	if c.closedFunc() {
		return nil, &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}
	return nil, &types.StatusError{Code: types.ErrorUnimplemented, Message: "ApproveDraftChunk is not supported by the fake client"}
}

// RejectDraftChunk returns Unimplemented.
func (c *fakePolicyClient) RejectDraftChunk(_ context.Context, _, _, _, _ string) error {
	if c.closedFunc() {
		return &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}
	return &types.StatusError{Code: types.ErrorUnimplemented, Message: "RejectDraftChunk is not supported by the fake client"}
}

// ApproveAllDraftChunks returns Unimplemented.
func (c *fakePolicyClient) ApproveAllDraftChunks(_ context.Context, _, _ string, _ ...v1.ApproveAllOption) (*types.ApproveAllResult, error) {
	if c.closedFunc() {
		return nil, &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}
	return nil, &types.StatusError{Code: types.ErrorUnimplemented, Message: "ApproveAllDraftChunks is not supported by the fake client"}
}

// ClearDraftChunks returns Unimplemented.
func (c *fakePolicyClient) ClearDraftChunks(_ context.Context, _, _ string) (*types.ClearResult, error) {
	if c.closedFunc() {
		return nil, &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}
	return nil, &types.StatusError{Code: types.ErrorUnimplemented, Message: "ClearDraftChunks is not supported by the fake client"}
}

// GetDraftHistory returns Unimplemented.
func (c *fakePolicyClient) GetDraftHistory(_ context.Context, _, _ string) ([]types.DraftHistoryEntry, error) {
	if c.closedFunc() {
		return nil, &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}
	return nil, &types.StatusError{Code: types.ErrorUnimplemented, Message: "GetDraftHistory is not supported by the fake client"}
}

// GetStatus returns the status of a policy revision. When the global option is
// set, it queries global revisions; otherwise it queries sandbox-scoped ones.
func (c *fakePolicyClient) GetStatus(_ context.Context, workspace, sandboxName string, opts ...v1.GetStatusOption) (*types.PolicyStatusResult, error) {
	if c.closedFunc() {
		return nil, &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}
	cfg := types.ApplyGetStatusOptions(opts)

	c.mu.RLock()
	defer c.mu.RUnlock()

	var revisions []types.SandboxPolicyRevision
	if cfg.Global() {
		revisions = c.globalRevisions
	} else {
		key := workspace + "/" + sandboxName
		revisions = c.sandboxRevisions[key]
	}

	if len(revisions) == 0 {
		return nil, &types.StatusError{Code: types.ErrorNotFound, Message: "no policy revisions found"}
	}

	// Find the active version (highest version with Loaded status).
	var activeVersion uint32
	for _, r := range revisions {
		if r.Status == types.PolicyLoadStatusLoaded && r.Version > activeVersion {
			activeVersion = r.Version
		}
	}
	// If no loaded version, use the highest version.
	var maxVersion uint32
	var maxIdx int
	for i, r := range revisions {
		if r.Version > maxVersion {
			maxVersion = r.Version
			maxIdx = i
		}
	}
	if activeVersion == 0 {
		activeVersion = maxVersion
	}

	// Find the requested revision.
	targetVersion := cfg.Version()
	if targetVersion == 0 {
		// Latest revision (by highest version, not insertion order).
		rev := copySandboxPolicyRevision(revisions[maxIdx])
		return &types.PolicyStatusResult{Revision: rev, ActiveVersion: activeVersion}, nil
	}

	for _, r := range revisions {
		if r.Version == targetVersion {
			rev := copySandboxPolicyRevision(r)
			return &types.PolicyStatusResult{Revision: rev, ActiveVersion: activeVersion}, nil
		}
	}

	return nil, &types.StatusError{Code: types.ErrorNotFound, Message: "policy version not found"}
}

// List returns policy revisions. When the global option is set, it returns
// global revisions; otherwise it returns all sandbox-scoped revisions for the
// given workspace.
func (c *fakePolicyClient) List(_ context.Context, workspace string, opts ...v1.ListPolicyOption) ([]types.SandboxPolicyRevision, error) {
	if c.closedFunc() {
		return nil, &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}
	cfg := types.ApplyListPolicyOptions(opts)

	c.mu.RLock()
	defer c.mu.RUnlock()

	var revisions []types.SandboxPolicyRevision
	if cfg.Global() {
		revisions = slices.Clone(c.globalRevisions)
	} else {
		// Collect all revisions for sandboxes in this workspace.
		prefix := workspace + "/"
		for key, revs := range c.sandboxRevisions {
			if strings.HasPrefix(key, prefix) {
				revisions = append(revisions, revs...)
			}
		}
	}

	if len(revisions) == 0 {
		return nil, nil
	}

	// Sort by version for deterministic ordering (map iteration is random).
	slices.SortFunc(revisions, func(a, b types.SandboxPolicyRevision) int {
		if a.Version < b.Version {
			return -1
		}
		if a.Version > b.Version {
			return 1
		}
		return 0
	})

	// Apply pagination.
	offset := int(cfg.Offset())
	if offset >= len(revisions) {
		return nil, nil
	}
	revisions = revisions[offset:]

	if limit := int(cfg.Limit()); limit > 0 && limit < len(revisions) {
		revisions = revisions[:limit]
	}

	result := make([]types.SandboxPolicyRevision, len(revisions))
	for i, r := range revisions {
		result[i] = copySandboxPolicyRevision(r)
	}
	return result, nil
}

// EditDraftChunk returns Unimplemented.
func (c *fakePolicyClient) EditDraftChunk(_ context.Context, _, _, _ string, _ *types.NetworkPolicyRule) error {
	if c.closedFunc() {
		return &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}
	return &types.StatusError{Code: types.ErrorUnimplemented, Message: "EditDraftChunk is not supported by the fake client"}
}

// UndoDraftChunk returns Unimplemented.
func (c *fakePolicyClient) UndoDraftChunk(_ context.Context, _, _, _ string) (*types.UndoResult, error) {
	if c.closedFunc() {
		return nil, &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}
	return nil, &types.StatusError{Code: types.ErrorUnimplemented, Message: "UndoDraftChunk is not supported by the fake client"}
}

// Compile-time check that fakePolicyClient implements v1.PolicyInterface.
var _ v1.PolicyInterface = (*fakePolicyClient)(nil)
