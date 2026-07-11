// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package fake

import (
	"context"

	v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1"
	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
)

// fakePolicyClient implements v1.PolicyInterface. All methods return
// Unimplemented because policy management requires a real gateway.
type fakePolicyClient struct {
	closedFunc func() bool
}

// newFakePolicyClient creates a new fakePolicyClient.
func newFakePolicyClient(closedFunc func() bool) *fakePolicyClient {
	return &fakePolicyClient{closedFunc: closedFunc}
}

// GetDraft returns Unimplemented.
func (c *fakePolicyClient) GetDraft(_ context.Context, _ string, _ ...v1.GetDraftOption) (*types.DraftPolicy, error) {
	if c.closedFunc() {
		return nil, &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}
	return nil, &types.StatusError{Code: types.ErrorUnimplemented, Message: "GetDraft is not supported by the fake client"}
}

// ApproveDraftChunk returns Unimplemented.
func (c *fakePolicyClient) ApproveDraftChunk(_ context.Context, _, _ string) (*types.ApproveResult, error) {
	if c.closedFunc() {
		return nil, &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}
	return nil, &types.StatusError{Code: types.ErrorUnimplemented, Message: "ApproveDraftChunk is not supported by the fake client"}
}

// RejectDraftChunk returns Unimplemented.
func (c *fakePolicyClient) RejectDraftChunk(_ context.Context, _, _, _ string) error {
	if c.closedFunc() {
		return &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}
	return &types.StatusError{Code: types.ErrorUnimplemented, Message: "RejectDraftChunk is not supported by the fake client"}
}

// ApproveAllDraftChunks returns Unimplemented.
func (c *fakePolicyClient) ApproveAllDraftChunks(_ context.Context, _ string, _ ...v1.ApproveAllOption) (*types.ApproveAllResult, error) {
	if c.closedFunc() {
		return nil, &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}
	return nil, &types.StatusError{Code: types.ErrorUnimplemented, Message: "ApproveAllDraftChunks is not supported by the fake client"}
}

// ClearDraftChunks returns Unimplemented.
func (c *fakePolicyClient) ClearDraftChunks(_ context.Context, _ string) (*types.ClearResult, error) {
	if c.closedFunc() {
		return nil, &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}
	return nil, &types.StatusError{Code: types.ErrorUnimplemented, Message: "ClearDraftChunks is not supported by the fake client"}
}

// GetDraftHistory returns Unimplemented.
func (c *fakePolicyClient) GetDraftHistory(_ context.Context, _ string) ([]types.DraftHistoryEntry, error) {
	if c.closedFunc() {
		return nil, &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}
	return nil, &types.StatusError{Code: types.ErrorUnimplemented, Message: "GetDraftHistory is not supported by the fake client"}
}

// GetStatus returns Unimplemented.
func (c *fakePolicyClient) GetStatus(_ context.Context, _ string, _ ...v1.GetStatusOption) (*types.PolicyStatusResult, error) {
	if c.closedFunc() {
		return nil, &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}
	return nil, &types.StatusError{Code: types.ErrorUnimplemented, Message: "GetStatus is not supported by the fake client"}
}

// List returns Unimplemented.
func (c *fakePolicyClient) List(_ context.Context, _ string, _ ...v1.ListPolicyOption) ([]types.SandboxPolicyRevision, error) {
	if c.closedFunc() {
		return nil, &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}
	return nil, &types.StatusError{Code: types.ErrorUnimplemented, Message: "List is not supported by the fake client"}
}

// EditDraftChunk returns Unimplemented.
func (c *fakePolicyClient) EditDraftChunk(_ context.Context, _, _ string, _ *types.NetworkPolicyRule) error {
	if c.closedFunc() {
		return &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}
	return &types.StatusError{Code: types.ErrorUnimplemented, Message: "EditDraftChunk is not supported by the fake client"}
}

// UndoDraftChunk returns Unimplemented.
func (c *fakePolicyClient) UndoDraftChunk(_ context.Context, _, _ string) (*types.UndoResult, error) {
	if c.closedFunc() {
		return nil, &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}
	return nil, &types.StatusError{Code: types.ErrorUnimplemented, Message: "UndoDraftChunk is not supported by the fake client"}
}

// Compile-time check that fakePolicyClient implements v1.PolicyInterface.
var _ v1.PolicyInterface = (*fakePolicyClient)(nil)
