// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package fake

import (
	"context"

	v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1"
	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
)

// fakeProfileClient implements v1.ProfileInterface. All methods return
// Unimplemented because profile management requires a real server.
type fakeProfileClient struct {
	closedFunc func() bool
}

// newFakeProfileClient creates a new fakeProfileClient.
func newFakeProfileClient(closedFunc func() bool) *fakeProfileClient {
	return &fakeProfileClient{closedFunc: closedFunc}
}

// List returns Unimplemented.
func (c *fakeProfileClient) List(_ context.Context, _ string, _ ...v1.ListOptions) ([]*types.ProviderProfile, error) {
	if c.closedFunc() {
		return nil, &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}
	return nil, &types.StatusError{Code: types.ErrorUnimplemented, Message: "List is not supported by the fake client"}
}

// Get returns Unimplemented.
func (c *fakeProfileClient) Get(_ context.Context, _, _ string) (*types.ProviderProfile, error) {
	if c.closedFunc() {
		return nil, &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}
	return nil, &types.StatusError{Code: types.ErrorUnimplemented, Message: "Get is not supported by the fake client"}
}

// Import returns Unimplemented.
func (c *fakeProfileClient) Import(_ context.Context, _ string, _ []types.ProfileImportItem) (*types.ImportResult, error) {
	if c.closedFunc() {
		return nil, &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}
	return nil, &types.StatusError{Code: types.ErrorUnimplemented, Message: "Import is not supported by the fake client"}
}

// Update returns Unimplemented.
func (c *fakeProfileClient) Update(_ context.Context, _, _ string, _ uint64, _ types.ProfileImportItem) (*types.UpdateResult, error) {
	if c.closedFunc() {
		return nil, &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}
	return nil, &types.StatusError{Code: types.ErrorUnimplemented, Message: "Update is not supported by the fake client"}
}

// Lint returns Unimplemented.
func (c *fakeProfileClient) Lint(_ context.Context, _ string, _ []types.ProfileImportItem) (*types.LintResult, error) {
	if c.closedFunc() {
		return nil, &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}
	return nil, &types.StatusError{Code: types.ErrorUnimplemented, Message: "Lint is not supported by the fake client"}
}

// Delete returns Unimplemented.
func (c *fakeProfileClient) Delete(_ context.Context, _, _ string) (bool, error) {
	if c.closedFunc() {
		return false, &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}
	return false, &types.StatusError{Code: types.ErrorUnimplemented, Message: "Delete is not supported by the fake client"}
}

// Compile-time check that fakeProfileClient implements v1.ProfileInterface.
var _ v1.ProfileInterface = (*fakeProfileClient)(nil)
