// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package fake

import (
	"context"

	v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1"
	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
)

// fakeRefreshClient implements v1.RefreshInterface. All methods return
// Unimplemented because credential refresh requires a real server.
type fakeRefreshClient struct {
	closedFunc func() bool
}

// newFakeRefreshClient creates a new fakeRefreshClient.
func newFakeRefreshClient(closedFunc func() bool) *fakeRefreshClient {
	return &fakeRefreshClient{closedFunc: closedFunc}
}

// GetStatus returns Unimplemented.
func (c *fakeRefreshClient) GetStatus(_ context.Context, _, _, _ string) ([]*types.RefreshStatus, error) {
	if c.closedFunc() {
		return nil, &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}
	return nil, &types.StatusError{Code: types.ErrorUnimplemented, Message: "GetStatus is not supported by the fake client"}
}

// Configure returns Unimplemented.
func (c *fakeRefreshClient) Configure(_ context.Context, _ string, _ *types.RefreshConfig) (*types.RefreshStatus, error) {
	if c.closedFunc() {
		return nil, &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}
	return nil, &types.StatusError{Code: types.ErrorUnimplemented, Message: "Configure is not supported by the fake client"}
}

// Rotate returns Unimplemented.
func (c *fakeRefreshClient) Rotate(_ context.Context, _, _, _ string) (*types.RefreshStatus, error) {
	if c.closedFunc() {
		return nil, &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}
	return nil, &types.StatusError{Code: types.ErrorUnimplemented, Message: "Rotate is not supported by the fake client"}
}

// Delete returns Unimplemented.
func (c *fakeRefreshClient) Delete(_ context.Context, _, _, _ string) (bool, error) {
	if c.closedFunc() {
		return false, &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}
	return false, &types.StatusError{Code: types.ErrorUnimplemented, Message: "Delete is not supported by the fake client"}
}

// Compile-time check that fakeRefreshClient implements v1.RefreshInterface.
var _ v1.RefreshInterface = (*fakeRefreshClient)(nil)
