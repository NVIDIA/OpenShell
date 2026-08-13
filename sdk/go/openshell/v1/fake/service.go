// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package fake

import (
	"context"

	v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1"
	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
)

// fakeServiceClient implements v1.ServiceInterface. All methods return
// Unimplemented because service exposure requires a real sandbox runtime.
type fakeServiceClient struct {
	closedFunc func() bool
}

// newFakeServiceClient creates a new fakeServiceClient.
func newFakeServiceClient(closedFunc func() bool) *fakeServiceClient {
	return &fakeServiceClient{closedFunc: closedFunc}
}

// Expose returns Unimplemented.
func (c *fakeServiceClient) Expose(_ context.Context, _, _, _ string, _ uint32, _ bool) (*types.ServiceEndpoint, error) {
	if c.closedFunc() {
		return nil, &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}
	return nil, &types.StatusError{Code: types.ErrorUnimplemented, Message: "Expose is not supported by the fake client"}
}

// Get returns Unimplemented.
func (c *fakeServiceClient) Get(_ context.Context, _, _, _ string) (*types.ServiceEndpoint, error) {
	if c.closedFunc() {
		return nil, &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}
	return nil, &types.StatusError{Code: types.ErrorUnimplemented, Message: "Get is not supported by the fake client"}
}

// List returns Unimplemented.
func (c *fakeServiceClient) List(_ context.Context, _, _ string, _ ...v1.ListOptions) ([]*types.ServiceEndpoint, error) {
	if c.closedFunc() {
		return nil, &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}
	return nil, &types.StatusError{Code: types.ErrorUnimplemented, Message: "List is not supported by the fake client"}
}

// Delete returns Unimplemented.
func (c *fakeServiceClient) Delete(_ context.Context, _, _, _ string) error {
	if c.closedFunc() {
		return &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}
	return &types.StatusError{Code: types.ErrorUnimplemented, Message: "Delete is not supported by the fake client"}
}

// Compile-time check that fakeServiceClient implements v1.ServiceInterface.
var _ v1.ServiceInterface = (*fakeServiceClient)(nil)
