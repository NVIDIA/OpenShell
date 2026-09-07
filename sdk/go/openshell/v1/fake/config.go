// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package fake

import (
	"context"

	v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1"
	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
)

// fakeConfigClient implements v1.ConfigInterface. All methods return
// Unimplemented because configuration management requires a real gateway.
type fakeConfigClient struct {
	closedFunc func() bool
}

// newFakeConfigClient creates a new fakeConfigClient.
func newFakeConfigClient(closedFunc func() bool) *fakeConfigClient {
	return &fakeConfigClient{closedFunc: closedFunc}
}

// GetSandbox returns Unimplemented.
func (c *fakeConfigClient) GetSandbox(_ context.Context, _, sandboxName string) (*types.SandboxConfig, error) {
	if c.closedFunc() {
		return nil, &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}
	if sandboxName == "" {
		return nil, &types.StatusError{Code: types.ErrorInvalidArgument, Message: "sandbox name must not be empty"}
	}
	return nil, &types.StatusError{Code: types.ErrorUnimplemented, Message: "GetSandbox is not supported by the fake client"}
}

// GetGateway returns Unimplemented.
func (c *fakeConfigClient) GetGateway(_ context.Context) (*types.GatewayConfig, error) {
	if c.closedFunc() {
		return nil, &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}
	return nil, &types.StatusError{Code: types.ErrorUnimplemented, Message: "GetGateway is not supported by the fake client"}
}

// Update returns Unimplemented. A nil update is rejected with InvalidArgument
// to match the real client's behavior.
func (c *fakeConfigClient) Update(_ context.Context, _ string, update *types.ConfigUpdate) (*types.ConfigUpdateResult, error) {
	if c.closedFunc() {
		return nil, &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}
	if update == nil {
		return nil, &types.StatusError{Code: types.ErrorInvalidArgument, Message: "update must not be nil"}
	}
	return nil, &types.StatusError{Code: types.ErrorUnimplemented, Message: "Update is not supported by the fake client"}
}

// Compile-time check that fakeConfigClient implements v1.ConfigInterface.
var _ v1.ConfigInterface = (*fakeConfigClient)(nil)
