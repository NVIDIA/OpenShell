// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package fake

import (
	"context"
	"fmt"
	"io"

	v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1"
	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
)

// fakeSSHClient implements v1.SSHInterface. All methods return
// Unimplemented because SSH session management requires a real gateway.
type fakeSSHClient struct {
	closedFunc func() bool
}

// newFakeSSHClient creates a new fakeSSHClient.
func newFakeSSHClient(closedFunc func() bool) *fakeSSHClient {
	return &fakeSSHClient{closedFunc: closedFunc}
}

// CreateSession returns Unimplemented.
func (c *fakeSSHClient) CreateSession(_ context.Context, _, _ string) (*types.SSHSession, error) {
	if c.closedFunc() {
		return nil, &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}
	return nil, &types.StatusError{Code: types.ErrorUnimplemented, Message: "CreateSession is not supported by the fake client"}
}

// RevokeSession returns Unimplemented.
func (c *fakeSSHClient) RevokeSession(_ context.Context, _, _ string) (bool, error) {
	if c.closedFunc() {
		return false, &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}
	return false, &types.StatusError{Code: types.ErrorUnimplemented, Message: "RevokeSession is not supported by the fake client"}
}

// Tunnel returns Unimplemented. Ports outside 1-65535 and empty sandbox names
// are rejected with InvalidArgument to match the real client's behavior.
func (c *fakeSSHClient) Tunnel(_ context.Context, _, sandboxName string, port uint32, _ ...v1.TunnelOption) (io.ReadWriteCloser, error) {
	if c.closedFunc() {
		return nil, &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}
	if sandboxName == "" {
		return nil, &types.StatusError{Code: types.ErrorInvalidArgument, Message: "sandbox name must not be empty"}
	}
	if port == 0 || port > 65535 {
		return nil, &types.StatusError{Code: types.ErrorInvalidArgument, Message: fmt.Sprintf("port must be in range 1-65535, got %d", port)}
	}
	return nil, &types.StatusError{Code: types.ErrorUnimplemented, Message: "Tunnel is not supported by the fake client"}
}

// Compile-time check that fakeSSHClient implements v1.SSHInterface.
var _ v1.SSHInterface = (*fakeSSHClient)(nil)
