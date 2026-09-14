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

// fakeTCPClient implements v1.TCPInterface. All methods return
// Unimplemented because TCP port forwarding requires a real sandbox runtime.
type fakeTCPClient struct {
	closedFunc func() bool
}

// newFakeTCPClient creates a new fakeTCPClient.
func newFakeTCPClient(closedFunc func() bool) *fakeTCPClient {
	return &fakeTCPClient{closedFunc: closedFunc}
}

// Forward returns Unimplemented. Ports outside 1-65535 are rejected with
// InvalidArgument to match the real client's behavior.
func (c *fakeTCPClient) Forward(_ context.Context, _, sandboxName string, port uint32, _ ...v1.ForwardOption) (io.ReadWriteCloser, error) {
	if c.closedFunc() {
		return nil, &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}
	if sandboxName == "" {
		return nil, &types.StatusError{Code: types.ErrorInvalidArgument, Message: "sandbox name must not be empty"}
	}
	if port == 0 || port > 65535 {
		return nil, &types.StatusError{Code: types.ErrorInvalidArgument, Message: fmt.Sprintf("port must be in range 1-65535, got %d", port)}
	}
	return nil, &types.StatusError{Code: types.ErrorUnimplemented, Message: "Forward is not supported by the fake client"}
}

// Listen validates inputs then returns Unimplemented. The fake does not bind
// any local port; it checks that sandboxName is non-empty, remotePort is in
// the range 1-65535, and localPort is in the range 0-65535.
func (c *fakeTCPClient) Listen(_ context.Context, _, sandboxName string, remotePort uint32, localPort uint32, _ ...v1.ListenOption) (v1.ForwardListener, error) {
	if c.closedFunc() {
		return nil, &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}
	if sandboxName == "" {
		return nil, &types.StatusError{Code: types.ErrorInvalidArgument, Message: "sandbox name must not be empty"}
	}
	if remotePort == 0 || remotePort > 65535 {
		return nil, &types.StatusError{Code: types.ErrorInvalidArgument, Message: fmt.Sprintf("port must be in range 1-65535, got %d", remotePort)}
	}
	if localPort > 65535 {
		return nil, &types.StatusError{Code: types.ErrorInvalidArgument, Message: fmt.Sprintf("local port must be in range 0-65535, got %d", localPort)}
	}
	return nil, &types.StatusError{Code: types.ErrorUnimplemented, Message: "Listen is not supported by the fake client"}
}

// Compile-time check that fakeTCPClient implements v1.TCPInterface.
var _ v1.TCPInterface = (*fakeTCPClient)(nil)
