// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package fake

import (
	"context"

	v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1"
	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
)

var _ v1.ExecInterface = (*fakeExecClient)(nil)

// fakeExecClient implements v1.ExecInterface. All methods return
// Unimplemented because command execution requires a real sandbox runtime.
type fakeExecClient struct {
	closedFunc func() bool
}

// newFakeExecClient creates a new fakeExecClient.
func newFakeExecClient(closedFunc func() bool) *fakeExecClient {
	return &fakeExecClient{closedFunc: closedFunc}
}

// Run returns Unimplemented.
func (c *fakeExecClient) Run(_ context.Context, _, sandboxName string, _ []string, _ ...v1.ExecOptions) (*types.ExecResult, error) {
	if c.closedFunc() {
		return nil, &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}
	if sandboxName == "" {
		return nil, &types.StatusError{Code: types.ErrorInvalidArgument, Message: "sandbox name must not be empty"}
	}
	return nil, &types.StatusError{Code: types.ErrorUnimplemented, Message: "Run is not supported by the fake client"}
}

// Stream returns Unimplemented.
func (c *fakeExecClient) Stream(_ context.Context, _, sandboxName string, _ []string, _ ...v1.ExecOptions) (v1.ExecStream, error) {
	if c.closedFunc() {
		return nil, &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}
	if sandboxName == "" {
		return nil, &types.StatusError{Code: types.ErrorInvalidArgument, Message: "sandbox name must not be empty"}
	}
	return nil, &types.StatusError{Code: types.ErrorUnimplemented, Message: "Stream is not supported by the fake client"}
}

// Interactive returns Unimplemented.
func (c *fakeExecClient) Interactive(_ context.Context, _, sandboxName string, _ []string, _, _ uint32, _ ...v1.ExecOptions) (v1.InteractiveSession, error) {
	if c.closedFunc() {
		return nil, &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}
	if sandboxName == "" {
		return nil, &types.StatusError{Code: types.ErrorInvalidArgument, Message: "sandbox name must not be empty"}
	}
	return nil, &types.StatusError{Code: types.ErrorUnimplemented, Message: "Interactive is not supported by the fake client"}
}
