// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package fake

import (
	"context"

	v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1"
	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
)

var _ v1.FileInterface = (*fakeFileClient)(nil)

// fakeFileClient implements v1.FileInterface. All methods return
// Unimplemented because file transfer requires a real sandbox runtime.
type fakeFileClient struct {
	closedFunc func() bool
}

// newFakeFileClient creates a new fakeFileClient.
func newFakeFileClient(closedFunc func() bool) *fakeFileClient {
	return &fakeFileClient{closedFunc: closedFunc}
}

// Upload returns Unimplemented.
func (c *fakeFileClient) Upload(_ context.Context, _, sandboxName, _, remotePath string) error {
	if c.closedFunc() {
		return &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}
	if sandboxName == "" {
		return &types.StatusError{Code: types.ErrorInvalidArgument, Message: "sandbox name must not be empty"}
	}
	if remotePath == "" {
		return &types.StatusError{Code: types.ErrorInvalidArgument, Message: "remote path must not be empty"}
	}
	return &types.StatusError{Code: types.ErrorUnimplemented, Message: "Upload is not supported by the fake client"}
}

// Download returns Unimplemented.
func (c *fakeFileClient) Download(_ context.Context, _, sandboxName, remotePath, _ string) error {
	if c.closedFunc() {
		return &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}
	if sandboxName == "" {
		return &types.StatusError{Code: types.ErrorInvalidArgument, Message: "sandbox name must not be empty"}
	}
	if remotePath == "" {
		return &types.StatusError{Code: types.ErrorInvalidArgument, Message: "remote path must not be empty"}
	}
	return &types.StatusError{Code: types.ErrorUnimplemented, Message: "Download is not supported by the fake client"}
}
