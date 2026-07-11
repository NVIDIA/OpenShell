// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package fake

import (
	"context"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
)

// fakeHealthClient implements v1.HealthInterface with a configurable
// health result. When no custom result is provided, Check returns a
// default healthy response.
type fakeHealthClient struct {
	result     *types.HealthResult
	closedFunc func() bool
}

// newFakeHealthClient creates a new fakeHealthClient. If result is nil,
// Check will return the default healthy response.
func newFakeHealthClient(result *types.HealthResult, closedFunc func() bool) *fakeHealthClient {
	return &fakeHealthClient{
		result:     result,
		closedFunc: closedFunc,
	}
}

// Check returns the configured health result. If no custom result was
// provided, it returns {Healthy: true, Version: "fake"}.
func (c *fakeHealthClient) Check(_ context.Context) (*types.HealthResult, error) {
	if c.closedFunc() {
		return nil, &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}

	if c.result != nil {
		cp := *c.result
		return &cp, nil
	}

	return &types.HealthResult{
		Healthy: true,
		Version: "fake",
	}, nil
}
