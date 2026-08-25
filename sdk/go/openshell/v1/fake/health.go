// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package fake

import (
	"context"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
)

// fakeHealthClient implements v1.HealthInterface with configurable
// responses. When no custom result is provided, Check returns a
// default healthy response.
type fakeHealthClient struct {
	result      *types.HealthResult
	gatewayInfo *types.GatewayInfo
	currentUser *types.CurrentUser
	closedFunc  func() bool
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

// GetGatewayInfo returns the configured gateway info. If no custom info
// was provided, it returns a default healthy response.
func (c *fakeHealthClient) GetGatewayInfo(_ context.Context) (*types.GatewayInfo, error) {
	if c.closedFunc() {
		return nil, &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}

	if c.gatewayInfo != nil {
		return copyGatewayInfo(c.gatewayInfo), nil
	}

	return &types.GatewayInfo{
		Status:  types.ServiceStatusHealthy,
		Version: "fake",
	}, nil
}

// GetCurrentUser returns the configured current user. If no custom user
// was provided, it returns a default user.
func (c *fakeHealthClient) GetCurrentUser(_ context.Context) (*types.CurrentUser, error) {
	if c.closedFunc() {
		return nil, &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}

	if c.currentUser != nil {
		return copyCurrentUser(c.currentUser), nil
	}

	return &types.CurrentUser{
		Subject:     "fake-user",
		DisplayName: "Fake User",
	}, nil
}

func copyGatewayInfo(info *types.GatewayInfo) *types.GatewayInfo {
	if info == nil {
		return nil
	}
	cp := *info
	if info.ComputeDrivers != nil {
		cp.ComputeDrivers = make([]types.ComputeDriverInfo, len(info.ComputeDrivers))
		copy(cp.ComputeDrivers, info.ComputeDrivers)
	}
	return &cp
}

func copyCurrentUser(user *types.CurrentUser) *types.CurrentUser {
	if user == nil {
		return nil
	}
	cp := *user
	cp.Roles = copyStringSlice(user.Roles)
	cp.Scopes = copyStringSlice(user.Scopes)
	return &cp
}
