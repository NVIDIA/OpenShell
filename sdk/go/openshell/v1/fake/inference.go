// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package fake

import (
	"context"
	"sync"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
)

type fakeInferenceClient struct {
	mu         sync.RWMutex
	routes     map[string]*types.InferenceRoute // keyed by "workspace/routeName"
	closedFunc func() bool
}

func newFakeInferenceClient(closedFunc func() bool) *fakeInferenceClient {
	return &fakeInferenceClient{
		routes:     make(map[string]*types.InferenceRoute),
		closedFunc: closedFunc,
	}
}

func inferenceKey(workspace, routeName string) string {
	return workspace + "/" + routeName
}

func copyInferenceRoute(r *types.InferenceRoute) *types.InferenceRoute {
	if r == nil {
		return nil
	}
	cp := *r
	if r.ValidatedEndpoints != nil {
		cp.ValidatedEndpoints = make([]types.ValidatedEndpoint, len(r.ValidatedEndpoints))
		copy(cp.ValidatedEndpoints, r.ValidatedEndpoints)
	}
	return &cp
}

func (c *fakeInferenceClient) SetRoute(_ context.Context, workspace string, config *types.InferenceRouteConfig) (*types.InferenceRoute, error) {
	if c.closedFunc() {
		return nil, &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}
	if workspace == "" {
		return nil, &types.StatusError{Code: types.ErrorInvalidArgument, Message: "workspace must not be empty"}
	}
	if config == nil {
		return nil, &types.StatusError{Code: types.ErrorInvalidArgument, Message: "config must not be nil"}
	}
	if config.ProviderName == "" {
		return nil, &types.StatusError{Code: types.ErrorInvalidArgument, Message: "provider name must not be empty"}
	}
	if config.ModelID == "" {
		return nil, &types.StatusError{Code: types.ErrorInvalidArgument, Message: "model ID must not be empty"}
	}

	key := inferenceKey(workspace, config.RouteName)

	c.mu.Lock()
	defer c.mu.Unlock()

	// Determine version: increment if route exists, start at 1 otherwise.
	var version uint64 = 1
	if existing, ok := c.routes[key]; ok {
		version = existing.Version + 1
	}

	route := &types.InferenceRoute{
		ProviderName: config.ProviderName,
		ModelID:      config.ModelID,
		Version:      version,
		RouteName:    config.RouteName,
		TimeoutSecs:  config.TimeoutSecs,
		Workspace:    workspace,
	}

	c.routes[key] = copyInferenceRoute(route)
	return copyInferenceRoute(route), nil
}

func (c *fakeInferenceClient) GetRoute(_ context.Context, workspace, routeName string) (*types.InferenceRoute, error) {
	if c.closedFunc() {
		return nil, &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}
	if workspace == "" {
		return nil, &types.StatusError{Code: types.ErrorInvalidArgument, Message: "workspace must not be empty"}
	}

	key := inferenceKey(workspace, routeName)

	c.mu.RLock()
	defer c.mu.RUnlock()

	route, ok := c.routes[key]
	if !ok {
		return nil, &types.StatusError{Code: types.ErrorNotFound, Message: "route not found"}
	}
	return copyInferenceRoute(route), nil
}

func (c *fakeInferenceClient) DeleteRoute(_ context.Context, workspace, routeName string) error {
	if c.closedFunc() {
		return &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}
	if workspace == "" {
		return &types.StatusError{Code: types.ErrorInvalidArgument, Message: "workspace must not be empty"}
	}

	key := inferenceKey(workspace, routeName)

	c.mu.Lock()
	defer c.mu.Unlock()

	// Idempotent: deleting a non-existent route is not an error.
	delete(c.routes, key)
	return nil
}
