// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
)

// InferenceRouteConfig holds parameters for setting an inference route.
type InferenceRouteConfig = types.InferenceRouteConfig

// InferenceRoute represents a configured inference route as returned by the
// gateway.
type InferenceRoute = types.InferenceRoute

// ValidatedEndpoint represents an endpoint probed during route validation.
type ValidatedEndpoint = types.ValidatedEndpoint

// InferenceInterface defines inference route management operations.
// Accessed via client.Inference().
type InferenceInterface interface {
	// SetRoute configures an inference route for a workspace.
	// Returns ErrorInvalidArgument if workspace, providerName, or modelID is empty.
	SetRoute(ctx context.Context, workspace string, config *InferenceRouteConfig) (*InferenceRoute, error)

	// GetRoute retrieves the inference route for a workspace by route name.
	// Returns ErrorInvalidArgument if workspace is empty.
	// Returns ErrorNotFound if no route exists for the given name.
	GetRoute(ctx context.Context, workspace, routeName string) (*InferenceRoute, error)

	// DeleteRoute removes an inference route from a workspace.
	// Returns ErrorInvalidArgument if workspace is empty.
	// Idempotent: deleting a non-existent route is not an error.
	DeleteRoute(ctx context.Context, workspace, routeName string) error
}
