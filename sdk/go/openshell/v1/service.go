// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
)

// ServiceEndpoint represents an exposed HTTP service endpoint within a sandbox.
type ServiceEndpoint = types.ServiceEndpoint

// ServiceInterface defines operations for managing sandbox service endpoints.
type ServiceInterface interface {
	Expose(ctx context.Context, workspace, sandboxName, serviceName string, targetPort uint32, domain bool) (*ServiceEndpoint, error)
	Get(ctx context.Context, workspace, sandboxName, serviceName string) (*ServiceEndpoint, error)
	List(ctx context.Context, workspace, sandboxName string, opts ...ListOptions) ([]*ServiceEndpoint, error)
	Delete(ctx context.Context, workspace, sandboxName, serviceName string) error
}
