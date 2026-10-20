// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
)

// ServiceEndpoint represents an exposed HTTP service endpoint within a sandbox.
type ServiceEndpoint = types.ServiceEndpoint

// ServiceExposure describes a loopback HTTP service to expose during sandbox creation.
type ServiceExposure = types.ServiceExposure

// ServiceAuthorizationMode controls handling of an incoming application Authorization header.
type ServiceAuthorizationMode = types.ServiceAuthorizationMode

const (
	// ServiceAuthorizationModeStrip removes Authorization before proxying to the service.
	ServiceAuthorizationModeStrip = types.ServiceAuthorizationModeStrip
	// ServiceAuthorizationModeBearerPassthrough forwards one valid bearer credential unchanged.
	ServiceAuthorizationModeBearerPassthrough = types.ServiceAuthorizationModeBearerPassthrough
)

// ExposeServiceOptions configures service exposure behavior.
type ExposeServiceOptions struct {
	AuthorizationMode ServiceAuthorizationMode
}

// ServiceInterface defines operations for managing sandbox service endpoints.
type ServiceInterface interface {
	Expose(ctx context.Context, workspace, sandboxName, serviceName string, targetPort uint32, domain bool, opts ...ExposeServiceOptions) (*ServiceEndpoint, error)
	Get(ctx context.Context, workspace, sandboxName, serviceName string) (*ServiceEndpoint, error)
	List(workspace, sandboxName string, opts ...ListOptions) (*Pager[*ServiceEndpoint], error)
	ListAll(ctx context.Context, workspace, sandboxName string, opts ...ListOptions) ([]*ServiceEndpoint, error)
	Delete(ctx context.Context, workspace, sandboxName, serviceName string, opts ...DeleteOptions) (*DeletionResult, error)
}
