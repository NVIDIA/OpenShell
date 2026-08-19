// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
)

// HealthResult holds the result of a health check.
type HealthResult = types.HealthResult

// GatewayInfo holds operational metadata about the gateway.
type GatewayInfo = types.GatewayInfo

// ComputeDriverInfo describes a compute backend available on the gateway.
type ComputeDriverInfo = types.ComputeDriverInfo

// ServiceStatus describes the health state of the gateway.
type ServiceStatus = types.ServiceStatus

// ServiceStatus constants.
const (
	ServiceStatusHealthy   = types.ServiceStatusHealthy
	ServiceStatusDegraded  = types.ServiceStatusDegraded
	ServiceStatusUnhealthy = types.ServiceStatusUnhealthy
	ServiceStatusUnknown   = types.ServiceStatusUnknown
)

// CurrentUser holds the authenticated caller's identity.
type CurrentUser = types.CurrentUser

// HealthInterface defines health check and gateway info operations.
type HealthInterface interface {
	Check(ctx context.Context) (*HealthResult, error)
	GetGatewayInfo(ctx context.Context) (*GatewayInfo, error)
	GetCurrentUser(ctx context.Context) (*CurrentUser, error)
}
