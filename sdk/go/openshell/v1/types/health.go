// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package types

// HealthResult holds the result of a health check.
type HealthResult struct {
	Healthy bool
	Version string
}

// ServiceStatus describes the health state of the gateway.
type ServiceStatus string

// ServiceStatus constants.
const (
	ServiceStatusHealthy   ServiceStatus = "Healthy"
	ServiceStatusDegraded  ServiceStatus = "Degraded"
	ServiceStatusUnhealthy ServiceStatus = "Unhealthy"
	ServiceStatusUnknown   ServiceStatus = "Unknown"
)

// GatewayInfo holds operational metadata about the gateway.
type GatewayInfo struct {
	Status         ServiceStatus
	Version        string
	ComputeDrivers []ComputeDriverInfo
}

// ComputeDriverInfo describes a compute backend available on the gateway.
type ComputeDriverInfo struct {
	Name          string
	DriverName    string
	DriverVersion string
}

// CurrentUser holds the authenticated caller's identity.
type CurrentUser struct {
	Subject          string
	DisplayName      string
	Roles            []string
	Scopes           []string
	IdentityProvider string
}
