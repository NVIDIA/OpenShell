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
	Extensions     []ExtensionInfo
}

// ExtensionKind identifies one supported extension family.
type ExtensionKind string

// Extension kind constants.
const (
	ExtensionKindComputeDriver        ExtensionKind = "ComputeDriver"
	ExtensionKindCredentialDriver     ExtensionKind = "CredentialDriver"
	ExtensionKindGatewayInterceptor   ExtensionKind = "GatewayInterceptor"
	ExtensionKindSupervisorMiddleware ExtensionKind = "SupervisorMiddleware"
	ExtensionKindUnknown              ExtensionKind = "Unknown"
)

// ExtensionInfo describes one successful gateway/extension negotiation.
type ExtensionInfo struct {
	Kind                  ExtensionKind
	ConfiguredName        string
	ImplementationName    string
	ImplementationVersion string
	ProtocolMajor         uint32
	ProtocolMinor         uint32
	SupportedCapabilities []string
	RequiredCapabilities  []string
}

// ComputeDriverInfo describes a compute backend available on the gateway.
type ComputeDriverInfo struct {
	Name          string
	DriverName    string
	DriverVersion string
	// WorkloadCompatibility is nil when the configured driver does not report it.
	WorkloadCompatibility *WorkloadCompatibility
}

// WorkloadCompatibility describes the workload, separately from the gateway host.
// Empty platform fields and an empty restriction list remain unreported; this
// metadata neither establishes installation health nor admits a command.
type WorkloadCompatibility struct {
	OperatingSystem       string
	Architecture          string
	ExecutionRestrictions []string
}

// CurrentUser holds the authenticated caller's identity.
type CurrentUser struct {
	Subject          string
	DisplayName      string
	Roles            []string
	Scopes           []string
	IdentityProvider string
}
