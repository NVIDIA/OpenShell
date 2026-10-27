// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package types

import "time"

// ServiceRouteEndpoint is the trusted supervisor app listener, not a workload port.
type ServiceRouteEndpoint struct {
	Host string
	Port uint32
}

// DiscoveredServiceRoute is accepted installation evidence, not application health.
// Preserve Hostname as TLS SNI and HTTP authority when using Endpoint.
type DiscoveredServiceRoute struct {
	Workspace           string
	Sandbox             string
	Name                string
	Hostname            string
	Endpoint            ServiceRouteEndpoint
	InstallationVersion string
	DeclarationRevision uint64
	ExpiresAt           time.Time
}

// ServiceRouteSnapshot replaces the complete selected route view. Revision is
// an opaque equality token, including renewal-only expiry changes, not a cursor.
type ServiceRouteSnapshot struct {
	Revision string
	Routes   []DiscoveredServiceRoute
}

// ServiceRouteScope selects one workspace, a finite named set, or all active workspaces.
// AllWorkspaces is mutually exclusive with Workspaces; neither may be omitted.
type ServiceRouteScope struct {
	Workspaces    []string
	AllWorkspaces bool
}
