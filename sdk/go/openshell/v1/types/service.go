// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package types

import "time"

// HTTPReadinessCheck checks application readiness on the service's target port.
// Path defaults to /. Only HTTP 2xx responses pass.
type HTTPReadinessCheck struct {
	Path string
}

// ServiceHealthState is the current cached service health.
type ServiceHealthState int32

// Service health states.
const (
	ServiceHealthStateUnknown   ServiceHealthState = 1
	ServiceHealthStateHealthy   ServiceHealthState = 2
	ServiceHealthStateUnhealthy ServiceHealthState = 3
)

// ServiceHealth records the latest HTTP observation. It does not control routing.
type ServiceHealth struct {
	State           ServiceHealthState
	LastCheckedTime *time.Time
	Message         string
	HTTPStatusCode  *uint32
}

// ServiceAuthorizationMode controls handling of an incoming application Authorization header.
type ServiceAuthorizationMode int32

const (
	// ServiceAuthorizationModeStrip removes Authorization before proxying to the sandbox service.
	ServiceAuthorizationModeStrip ServiceAuthorizationMode = 1
	// ServiceAuthorizationModeBearerPassthrough forwards one valid bearer credential unchanged.
	ServiceAuthorizationModeBearerPassthrough ServiceAuthorizationMode = 2
)

// ServiceExposure describes a loopback HTTP service to expose during sandbox creation.
type ServiceExposure struct {
	Service           string
	TargetPort        uint32
	AuthorizationMode ServiceAuthorizationMode
	ReadinessCheck    *HTTPReadinessCheck
}

// ServiceEndpoint represents an exposed HTTP service on a sandbox.
type ServiceEndpoint struct {
	ID                string
	SandboxID         string
	Sandbox           string
	Name              string
	TargetPort        uint32
	Domain            bool
	URL               string
	Workspace         string
	AuthorizationMode ServiceAuthorizationMode
	ReadinessCheck    *HTTPReadinessCheck
	Health            *ServiceHealth
}
