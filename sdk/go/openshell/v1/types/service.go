// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package types

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
}
