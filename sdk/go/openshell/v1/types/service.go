// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package types

// ServiceExposure describes a loopback HTTP service to expose during sandbox creation.
type ServiceExposure struct {
	Service    string
	TargetPort uint32
}

// ServiceEndpoint represents an exposed HTTP service on a sandbox.
type ServiceEndpoint struct {
	ID         string
	SandboxID  string
	Sandbox    string
	Name       string
	TargetPort uint32
	Domain     bool
	URL        string
	Workspace  string
}
