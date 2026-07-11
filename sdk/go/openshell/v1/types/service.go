// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package types

// ServiceEndpoint represents an exposed HTTP service on a sandbox.
type ServiceEndpoint struct {
	ID          string
	SandboxID   string
	SandboxName string
	ServiceName string
	TargetPort  uint32
	Domain      bool
	URL         string
}
