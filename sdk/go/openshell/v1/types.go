// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
)

// SandboxPhase represents the lifecycle phase of a sandbox.
type SandboxPhase = types.SandboxPhase

// SandboxPhase values for sandbox lifecycle.
const (
	SandboxProvisioning = types.SandboxProvisioning
	SandboxReady        = types.SandboxReady
	SandboxError        = types.SandboxError
	SandboxDeleting     = types.SandboxDeleting
	SandboxUnknown      = types.SandboxUnknown
	SandboxStopping     = types.SandboxStopping
	SandboxStopped      = types.SandboxStopped
	SandboxStarting     = types.SandboxStarting
)

// EventType classifies watch events.
type EventType = types.EventType

// EventType values for watch events.
const (
	EventAdded    = types.EventAdded
	EventModified = types.EventModified
	EventDeleted  = types.EventDeleted
	EventError    = types.EventError
)

// StreamType identifies which output stream a chunk belongs to.
type StreamType = types.StreamType

// StreamType values for exec output.
const (
	StreamStdout = types.StreamStdout
	StreamStderr = types.StreamStderr
)

// TLSConfig holds TLS connection settings.
type TLSConfig = types.TLSConfig

// RetryPolicy configures automatic retry behavior for failed RPCs.
type RetryPolicy = types.RetryPolicy
