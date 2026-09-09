// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package types

import "time"

// SandboxPhase represents the lifecycle phase of a sandbox.
type SandboxPhase string

// SandboxPhase values for sandbox lifecycle.
const (
	SandboxProvisioning SandboxPhase = "Provisioning"
	SandboxReady        SandboxPhase = "Ready"
	SandboxError        SandboxPhase = "Error"
	SandboxDeleting     SandboxPhase = "Deleting"
	SandboxUnknown      SandboxPhase = "Unknown"
	SandboxStopping     SandboxPhase = "Stopping"
	SandboxStopped      SandboxPhase = "Stopped"
	SandboxStarting     SandboxPhase = "Starting"
	SandboxCompleted    SandboxPhase = "Completed"
)

// EventType classifies watch events.
type EventType string

// EventType values for watch events.
const (
	EventAdded    EventType = "ADDED"
	EventModified EventType = "MODIFIED"
	EventDeleted  EventType = "DELETED"
	EventError    EventType = "ERROR"
)

// StreamType identifies which output stream a chunk belongs to.
type StreamType string

// StreamType values for exec output.
const (
	StreamStdout StreamType = "stdout"
	StreamStderr StreamType = "stderr"
)

// TLSConfig holds TLS connection settings.
type TLSConfig struct {
	CertFile string
	KeyFile  string
	CAFile   string
	Insecure bool
}

// RetryPolicy configures automatic retry behavior for failed RPCs.
type RetryPolicy struct {
	MaxRetries  int
	InitialWait time.Duration
	MaxWait     time.Duration
}
