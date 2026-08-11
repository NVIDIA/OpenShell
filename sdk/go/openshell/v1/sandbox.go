// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
)

// Sandbox represents a sandbox instance.
type Sandbox = types.Sandbox

// SandboxSpec holds the desired state of a sandbox.
type SandboxSpec = types.SandboxSpec

// SandboxTemplate defines the container template for a sandbox.
type SandboxTemplate = types.SandboxTemplate

// SandboxStatus holds the observed state of a sandbox.
type SandboxStatus = types.SandboxStatus

// SandboxCondition describes an observed condition of a sandbox.
type SandboxCondition = types.SandboxCondition

// AttachProviderResult holds the result of attaching a provider to a sandbox.
type AttachProviderResult = types.AttachProviderResult

// DetachProviderResult holds the result of detaching a provider from a sandbox.
type DetachProviderResult = types.DetachProviderResult

// LogLine represents a single log entry from a sandbox.
type LogLine = types.LogLine

// LogResult contains the result of a GetLogs call.
type LogResult = types.LogResult

// LogOption configures a GetLogs call.
type LogOption = types.LogOption

// WithLogLines sets the maximum number of log lines to return.
var WithLogLines = types.WithLogLines

// WithLogSince filters logs to entries at or after the given time.
var WithLogSince = types.WithLogSince

// WithLogSources filters logs by source (e.g., "gateway", "sandbox").
var WithLogSources = types.WithLogSources

// WithLogMinLevel sets the minimum log level to include.
var WithLogMinLevel = types.WithLogMinLevel

// SandboxInterface defines lifecycle operations on sandboxes.
type SandboxInterface interface {
	Create(ctx context.Context, workspace, name string, spec *SandboxSpec, labels map[string]string) (*Sandbox, error)
	Get(ctx context.Context, workspace, name string) (*Sandbox, error)
	List(ctx context.Context, workspace string, opts ...ListOptions) ([]*Sandbox, error)
	Stop(ctx context.Context, workspace, name string) (*Sandbox, error)
	Start(ctx context.Context, workspace, name string) (*Sandbox, error)
	Delete(ctx context.Context, workspace, name string) error
	AttachProvider(ctx context.Context, workspace, sandboxName, providerName string, expectedResourceVersion uint64) (*AttachProviderResult, error)
	DetachProvider(ctx context.Context, workspace, sandboxName, providerName string, expectedResourceVersion uint64) (*DetachProviderResult, error)
	ListProviders(ctx context.Context, workspace, sandboxName string) ([]*Provider, error)
	WaitReady(ctx context.Context, workspace, name string, opts ...WaitOptions) (*Sandbox, error)
	WaitStopped(ctx context.Context, workspace, name string, opts ...WaitOptions) (*Sandbox, error)
	Watch(ctx context.Context, workspace, name string, opts ...WatchOptions) (WatchInterface[*Sandbox], error)
	// GetLogs retrieves log entries for a sandbox. The sandbox is resolved
	// by name (an internal Get call translates name to ID). Use
	// WithLogLines, WithLogSince, WithLogSources, and WithLogMinLevel to
	// filter the results.
	//
	// Errors: NotFound if the sandbox does not exist; InvalidArgument if
	// the sandbox name is empty; Unimplemented by the fake client.
	GetLogs(ctx context.Context, workspace, sandboxName string, opts ...LogOption) (*LogResult, error)
}
