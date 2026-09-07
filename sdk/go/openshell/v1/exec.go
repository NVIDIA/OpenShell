// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
)

// ExecResult holds the collected output of a completed command execution.
type ExecResult = types.ExecResult

// ExecChunk represents a single chunk of output from a streaming command execution.
type ExecChunk = types.ExecChunk

// ExecStream provides an iterator interface over streaming command output.
type ExecStream interface {
	Next() (*ExecChunk, error)
	ExitCode() (int, error)
	Close() error
}

// InteractiveSession provides bidirectional I/O for interactive command execution.
type InteractiveSession interface {
	Read(p []byte) (int, error)
	Write(p []byte) (int, error)
	Resize(cols, rows uint32) error
	ExitCode() (int, error)
	Close() error
}

// ExecInterface defines command execution operations on sandboxes.
// Methods accept a sandbox name and resolve it to an ID internally.
type ExecInterface interface {
	Run(ctx context.Context, workspace, sandboxName string, command []string, opts ...ExecOptions) (*ExecResult, error)
	Stream(ctx context.Context, workspace, sandboxName string, command []string, opts ...ExecOptions) (ExecStream, error)
	Interactive(ctx context.Context, workspace, sandboxName string, command []string, cols, rows uint32, opts ...ExecOptions) (InteractiveSession, error)
}
