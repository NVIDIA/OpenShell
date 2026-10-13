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
	// ExitCode waits for final stream completion. An observed exit code is
	// returned alongside any later transport error. Drain Read concurrently.
	ExitCode() (int, error)
	Close() error
}

// InteractiveSessionControl adds optional input closure and cancellation to
// InteractiveSession without requiring existing implementations to add methods.
// Sessions returned by this SDK implement both interfaces.
type InteractiveSessionControl interface {
	InteractiveSession
	// CloseWrite ends stdin and resize input without cancelling output.
	CloseWrite() error
	// Cancel aborts the RPC. Close retains the same full-close behavior.
	Cancel() error
}

// CloseInteractiveInput ends input while preserving output when supported.
// Unsupported sessions return ErrorUnimplemented and are left open.
func CloseInteractiveInput(session InteractiveSession) error {
	if closer, ok := session.(interface{ CloseWrite() error }); ok {
		return closer.CloseWrite()
	}
	return &StatusError{Code: ErrorUnimplemented, Message: "interactive session does not support closing input independently"}
}

// CancelInteractive aborts a session, falling back to the original Close contract.
func CancelInteractive(session InteractiveSession) error {
	if canceler, ok := session.(interface{ Cancel() error }); ok {
		return canceler.Cancel()
	}
	return session.Close()
}

// ExecInterface defines command execution operations on sandboxes.
// Methods accept a sandbox name and resolve it to an ID internally.
type ExecInterface interface {
	Run(ctx context.Context, workspace, sandboxName string, command []string, opts ...ExecOptions) (*ExecResult, error)
	Stream(ctx context.Context, workspace, sandboxName string, command []string, opts ...ExecOptions) (ExecStream, error)
	Interactive(ctx context.Context, workspace, sandboxName string, command []string, cols, rows uint32, opts ...ExecOptions) (InteractiveSession, error)
}
