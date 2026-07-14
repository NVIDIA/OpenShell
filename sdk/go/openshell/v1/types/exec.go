// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package types

// ExecResult holds the collected output of a completed command execution.
type ExecResult struct {
	ExitCode int
	Stdout   []byte
	Stderr   []byte
}

// ExecChunk represents a single chunk of output from a streaming command execution.
type ExecChunk struct {
	Stream StreamType
	Data   []byte
}
