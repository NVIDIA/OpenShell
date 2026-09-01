// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package converter

import (
	"fmt"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
)

// ExecChunkFromEvent converts a proto ExecSandboxEvent to an ExecChunk and/or exit code.
// For stdout/stderr events, returns the chunk with exitCode -1.
// For exit events, returns nil chunk with the exit code.
func ExecChunkFromEvent(event *pb.ExecSandboxEvent) (*types.ExecChunk, int, error) {
	if event == nil {
		return nil, -1, fmt.Errorf("nil exec event")
	}

	switch p := event.Payload.(type) {
	case *pb.ExecSandboxEvent_Stdout:
		return &types.ExecChunk{
			Stream: types.StreamStdout,
			Data:   append([]byte(nil), p.Stdout.GetData()...),
		}, -1, nil
	case *pb.ExecSandboxEvent_Stderr:
		return &types.ExecChunk{
			Stream: types.StreamStderr,
			Data:   append([]byte(nil), p.Stderr.GetData()...),
		}, -1, nil
	case *pb.ExecSandboxEvent_Exit:
		return nil, int(p.Exit.GetExitCode()), nil
	default:
		return nil, -1, fmt.Errorf("unknown exec event payload type: %T", p)
	}
}

// ExecRequestToProto builds a proto ExecSandboxRequest for Run/Stream modes.
func ExecRequestToProto(sandboxID string, command []string, opts *types.ExecOptions) *pb.ExecSandboxRequest {
	req := &pb.ExecSandboxRequest{
		SandboxId: sandboxID,
		Command:   CopyStringSlice(command),
	}
	if opts != nil {
		req.Workdir = opts.WorkDir
		req.Environment = CopyStringMap(opts.Env)
		req.NoLoginShell = opts.NoLoginShell
	}
	return req
}

// ExecInteractiveRequestToProto builds a proto ExecSandboxRequest for Interactive mode.
func ExecInteractiveRequestToProto(sandboxID string, command []string, cols, rows uint32, opts *types.ExecOptions) *pb.ExecSandboxRequest {
	req := ExecRequestToProto(sandboxID, command, opts)
	req.Tty = true
	req.Cols = cols
	req.Rows = rows
	return req
}

// ExecResultFromEvents collects a sequence of ExecSandboxEvents into an ExecResult.
func ExecResultFromEvents(events []*pb.ExecSandboxEvent) (*types.ExecResult, error) {
	if len(events) == 0 {
		return nil, fmt.Errorf("no exec events received")
	}

	var stdout, stderr []byte
	exitCode := -1
	sawExit := false

	for _, event := range events {
		chunk, code, err := ExecChunkFromEvent(event)
		if err != nil {
			return nil, err
		}
		if chunk != nil {
			switch chunk.Stream {
			case types.StreamStdout:
				stdout = append(stdout, chunk.Data...)
			case types.StreamStderr:
				stderr = append(stderr, chunk.Data...)
			}
		} else {
			exitCode = code
			sawExit = true
		}
	}

	if !sawExit {
		return nil, fmt.Errorf("no exit event received")
	}

	return &types.ExecResult{
		ExitCode: exitCode,
		Stdout:   stdout,
		Stderr:   stderr,
	}, nil
}
