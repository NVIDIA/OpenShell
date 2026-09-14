// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package converter

import (
	"testing"

	v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExecChunkFromEvent_Stdout(t *testing.T) {
	event := &pb.ExecSandboxEvent{
		Payload: &pb.ExecSandboxEvent_Stdout{
			Stdout: &pb.ExecSandboxStdout{
				Data: []byte("hello world"),
			},
		},
	}

	chunk, exitCode, err := ExecChunkFromEvent(event)

	require.NoError(t, err)
	require.NotNil(t, chunk)
	assert.Equal(t, v1.StreamStdout, chunk.Stream)
	assert.Equal(t, []byte("hello world"), chunk.Data)
	assert.Equal(t, -1, exitCode)
}

func TestExecChunkFromEvent_Stderr(t *testing.T) {
	event := &pb.ExecSandboxEvent{
		Payload: &pb.ExecSandboxEvent_Stderr{
			Stderr: &pb.ExecSandboxStderr{
				Data: []byte("error output"),
			},
		},
	}

	chunk, exitCode, err := ExecChunkFromEvent(event)

	require.NoError(t, err)
	require.NotNil(t, chunk)
	assert.Equal(t, v1.StreamStderr, chunk.Stream)
	assert.Equal(t, []byte("error output"), chunk.Data)
	assert.Equal(t, -1, exitCode)
}

func TestExecChunkFromEvent_Exit(t *testing.T) {
	event := &pb.ExecSandboxEvent{
		Payload: &pb.ExecSandboxEvent_Exit{
			Exit: &pb.ExecSandboxExit{
				ExitCode: 42,
			},
		},
	}

	chunk, exitCode, err := ExecChunkFromEvent(event)

	require.NoError(t, err)
	assert.Nil(t, chunk)
	assert.Equal(t, 42, exitCode)
}

func TestExecChunkFromEvent_ExitZero(t *testing.T) {
	event := &pb.ExecSandboxEvent{
		Payload: &pb.ExecSandboxEvent_Exit{
			Exit: &pb.ExecSandboxExit{
				ExitCode: 0,
			},
		},
	}

	chunk, exitCode, err := ExecChunkFromEvent(event)

	require.NoError(t, err)
	assert.Nil(t, chunk)
	assert.Equal(t, 0, exitCode)
}

func TestExecChunkFromEvent_NilEvent(t *testing.T) {
	_, _, err := ExecChunkFromEvent(nil)
	assert.Error(t, err)
}

func TestExecChunkFromEvent_NilPayload(t *testing.T) {
	event := &pb.ExecSandboxEvent{}

	_, _, err := ExecChunkFromEvent(event)
	assert.Error(t, err)
}

func TestExecChunkFromEvent_EmptyStdout(t *testing.T) {
	event := &pb.ExecSandboxEvent{
		Payload: &pb.ExecSandboxEvent_Stdout{
			Stdout: &pb.ExecSandboxStdout{
				Data: []byte{},
			},
		},
	}

	chunk, exitCode, err := ExecChunkFromEvent(event)

	require.NoError(t, err)
	require.NotNil(t, chunk)
	assert.Equal(t, v1.StreamStdout, chunk.Stream)
	assert.Empty(t, chunk.Data)
	assert.Equal(t, -1, exitCode)
}

func TestExecRequestToProto(t *testing.T) {
	req := ExecRequestToProto("sb-1", []string{"ls", "-la"}, &v1.ExecOptions{
		Env:     map[string]string{"FOO": "bar"},
		WorkDir: "/home/user",
	})

	require.NotNil(t, req)
	assert.Equal(t, "sb-1", req.SandboxId)
	assert.Equal(t, []string{"ls", "-la"}, req.Command)
	assert.Equal(t, "/home/user", req.Workdir)
	assert.Equal(t, map[string]string{"FOO": "bar"}, req.Environment)
	assert.False(t, req.Tty)
}

func TestExecRequestToProto_NilOptions(t *testing.T) {
	req := ExecRequestToProto("sb-2", []string{"echo", "hi"}, nil)

	require.NotNil(t, req)
	assert.Equal(t, "sb-2", req.SandboxId)
	assert.Equal(t, []string{"echo", "hi"}, req.Command)
	assert.Empty(t, req.Workdir)
	assert.Nil(t, req.Environment)
}

func TestExecRequestToProto_Interactive(t *testing.T) {
	req := ExecInteractiveRequestToProto("sb-3", []string{"/bin/bash"}, 80, 24, &v1.ExecOptions{
		Env:     map[string]string{"TERM": "xterm"},
		WorkDir: "/root",
	})

	require.NotNil(t, req)
	assert.Equal(t, "sb-3", req.SandboxId)
	assert.Equal(t, []string{"/bin/bash"}, req.Command)
	assert.Equal(t, "/root", req.Workdir)
	assert.Equal(t, map[string]string{"TERM": "xterm"}, req.Environment)
	assert.True(t, req.Tty)
	assert.Equal(t, uint32(80), req.Cols)
	assert.Equal(t, uint32(24), req.Rows)
}

func TestExecResultFromEvents(t *testing.T) {
	events := []*pb.ExecSandboxEvent{
		{Payload: &pb.ExecSandboxEvent_Stdout{Stdout: &pb.ExecSandboxStdout{Data: []byte("line1\n")}}},
		{Payload: &pb.ExecSandboxEvent_Stderr{Stderr: &pb.ExecSandboxStderr{Data: []byte("warn\n")}}},
		{Payload: &pb.ExecSandboxEvent_Stdout{Stdout: &pb.ExecSandboxStdout{Data: []byte("line2\n")}}},
		{Payload: &pb.ExecSandboxEvent_Exit{Exit: &pb.ExecSandboxExit{ExitCode: 0}}},
	}

	result, err := ExecResultFromEvents(events)

	require.NoError(t, err)
	assert.Equal(t, 0, result.ExitCode)
	assert.Equal(t, []byte("line1\nline2\n"), result.Stdout)
	assert.Equal(t, []byte("warn\n"), result.Stderr)
}

func TestExecResultFromEvents_NoExit(t *testing.T) {
	events := []*pb.ExecSandboxEvent{
		{Payload: &pb.ExecSandboxEvent_Stdout{Stdout: &pb.ExecSandboxStdout{Data: []byte("data")}}},
	}

	_, err := ExecResultFromEvents(events)
	assert.Error(t, err)
}

func TestExecResultFromEvents_Empty(t *testing.T) {
	_, err := ExecResultFromEvents(nil)
	assert.Error(t, err)
}

func TestExecResultFromEvents_OnlyExit(t *testing.T) {
	events := []*pb.ExecSandboxEvent{
		{Payload: &pb.ExecSandboxEvent_Exit{Exit: &pb.ExecSandboxExit{ExitCode: 1}}},
	}

	result, err := ExecResultFromEvents(events)

	require.NoError(t, err)
	assert.Equal(t, 1, result.ExitCode)
	assert.Empty(t, result.Stdout)
	assert.Empty(t, result.Stderr)
}
