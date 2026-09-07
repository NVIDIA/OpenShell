// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package converter

import (
	"testing"

	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- LogLine ---

func TestLogLineFromProto(t *testing.T) {
	proto := &pb.SandboxLogLine{
		SandboxId:   "sbx-1",
		TimestampMs: 1700000000000,
		Level:       "INFO",
		Target:      "network",
		Message:     "Connection established",
		Source:      "sandbox-agent",
		Fields: map[string]string{
			"host": "api.example.com",
			"port": "443",
		},
	}

	line := LogLineFromProto(proto)

	require.NotNil(t, line)
	assert.False(t, line.Timestamp.IsZero())
	assert.Equal(t, "INFO", line.Level)
	assert.Equal(t, "network", line.Target)
	assert.Equal(t, "Connection established", line.Message)
	assert.Equal(t, "sandbox-agent", line.Source)
	assert.Equal(t, "api.example.com", line.Fields["host"])
	assert.Equal(t, "443", line.Fields["port"])
}

func TestLogLineFromProto_Nil(t *testing.T) {
	assert.Nil(t, LogLineFromProto(nil))
}

func TestLogLineDeepCopy(t *testing.T) {
	proto := &pb.SandboxLogLine{
		TimestampMs: 1700000000000,
		Level:       "WARN",
		Message:     "test",
		Fields: map[string]string{
			"key": "value",
		},
	}

	line := LogLineFromProto(proto)
	proto.Fields["key"] = "changed"

	assert.Equal(t, "value", line.Fields["key"])
}

// --- LogResult ---

func TestLogResultFromProto(t *testing.T) {
	proto := &pb.GetSandboxLogsResponse{
		Logs: []*pb.SandboxLogLine{
			{TimestampMs: 1700000000000, Level: "INFO", Message: "first"},
			{TimestampMs: 1700000001000, Level: "DEBUG", Message: "second"},
		},
		BufferTotal: 100,
	}

	result := LogResultFromProto(proto)

	require.NotNil(t, result)
	assert.Len(t, result.Lines, 2)
	assert.Equal(t, "INFO", result.Lines[0].Level)
	assert.Equal(t, "first", result.Lines[0].Message)
	assert.Equal(t, "DEBUG", result.Lines[1].Level)
	assert.Equal(t, "second", result.Lines[1].Message)
	assert.Equal(t, uint32(100), result.BufferTotal)
}

func TestLogResultFromProto_Nil(t *testing.T) {
	assert.Nil(t, LogResultFromProto(nil))
}

func TestLogResultFromProto_EmptyLogs(t *testing.T) {
	proto := &pb.GetSandboxLogsResponse{
		BufferTotal: 0,
	}

	result := LogResultFromProto(proto)
	require.NotNil(t, result)
	assert.Empty(t, result.Lines)
	assert.Equal(t, uint32(0), result.BufferTotal)
}
