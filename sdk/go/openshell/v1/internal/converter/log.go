// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package converter

import (
	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
)

// --- LogLine ---

// LogLineFromProto converts a proto SandboxLogLine to an SDK LogLine.
func LogLineFromProto(l *pb.SandboxLogLine) *types.LogLine {
	if l == nil {
		return nil
	}
	return &types.LogLine{
		Timestamp: TimeFromMillis(l.GetTimestampMs()),
		Level:     l.GetLevel(),
		Target:    l.GetTarget(),
		Message:   l.GetMessage(),
		Source:    l.GetSource(),
		Fields:    CopyStringMap(l.GetFields()),
	}
}

// --- LogResult ---

// LogResultFromProto converts a proto GetSandboxLogsResponse to an SDK LogResult.
func LogResultFromProto(r *pb.GetSandboxLogsResponse) *types.LogResult {
	if r == nil {
		return nil
	}
	result := &types.LogResult{
		BufferTotal: r.GetBufferTotal(),
	}
	if logs := r.GetLogs(); len(logs) > 0 {
		result.Lines = make([]types.LogLine, 0, len(logs))
		for _, l := range logs {
			if converted := LogLineFromProto(l); converted != nil {
				result.Lines = append(result.Lines, *converted)
			}
		}
	}
	return result
}
