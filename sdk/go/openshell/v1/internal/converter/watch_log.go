// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package converter

import (
	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
)

// --- PlatformEvent ---

// PlatformEventFromProto converts a proto PlatformEvent to an SDK PlatformEvent.
func PlatformEventFromProto(e *pb.PlatformEvent) *types.PlatformEvent {
	if e == nil {
		return nil
	}
	return &types.PlatformEvent{
		Timestamp: TimeFromProto(e.GetEventTime()),
		Source:    e.GetSource(),
		Type:      e.GetType(),
		Reason:    e.GetReason(),
		Message:   e.GetMessage(),
		Metadata:  CopyStringMap(e.GetMetadata()),
	}
}

// --- WatchLogEvent ---

// WatchLogEventFromProto converts a watch stream event into a WatchLogEvent.
//
// Returns nil for payloads that are not part of the log and platform event
// stream (status snapshots, draft policy updates), which callers skip.
func WatchLogEventFromProto(ev *pb.SandboxStreamEvent) *types.WatchLogEvent {
	if ev == nil {
		return nil
	}
	switch payload := ev.GetPayload().(type) {
	case *pb.SandboxStreamEvent_Log:
		line := LogLineFromProto(payload.Log)
		if line == nil {
			return nil
		}
		return &types.WatchLogEvent{Kind: types.WatchLogKindLog, Log: line, Cursor: ev.GetCursor()}
	case *pb.SandboxStreamEvent_Event:
		event := PlatformEventFromProto(payload.Event)
		if event == nil {
			return nil
		}
		return &types.WatchLogEvent{Kind: types.WatchLogKindEvent, Event: event, Cursor: ev.GetCursor()}
	case *pb.SandboxStreamEvent_Warning:
		if payload.Warning == nil {
			return nil
		}
		// Warnings are not resumable and carry no cursor.
		return &types.WatchLogEvent{Kind: types.WatchLogKindWarning, Warning: payload.Warning.GetMessage()}
	default:
		return nil
	}
}
