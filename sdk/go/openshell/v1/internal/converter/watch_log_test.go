// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package converter

import (
	"testing"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
	dm "github.com/NVIDIA/OpenShell/sdk/go/proto/datamodelv1"
	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- PlatformEvent ---

func TestPlatformEventFromProto(t *testing.T) {
	event := PlatformEventFromProto(&pb.PlatformEvent{
		EventTime: TimestampFromMillis(1700000000000),
		Source:    "kubernetes",
		Type:      "Normal",
		Reason:    "Pulled",
		Message:   "Container image pulled",
		Metadata:  map[string]string{"pod": "sb-1"},
	})

	require.NotNil(t, event)
	assert.False(t, event.Timestamp.IsZero())
	assert.Equal(t, "kubernetes", event.Source)
	assert.Equal(t, "Normal", event.Type)
	assert.Equal(t, "Pulled", event.Reason)
	assert.Equal(t, "Container image pulled", event.Message)
	assert.Equal(t, map[string]string{"pod": "sb-1"}, event.Metadata)
}

func TestPlatformEventFromProtoNil(t *testing.T) {
	assert.Nil(t, PlatformEventFromProto(nil))
}

func TestPlatformEventFromProtoCopiesMetadata(t *testing.T) {
	metadata := map[string]string{"pod": "sb-1"}
	event := PlatformEventFromProto(&pb.PlatformEvent{Metadata: metadata})
	require.NotNil(t, event)

	metadata["pod"] = "mutated"
	assert.Equal(t, "sb-1", event.Metadata["pod"])
}

// --- WatchLogEvent ---

func TestWatchLogEventFromProtoLog(t *testing.T) {
	item := WatchLogEventFromProto(&pb.SandboxStreamEvent{
		Cursor:  "0000000001",
		Payload: &pb.SandboxStreamEvent_Log{Log: &pb.SandboxLogLine{Message: "hello"}},
	})

	require.NotNil(t, item)
	assert.Equal(t, types.WatchLogKindLog, item.Kind)
	assert.Equal(t, "0000000001", item.Cursor)
	require.NotNil(t, item.Log)
	assert.Equal(t, "hello", item.Log.Message)
	assert.Nil(t, item.Event)
	assert.Empty(t, item.Warning)
}

func TestWatchLogEventFromProtoEvent(t *testing.T) {
	item := WatchLogEventFromProto(&pb.SandboxStreamEvent{
		Cursor:  "0000000002",
		Payload: &pb.SandboxStreamEvent_Event{Event: &pb.PlatformEvent{Reason: "Started"}},
	})

	require.NotNil(t, item)
	assert.Equal(t, types.WatchLogKindEvent, item.Kind)
	assert.Equal(t, "0000000002", item.Cursor)
	require.NotNil(t, item.Event)
	assert.Equal(t, "Started", item.Event.Reason)
	assert.Nil(t, item.Log)
}

func TestWatchLogEventFromProtoWarningHasNoCursor(t *testing.T) {
	// The server stamps warnings with an empty cursor because they are not
	// resumable; the converter must not invent one either.
	item := WatchLogEventFromProto(&pb.SandboxStreamEvent{
		Payload: &pb.SandboxStreamEvent_Warning{Warning: &pb.SandboxStreamWarning{Message: "lagged"}},
	})

	require.NotNil(t, item)
	assert.Equal(t, types.WatchLogKindWarning, item.Kind)
	assert.Equal(t, "lagged", item.Warning)
	assert.Empty(t, item.Cursor)
}

func TestWatchLogEventFromProtoSkipsNonStreamPayloads(t *testing.T) {
	tests := map[string]*pb.SandboxStreamEvent{
		"nil": nil,
		"no payload": {
			Cursor: "0000000001",
		},
		"sandbox snapshot": {
			Payload: &pb.SandboxStreamEvent_Sandbox{Sandbox: &pb.Sandbox{
				Metadata: &dm.ObjectMeta{Name: "sb-1"},
			}},
		},
		"draft policy update": {
			Payload: &pb.SandboxStreamEvent_DraftPolicyUpdate{DraftPolicyUpdate: &pb.DraftPolicyUpdate{}},
		},
		"empty log payload": {
			Payload: &pb.SandboxStreamEvent_Log{},
		},
		"empty event payload": {
			Payload: &pb.SandboxStreamEvent_Event{},
		},
		"empty warning payload": {
			Payload: &pb.SandboxStreamEvent_Warning{},
		},
	}

	for name, event := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Nil(t, WatchLogEventFromProto(event))
		})
	}
}
