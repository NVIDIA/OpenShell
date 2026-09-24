// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"
	"sync"
	"testing"
	"time"

	dm "github.com/NVIDIA/OpenShell/sdk/go/proto/datamodelv1"
	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// watchLogsMock returns a mock server with one Ready sandbox registered so
// WatchLogs' name resolution succeeds.
func watchLogsMock() *mockSandboxServer {
	mock := newMockSandboxServer()
	mock.sandboxes["sb-1"] = &pb.Sandbox{
		Metadata: &dm.ObjectMeta{Id: "id-1", Name: "sb-1"},
		Status:   &pb.SandboxStatus{Phase: pb.SandboxPhase_SANDBOX_PHASE_READY},
	}
	return mock
}

func logEvent(cursor, message string) *pb.SandboxStreamEvent {
	return &pb.SandboxStreamEvent{
		Cursor:  cursor,
		Payload: &pb.SandboxStreamEvent_Log{Log: &pb.SandboxLogLine{Message: message, Level: "INFO"}},
	}
}

func platformEvent(cursor, reason string) *pb.SandboxStreamEvent {
	return &pb.SandboxStreamEvent{
		Cursor: cursor,
		Payload: &pb.SandboxStreamEvent_Event{Event: &pb.PlatformEvent{
			Reason: reason,
			Type:   "Normal",
			Source: "kubernetes",
		}},
	}
}

func warningEvent(message string) *pb.SandboxStreamEvent {
	return &pb.SandboxStreamEvent{
		Payload: &pb.SandboxStreamEvent_Warning{Warning: &pb.SandboxStreamWarning{Message: message}},
	}
}

// drainWatchLogs collects every event until the channel closes.
func drainWatchLogs(t *testing.T, w WatchInterface[*WatchLogEvent]) []Event[*WatchLogEvent] {
	t.Helper()
	var events []Event[*WatchLogEvent]
	timeout := time.After(10 * time.Second)
	for {
		select {
		case ev, ok := <-w.ResultChan():
			if !ok {
				return events
			}
			events = append(events, ev)
		case <-timeout:
			t.Fatal("timed out waiting for WatchLogs channel to close")
		}
	}
}

func TestWatchLogs_DeliversLogsEventsAndWarnings(t *testing.T) {
	mock := watchLogsMock()
	mock.watchEvents = []*pb.SandboxStreamEvent{
		{
			Cursor: "0000000001",
			Payload: &pb.SandboxStreamEvent_Log{Log: &pb.SandboxLogLine{
				Message:   "hello",
				Level:     "INFO",
				Target:    "supervisor",
				Source:    "sandbox",
				EventTime: timestamppb.New(time.UnixMilli(1700000000000)),
				Fields:    map[string]string{"dst_host": "example.test"},
			}},
		},
		platformEvent("0000000002", "Started"),
		warningEvent("dropped 3 messages"),
	}
	client, cleanup := setupSandboxTest(t, mock)
	defer cleanup()

	w, err := client.WatchLogs(context.Background(), "default", "sb-1", WatchLogsOptions{
		FollowLogs:   true,
		FollowEvents: true,
	})
	require.NoError(t, err)
	defer w.Stop()

	events := drainWatchLogs(t, w)
	require.Len(t, events, 3)

	require.Equal(t, EventAdded, events[0].Type)
	logItem := events[0].Object
	require.NotNil(t, logItem)
	assert.Equal(t, WatchLogKindLog, logItem.Kind)
	assert.Equal(t, "0000000001", logItem.Cursor)
	require.NotNil(t, logItem.Log)
	assert.Equal(t, "hello", logItem.Log.Message)
	assert.Equal(t, "sandbox", logItem.Log.Source)
	assert.Equal(t, map[string]string{"dst_host": "example.test"}, logItem.Log.Fields)
	assert.Nil(t, logItem.Event)

	platformItem := events[1].Object
	require.NotNil(t, platformItem)
	assert.Equal(t, WatchLogKindEvent, platformItem.Kind)
	assert.Equal(t, "0000000002", platformItem.Cursor)
	require.NotNil(t, platformItem.Event)
	assert.Equal(t, "Started", platformItem.Event.Reason)
	assert.Nil(t, platformItem.Log)

	warnItem := events[2].Object
	require.NotNil(t, warnItem)
	assert.Equal(t, WatchLogKindWarning, warnItem.Kind)
	assert.Equal(t, "dropped 3 messages", warnItem.Warning)
	// Warnings are not resumable, so they carry no cursor.
	assert.Empty(t, warnItem.Cursor)
}

func TestWatchLogs_SkipsNonResumablePayloads(t *testing.T) {
	mock := watchLogsMock()
	mock.watchEvents = []*pb.SandboxStreamEvent{
		{Payload: &pb.SandboxStreamEvent_Sandbox{Sandbox: &pb.Sandbox{
			Metadata: &dm.ObjectMeta{Name: "sb-1"},
			Status:   &pb.SandboxStatus{Phase: pb.SandboxPhase_SANDBOX_PHASE_READY},
		}}},
		logEvent("0000000001", "only this"),
	}
	client, cleanup := setupSandboxTest(t, mock)
	defer cleanup()

	w, err := client.WatchLogs(context.Background(), "default", "sb-1")
	require.NoError(t, err)
	defer w.Stop()

	events := drainWatchLogs(t, w)
	require.Len(t, events, 1)
	assert.Equal(t, WatchLogKindLog, events[0].Object.Kind)
	assert.Equal(t, "only this", events[0].Object.Log.Message)
}

func TestWatchLogs_RequestFields(t *testing.T) {
	mock := watchLogsMock()
	client, cleanup := setupSandboxTest(t, mock)
	defer cleanup()

	w, err := client.WatchLogs(context.Background(), "default", "sb-1", WatchLogsOptions{
		FollowLogs:        true,
		FollowEvents:      true,
		LogSources:        []string{"sandbox"},
		LogMinLevel:       "WARN",
		ResumeAfterCursor: "0000000007",
		LogTailLines:      25,
		EventTail:         5,
	})
	require.NoError(t, err)
	defer w.Stop()

	drainWatchLogs(t, w)

	mock.mu.Lock()
	req := mock.watchRequest
	mock.mu.Unlock()
	require.NotNil(t, req)
	assert.False(t, req.GetFollowStatus())
	assert.True(t, req.GetFollowLogs())
	assert.True(t, req.GetFollowEvents())
	assert.Equal(t, []string{"sandbox"}, req.GetLogSources())
	assert.Equal(t, "WARN", req.GetLogMinLevel())
	assert.Equal(t, "0000000007", req.GetResumeAfterCursor())
	assert.Equal(t, uint32(25), req.GetLogTailLines())
	assert.Equal(t, uint32(5), req.GetEventTail())
}

func TestWatchLogs_DefaultsToFollowingLogs(t *testing.T) {
	mock := watchLogsMock()
	client, cleanup := setupSandboxTest(t, mock)
	defer cleanup()

	w, err := client.WatchLogs(context.Background(), "default", "sb-1")
	require.NoError(t, err)
	defer w.Stop()

	drainWatchLogs(t, w)

	mock.mu.Lock()
	req := mock.watchRequest
	mock.mu.Unlock()
	require.NotNil(t, req)
	assert.True(t, req.GetFollowLogs())
	assert.False(t, req.GetFollowEvents())
}

func TestWatchLogs_ReconnectResumesFromHighestCursor(t *testing.T) {
	mock := watchLogsMock()
	mock.watchFunc = func(attempt int, _ *pb.WatchSandboxRequest, stream grpc.ServerStreamingServer[pb.SandboxStreamEvent]) error {
		switch attempt {
		case 0:
			if err := stream.Send(logEvent("0000000001", "first")); err != nil {
				return err
			}
			if err := stream.Send(platformEvent("0000000003", "Pulled")); err != nil {
				return err
			}
			return status.Error(codes.Unavailable, "connection reset")
		default:
			return stream.Send(logEvent("0000000004", "after resume"))
		}
	}
	client, cleanup := setupSandboxTest(t, mock)
	defer cleanup()

	w, err := client.WatchLogs(context.Background(), "default", "sb-1", WatchLogsOptions{
		FollowLogs:   true,
		FollowEvents: true,
	})
	require.NoError(t, err)
	defer w.Stop()

	events := drainWatchLogs(t, w)
	require.Len(t, events, 3, "reconnect must not drop or duplicate events")
	assert.Equal(t, "first", events[0].Object.Log.Message)
	assert.Equal(t, "Pulled", events[1].Object.Event.Reason)
	assert.Equal(t, "after resume", events[2].Object.Log.Message)
	for _, ev := range events {
		assert.NotEqual(t, EventError, ev.Type)
	}

	mock.mu.Lock()
	requests := mock.watchRequests
	mock.mu.Unlock()
	require.Len(t, requests, 2)
	assert.Empty(t, requests[0].GetResumeAfterCursor())
	assert.Equal(t, "0000000003", requests[1].GetResumeAfterCursor())
}

func TestWatchLogs_CursorIsHighWaterMark(t *testing.T) {
	// The gateway reads the log and platform sources independently during live
	// delivery, so a lower cursor can arrive after a higher one. The resume
	// point must not rewind.
	mock := watchLogsMock()
	mock.watchFunc = func(attempt int, _ *pb.WatchSandboxRequest, stream grpc.ServerStreamingServer[pb.SandboxStreamEvent]) error {
		if attempt == 0 {
			if err := stream.Send(logEvent("0000000005", "high")); err != nil {
				return err
			}
			if err := stream.Send(platformEvent("0000000002", "Late")); err != nil {
				return err
			}
			return status.Error(codes.Unavailable, "connection reset")
		}
		return nil
	}
	client, cleanup := setupSandboxTest(t, mock)
	defer cleanup()

	w, err := client.WatchLogs(context.Background(), "default", "sb-1", WatchLogsOptions{
		FollowLogs:   true,
		FollowEvents: true,
	})
	require.NoError(t, err)
	defer w.Stop()

	drainWatchLogs(t, w)

	mock.mu.Lock()
	requests := mock.watchRequests
	mock.mu.Unlock()
	require.Len(t, requests, 2)
	assert.Equal(t, "0000000005", requests[1].GetResumeAfterCursor())
}

func TestWatchLogs_WarningDoesNotAdvanceCursor(t *testing.T) {
	mock := watchLogsMock()
	mock.watchFunc = func(attempt int, _ *pb.WatchSandboxRequest, stream grpc.ServerStreamingServer[pb.SandboxStreamEvent]) error {
		if attempt == 0 {
			if err := stream.Send(logEvent("0000000001", "before")); err != nil {
				return err
			}
			if err := stream.Send(warningEvent("dropped 2 messages")); err != nil {
				return err
			}
			return status.Error(codes.Unavailable, "connection reset")
		}
		return nil
	}
	client, cleanup := setupSandboxTest(t, mock)
	defer cleanup()

	w, err := client.WatchLogs(context.Background(), "default", "sb-1")
	require.NoError(t, err)
	defer w.Stop()

	events := drainWatchLogs(t, w)
	require.Len(t, events, 2)
	assert.Equal(t, WatchLogKindWarning, events[1].Object.Kind)

	mock.mu.Lock()
	requests := mock.watchRequests
	mock.mu.Unlock()
	require.Len(t, requests, 2)
	assert.Equal(t, "0000000001", requests[1].GetResumeAfterCursor())
}

func TestWatchLogs_OutOfRangeIsTerminal(t *testing.T) {
	mock := watchLogsMock()
	mock.watchFunc = func(_ int, _ *pb.WatchSandboxRequest, stream grpc.ServerStreamingServer[pb.SandboxStreamEvent]) error {
		if err := stream.Send(logEvent("0000000001", "before the gap")); err != nil {
			return err
		}
		return status.Error(codes.OutOfRange, "resume cursor was trimmed")
	}
	client, cleanup := setupSandboxTest(t, mock)
	defer cleanup()

	w, err := client.WatchLogs(context.Background(), "default", "sb-1")
	require.NoError(t, err)
	defer w.Stop()

	events := drainWatchLogs(t, w)
	require.Len(t, events, 2)
	assert.Equal(t, WatchLogKindLog, events[0].Object.Kind)

	last := events[1]
	assert.Equal(t, EventError, last.Type)
	require.Error(t, last.Err)
	assert.True(t, IsOutOfRange(last.Err), "want ErrorOutOfRange, got %v", last.Err)
	assert.False(t, IsInvalidArgument(last.Err))

	mock.mu.Lock()
	attempts := len(mock.watchRequests)
	mock.mu.Unlock()
	assert.Equal(t, 1, attempts, "OUT_OF_RANGE must not be retried")
}

func TestWatchLogs_NonRetryableErrorIsTerminal(t *testing.T) {
	mock := watchLogsMock()
	mock.watchFunc = func(_ int, _ *pb.WatchSandboxRequest, _ grpc.ServerStreamingServer[pb.SandboxStreamEvent]) error {
		return status.Error(codes.PermissionDenied, "nope")
	}
	client, cleanup := setupSandboxTest(t, mock)
	defer cleanup()

	w, err := client.WatchLogs(context.Background(), "default", "sb-1")
	require.NoError(t, err)
	defer w.Stop()

	events := drainWatchLogs(t, w)
	require.Len(t, events, 1)
	assert.Equal(t, EventError, events[0].Type)
	assert.True(t, IsPermissionDenied(events[0].Err))

	mock.mu.Lock()
	attempts := len(mock.watchRequests)
	mock.mu.Unlock()
	assert.Equal(t, 1, attempts)
}

func TestWatchLogs_BackoffResetsAfterDeliveredEvent(t *testing.T) {
	// Two drops separated by a delivered event must both request the initial
	// backoff, not an escalating one.
	const attempts = 3
	mock := watchLogsMock()
	var recordedBackoffs []time.Duration
	var mu sync.Mutex

	// Inject test hook to record requested backoff delays without wall-clock overhead.
	oldHook := testHookWatchLogsSleep
	testHookWatchLogsSleep = func(d time.Duration) {
		mu.Lock()
		recordedBackoffs = append(recordedBackoffs, d)
		mu.Unlock()
	}
	defer func() { testHookWatchLogsSleep = oldHook }()

	mock.watchFunc = func(attempt int, _ *pb.WatchSandboxRequest, stream grpc.ServerStreamingServer[pb.SandboxStreamEvent]) error {
		if attempt >= attempts-1 {
			return nil
		}
		if err := stream.Send(logEvent("000000000"+string(rune('1'+attempt)), "tick")); err != nil {
			return err
		}
		return status.Error(codes.Unavailable, "connection reset")
	}
	client, cleanup := setupSandboxTest(t, mock)
	defer cleanup()

	w, err := client.WatchLogs(context.Background(), "default", "sb-1")
	require.NoError(t, err)
	defer w.Stop()

	events := drainWatchLogs(t, w)
	require.Len(t, events, attempts-1)

	// Both backoff requests should be at the initial delay (reset between drops).
	require.Len(t, recordedBackoffs, 2)
	assert.Equal(t, watchLogsInitialBackoff, recordedBackoffs[0])
	assert.Equal(t, watchLogsInitialBackoff, recordedBackoffs[1])
}

func TestWatchLogs_StopClosesChannel(t *testing.T) {
	mock := watchLogsMock()
	keepOpen := make(chan struct{})
	defer close(keepOpen)
	mock.watchEvents = []*pb.SandboxStreamEvent{logEvent("0000000001", "hello")}
	mock.watchKeepOpen = keepOpen
	client, cleanup := setupSandboxTest(t, mock)
	defer cleanup()

	w, err := client.WatchLogs(context.Background(), "default", "sb-1")
	require.NoError(t, err)

	ev := <-w.ResultChan()
	assert.Equal(t, "hello", ev.Object.Log.Message)

	w.Stop()
	select {
	case _, ok := <-w.ResultChan():
		if ok {
			// A queued event may still drain before the close.
			_, ok = <-w.ResultChan()
		}
		assert.False(t, ok, "channel should close after Stop")
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for channel close after Stop")
	}
}

func TestWatchLogs_ContextCancelClosesChannel(t *testing.T) {
	mock := watchLogsMock()
	keepOpen := make(chan struct{})
	defer close(keepOpen)
	mock.watchKeepOpen = keepOpen
	client, cleanup := setupSandboxTest(t, mock)
	defer cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	w, err := client.WatchLogs(ctx, "default", "sb-1")
	require.NoError(t, err)
	defer w.Stop()

	cancel()
	drainWatchLogs(t, w)
}

func TestWatchLogs_EmptyName(t *testing.T) {
	mock := watchLogsMock()
	client, cleanup := setupSandboxTest(t, mock)
	defer cleanup()

	_, err := client.WatchLogs(context.Background(), "default", "")
	require.Error(t, err)
	assert.True(t, IsInvalidArgument(err))
}

func TestWatchLogs_UnknownSandbox(t *testing.T) {
	mock := watchLogsMock()
	client, cleanup := setupSandboxTest(t, mock)
	defer cleanup()

	_, err := client.WatchLogs(context.Background(), "default", "missing")
	require.Error(t, err)
	assert.True(t, IsNotFound(err))

	mock.mu.Lock()
	attempts := len(mock.watchRequests)
	mock.mu.Unlock()
	assert.Zero(t, attempts, "resolution failure must not open a stream")
}
