// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/internal/converter"
	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	// watchLogsInitialBackoff is the delay before the first reconnect attempt.
	// It is restored after every delivered event, so a long-lived stream that
	// drops retries promptly instead of at the capped delay.
	watchLogsInitialBackoff = 100 * time.Millisecond
	// watchLogsMaxBackoff caps the reconnect delay.
	watchLogsMaxBackoff = 2 * time.Second
	// watchLogsChannelBuffer is the result channel depth.
	watchLogsChannelBuffer = 64
)

// testHookWatchLogsSleep allows tests to inject a function to observe requested
// backoff delays without wall-clock overhead. In production, it is time.Sleep.
var testHookWatchLogsSleep = time.Sleep

// WatchLogs streams a sandbox's log lines and platform events with loss-aware
// resume.
//
// Each delivered event carries an opaque cursor. The watcher tracks the highest
// cursor it has seen, reconnects transparently on transient stream errors, and
// asks the gateway to replay only what follows that cursor, so a reconnect
// neither loses nor duplicates events.
//
// Loss is never silent. A recoverable server-side gap arrives as a
// WatchLogKindWarning event and the stream continues. An unrecoverable gap ends
// the stream with an ERROR event carrying ErrorOutOfRange: the resume point is
// gone, so the events after it cannot be replayed. That error is deliberately
// not retried, because restarting from the tail would hide the loss this API
// exists to surface. A caller that accepts the gap can start a new watch with
// an empty ResumeAfterCursor; retrying the same cursor fails identically.
//
// The returned watcher's channel closes when the server ends the stream, when
// the context is cancelled, or after Stop. Call Stop to release the stream.
func (s *sandboxClient) WatchLogs(ctx context.Context, workspace, name string, opts ...WatchLogsOptions) (WatchInterface[*WatchLogEvent], error) {
	if name == "" {
		return nil, &StatusError{Code: ErrorInvalidArgument, Message: "sandbox name must not be empty"}
	}

	var cfg WatchLogsOptions
	if len(opts) > 0 {
		cfg = opts[0]
	}
	if !cfg.FollowLogs && !cfg.FollowEvents {
		cfg.FollowLogs = true
	}

	// Resolve and confirm the sandbox under this workspace before opening the
	// stream, so a bad name fails here rather than inside the reconnect loop.
	sb, err := s.Get(ctx, workspace, name)
	if err != nil {
		return nil, err
	}
	resolved := name
	if sb != nil && sb.Name != "" {
		resolved = sb.Name
	}

	streamCtx, streamCancel := context.WithCancel(ctx)
	ch := make(chan Event[*WatchLogEvent], watchLogsChannelBuffer)
	w := newWatcher(ch, streamCancel)

	go s.runWatchLogs(streamCtx, w, workspace, resolved, cfg)

	return w, nil
}

// runWatchLogs drives the reconnect/resume loop until the stream ends cleanly,
// a terminal error occurs, or the consumer stops watching.
func (s *sandboxClient) runWatchLogs(ctx context.Context, w *watcher[*WatchLogEvent], workspace, name string, cfg WatchLogsOptions) {
	defer close(w.result)
	defer w.cancel()

	cursor := cfg.ResumeAfterCursor
	backoff := watchLogsInitialBackoff

	for {
		req := &pb.WatchSandboxRequest{
			Sandbox:           name,
			WorkspaceScope:    namedWorkspaceScope(workspace),
			FollowStatus:      false,
			FollowLogs:        cfg.FollowLogs,
			FollowEvents:      cfg.FollowEvents,
			LogTailLines:      cfg.LogTailLines,
			EventTail:         cfg.EventTail,
			LogSources:        converter.CopyStringSlice(cfg.LogSources),
			LogMinLevel:       cfg.LogMinLevel,
			ResumeAfterCursor: cursor,
		}

		stream, err := s.client.WatchSandbox(ctx, req)
		if err != nil {
			if !retryWatchLogs(ctx, w, err, &backoff) {
				return
			}
			continue
		}

		reconnect := false
		for {
			ev, recvErr := stream.Recv()
			if recvErr != nil {
				if errors.Is(recvErr, io.EOF) {
					// Server closed the stream cleanly; nothing left to resume.
					return
				}
				reconnect = retryWatchLogs(ctx, w, recvErr, &backoff)
				break
			}

			// A delivered event means the connection is healthy again.
			backoff = watchLogsInitialBackoff

			item := converter.WatchLogEventFromProto(ev)
			if item == nil {
				continue
			}
			// The gateway reads the log and platform sources independently
			// during live delivery, so arrival order can differ from cursor
			// order. Keep the high-water mark: assigning directly would let a
			// later lower cursor rewind the resume point and replay
			// already-delivered events after a reconnect.
			if item.Cursor > cursor {
				cursor = item.Cursor
			}
			if !w.emit(ctx, Event[*WatchLogEvent]{Type: EventAdded, Object: item}) {
				return
			}
		}
		if !reconnect {
			return
		}
	}
}

// retryWatchLogs decides what to do with a stream error. It returns true when
// the caller should redial from the tracked cursor, having already waited out
// the backoff and doubled it. Otherwise the error is terminal: it is reported
// as an ERROR event (unless the consumer already stopped) and the watch ends.
func retryWatchLogs(ctx context.Context, w *watcher[*WatchLogEvent], err error, backoff *time.Duration) bool {
	if w.stopped() || ctx.Err() != nil {
		return false
	}
	converted := converter.FromGRPCError(err)
	if !isRetryableWatchLogsError(converted) {
		// Terminal, including ErrorOutOfRange: the resume point is gone, and
		// restarting from the tail here would silently swallow the gap.
		w.emit(ctx, Event[*WatchLogEvent]{Type: EventError, Err: converted})
		return false
	}
	testHookWatchLogsSleep(*backoff)
	if !w.sleep(ctx, *backoff) {
		return false
	}
	*backoff = min(*backoff*2, watchLogsMaxBackoff)
	return true
}

// isRetryableWatchLogsError reports whether a stream error is a transient
// condition worth reconnecting on. Only Unavailable (connection drop, gateway
// restart) qualifies; every other status is surfaced to the caller instead of
// looping.
func isRetryableWatchLogsError(err error) bool {
	var se *types.StatusError
	if errors.As(err, &se) {
		return se.GRPCCode == int32(codes.Unavailable)
	}
	return status.Code(err) == codes.Unavailable
}
