// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package types

import "time"

// PlatformEvent is a runtime event observed for a sandbox, such as a scheduling
// or image-pull event reported by the compute backend.
type PlatformEvent struct {
	// Timestamp is when the event occurred.
	Timestamp time.Time
	// Source is the reporting subsystem (e.g. "kubernetes", "docker", "process").
	Source string
	// Type is the event severity (e.g. "Normal", "Warning").
	Type string
	// Reason is a short reason code (e.g. "Started", "Pulled", "Failed").
	Reason string
	// Message is the human-readable event text.
	Message string
	// Metadata holds optional key-value pairs.
	Metadata map[string]string
}

// WatchLogKind classifies a WatchLogs stream item.
type WatchLogKind string

// WatchLogKind values.
const (
	// WatchLogKindLog marks an item carrying a log line.
	WatchLogKindLog WatchLogKind = "LOG"
	// WatchLogKindEvent marks an item carrying a platform event.
	WatchLogKindEvent WatchLogKind = "EVENT"
	// WatchLogKindWarning marks a recoverable loss notice. The stream continues.
	WatchLogKindWarning WatchLogKind = "WARNING"
)

// WatchLogEvent is one item from a resumable sandbox log and platform event
// stream.
//
// Exactly one of Log, Event, or Warning is populated, selected by Kind.
type WatchLogEvent struct {
	// Kind selects the populated payload.
	Kind WatchLogKind
	// Log is set when Kind is WatchLogKindLog.
	Log *LogLine
	// Event is set when Kind is WatchLogKindEvent.
	Event *PlatformEvent
	// Warning is set when Kind is WatchLogKindWarning. It reports recoverable
	// loss: the server skipped ahead after a broadcast lag instead of
	// terminating, and the stream keeps running. Because cursors are opaque,
	// this is the only signal that events were skipped.
	Warning string
	// Cursor is the opaque resume position of this item, empty for warnings.
	//
	// Do not parse or construct a cursor; its encoding is not part of the
	// gateway's contract. The only supported operation is comparing two
	// non-empty cursors observed on the same stream and keeping the greater
	// one, then passing it as WatchLogsOptions.ResumeAfterCursor.
	Cursor string
}
