// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package types

import "time"

// CreateOptions configures resource creation.
type CreateOptions struct {
	Annotations map[string]string
	// ServiceExposures are loopback HTTP services registered with the sandbox.
	ServiceExposures []ServiceExposure
}

// ListOptions configures resource listing with pagination and filtering.
type ListOptions struct {
	// PageSize is the maximum number of resources requested per RPC.
	PageSize int
	// PageToken resumes after a page returned by the same list query.
	PageToken     string
	LabelSelector string
	// AllWorkspaces selects a platform-admin view across workspace boundaries.
	AllWorkspaces bool
}

// WatchOptions configures watch behavior.
type WatchOptions struct {
	// StopOnTerminal causes the watch to close automatically when the sandbox
	// reaches a terminal phase (Ready or Error).
	StopOnTerminal bool
}

// WatchLogsOptions configures a resumable sandbox log and platform event watch.
type WatchLogsOptions struct {
	// FollowLogs streams sandbox log lines.
	FollowLogs bool
	// FollowEvents streams platform events.
	FollowEvents bool
	// LogSources filters log lines by source (e.g. "gateway", "sandbox").
	LogSources []string
	// LogMinLevel sets the minimum log level to include.
	LogMinLevel string
	// ResumeAfterCursor replays only what follows an opaque cursor taken from a
	// WatchLogEvent of an earlier watch on the same sandbox. Empty starts from
	// the tail bounded by LogTailLines and EventTail.
	//
	// If the cursor was already trimmed from the server's buffer, or came from
	// a cursor space the gateway no longer has (a restart, or a different
	// replica), the watch fails with ErrorOutOfRange rather than silently
	// skipping the missing events.
	ResumeAfterCursor string
	// LogTailLines bounds the initial log backfill. Ignored when
	// ResumeAfterCursor is set.
	LogTailLines uint32
	// EventTail bounds the initial platform event backfill. Ignored when
	// ResumeAfterCursor is set.
	EventTail uint32
}

// WaitOptions configures wait behavior. Use context for timeout control.
type WaitOptions struct {
	PollInterval time.Duration
}

// ExecOptions configures command execution.
type ExecOptions struct {
	Env     map[string]string
	WorkDir string
	// NoLoginShell skips sourcing shell login/profile startup files before the
	// command. The zero value (false) preserves login-shell behavior. Set it
	// for automation and managed checks that need predictable startup behavior.
	NoLoginShell bool
}
