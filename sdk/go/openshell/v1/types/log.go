// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package types

import "time"

// LogLine represents a single log entry from a sandbox.
type LogLine struct {
	// Timestamp is when the log entry was recorded.
	Timestamp time.Time
	// Level is the log severity level (e.g., "INFO", "WARN", "ERROR").
	Level string
	// Target is the log target/module.
	Target string
	// Message is the log message text.
	Message string
	// Source is the log source: "gateway" or "sandbox".
	Source string
	// Fields contains structured key-value fields from the tracing event.
	Fields map[string]string
}

// LogResult contains the result of a GetLogs call.
type LogResult struct {
	// Lines contains the log entries in chronological order.
	Lines []LogLine
	// BufferTotal is the total number of lines in the server's buffer.
	BufferTotal uint32
}

// logConfig holds configuration for GetLogs calls.
type logConfig struct {
	lines    uint32
	since    time.Time
	sources  []string
	minLevel string
}

// LogOption configures a GetLogs call.
type LogOption func(*logConfig)

// WithLogLines sets the maximum number of log lines to return.
func WithLogLines(n uint32) LogOption {
	return func(c *logConfig) {
		c.lines = n
	}
}

// WithLogSince filters logs to entries at or after the given time.
func WithLogSince(t time.Time) LogOption {
	return func(c *logConfig) {
		c.since = t
	}
}

// WithLogSources filters logs by source (e.g., "gateway", "sandbox").
func WithLogSources(sources ...string) LogOption {
	return func(c *logConfig) {
		c.sources = sources
	}
}

// WithLogMinLevel sets the minimum log level to include.
func WithLogMinLevel(level string) LogOption {
	return func(c *logConfig) {
		c.minLevel = level
	}
}

// ApplyLogOptions applies options and returns the config.
func ApplyLogOptions(opts []LogOption) logConfig { //nolint:revive // unexported return is intentional; consumed only by v1 package
	var cfg logConfig
	for _, opt := range opts {
		opt(&cfg)
	}
	return cfg
}

// Lines returns the configured max lines (0 means server default).
func (c *logConfig) Lines() uint32 {
	return c.lines
}

// Since returns the configured since timestamp (zero means no filter).
func (c *logConfig) Since() time.Time {
	return c.since
}

// Sources returns the configured source filters.
func (c *logConfig) Sources() []string {
	return c.sources
}

// MinLevel returns the configured minimum log level.
func (c *logConfig) MinLevel() string {
	return c.minLevel
}
