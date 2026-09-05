// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package types

import "time"

// createConfig holds configuration for Create calls.
type createConfig struct {
	labels      map[string]string
	annotations map[string]string
}

// CreateOption configures a Create call.
type CreateOption func(*createConfig)

// WithLabels sets labels on the created resource.
func WithLabels(labels map[string]string) CreateOption {
	return func(c *createConfig) {
		c.labels = labels
	}
}

// WithAnnotations sets annotations on the created resource.
func WithAnnotations(annotations map[string]string) CreateOption {
	return func(c *createConfig) {
		c.annotations = annotations
	}
}

// ApplyCreateOptions applies options and returns the config.
func ApplyCreateOptions(opts []CreateOption) createConfig { //nolint:revive // unexported return is intentional; consumed only by v1 package
	var cfg createConfig
	for _, opt := range opts {
		opt(&cfg)
	}
	return cfg
}

// Labels returns the configured labels.
func (c *createConfig) Labels() map[string]string {
	return c.labels
}

// Annotations returns the configured annotations.
func (c *createConfig) Annotations() map[string]string {
	return c.annotations
}

// ListOptions configures resource listing with pagination and filtering.
type ListOptions struct {
	Limit         int
	Offset        int
	LabelSelector string
	AllWorkspaces bool
}

// WatchOptions configures watch behavior.
type WatchOptions struct {
	// StopOnTerminal causes the watch to close automatically when the sandbox
	// reaches a terminal phase (Ready or Error).
	StopOnTerminal bool
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
