// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"fmt"
	"os/exec"
	"runtime"
)

// browserCommand returns the platform-specific command name and
// arguments for opening a URL in the user's default browser.
func browserCommand(url string) (string, []string) {
	switch runtime.GOOS {
	case "darwin":
		return "open", []string{url}
	case "linux":
		return "xdg-open", []string{url}
	case "windows":
		return "cmd", []string{"/c", "start", "", url}
	default:
		// Fallback: try xdg-open (common on Unix-like systems).
		return "xdg-open", []string{url}
	}
}

// openBrowser attempts to open the given URL in the user's default
// browser using the platform-appropriate command. Returns an error if
// the browser could not be launched.
func openBrowser(url string) error {
	name, args := browserCommand(url)
	return openBrowserWith(name, args...)
}

// openBrowserWith runs the given command with the provided arguments.
// This is separated from openBrowser to allow testing with arbitrary
// command names.
func openBrowserWith(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to open browser with %s: %w", name, err)
	}
	// We don't wait for the browser process to exit. It runs
	// independently, and we only care that it launched.
	return nil
}
