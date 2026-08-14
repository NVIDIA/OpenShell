// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"fmt"
	"net/url"
	"os/exec"
	"runtime"
)

// browserCommand returns the platform-specific command name and
// arguments for opening a URL in the user's default browser.
func browserCommand(url string) (string, []string) {
	return browserCommandForOS(runtime.GOOS, url)
}

func browserCommandForOS(goos, url string) (string, []string) {
	switch goos {
	case "darwin":
		return "open", []string{url}
	case "linux":
		return "xdg-open", []string{url}
	case "windows":
		// Invoke the URL handler directly. Passing an authorization URL to
		// cmd.exe would allow '&' and other shell metacharacters in its query
		// string to be interpreted as commands.
		return "rundll32", []string{"url.dll,FileProtocolHandler", url}
	default:
		// Fallback: try xdg-open (common on Unix-like systems).
		return "xdg-open", []string{url}
	}
}

// openBrowser attempts to open the given URL in the user's default
// browser using the platform-appropriate command. Returns an error if
// the browser could not be launched.
func openBrowser(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return fmt.Errorf("refusing to open non-HTTP URL: %s", rawURL)
	}
	name, args := browserCommand(rawURL)
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
