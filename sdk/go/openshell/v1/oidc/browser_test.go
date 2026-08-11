// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"runtime"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
)

// T015: Browser opener tests

func TestBrowserCommand_Platform(t *testing.T) {
	name, args := browserCommand("https://example.com/auth")

	switch runtime.GOOS {
	case "darwin":
		assert.Equal(t, "open", name)
		assert.Equal(t, []string{"https://example.com/auth"}, args)
	case "linux":
		assert.Equal(t, "xdg-open", name)
		assert.Equal(t, []string{"https://example.com/auth"}, args)
	case "windows":
		assert.Equal(t, "cmd", name)
		assert.Contains(t, args, "/c")
		assert.Contains(t, args, "start")
	default:
		// Unknown platform should still return something (even if it fails).
		assert.NotEmpty(t, name)
	}
}

func TestBrowserCommand_URLPassedAsArg(t *testing.T) {
	testURL := "https://auth.example.com/authorize?client_id=test&state=abc"
	_, args := browserCommand(testURL)

	assert.True(t, slices.Contains(args, testURL), "URL should be passed as an argument to the browser command")
}

func TestBrowserCommandForOS_WindowsDoesNotUseCommandShell(t *testing.T) {
	name, args := browserCommandForOS("windows", "https://auth.example.com/authorize?client_id=test&state=abc")

	assert.NotEqual(t, "cmd", name)
	assert.NotContains(t, args, "/c")
}

func TestOpenBrowser_InvalidCommand(t *testing.T) {
	// Attempting to open a browser with a non-existent command should
	// return an error rather than panic.
	err := openBrowserWith("nonexistent-browser-cmd-that-does-not-exist", "https://example.com")
	assert.Error(t, err, "should fail when the browser command does not exist")
}
