// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// T014: Keyboard fallback flow tests

func TestKeyboardFlow_ReadsCode(t *testing.T) {
	// Simulate user pasting a code via stdin.
	input := strings.NewReader("my-auth-code\n")
	output := &bytes.Buffer{}

	code, err := keyboardFlow(
		context.Background(),
		"https://auth.example.com/authorize?client_id=test",
		input,
		output,
	)
	require.NoError(t, err)
	assert.Equal(t, "my-auth-code", code)

	// Verify that the URL was displayed to the user.
	assert.Contains(t, output.String(), "https://auth.example.com/authorize?client_id=test")
}

func TestInputDispatcher_BoundsBlockedReads(t *testing.T) {
	d := newInputDispatcher()
	reader := &countingBlockingReader{release: make(chan struct{})}
	t.Cleanup(func() { close(reader.release) })

	for range 5 {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		_, err := d.read(ctx, reader)
		cancel()
		require.Error(t, err)
	}
	assert.Equal(t, int32(1), reader.max.Load())
}

func TestKeyboardFlow_TrimsWhitespace(t *testing.T) {
	input := strings.NewReader("  some-code-with-spaces  \n")
	output := &bytes.Buffer{}

	code, err := keyboardFlow(
		context.Background(),
		"https://auth.example.com/authorize",
		input,
		output,
	)
	require.NoError(t, err)
	assert.Equal(t, "some-code-with-spaces", code)
}

func TestKeyboardFlow_EmptyInput(t *testing.T) {
	input := strings.NewReader("\n")
	output := &bytes.Buffer{}

	_, err := keyboardFlow(
		context.Background(),
		"https://auth.example.com/authorize",
		input,
		output,
	)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrAuthCode))
}

func TestKeyboardFlow_EOFBeforeInput(t *testing.T) {
	// Reader that returns EOF immediately (e.g., piped /dev/null).
	input := strings.NewReader("")
	output := &bytes.Buffer{}

	_, err := keyboardFlow(
		context.Background(),
		"https://auth.example.com/authorize",
		input,
		output,
	)
	require.Error(t, err)
	// Should be ErrAuthCode since no code was received.
	assert.True(t, errors.Is(err, ErrAuthCode))
}

func TestKeyboardFlow_ContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

	// Use a reader that blocks forever (until context cancel).
	input := &blockingReader{}
	output := &bytes.Buffer{}

	_, err := keyboardFlow(ctx, "https://auth.example.com/authorize", input, output)
	require.Error(t, err)
}

func TestKeyboardFlow_DisplaysInstructions(t *testing.T) {
	input := strings.NewReader("test-code\n")
	output := &bytes.Buffer{}

	_, err := keyboardFlow(
		context.Background(),
		"https://auth.example.com/authorize?response_type=code",
		input,
		output,
	)
	require.NoError(t, err)

	displayed := output.String()
	// Must show the URL and some instruction text.
	assert.Contains(t, displayed, "https://auth.example.com/authorize?response_type=code")
	// Should prompt user to paste the code.
	lower := strings.ToLower(displayed)
	assert.True(t,
		strings.Contains(lower, "paste") || strings.Contains(lower, "code") || strings.Contains(lower, "enter"),
		"output should instruct the user to paste or enter the code",
	)
}

func TestKeyboardFlow_Timeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	// Reader that never returns data.
	input := &blockingReader{}
	output := &bytes.Buffer{}

	_, err := keyboardFlow(ctx, "https://example.com/auth", input, output)
	require.Error(t, err)
}

// blockingReader is an io.Reader that blocks until the context is cancelled.
// It is used to simulate a user who never types anything.
type blockingReader struct{}

func (r *blockingReader) Read(_ []byte) (int, error) {
	// Block for a long time to simulate waiting for input.
	time.Sleep(100 * time.Millisecond)
	return 0, io.EOF
}

type countingBlockingReader struct {
	active  atomic.Int32
	max     atomic.Int32
	release chan struct{}
}

func (r *countingBlockingReader) Read(_ []byte) (int, error) {
	active := r.active.Add(1)
	for {
		old := r.max.Load()
		if active <= old || r.max.CompareAndSwap(old, active) {
			break
		}
	}
	<-r.release
	r.active.Add(-1)
	return 0, io.EOF
}
