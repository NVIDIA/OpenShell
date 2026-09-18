// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

// Deliberately implements only the original interface: downstream mocks must
// continue compiling without adding the optional lifecycle methods.
type legacyInteractiveSession struct {
	closed bool
	err    error
}

var _ InteractiveSession = (*legacyInteractiveSession)(nil)

func (*legacyInteractiveSession) Read([]byte) (int, error)    { return 0, io.EOF }
func (*legacyInteractiveSession) Write(p []byte) (int, error) { return len(p), nil }
func (*legacyInteractiveSession) Resize(uint32, uint32) error { return nil }
func (*legacyInteractiveSession) ExitCode() (int, error)      { return 0, nil }
func (s *legacyInteractiveSession) Close() error              { s.closed = true; return s.err }

type controlledInteractiveSession struct {
	legacyInteractiveSession
	inputClosed bool
	cancelled   bool
}

func (s *controlledInteractiveSession) CloseWrite() error { s.inputClosed = true; return s.err }
func (s *controlledInteractiveSession) Cancel() error     { s.cancelled = true; return s.err }

func TestInteractiveControlLegacyCompatibility(t *testing.T) {
	s := &legacyInteractiveSession{err: errors.New("close error")}
	var statusErr *StatusError
	require.ErrorAs(t, CloseInteractiveInput(s), &statusErr)
	require.Equal(t, ErrorUnimplemented, statusErr.Code)
	require.False(t, s.closed, "unsupported input closure must not cancel the session")
	require.ErrorIs(t, CancelInteractive(s), s.err)
	require.True(t, s.closed)
}

func TestInteractiveControlDispatch(t *testing.T) {
	s := &controlledInteractiveSession{legacyInteractiveSession: legacyInteractiveSession{err: errors.New("control error")}}
	require.Implements(t, (*InteractiveSessionControl)(nil), s)
	require.ErrorIs(t, CloseInteractiveInput(s), s.err)
	require.True(t, s.inputClosed)
	require.ErrorIs(t, CancelInteractive(s), s.err)
	require.True(t, s.cancelled)
	require.False(t, s.closed, "explicit cancellation takes precedence over fallback")
}
