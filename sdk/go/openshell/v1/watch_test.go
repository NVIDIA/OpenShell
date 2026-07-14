// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestWatcher creates a watcher with a simulated producer goroutine that
// forwards events from src to the watcher's channel and closes it when the
// producer finishes or Stop is called.
func newTestWatcher(src <-chan Event[string]) *watcher[string] {
	ch := make(chan Event[string], 10)
	w := newWatcher(ch, nil)
	go func() {
		defer close(ch)
		for {
			select {
			case ev, ok := <-src:
				if !ok {
					return
				}
				select {
				case ch <- ev:
				case <-w.done:
					return
				}
			case <-w.done:
				return
			}
		}
	}()
	return w
}

// --- T038: WatchInterface event delivery, Stop, and error handling ---

func TestWatcher_DeliversEvents(t *testing.T) {
	src := make(chan Event[string], 10)
	w := newTestWatcher(src)

	src <- Event[string]{Type: EventAdded, Object: "sandbox-1"}
	src <- Event[string]{Type: EventModified, Object: "sandbox-1"}

	resultCh := w.ResultChan()

	ev1 := <-resultCh
	assert.Equal(t, EventAdded, ev1.Type)
	assert.Equal(t, "sandbox-1", ev1.Object)

	ev2 := <-resultCh
	assert.Equal(t, EventModified, ev2.Type)
	assert.Equal(t, "sandbox-1", ev2.Object)
}

func TestWatcher_StopClosesChannel(t *testing.T) {
	src := make(chan Event[string], 10)
	w := newTestWatcher(src)

	w.Stop()

	select {
	case _, ok := <-w.ResultChan():
		assert.False(t, ok, "channel should be closed after Stop")
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for channel close")
	}
}

func TestWatcher_StopIsIdempotent(_ *testing.T) {
	src := make(chan Event[string], 10)
	w := newTestWatcher(src)

	w.Stop()
	w.Stop() // must not panic
}

func TestWatcher_ErrorEvent(t *testing.T) {
	src := make(chan Event[string], 10)
	w := newTestWatcher(src)

	src <- Event[string]{Type: EventError, Object: "error details"}

	ev := <-w.ResultChan()
	assert.Equal(t, EventError, ev.Type)
	assert.Equal(t, "error details", ev.Object)
}

func TestWatcher_ChannelClosesWhenSourceEnds(t *testing.T) {
	src := make(chan Event[string], 10)
	w := newTestWatcher(src)

	src <- Event[string]{Type: EventAdded, Object: "sb-1"}
	close(src)

	ev := <-w.ResultChan()
	require.Equal(t, "sb-1", ev.Object)

	select {
	case _, ok := <-w.ResultChan():
		assert.False(t, ok, "channel should close when source ends")
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for channel to close")
	}
}

func TestWatcher_DrainAfterStop(t *testing.T) {
	src := make(chan Event[string], 10)
	w := newTestWatcher(src)

	src <- Event[string]{Type: EventAdded, Object: "sb-1"}

	ev := <-w.ResultChan()
	require.Equal(t, "sb-1", ev.Object)

	w.Stop()

	timeout := time.After(time.Second)
	for {
		select {
		case _, ok := <-w.ResultChan():
			if !ok {
				return // success: channel closed
			}
		case <-timeout:
			t.Fatal("timed out waiting for channel to close after Stop")
		}
	}
}
