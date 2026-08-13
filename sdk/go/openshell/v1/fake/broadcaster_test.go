// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package fake

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
)

// --- T005: watchBroadcaster tests ---

func TestWatchBroadcaster_Watch_ReceivesEvents(t *testing.T) {
	b := newWatchBroadcaster[*testItem]()

	w := b.Watch("")
	defer w.Stop()

	item := &testItem{Name: "alpha", Value: "v1"}
	b.Broadcast(types.Event[*testItem]{Type: types.EventAdded, Object: item}, "alpha")

	select {
	case ev := <-w.ResultChan():
		assert.Equal(t, types.EventAdded, ev.Type)
		assert.Equal(t, "alpha", ev.Object.Name)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for event")
	}
}

func TestWatchBroadcaster_DoesNotDropBurstEvents(t *testing.T) {
	b := newWatchBroadcaster[*testItem]()
	w := b.Watch("")
	defer w.Stop()

	const count = watchChannelBuffer + 50
	for i := range count {
		b.Broadcast(types.Event[*testItem]{Object: &testItem{Name: fmt.Sprint(i)}}, "")
	}
	for range count {
		select {
		case <-w.ResultChan():
		case <-time.After(time.Second):
			t.Fatal("watch event was dropped")
		}
	}
}

func TestWatchBroadcaster_Watch_NameFiltering(t *testing.T) {
	b := newWatchBroadcaster[*testItem]()

	// Watcher filtered to "alpha" only
	wAlpha := b.Watch("alpha")
	defer wAlpha.Stop()

	// Watcher filtered to "beta" only
	wBeta := b.Watch("beta")
	defer wBeta.Stop()

	// Broadcast event for "alpha"
	b.Broadcast(types.Event[*testItem]{Type: types.EventAdded, Object: &testItem{Name: "alpha"}}, "alpha")

	// alpha watcher should receive event
	select {
	case ev := <-wAlpha.ResultChan():
		assert.Equal(t, "alpha", ev.Object.Name)
	case <-time.After(time.Second):
		t.Fatal("alpha watcher: timed out waiting for event")
	}

	// beta watcher should NOT receive event
	select {
	case ev := <-wBeta.ResultChan():
		t.Fatalf("beta watcher: unexpected event %v", ev)
	case <-time.After(50 * time.Millisecond):
		// Expected: no event for beta
	}
}

func TestWatchBroadcaster_Watch_EmptyNameReceivesAll(t *testing.T) {
	b := newWatchBroadcaster[*testItem]()

	// Watcher with empty name receives all events
	w := b.Watch("")
	defer w.Stop()

	b.Broadcast(types.Event[*testItem]{Type: types.EventAdded, Object: &testItem{Name: "alpha"}}, "alpha")
	b.Broadcast(types.Event[*testItem]{Type: types.EventAdded, Object: &testItem{Name: "beta"}}, "beta")

	received := make([]string, 0, 2)
	for i := 0; i < 2; i++ {
		select {
		case ev := <-w.ResultChan():
			received = append(received, ev.Object.Name)
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for event")
		}
	}
	assert.ElementsMatch(t, []string{"alpha", "beta"}, received)
}

func TestWatchBroadcaster_MultipleWatchers(t *testing.T) {
	b := newWatchBroadcaster[*testItem]()

	w1 := b.Watch("")
	defer w1.Stop()
	w2 := b.Watch("")
	defer w2.Stop()

	b.Broadcast(types.Event[*testItem]{Type: types.EventAdded, Object: &testItem{Name: "alpha"}}, "alpha")

	// Both watchers should receive the event
	for _, w := range []types.WatchInterface[*testItem]{w1, w2} {
		select {
		case ev := <-w.ResultChan():
			assert.Equal(t, "alpha", ev.Object.Name)
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for event")
		}
	}
}

func TestWatchBroadcaster_Stop_ClosesChannel(t *testing.T) {
	b := newWatchBroadcaster[*testItem]()

	w := b.Watch("")
	w.Stop()

	// Channel should be closed after Stop
	_, ok := <-w.ResultChan()
	assert.False(t, ok, "channel should be closed after Stop")
}

func TestWatchBroadcaster_Stop_Idempotent(_ *testing.T) {
	b := newWatchBroadcaster[*testItem]()

	w := b.Watch("")

	// Multiple stops should not panic
	w.Stop()
	w.Stop()
}

func TestWatchBroadcaster_StopAll(t *testing.T) {
	b := newWatchBroadcaster[*testItem]()

	w1 := b.Watch("")
	w2 := b.Watch("alpha")

	b.StopAll()

	// Both channels should be closed
	_, ok1 := <-w1.ResultChan()
	assert.False(t, ok1, "w1 channel should be closed after StopAll")

	_, ok2 := <-w2.ResultChan()
	assert.False(t, ok2, "w2 channel should be closed after StopAll")
}

func TestWatchBroadcaster_BroadcastAfterStop_NoDelivery(_ *testing.T) {
	b := newWatchBroadcaster[*testItem]()

	w := b.Watch("")
	w.Stop()

	// Broadcasting after a watcher stops should not panic
	b.Broadcast(types.Event[*testItem]{Type: types.EventAdded, Object: &testItem{Name: "alpha"}}, "alpha")
}

func TestWatchBroadcaster_StoppedWatcher_RemovedFromBroadcast(t *testing.T) {
	b := newWatchBroadcaster[*testItem]()

	w1 := b.Watch("")
	w2 := b.Watch("")

	// Stop w1, keep w2
	w1.Stop()

	b.Broadcast(types.Event[*testItem]{Type: types.EventAdded, Object: &testItem{Name: "alpha"}}, "alpha")

	// w2 should still receive events
	select {
	case ev := <-w2.ResultChan():
		assert.Equal(t, "alpha", ev.Object.Name)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for event on w2")
	}

	w2.Stop()
}
