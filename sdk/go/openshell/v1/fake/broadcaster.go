// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package fake

import (
	"sync"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
)

const watchChannelBuffer = 100

// watchBroadcaster manages a set of watchers and broadcasts events to them.
// Each watcher can optionally filter events by resource name.
type watchBroadcaster[T any] struct {
	mu       sync.Mutex
	watchers []*fakeWatcher[T]
}

// newWatchBroadcaster creates a new watchBroadcaster.
func newWatchBroadcaster[T any]() *watchBroadcaster[T] {
	return &watchBroadcaster[T]{}
}

// Watch registers a new watcher. If name is non-empty, the watcher only
// receives events matching that name. If name is empty, all events are
// delivered. The returned WatchInterface must be stopped by the caller.
func (b *watchBroadcaster[T]) Watch(name string) types.WatchInterface[T] {
	w := &fakeWatcher[T]{
		ch:     make(chan types.Event[T], watchChannelBuffer),
		name:   name,
		wake:   make(chan struct{}, 1),
		stopCh: make(chan struct{}),
		done:   make(chan struct{}),
	}
	go w.run()

	b.mu.Lock()
	b.watchers = append(b.watchers, w)
	b.mu.Unlock()

	return w
}

// Broadcast sends an event to all registered watchers whose name filter
// matches (or whose filter is empty). Stopped watchers are skipped and
// cleaned up lazily.
func (b *watchBroadcaster[T]) Broadcast(event types.Event[T], name string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	active := b.watchers[:0]
	for _, w := range b.watchers {
		if w.isStopped() {
			continue
		}
		active = append(active, w)

		if w.name != "" && w.name != name {
			continue
		}

		w.send(event)
	}
	b.watchers = active
}

// StopAll closes all active watchers.
func (b *watchBroadcaster[T]) StopAll() {
	b.mu.Lock()
	defer b.mu.Unlock()

	for _, w := range b.watchers {
		w.Stop()
	}
	b.watchers = nil
}

// fakeWatcher implements types.WatchInterface[T] with a buffered channel
// and optional name filter.
type fakeWatcher[T any] struct {
	ch      chan types.Event[T]
	name    string
	once    sync.Once
	stopped bool
	mu      sync.Mutex
	queue   []types.Event[T]
	wake    chan struct{}
	stopCh  chan struct{}
	done    chan struct{}
}

// ResultChan returns the channel delivering watch events.
func (w *fakeWatcher[T]) ResultChan() <-chan types.Event[T] {
	return w.ch
}

// send delivers an event to the watcher under its lock, preventing a
// race between Broadcast (send) and Stop (close) on w.ch.
func (w *fakeWatcher[T]) send(event types.Event[T]) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.stopped {
		return
	}
	w.queue = append(w.queue, event)
	select {
	case w.wake <- struct{}{}:
	default:
	}
}

// Stop closes the event channel. It is safe to call multiple times.
func (w *fakeWatcher[T]) Stop() {
	w.once.Do(func() {
		w.mu.Lock()
		w.stopped = true
		w.mu.Unlock()
		close(w.stopCh)
		<-w.done
	})
}

// isStopped returns true if Stop has been called.
func (w *fakeWatcher[T]) isStopped() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.stopped
}

func (w *fakeWatcher[T]) run() {
	defer close(w.done)
	defer close(w.ch)
	for {
		w.mu.Lock()
		if len(w.queue) > 0 {
			event := w.queue[0]
			w.queue = w.queue[1:]
			w.mu.Unlock()
			select {
			case w.ch <- event:
			case <-w.stopCh:
				return
			}
			continue
		}
		w.mu.Unlock()
		select {
		case <-w.wake:
		case <-w.stopCh:
			return
		}
	}
}
