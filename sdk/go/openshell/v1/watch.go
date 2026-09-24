// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"
	"sync"
	"time"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
)

// Event represents a watch event carrying a resource that changed.
type Event[T any] = types.Event[T]

// WatchInterface delivers a stream of typed events. Modeled after
// k8s.io/apimachinery/pkg/watch.Interface.
type WatchInterface[T any] = types.WatchInterface[T]

type watcher[T any] struct {
	result   chan Event[T]
	done     chan struct{}
	cancel   context.CancelFunc
	stopOnce sync.Once
}

func newWatcher[T any](ch chan Event[T], cancel context.CancelFunc) *watcher[T] {
	return &watcher[T]{
		result: ch,
		done:   make(chan struct{}),
		cancel: cancel,
	}
}

// emit delivers an event unless the watcher was stopped or the context ended
// first. Returns false when the caller should stop producing.
func (w *watcher[T]) emit(ctx context.Context, ev Event[T]) bool {
	select {
	case w.result <- ev:
		return true
	case <-w.done:
		return false
	case <-ctx.Done():
		return false
	}
}

// sleep waits for d, returning false if the watcher was stopped or the context
// ended first.
func (w *watcher[T]) sleep(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-w.done:
		return false
	case <-ctx.Done():
		return false
	}
}

// stopped reports whether the consumer already called Stop.
func (w *watcher[T]) stopped() bool {
	select {
	case <-w.done:
		return true
	default:
		return false
	}
}

func (w *watcher[T]) ResultChan() <-chan Event[T] {
	return w.result
}

func (w *watcher[T]) Stop() {
	w.stopOnce.Do(func() {
		close(w.done)
		if w.cancel != nil {
			w.cancel()
		}
	})
}
