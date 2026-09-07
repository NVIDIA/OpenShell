// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"
	"sync"

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
