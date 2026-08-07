// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package types

// Event represents a watch event carrying a resource that changed.
type Event[T any] struct {
	Type   EventType
	Object T
	Err    error
}

// WatchInterface delivers a stream of typed events. Modeled after
// k8s.io/apimachinery/pkg/watch.Interface.
type WatchInterface[T any] interface {
	ResultChan() <-chan Event[T]
	Stop()
}
