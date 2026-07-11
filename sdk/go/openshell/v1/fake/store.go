// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package fake

import (
	"fmt"
	"sync"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
)

// objectStore is a generic, thread-safe, in-memory store for named objects.
// It deep-copies objects at all boundaries (insert and retrieval) to prevent
// callers from mutating internal state.
type objectStore[T any] struct {
	mu       sync.RWMutex
	items    map[string]T
	nameFunc func(T) string
	copyFunc func(T) T
}

// newobjectStore creates a new objectStore with the given name-extraction
// and deep-copy functions.
func newobjectStore[T any](nameFunc func(T) string, copyFunc func(T) T) *objectStore[T] {
	return &objectStore[T]{
		items:    make(map[string]T),
		nameFunc: nameFunc,
		copyFunc: copyFunc,
	}
}

// Create adds a new object to the store. Returns AlreadyExists if an object
// with the same name already exists. The object is deep-copied on insert and
// a deep copy is returned.
func (s *objectStore[T]) Create(obj T) (T, error) {
	name := s.nameFunc(obj)
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.items[name]; exists {
		var zero T
		return zero, &types.StatusError{
			Code:    types.ErrorAlreadyExists,
			Message: fmt.Sprintf("%s already exists", name),
		}
	}

	stored := s.copyFunc(obj)
	s.items[name] = stored
	return s.copyFunc(stored), nil
}

// Get retrieves an object by name. Returns NotFound if the object does not exist.
// The returned object is a deep copy.
func (s *objectStore[T]) Get(name string) (T, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	obj, exists := s.items[name]
	if !exists {
		var zero T
		return zero, &types.StatusError{
			Code:    types.ErrorNotFound,
			Message: fmt.Sprintf("%s not found", name),
		}
	}
	return s.copyFunc(obj), nil
}

// List returns deep copies of all objects in the store. The order is not
// guaranteed.
func (s *objectStore[T]) List() []T {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]T, 0, len(s.items))
	for _, obj := range s.items {
		result = append(result, s.copyFunc(obj))
	}
	return result
}

// Update replaces an existing object in the store. Returns NotFound if the
// object does not exist. The object is deep-copied on insert and a deep copy
// is returned.
func (s *objectStore[T]) Update(obj T) (T, error) {
	name := s.nameFunc(obj)
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.items[name]; !exists {
		var zero T
		return zero, &types.StatusError{
			Code:    types.ErrorNotFound,
			Message: fmt.Sprintf("%s not found", name),
		}
	}

	stored := s.copyFunc(obj)
	s.items[name] = stored
	return s.copyFunc(stored), nil
}

// Delete removes an object from the store by name. The operation is
// idempotent — deleting a non-existent object is a no-op.
func (s *objectStore[T]) Delete(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.items, name)
}

// DeleteAndGet atomically removes an object from the store and returns a
// deep copy of the removed object. Returns the zero value and false if the
// object did not exist. This avoids the race between a separate Get+Delete.
func (s *objectStore[T]) DeleteAndGet(name string) (T, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	obj, exists := s.items[name]
	if !exists {
		var zero T
		return zero, false
	}
	delete(s.items, name)
	return s.copyFunc(obj), true
}

// Insert directly places an object into the store without checking for
// duplicates. This is intended for pre-seeding test fixtures. The object
// is deep-copied on insert.
func (s *objectStore[T]) Insert(obj T) {
	name := s.nameFunc(obj)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[name] = s.copyFunc(obj)
}
