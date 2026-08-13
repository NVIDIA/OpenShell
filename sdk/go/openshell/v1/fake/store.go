// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package fake

import (
	"fmt"
	"strings"
	"sync"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
)

func compositeKey(workspace, name string) string {
	return workspace + "/" + name
}

// objectStore is a generic, thread-safe, in-memory store for named objects.
// It deep-copies objects at all boundaries (insert and retrieval) to prevent
// callers from mutating internal state. Items are keyed by composite
// "workspace/name" keys for workspace isolation.
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

// Create adds a new object to the store scoped to the given workspace.
// Returns AlreadyExists if an object with the same workspace/name already
// exists. The object is deep-copied on insert and a deep copy is returned.
func (s *objectStore[T]) Create(workspace string, obj T) (T, error) {
	name := s.nameFunc(obj)
	key := compositeKey(workspace, name)
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.items[key]; exists {
		var zero T
		return zero, &types.StatusError{
			Code:    types.ErrorAlreadyExists,
			Message: fmt.Sprintf("%s already exists", name),
		}
	}

	stored := s.copyFunc(obj)
	s.items[key] = stored
	return s.copyFunc(stored), nil
}

// Get retrieves an object by workspace and name. Returns NotFound if the
// object does not exist. The returned object is a deep copy.
func (s *objectStore[T]) Get(workspace, name string) (T, error) {
	key := compositeKey(workspace, name)
	s.mu.RLock()
	defer s.mu.RUnlock()

	obj, exists := s.items[key]
	if !exists {
		var zero T
		return zero, &types.StatusError{
			Code:    types.ErrorNotFound,
			Message: fmt.Sprintf("%s not found", name),
		}
	}
	return s.copyFunc(obj), nil
}

// List returns deep copies of all objects in the given workspace.
func (s *objectStore[T]) List(workspace string) []T {
	prefix := workspace + "/"
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]T, 0)
	for key, obj := range s.items {
		if strings.HasPrefix(key, prefix) {
			result = append(result, s.copyFunc(obj))
		}
	}
	return result
}

// ListAll returns deep copies of all objects across all workspaces.
func (s *objectStore[T]) ListAll() []T {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]T, 0, len(s.items))
	for _, obj := range s.items {
		result = append(result, s.copyFunc(obj))
	}
	return result
}

// Update replaces an existing object in the store within the given workspace.
// Returns NotFound if the object does not exist. The object is deep-copied
// on insert and a deep copy is returned.
func (s *objectStore[T]) Update(workspace string, obj T) (T, error) {
	name := s.nameFunc(obj)
	key := compositeKey(workspace, name)
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.items[key]; !exists {
		var zero T
		return zero, &types.StatusError{
			Code:    types.ErrorNotFound,
			Message: fmt.Sprintf("%s not found", name),
		}
	}

	stored := s.copyFunc(obj)
	s.items[key] = stored
	return s.copyFunc(stored), nil
}

// Delete removes an object from the store by workspace and name. The
// operation is idempotent.
func (s *objectStore[T]) Delete(workspace, name string) {
	key := compositeKey(workspace, name)
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.items, key)
}

func (s *objectStore[T]) DeleteWorkspace(workspace string) {
	prefix := workspace + "/"
	s.mu.Lock()
	defer s.mu.Unlock()
	for key := range s.items {
		if strings.HasPrefix(key, prefix) {
			delete(s.items, key)
		}
	}
}

// DeleteAndGet atomically removes an object from the store and returns a
// deep copy of the removed object. Returns the zero value and false if the
// object did not exist.
func (s *objectStore[T]) DeleteAndGet(workspace, name string) (T, bool) {
	key := compositeKey(workspace, name)
	s.mu.Lock()
	defer s.mu.Unlock()

	obj, exists := s.items[key]
	if !exists {
		var zero T
		return zero, false
	}
	delete(s.items, key)
	return s.copyFunc(obj), true
}

// Insert directly places an object into the store without checking for
// duplicates. This is intended for pre-seeding test fixtures. The object
// is deep-copied on insert.
func (s *objectStore[T]) Insert(workspace string, obj T) {
	name := s.nameFunc(obj)
	key := compositeKey(workspace, name)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[key] = s.copyFunc(obj)
}
