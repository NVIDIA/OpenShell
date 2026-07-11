// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package fake

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
)

// testItem is a simple struct used for objectStore tests.
type testItem struct {
	Name  string
	Value string
	Tags  map[string]string
}

func testItemName(t *testItem) string { return t.Name }

func copyTestItem(t *testItem) *testItem {
	if t == nil {
		return nil
	}
	c := *t
	if t.Tags != nil {
		c.Tags = make(map[string]string, len(t.Tags))
		for k, v := range t.Tags {
			c.Tags[k] = v
		}
	}
	return &c
}

func newTestStore() *objectStore[*testItem] {
	return newobjectStore(testItemName, copyTestItem)
}

// --- T004: objectStore CRUD tests ---

func TestObjectStore_Create(t *testing.T) {
	s := newTestStore()

	item := &testItem{Name: "alpha", Value: "v1"}
	created, err := s.Create(item)
	require.NoError(t, err)
	assert.Equal(t, "alpha", created.Name)
	assert.Equal(t, "v1", created.Value)
}

func TestObjectStore_Create_AlreadyExists(t *testing.T) {
	s := newTestStore()

	_, err := s.Create(&testItem{Name: "alpha", Value: "v1"})
	require.NoError(t, err)

	_, err = s.Create(&testItem{Name: "alpha", Value: "v2"})
	require.Error(t, err)
	assert.True(t, types.IsAlreadyExists(err), "expected AlreadyExists error, got: %v", err)
}

func TestObjectStore_Get(t *testing.T) {
	s := newTestStore()

	_, err := s.Create(&testItem{Name: "alpha", Value: "v1"})
	require.NoError(t, err)

	got, err := s.Get("alpha")
	require.NoError(t, err)
	assert.Equal(t, "alpha", got.Name)
	assert.Equal(t, "v1", got.Value)
}

func TestObjectStore_Get_NotFound(t *testing.T) {
	s := newTestStore()

	_, err := s.Get("nonexistent")
	require.Error(t, err)
	assert.True(t, types.IsNotFound(err), "expected NotFound error, got: %v", err)
}

func TestObjectStore_List_Empty(t *testing.T) {
	s := newTestStore()
	items := s.List()
	assert.Empty(t, items)
}

func TestObjectStore_List(t *testing.T) {
	s := newTestStore()

	_, _ = s.Create(&testItem{Name: "alpha", Value: "v1"})
	_, _ = s.Create(&testItem{Name: "beta", Value: "v2"})

	items := s.List()
	assert.Len(t, items, 2)

	// Sort for deterministic comparison
	sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })
	assert.Equal(t, "alpha", items[0].Name)
	assert.Equal(t, "beta", items[1].Name)
}

func TestObjectStore_Update(t *testing.T) {
	s := newTestStore()

	_, _ = s.Create(&testItem{Name: "alpha", Value: "v1"})

	updated, err := s.Update(&testItem{Name: "alpha", Value: "v2"})
	require.NoError(t, err)
	assert.Equal(t, "v2", updated.Value)

	// Verify the stored value is updated
	got, err := s.Get("alpha")
	require.NoError(t, err)
	assert.Equal(t, "v2", got.Value)
}

func TestObjectStore_Update_NotFound(t *testing.T) {
	s := newTestStore()

	_, err := s.Update(&testItem{Name: "nonexistent", Value: "v1"})
	require.Error(t, err)
	assert.True(t, types.IsNotFound(err), "expected NotFound error, got: %v", err)
}

func TestObjectStore_Delete(t *testing.T) {
	s := newTestStore()

	_, _ = s.Create(&testItem{Name: "alpha", Value: "v1"})
	s.Delete("alpha")

	_, err := s.Get("alpha")
	require.Error(t, err)
	assert.True(t, types.IsNotFound(err))
}

func TestObjectStore_Delete_Idempotent(_ *testing.T) {
	s := newTestStore()

	// Deleting a non-existent item should not panic or error
	s.Delete("nonexistent")

	// Create and delete twice
	_, _ = s.Create(&testItem{Name: "alpha", Value: "v1"})
	s.Delete("alpha")
	s.Delete("alpha") // second delete should be idempotent
}

func TestObjectStore_Insert(t *testing.T) {
	s := newTestStore()

	// Insert bypasses duplicate checks (for pre-seeding)
	s.Insert(&testItem{Name: "alpha", Value: "v1"})

	got, err := s.Get("alpha")
	require.NoError(t, err)
	assert.Equal(t, "v1", got.Value)
}

func TestObjectStore_Insert_Overwrites(t *testing.T) {
	s := newTestStore()

	s.Insert(&testItem{Name: "alpha", Value: "v1"})
	s.Insert(&testItem{Name: "alpha", Value: "v2"})

	got, err := s.Get("alpha")
	require.NoError(t, err)
	assert.Equal(t, "v2", got.Value)
}

func TestObjectStore_DeepCopy_OnCreate(t *testing.T) {
	s := newTestStore()

	original := &testItem{Name: "alpha", Value: "v1", Tags: map[string]string{"env": "test"}}
	created, err := s.Create(original)
	require.NoError(t, err)

	// Mutating original should not affect stored object
	original.Value = "mutated"
	original.Tags["env"] = "mutated"

	got, err := s.Get("alpha")
	require.NoError(t, err)
	assert.Equal(t, "v1", got.Value)
	assert.Equal(t, "test", got.Tags["env"])

	// Mutating returned object should not affect stored object
	created.Value = "mutated-created"
	got2, err := s.Get("alpha")
	require.NoError(t, err)
	assert.Equal(t, "v1", got2.Value)
}

func TestObjectStore_DeepCopy_OnGet(t *testing.T) {
	s := newTestStore()

	_, _ = s.Create(&testItem{Name: "alpha", Value: "v1", Tags: map[string]string{"env": "test"}})

	got, err := s.Get("alpha")
	require.NoError(t, err)

	// Mutating retrieved object should not affect stored object
	got.Value = "mutated"
	got.Tags["env"] = "mutated"

	got2, err := s.Get("alpha")
	require.NoError(t, err)
	assert.Equal(t, "v1", got2.Value)
	assert.Equal(t, "test", got2.Tags["env"])
}

func TestObjectStore_DeepCopy_OnList(t *testing.T) {
	s := newTestStore()

	_, _ = s.Create(&testItem{Name: "alpha", Value: "v1", Tags: map[string]string{"env": "test"}})

	items := s.List()
	require.Len(t, items, 1)

	// Mutating listed object should not affect stored object
	items[0].Value = "mutated"
	items[0].Tags["env"] = "mutated"

	got, err := s.Get("alpha")
	require.NoError(t, err)
	assert.Equal(t, "v1", got.Value)
	assert.Equal(t, "test", got.Tags["env"])
}

func TestObjectStore_DeepCopy_OnInsert(t *testing.T) {
	s := newTestStore()

	original := &testItem{Name: "alpha", Value: "v1", Tags: map[string]string{"env": "test"}}
	s.Insert(original)

	// Mutating original should not affect stored object
	original.Value = "mutated"
	original.Tags["env"] = "mutated"

	got, err := s.Get("alpha")
	require.NoError(t, err)
	assert.Equal(t, "v1", got.Value)
	assert.Equal(t, "test", got.Tags["env"])
}
