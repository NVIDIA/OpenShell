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

const testWorkspace = "default"

func TestObjectStore_Create(t *testing.T) {
	s := newTestStore()

	item := &testItem{Name: "alpha", Value: "v1"}
	created, err := s.Create(testWorkspace, item)
	require.NoError(t, err)
	assert.Equal(t, "alpha", created.Name)
	assert.Equal(t, "v1", created.Value)
}

func TestObjectStore_Create_AlreadyExists(t *testing.T) {
	s := newTestStore()

	_, err := s.Create(testWorkspace, &testItem{Name: "alpha", Value: "v1"})
	require.NoError(t, err)

	_, err = s.Create(testWorkspace, &testItem{Name: "alpha", Value: "v2"})
	require.Error(t, err)
	assert.True(t, types.IsAlreadyExists(err), "expected AlreadyExists error, got: %v", err)
}

func TestObjectStore_Create_SameNameDifferentWorkspace(t *testing.T) {
	s := newTestStore()

	_, err := s.Create("ws-a", &testItem{Name: "alpha", Value: "v1"})
	require.NoError(t, err)

	_, err = s.Create("ws-b", &testItem{Name: "alpha", Value: "v2"})
	require.NoError(t, err)

	gotA, err := s.Get("ws-a", "alpha")
	require.NoError(t, err)
	assert.Equal(t, "v1", gotA.Value)

	gotB, err := s.Get("ws-b", "alpha")
	require.NoError(t, err)
	assert.Equal(t, "v2", gotB.Value)
}

func TestObjectStore_Get(t *testing.T) {
	s := newTestStore()

	_, err := s.Create(testWorkspace, &testItem{Name: "alpha", Value: "v1"})
	require.NoError(t, err)

	got, err := s.Get(testWorkspace, "alpha")
	require.NoError(t, err)
	assert.Equal(t, "alpha", got.Name)
	assert.Equal(t, "v1", got.Value)
}

func TestObjectStore_Get_NotFound(t *testing.T) {
	s := newTestStore()

	_, err := s.Get(testWorkspace, "nonexistent")
	require.Error(t, err)
	assert.True(t, types.IsNotFound(err), "expected NotFound error, got: %v", err)
}

func TestObjectStore_Get_WrongWorkspace(t *testing.T) {
	s := newTestStore()

	_, err := s.Create("ws-a", &testItem{Name: "alpha", Value: "v1"})
	require.NoError(t, err)

	_, err = s.Get("ws-b", "alpha")
	require.Error(t, err)
	assert.True(t, types.IsNotFound(err), "expected NotFound for wrong workspace")
}

func TestObjectStore_List_Empty(t *testing.T) {
	s := newTestStore()
	items := s.List(testWorkspace)
	assert.Empty(t, items)
}

func TestObjectStore_List(t *testing.T) {
	s := newTestStore()

	_, _ = s.Create(testWorkspace, &testItem{Name: "alpha", Value: "v1"})
	_, _ = s.Create(testWorkspace, &testItem{Name: "beta", Value: "v2"})

	items := s.List(testWorkspace)
	assert.Len(t, items, 2)

	sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })
	assert.Equal(t, "alpha", items[0].Name)
	assert.Equal(t, "beta", items[1].Name)
}

func TestObjectStore_List_WorkspaceIsolation(t *testing.T) {
	s := newTestStore()

	_, _ = s.Create("ws-a", &testItem{Name: "alpha", Value: "v1"})
	_, _ = s.Create("ws-b", &testItem{Name: "beta", Value: "v2"})
	_, _ = s.Create("ws-a", &testItem{Name: "gamma", Value: "v3"})

	itemsA := s.List("ws-a")
	assert.Len(t, itemsA, 2)

	itemsB := s.List("ws-b")
	assert.Len(t, itemsB, 1)
	assert.Equal(t, "beta", itemsB[0].Name)
}

func TestObjectStore_ListAll(t *testing.T) {
	s := newTestStore()

	_, _ = s.Create("ws-a", &testItem{Name: "alpha", Value: "v1"})
	_, _ = s.Create("ws-b", &testItem{Name: "beta", Value: "v2"})
	_, _ = s.Create("ws-a", &testItem{Name: "gamma", Value: "v3"})

	all := s.ListAll()
	assert.Len(t, all, 3)
}

func TestObjectStore_Update(t *testing.T) {
	s := newTestStore()

	_, _ = s.Create(testWorkspace, &testItem{Name: "alpha", Value: "v1"})

	updated, err := s.Update(testWorkspace, &testItem{Name: "alpha", Value: "v2"})
	require.NoError(t, err)
	assert.Equal(t, "v2", updated.Value)

	got, err := s.Get(testWorkspace, "alpha")
	require.NoError(t, err)
	assert.Equal(t, "v2", got.Value)
}

func TestObjectStore_Update_NotFound(t *testing.T) {
	s := newTestStore()

	_, err := s.Update(testWorkspace, &testItem{Name: "nonexistent", Value: "v1"})
	require.Error(t, err)
	assert.True(t, types.IsNotFound(err), "expected NotFound error, got: %v", err)
}

func TestObjectStore_Delete(t *testing.T) {
	s := newTestStore()

	_, _ = s.Create(testWorkspace, &testItem{Name: "alpha", Value: "v1"})
	s.Delete(testWorkspace, "alpha")

	_, err := s.Get(testWorkspace, "alpha")
	require.Error(t, err)
	assert.True(t, types.IsNotFound(err))
}

func TestObjectStore_Delete_Idempotent(_ *testing.T) {
	s := newTestStore()

	s.Delete(testWorkspace, "nonexistent")

	_, _ = s.Create(testWorkspace, &testItem{Name: "alpha", Value: "v1"})
	s.Delete(testWorkspace, "alpha")
	s.Delete(testWorkspace, "alpha")
}

func TestObjectStore_Insert(t *testing.T) {
	s := newTestStore()

	s.Insert(testWorkspace, &testItem{Name: "alpha", Value: "v1"})

	got, err := s.Get(testWorkspace, "alpha")
	require.NoError(t, err)
	assert.Equal(t, "v1", got.Value)
}

func TestObjectStore_Insert_Overwrites(t *testing.T) {
	s := newTestStore()

	s.Insert(testWorkspace, &testItem{Name: "alpha", Value: "v1"})
	s.Insert(testWorkspace, &testItem{Name: "alpha", Value: "v2"})

	got, err := s.Get(testWorkspace, "alpha")
	require.NoError(t, err)
	assert.Equal(t, "v2", got.Value)
}

func TestObjectStore_DeepCopy_OnCreate(t *testing.T) {
	s := newTestStore()

	original := &testItem{Name: "alpha", Value: "v1", Tags: map[string]string{"env": "test"}}
	created, err := s.Create(testWorkspace, original)
	require.NoError(t, err)

	original.Value = "mutated"
	original.Tags["env"] = "mutated"

	got, err := s.Get(testWorkspace, "alpha")
	require.NoError(t, err)
	assert.Equal(t, "v1", got.Value)
	assert.Equal(t, "test", got.Tags["env"])

	created.Value = "mutated-created"
	got2, err := s.Get(testWorkspace, "alpha")
	require.NoError(t, err)
	assert.Equal(t, "v1", got2.Value)
}

func TestObjectStore_DeepCopy_OnGet(t *testing.T) {
	s := newTestStore()

	_, _ = s.Create(testWorkspace, &testItem{Name: "alpha", Value: "v1", Tags: map[string]string{"env": "test"}})

	got, err := s.Get(testWorkspace, "alpha")
	require.NoError(t, err)

	got.Value = "mutated"
	got.Tags["env"] = "mutated"

	got2, err := s.Get(testWorkspace, "alpha")
	require.NoError(t, err)
	assert.Equal(t, "v1", got2.Value)
	assert.Equal(t, "test", got2.Tags["env"])
}

func TestObjectStore_DeepCopy_OnList(t *testing.T) {
	s := newTestStore()

	_, _ = s.Create(testWorkspace, &testItem{Name: "alpha", Value: "v1", Tags: map[string]string{"env": "test"}})

	items := s.List(testWorkspace)
	require.Len(t, items, 1)

	items[0].Value = "mutated"
	items[0].Tags["env"] = "mutated"

	got, err := s.Get(testWorkspace, "alpha")
	require.NoError(t, err)
	assert.Equal(t, "v1", got.Value)
	assert.Equal(t, "test", got.Tags["env"])
}

func TestObjectStore_DeepCopy_OnInsert(t *testing.T) {
	s := newTestStore()

	original := &testItem{Name: "alpha", Value: "v1", Tags: map[string]string{"env": "test"}}
	s.Insert(testWorkspace, original)

	original.Value = "mutated"
	original.Tags["env"] = "mutated"

	got, err := s.Get(testWorkspace, "alpha")
	require.NoError(t, err)
	assert.Equal(t, "v1", got.Value)
	assert.Equal(t, "test", got.Tags["env"])
}
