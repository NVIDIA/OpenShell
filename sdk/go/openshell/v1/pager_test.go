// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPagerIsLazyAndFetchesOnePageAtATime(t *testing.T) {
	requests := make([]string, 0)
	pager := NewPager("resume-token", func(_ context.Context, token string) (*Page[string], error) {
		requests = append(requests, token)
		if token == "resume-token" {
			return &Page[string]{Items: []string{"first"}, NextPageToken: "second-token"}, nil
		}
		return &Page[string]{Items: []string{"second"}}, nil
	})

	assert.Empty(t, requests)
	first, err := pager.NextPage(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []string{"first"}, first.Items)
	assert.Equal(t, "second-token", first.NextPageToken)
	assert.Equal(t, []string{"resume-token"}, requests)

	second, err := pager.NextPage(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []string{"second"}, second.Items)
	assert.Equal(t, []string{"resume-token", "second-token"}, requests)

	done, err := pager.NextPage(context.Background())
	require.NoError(t, err)
	assert.Nil(t, done)
}

func TestPagerAllRetriesTheCurrentTokenAfterError(t *testing.T) {
	wantErr := errors.New("temporary")
	attempts := 0
	pager := NewPager("", func(_ context.Context, token string) (*Page[int], error) {
		assert.Empty(t, token)
		attempts++
		if attempts == 1 {
			return nil, wantErr
		}
		return &Page[int]{Items: []int{1, 2}}, nil
	})

	_, err := pager.NextPage(context.Background())
	assert.ErrorIs(t, err, wantErr)
	items, err := pager.All(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []int{1, 2}, items)
}

func TestPagerNormalizesEmptyItems(t *testing.T) {
	pager := NewPager("", func(_ context.Context, _ string) (*Page[string], error) {
		return &Page[string]{}, nil
	})

	page, err := pager.NextPage(context.Background())
	require.NoError(t, err)
	assert.NotNil(t, page.Items)
	assert.Empty(t, page.Items)
}

func TestPagerRejectsNilPage(t *testing.T) {
	pager := NewPager("resume-token", func(_ context.Context, token string) (*Page[string], error) {
		assert.Equal(t, "resume-token", token)
		return nil, nil
	})

	page, err := pager.NextPage(context.Background())
	assert.Nil(t, page)
	assert.EqualError(t, err, "pager fetch returned a nil page")
}
