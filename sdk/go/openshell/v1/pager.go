// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"
	"errors"
)

// Page is one response page from a list operation.
type Page[T any] struct {
	Items         []T
	NextPageToken string
}

type pageFetcher[T any] func(context.Context, string) (*Page[T], error)

// Pager lazily fetches one RPC page per call to NextPage.
//
// A Pager is single-pass and must not be used concurrently.
type Pager[T any] struct {
	fetch         pageFetcher[T]
	nextPageToken *string
}

// NewPager constructs a pager from an RPC page fetcher.
func NewPager[T any](pageToken string, fetch func(context.Context, string) (*Page[T], error)) *Pager[T] {
	return &Pager[T]{fetch: fetch, nextPageToken: &pageToken}
}

func newPager[T any](pageToken string, fetch pageFetcher[T]) *Pager[T] {
	return NewPager(pageToken, fetch)
}

// NextPage fetches the next page. It returns nil after the final page.
func (p *Pager[T]) NextPage(ctx context.Context) (*Page[T], error) {
	if p.nextPageToken == nil {
		return nil, nil
	}
	page, err := p.fetch(ctx, *p.nextPageToken)
	if err != nil {
		return nil, err
	}
	if page == nil {
		return nil, errors.New("pager fetch returned a nil page")
	}
	if page.Items == nil {
		page.Items = make([]T, 0)
	}
	if page.NextPageToken == "" {
		p.nextPageToken = nil
	} else {
		next := page.NextPageToken
		p.nextPageToken = &next
	}
	return page, nil
}

// All consumes the pager and collects every remaining item.
func (p *Pager[T]) All(ctx context.Context) ([]T, error) {
	items := make([]T, 0)
	for {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		if page == nil {
			return items, nil
		}
		items = append(items, page.Items...)
	}
}
