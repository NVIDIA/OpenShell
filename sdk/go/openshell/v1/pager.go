// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"
	"errors"
)

const (
	maxConsumedPageTokens     = 10_000
	maxConsumedPageTokenBytes = 1 << 20
)

// Page is one response page from a list operation.
type Page[T any] struct {
	Items         []T
	NextPageToken string
}

type pageFetcher[T any] func(context.Context, string) (*Page[T], error)

// Pager lazily fetches pages from the continuation-token contract.
//
// A Pager is single-pass and must not be used concurrently. Its repeated-token
// guard has bounded memory and returns an error if the traversal exceeds its
// token-count or byte budget.
type Pager[T any] struct {
	fetch                 pageFetcher[T]
	nextPageToken         *string
	consumedTokens        map[string]struct{}
	consumedTokenBytes    int
	maxConsumedTokens     int
	maxConsumedTokenBytes int
}

// NewPager constructs a pager from an RPC page fetcher.
func NewPager[T any](pageToken string, fetch func(context.Context, string) (*Page[T], error)) *Pager[T] {
	return &Pager[T]{
		fetch:                 fetch,
		nextPageToken:         &pageToken,
		consumedTokens:        make(map[string]struct{}),
		maxConsumedTokens:     maxConsumedPageTokens,
		maxConsumedTokenBytes: maxConsumedPageTokenBytes,
	}
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
	if *p.nextPageToken != "" {
		tokenBytes := len(*p.nextPageToken)
		if len(p.consumedTokens) >= p.maxConsumedTokens || tokenBytes > p.maxConsumedTokenBytes-p.consumedTokenBytes {
			return nil, errors.New("pager continuation token history limit exceeded")
		}
		p.consumedTokens[*p.nextPageToken] = struct{}{}
		p.consumedTokenBytes += tokenBytes
	}
	if _, seen := p.consumedTokens[page.NextPageToken]; page.NextPageToken != "" && seen {
		return nil, errors.New("pager received a repeated continuation token")
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
