// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package fake

import (
	"context"
	"strconv"

	v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1"
	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
)

func newSlicePager[T any](items []T, pageSize int, pageToken string) (*v1.Pager[T], error) {
	if pageSize < 0 {
		return nil, &types.StatusError{Code: types.ErrorInvalidArgument, Message: "page size must not be negative"}
	}
	if pageSize == 0 {
		pageSize = 100
	}
	if _, err := parsePageOffset(pageToken, len(items)); err != nil {
		return nil, err
	}
	return v1.NewPager(pageToken, func(_ context.Context, token string) (*v1.Page[T], error) {
		start, err := parsePageOffset(token, len(items))
		if err != nil {
			return nil, err
		}
		end := min(start+pageSize, len(items))
		next := ""
		if end < len(items) {
			next = strconv.Itoa(end)
		}
		pageItems := append(make([]T, 0, end-start), items[start:end]...)
		return &v1.Page[T]{Items: pageItems, NextPageToken: next}, nil
	}), nil
}

func parsePageOffset(token string, length int) (int, error) {
	if token == "" {
		return 0, nil
	}
	offset, err := strconv.Atoi(token)
	if err != nil || offset < 0 || offset > length {
		return 0, &types.StatusError{Code: types.ErrorInvalidArgument, Message: "invalid page token"}
	}
	return offset, nil
}
