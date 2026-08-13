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

func TestContextError_Nil(t *testing.T) {
	result := contextError(nil)
	assert.Nil(t, result)
}

func TestContextError_DeadlineExceeded(t *testing.T) {
	result := contextError(context.DeadlineExceeded)

	require.Error(t, result)
	var se *StatusError
	require.True(t, errors.As(result, &se))
	assert.Equal(t, ErrorDeadlineExceeded, se.Code)
	assert.True(t, errors.Is(result, context.DeadlineExceeded))
}

func TestContextError_Canceled(t *testing.T) {
	result := contextError(context.Canceled)

	require.Error(t, result)
	var se *StatusError
	require.True(t, errors.As(result, &se))
	assert.Equal(t, ErrorCancelled, se.Code)
	assert.True(t, errors.Is(result, context.Canceled))
}

func TestContextError_Default(t *testing.T) {
	orig := errors.New("unexpected context error")
	result := contextError(orig)

	require.Error(t, result)
	var se *StatusError
	require.True(t, errors.As(result, &se))
	assert.Equal(t, ErrorInternal, se.Code)
	assert.True(t, errors.Is(result, orig))
}
