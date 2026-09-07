// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStatusError_Error(t *testing.T) {
	err := &StatusError{
		Code:    ErrorNotFound,
		Message: "sandbox not found",
	}
	s := err.Error()
	assert.Contains(t, s, "NotFound")
	assert.Contains(t, s, "sandbox not found")
}

func TestStatusError_ErrorWithCause(t *testing.T) {
	cause := errors.New("underlying error")
	err := &StatusError{
		Code:    ErrorInvalidArgument,
		Message: "bad name",
		Cause:   cause,
	}
	s := err.Error()
	assert.Contains(t, s, "InvalidArgument")
	assert.Contains(t, s, "bad name")
	assert.Equal(t, cause, errors.Unwrap(err))
}

func TestIsNotFound(t *testing.T) {
	err := &StatusError{Code: ErrorNotFound, Message: "not found"}
	assert.True(t, IsNotFound(err))
	assert.False(t, IsAlreadyExists(err))
}

func TestIsAlreadyExists(t *testing.T) {
	err := &StatusError{Code: ErrorAlreadyExists, Message: "exists"}
	assert.True(t, IsAlreadyExists(err))
	assert.False(t, IsNotFound(err))
}

func TestIsUnavailable(t *testing.T) {
	err := &StatusError{Code: ErrorUnavailable, Message: "down"}
	assert.True(t, IsUnavailable(err))
}

func TestIsPermissionDenied(t *testing.T) {
	err := &StatusError{Code: ErrorPermissionDenied, Message: "denied"}
	assert.True(t, IsPermissionDenied(err))
}

func TestIsInvalidArgument(t *testing.T) {
	err := &StatusError{Code: ErrorInvalidArgument, Message: "invalid"}
	assert.True(t, IsInvalidArgument(err))
}

func TestIsDeadlineExceeded(t *testing.T) {
	err := &StatusError{Code: ErrorDeadlineExceeded, Message: "timeout"}
	assert.True(t, IsDeadlineExceeded(err))
}

func TestIsCancelled(t *testing.T) {
	err := &StatusError{Code: ErrorCancelled, Message: "cancelled"}
	assert.True(t, IsCancelled(err))
}

func TestIsConflict(t *testing.T) {
	err := &StatusError{Code: ErrorConflict, Message: "version conflict"}
	assert.True(t, IsConflict(err))
	assert.False(t, IsNotFound(err))
}

func TestIsHelpers_NonStatusError(t *testing.T) {
	err := errors.New("plain error")
	assert.False(t, IsNotFound(err))
	assert.False(t, IsAlreadyExists(err))
	assert.False(t, IsUnavailable(err))
	assert.False(t, IsPermissionDenied(err))
	assert.False(t, IsInvalidArgument(err))
	assert.False(t, IsDeadlineExceeded(err))
	assert.False(t, IsCancelled(err))
	assert.False(t, IsConflict(err))
}

func TestIsHelpers_NilError(t *testing.T) {
	assert.False(t, IsNotFound(nil))
	assert.False(t, IsConflict(nil))
}

func TestStatusError_WrappedError(t *testing.T) {
	inner := &StatusError{Code: ErrorNotFound, Message: "not found"}
	wrapped := fmt.Errorf("operation failed: %w", inner)
	assert.True(t, IsNotFound(wrapped))

	var se *StatusError
	require.True(t, errors.As(wrapped, &se))
	assert.Equal(t, ErrorNotFound, se.Code)
}

func TestErrorCode_String(t *testing.T) {
	tests := []struct {
		code ErrorCode
		want string
	}{
		{ErrorNotFound, "NotFound"},
		{ErrorAlreadyExists, "AlreadyExists"},
		{ErrorUnavailable, "Unavailable"},
		{ErrorPermissionDenied, "PermissionDenied"},
		{ErrorInvalidArgument, "InvalidArgument"},
		{ErrorDeadlineExceeded, "DeadlineExceeded"},
		{ErrorCancelled, "Cancelled"},
		{ErrorInternal, "Internal"},
		{ErrorUnimplemented, "Unimplemented"},
		{ErrorConflict, "Conflict"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, tt.code.String())
	}
}
