// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"errors"
	"fmt"
)

// ErrorCode classifies SDK errors by their gRPC origin.
type ErrorCode int

// ErrorCode values for classifying gRPC errors.
const (
	ErrorNotFound ErrorCode = iota + 1
	ErrorAlreadyExists
	ErrorUnavailable
	ErrorPermissionDenied
	ErrorInvalidArgument
	ErrorDeadlineExceeded
	ErrorCancelled
	ErrorInternal
	ErrorUnimplemented
	ErrorConflict
	ErrorUnauthenticated
)

// String returns the human-readable name of the error code.
func (c ErrorCode) String() string {
	switch c {
	case ErrorNotFound:
		return "NotFound"
	case ErrorAlreadyExists:
		return "AlreadyExists"
	case ErrorUnavailable:
		return "Unavailable"
	case ErrorPermissionDenied:
		return "PermissionDenied"
	case ErrorInvalidArgument:
		return "InvalidArgument"
	case ErrorDeadlineExceeded:
		return "DeadlineExceeded"
	case ErrorCancelled:
		return "Cancelled"
	case ErrorInternal:
		return "Internal"
	case ErrorUnimplemented:
		return "Unimplemented"
	case ErrorConflict:
		return "Conflict"
	case ErrorUnauthenticated:
		return "Unauthenticated"
	default:
		return fmt.Sprintf("Unknown(%d)", int(c))
	}
}

// StatusError is the typed error returned by all SDK operations.
type StatusError struct {
	Code    ErrorCode
	Message string
	Cause   error
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func (e *StatusError) Unwrap() error {
	return e.Cause
}

// IsNotFound returns true if the error indicates a resource was not found.
func IsNotFound(err error) bool {
	return hasCode(err, ErrorNotFound)
}

// IsAlreadyExists returns true if the error indicates a resource already exists.
func IsAlreadyExists(err error) bool {
	return hasCode(err, ErrorAlreadyExists)
}

// IsUnavailable returns true if the error indicates the service is unavailable.
func IsUnavailable(err error) bool {
	return hasCode(err, ErrorUnavailable)
}

// IsPermissionDenied returns true if the error indicates insufficient permissions.
func IsPermissionDenied(err error) bool {
	return hasCode(err, ErrorPermissionDenied)
}

// IsInvalidArgument returns true if the error indicates an invalid argument.
func IsInvalidArgument(err error) bool {
	return hasCode(err, ErrorInvalidArgument)
}

// IsDeadlineExceeded returns true if the error indicates a deadline was exceeded.
func IsDeadlineExceeded(err error) bool {
	return hasCode(err, ErrorDeadlineExceeded)
}

// IsCancelled returns true if the error indicates the operation was cancelled.
func IsCancelled(err error) bool {
	return hasCode(err, ErrorCancelled)
}

// IsUnimplemented returns true if the error indicates the operation is not implemented.
func IsUnimplemented(err error) bool {
	return hasCode(err, ErrorUnimplemented)
}

// IsConflict returns true if the error indicates a conflict, such as
// optimistic concurrency or an invalid state transition.
func IsConflict(err error) bool {
	return hasCode(err, ErrorConflict)
}

// IsUnauthenticated returns true if the error indicates invalid or missing credentials.
func IsUnauthenticated(err error) bool {
	return hasCode(err, ErrorUnauthenticated)
}

func hasCode(err error, code ErrorCode) bool {
	if err == nil {
		return false
	}
	var se *StatusError
	if errors.As(err, &se) {
		return se.Code == code
	}
	return false
}
