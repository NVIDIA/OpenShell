// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
)

// ErrorCode classifies SDK errors by their gRPC origin.
type ErrorCode = types.ErrorCode

// ErrorCode values for classifying gRPC errors.
const (
	ErrorNotFound         = types.ErrorNotFound
	ErrorAlreadyExists    = types.ErrorAlreadyExists
	ErrorUnavailable      = types.ErrorUnavailable
	ErrorPermissionDenied = types.ErrorPermissionDenied
	ErrorInvalidArgument  = types.ErrorInvalidArgument
	ErrorDeadlineExceeded = types.ErrorDeadlineExceeded
	ErrorCancelled        = types.ErrorCancelled
	ErrorInternal         = types.ErrorInternal
	ErrorUnimplemented    = types.ErrorUnimplemented
	ErrorConflict         = types.ErrorConflict
	ErrorUnauthenticated  = types.ErrorUnauthenticated
)

// StatusError is the typed error returned by all SDK operations.
type StatusError = types.StatusError

// IsNotFound returns true if the error indicates a resource was not found.
func IsNotFound(err error) bool { return types.IsNotFound(err) }

// IsAlreadyExists returns true if the error indicates a resource already exists.
func IsAlreadyExists(err error) bool { return types.IsAlreadyExists(err) }

// IsUnavailable returns true if the error indicates the service is unavailable.
func IsUnavailable(err error) bool { return types.IsUnavailable(err) }

// IsPermissionDenied returns true if the error indicates insufficient permissions.
func IsPermissionDenied(err error) bool { return types.IsPermissionDenied(err) }

// IsInvalidArgument returns true if the error indicates an invalid argument.
func IsInvalidArgument(err error) bool { return types.IsInvalidArgument(err) }

// IsDeadlineExceeded returns true if the error indicates a deadline was exceeded.
func IsDeadlineExceeded(err error) bool { return types.IsDeadlineExceeded(err) }

// IsCancelled returns true if the error indicates the operation was cancelled.
func IsCancelled(err error) bool { return types.IsCancelled(err) }

// IsUnimplemented returns true if the error indicates the operation is not implemented.
func IsUnimplemented(err error) bool { return types.IsUnimplemented(err) }

// IsConflict returns true if the error indicates a conflict, such as
// optimistic concurrency or an invalid state transition.
func IsConflict(err error) bool { return types.IsConflict(err) }

// IsUnauthenticated returns true if the error indicates missing or invalid credentials.
func IsUnauthenticated(err error) bool { return types.IsUnauthenticated(err) }
