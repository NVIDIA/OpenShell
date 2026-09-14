// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package converter maps between gRPC/proto types and SDK domain types.
package converter

import (
	"maps"
	"time"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var grpcToSDK = map[codes.Code]types.ErrorCode{
	codes.NotFound:           types.ErrorNotFound,
	codes.AlreadyExists:      types.ErrorAlreadyExists,
	codes.Unavailable:        types.ErrorUnavailable,
	codes.PermissionDenied:   types.ErrorPermissionDenied,
	codes.InvalidArgument:    types.ErrorInvalidArgument,
	codes.DeadlineExceeded:   types.ErrorDeadlineExceeded,
	codes.Canceled:           types.ErrorCancelled,
	codes.Internal:           types.ErrorInternal,
	codes.Unimplemented:      types.ErrorUnimplemented,
	codes.Aborted:            types.ErrorConflict,
	codes.Unauthenticated:    types.ErrorUnauthenticated,
	codes.FailedPrecondition: types.ErrorConflict,
	codes.ResourceExhausted:  types.ErrorUnavailable,
	codes.OutOfRange:         types.ErrorInvalidArgument,
}

// FromGRPCError converts a gRPC error to a typed StatusError.
// Returns nil for nil errors and OK status. Non-gRPC errors pass through unchanged.
func FromGRPCError(err error) error {
	if err == nil {
		return nil
	}

	st, ok := status.FromError(err)
	if !ok {
		return err
	}

	if st.Code() == codes.OK {
		return nil
	}

	code, mapped := grpcToSDK[st.Code()]
	if !mapped {
		code = types.ErrorInternal
	}

	result := &types.StatusError{
		Code:     code,
		Message:  st.Message(),
		Cause:    err,
		GRPCCode: int32(st.Code()),
	}
	for _, detail := range st.Details() {
		switch detail := detail.(type) {
		case *errdetails.BadRequest:
			for _, violation := range detail.GetFieldViolations() {
				result.FieldViolations = append(result.FieldViolations, types.FieldViolation{
					Field: violation.GetField(), Description: violation.GetDescription(),
				})
			}
		case *errdetails.ErrorInfo:
			result.ErrorInfo = &types.ErrorInfo{
				Reason: detail.GetReason(), Domain: detail.GetDomain(),
				Metadata: maps.Clone(detail.GetMetadata()),
			}
		case *errdetails.RetryInfo:
			delay := detail.GetRetryDelay()
			if delay != nil && delay.CheckValid() == nil && delay.GetSeconds() >= 0 && delay.GetNanos() >= 0 {
				// AsDuration saturates values that exceed time.Duration's range.
				value := time.Duration(delay.AsDuration())
				result.RetryDelay = &value
			}
		}
	}
	return result
}
