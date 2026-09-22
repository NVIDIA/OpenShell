// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package converter

import (
	"testing"
	"time"

	v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestFromGRPCError_PreservesStructuredAndUnknownDetails(t *testing.T) {
	st, err := status.New(codes.ResourceExhausted, "try later").WithDetails(
		&errdetails.BadRequest{FieldViolations: []*errdetails.BadRequest_FieldViolation{
			{Field: "name", Description: "too long"},
		}},
		&errdetails.ErrorInfo{Reason: "RATE_LIMITED", Domain: "openshell.nvidia.com", Metadata: map[string]string{"key": "value"}},
		&errdetails.RetryInfo{RetryDelay: durationpb.New(time.Second)},
		wrapperspb.String("unrecognized detail"),
	)
	require.NoError(t, err)
	raw := st.Err()
	converted := FromGRPCError(raw)
	var typed *v1.StatusError
	require.ErrorAs(t, converted, &typed)
	assert.Equal(t, int32(codes.ResourceExhausted), typed.GRPCCode)
	assert.Equal(t, []v1.FieldViolation{{Field: "name", Description: "too long"}}, typed.FieldViolations)
	require.NotNil(t, typed.ErrorInfo)
	assert.Equal(t, "RATE_LIMITED", typed.ErrorInfo.Reason)
	require.NotNil(t, typed.RetryDelay)
	assert.Equal(t, time.Second, *typed.RetryDelay)
	assert.Same(t, raw, typed.Cause)
	// errors.Unwrap/status.FromError still exposes every original Any.
	assert.Equal(t, st.Proto().GetDetails(), status.Convert(converted).Proto().GetDetails())
	typed.ErrorInfo.Metadata["key"] = "changed"
	assert.Equal(t, "value", st.Details()[1].(*errdetails.ErrorInfo).GetMetadata()["key"])
}

func TestFromGRPCError_IgnoresInvalidRetryDelay(t *testing.T) {
	st, err := status.New(codes.Unavailable, "try later").WithDetails(
		&errdetails.RetryInfo{RetryDelay: durationpb.New(-time.Second)},
	)
	require.NoError(t, err)
	var typed *v1.StatusError
	require.ErrorAs(t, FromGRPCError(st.Err()), &typed)
	assert.Nil(t, typed.RetryDelay)
}

func TestFromGRPCError_NotFound(t *testing.T) {
	grpcErr := status.Error(codes.NotFound, "sandbox not found")
	err := FromGRPCError(grpcErr)
	require.Error(t, err)
	assert.True(t, v1.IsNotFound(err))
}

func TestFromGRPCError_AlreadyExists(t *testing.T) {
	grpcErr := status.Error(codes.AlreadyExists, "already exists")
	err := FromGRPCError(grpcErr)
	require.Error(t, err)
	assert.True(t, v1.IsAlreadyExists(err))
}

func TestFromGRPCError_Unavailable(t *testing.T) {
	grpcErr := status.Error(codes.Unavailable, "service down")
	err := FromGRPCError(grpcErr)
	require.Error(t, err)
	assert.True(t, v1.IsUnavailable(err))
}

func TestFromGRPCError_PermissionDenied(t *testing.T) {
	grpcErr := status.Error(codes.PermissionDenied, "denied")
	err := FromGRPCError(grpcErr)
	require.Error(t, err)
	assert.True(t, v1.IsPermissionDenied(err))
}

func TestFromGRPCError_InvalidArgument(t *testing.T) {
	grpcErr := status.Error(codes.InvalidArgument, "bad arg")
	err := FromGRPCError(grpcErr)
	require.Error(t, err)
	assert.True(t, v1.IsInvalidArgument(err))
}

func TestFromGRPCError_DeadlineExceeded(t *testing.T) {
	grpcErr := status.Error(codes.DeadlineExceeded, "timeout")
	err := FromGRPCError(grpcErr)
	require.Error(t, err)
	assert.True(t, v1.IsDeadlineExceeded(err))
}

func TestFromGRPCError_Cancelled(t *testing.T) {
	grpcErr := status.Error(codes.Canceled, "cancelled")
	err := FromGRPCError(grpcErr)
	require.Error(t, err)
	assert.True(t, v1.IsCancelled(err))
}

func TestFromGRPCError_Internal(t *testing.T) {
	grpcErr := status.Error(codes.Internal, "internal error")
	err := FromGRPCError(grpcErr)
	require.Error(t, err)

	var se *v1.StatusError
	require.ErrorAs(t, err, &se)
	assert.Equal(t, v1.ErrorInternal, se.Code)
}

func TestFromGRPCError_Unimplemented(t *testing.T) {
	grpcErr := status.Error(codes.Unimplemented, "not implemented")
	err := FromGRPCError(grpcErr)
	require.Error(t, err)

	var se *v1.StatusError
	require.ErrorAs(t, err, &se)
	assert.Equal(t, v1.ErrorUnimplemented, se.Code)
}

func TestFromGRPCError_Aborted(t *testing.T) {
	grpcErr := status.Error(codes.Aborted, "version conflict")
	err := FromGRPCError(grpcErr)
	require.Error(t, err)
	assert.True(t, v1.IsConflict(err))

	var se *v1.StatusError
	require.ErrorAs(t, err, &se)
	assert.Equal(t, v1.ErrorConflict, se.Code)
	assert.Equal(t, "version conflict", se.Message)
}

func TestFromGRPCError_UnmappedCode(t *testing.T) {
	grpcErr := status.Error(codes.DataLoss, "data loss")
	err := FromGRPCError(grpcErr)
	require.Error(t, err)

	var se *v1.StatusError
	require.ErrorAs(t, err, &se)
	assert.Equal(t, v1.ErrorInternal, se.Code)
}

func TestFromGRPCError_NilError(t *testing.T) {
	err := FromGRPCError(nil)
	assert.NoError(t, err)
}

func TestFromGRPCError_NonGRPCError(t *testing.T) {
	err := FromGRPCError(assert.AnError)
	require.Error(t, err)
	assert.Equal(t, assert.AnError, err)
}

func TestFromGRPCError_OKStatus(t *testing.T) {
	grpcErr := status.Error(codes.OK, "")
	err := FromGRPCError(grpcErr)
	assert.NoError(t, err)
}
