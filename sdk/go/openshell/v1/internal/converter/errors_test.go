// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package converter

import (
	"testing"

	v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

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
