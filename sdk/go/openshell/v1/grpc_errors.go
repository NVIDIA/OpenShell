// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package v1 provides the OpenShell SDK client.
// gRPC error conversion is handled by the internal/converter package.
package v1

import "context"

func contextError(err error) error {
	if err == nil {
		return nil
	}
	switch err {
	case context.DeadlineExceeded:
		return &StatusError{Code: ErrorDeadlineExceeded, Message: err.Error(), Cause: err}
	case context.Canceled:
		return &StatusError{Code: ErrorCancelled, Message: err.Error(), Cause: err}
	default:
		return &StatusError{Code: ErrorInternal, Message: err.Error(), Cause: err}
	}
}
