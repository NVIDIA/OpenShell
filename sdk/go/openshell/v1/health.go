// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
)

// HealthResult holds the result of a health check.
type HealthResult = types.HealthResult

// HealthInterface defines health check operations.
type HealthInterface interface {
	Check(ctx context.Context) (*HealthResult, error)
}
