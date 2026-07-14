// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package types

// HealthResult holds the result of a health check.
type HealthResult struct {
	Healthy bool
	Version string
}
