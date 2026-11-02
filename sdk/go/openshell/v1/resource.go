// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"
	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/internal/converter"
	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
)

// Probe only budget-bearing writes. Public health acknowledges wire support;
// compute admission remains responsible for the requested resource guarantee.
func requireSampledBudgetSupport(ctx context.Context, client pb.OpenShellClient) error {
	health, err := client.Health(ctx, &pb.HealthRequest{})
	if err != nil {
		return converter.FromGRPCError(err)
	}
	if !health.GetSupportsSampledResourceBudget() {
		return &StatusError{Code: ErrorInvalidArgument, Message: "gateway does not acknowledge sampled resource budgets; upgrade it before creating this workload"}
	}
	return nil
}
